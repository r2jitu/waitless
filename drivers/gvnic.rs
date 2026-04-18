// drivers/gvnic.rs — Google Virtual NIC (gVNIC) driver.
//
// Phase 1 scope: PCI probe, admin-queue bring-up, DESCRIBE_DEVICE.
// No datapath yet — we just log the device descriptor to serial so
// we can confirm the device speaks back on GCE. The datapath (TX/RX
// rings, RSS, etc.) lands in later phases.
//
// References (cloned locally while this driver was written):
//   https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-linux
//   https://github.com/GoogleCloudPlatform/compute-virtual-ethernet-freebsd
//
// gVNIC vs. virtio-net: virtio is standardized but GCE's legacy
// virtio backend doesn't actually distribute RX across queues (see
// reference_gce_legacy_mq.md). gVNIC is Google's own device format;
// it natively supports RSS, so this is the path to real multi-core
// scaling on GCE.
//
// Wire encoding: every multi-byte field in the BAR0 register window,
// admin-queue commands, and device descriptors is big-endian. The
// `reg_read32` / `reg_write32` helpers below swap on read/write so
// the rest of the code works in natural host-endian `u32`s.

use crate::{log, mmio_read32, mmio_write32};
use crate::pci;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use kernel::mm::{alloc_pages, phys_to_virt};
use kernel::sync::Spinlock;

// ---- PCI identity ----------------------------------------------------------

const PCI_VENDOR_GVE: u16 = 0x1ae0;
const PCI_DEVICE_GVE: u16 = 0x0042;

// ---- BAR0 register offsets (all fields big-endian on the wire) -------------
//
// Layout from `gve_register.h` in both the Linux and FreeBSD
// reference drivers. The first 12 bytes are read-only device
// advertising (status + max_tx / max_rx); the middle chunk is the
// legacy admin-queue interface; the trailing chunk is the modern
// 64-bit base-address form (unused on current GCE firmware).

const REG_DEVICE_STATUS: u64 = 0x00;
const REG_DRIVER_STATUS: u64 = 0x04;
const REG_MAX_TX_QUEUES: u64 = 0x08;
const REG_MAX_RX_QUEUES: u64 = 0x0C;
const REG_ADMINQ_PFN: u64 = 0x10;
const REG_ADMINQ_DOORBELL: u64 = 0x14;
const REG_ADMINQ_EVENT_COUNTER: u64 = 0x18;
// 0x1C..=0x1F: reserved (3) + driver_version (1)
// 0x20..=0x2B: modern adminq base_address_hi/lo + length (we don't use these)

const DEVICE_STATUS_RESET: u32 = 1 << 1;

// ---- Admin queue constants -------------------------------------------------

const ADMINQ_SIZE: usize = 4096; // single page, required by PFN addressing
const ADMINQ_SLOTS: usize = 64;  // ADMINQ_SIZE / sizeof(AdminqCommand)
const CMD_SIZE: usize = 64;

// Admin queue opcodes (only the ones Phase 1 needs are named).
const OP_DESCRIBE_DEVICE: u32 = 0x1;

// Adminq completion statuses.
const STATUS_UNSET: u32 = 0x0;
const STATUS_PASSED: u32 = 0x1;

// Version field the device expects in DESCRIBE_DEVICE.
const DEVICE_DESCRIPTOR_VERSION: u32 = 1;

// Maximum time we'll poll the event counter for a single command.
// Linux allows many seconds here; for Phase 1 we just need generous
// room for the device to service DESCRIBE_DEVICE in a freshly-booted
// VM.
const ADMINQ_WAIT_SPINS: u32 = 10_000_000;

// Device-option ids (only the ones we care to log at Phase 1).
const OPT_ID_GQI_RDA: u16 = 0x2;
const OPT_ID_GQI_QPL: u16 = 0x3;
const OPT_ID_DQO_RDA: u16 = 0x4;
const OPT_ID_DQO_QPL: u16 = 0x7;

// ---- Wire structures -------------------------------------------------------
//
// All numeric fields are big-endian on the wire. We read/write them
// through explicit byte-swap helpers (`put_be*` / `get_be*`) rather
// than `#[repr(packed)]` with `to_be()` per field — the helpers are
// cheaper to eyeball and survive any future alignment change.

/// One slot in the admin queue. 64 bytes, naturally aligned.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct AdminqCommand {
    bytes: [u8; CMD_SIZE],
}

impl AdminqCommand {
    const ZERO: Self = AdminqCommand { bytes: [0; CMD_SIZE] };
}

// ---- Driver state ----------------------------------------------------------

/// Publication guard. Set at the end of a successful `init()`. Lets
/// the rest of the system probe whether gVNIC came up without
/// racing against the init path on another core.
static GVNIC_OK: AtomicBool = AtomicBool::new(false);

struct State {
    /// Virtual address of the admin queue ring (one page, 64 × 64-byte
    /// commands). Backing physical page is held implicitly — we
    /// never free gVNIC allocations. Stored as a `u64` rather than a
    /// raw pointer so `State` can live behind a `Spinlock` (which
    /// requires `Send`).
    adminq_va: u64,
    /// Monotonically-increasing command counter. Writing this value
    /// to ADMINQ_DOORBELL tells the device "I've produced this many
    /// commands total"; waiting for ADMINQ_EVENT_COUNTER to catch up
    /// is how we wait for completion.
    prod_cnt: u32,
    /// Negotiated queue format — filled in by DESCRIBE_DEVICE.
    /// `None` until init runs. Phase 2+ reads this to pick a datapath.
    queue_format: Option<QueueFormat>,
    /// MAC from the device descriptor. Populated by DESCRIBE_DEVICE.
    mac: [u8; 6],
    /// Device-advertised caps from the device descriptor. Logged
    /// from init; consumed by later phases when they size rings.
    max_tx_queues: u32,
    max_rx_queues: u32,
    tx_queue_entries: u16,
    rx_queue_entries: u16,
    default_num_queues: u16,
    mtu: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueFormat {
    GqiRda,
    GqiQpl,
    DqoRda,
    DqoQpl,
}

impl QueueFormat {
    fn name(self) -> &'static [u8] {
        match self {
            QueueFormat::GqiRda => b"GQI_RDA",
            QueueFormat::GqiQpl => b"GQI_QPL",
            QueueFormat::DqoRda => b"DQO_RDA",
            QueueFormat::DqoQpl => b"DQO_QPL",
        }
    }
}

static STATE: Spinlock<Option<State>> = Spinlock::new(None);

// AtomicU64 cell used to publish the BAR0 virtual address cheaply —
// the hot register accessors want it without grabbing the state
// lock. Set before GVNIC_OK flips true.
static BAR0: AtomicU64 = AtomicU64::new(0);

// ---- Big-endian field helpers ---------------------------------------------

#[inline]
fn put_be16(dst: &mut [u8], offset: usize, v: u16) {
    dst[offset..offset + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn put_be32(dst: &mut [u8], offset: usize, v: u32) {
    dst[offset..offset + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn put_be64(dst: &mut [u8], offset: usize, v: u64) {
    dst[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
}

#[inline]
fn get_be16(src: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([src[offset], src[offset + 1]])
}

#[inline]
fn get_be32(src: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        src[offset], src[offset + 1], src[offset + 2], src[offset + 3],
    ])
}

// ---- BAR0 register accessors ----------------------------------------------
//
// The device presents the 32-bit registers in big-endian format, so
// every read/write goes through a byte-swap on host (x86_64 is LE).
// We never read these on aarch64 — gVNIC doesn't exist there — but
// the helpers compile regardless.

#[inline]
unsafe fn reg_read32(offset: u64) -> u32 {
    let base = BAR0.load(Ordering::Acquire);
    u32::from_be(unsafe { mmio_read32(base + offset) })
}

#[inline]
unsafe fn reg_write32(offset: u64, val: u32) {
    let base = BAR0.load(Ordering::Acquire);
    unsafe { mmio_write32(base + offset, val.to_be()) }
}

// ---- Public API ------------------------------------------------------------

/// Probe the PCI bus for a gVNIC device. Returns `true` if one is
/// present and init was attempted successfully. Intended as the
/// first-choice NIC on GCE; callers fall back to virtio-net on
/// `false`.
pub fn init() -> bool {
    if GVNIC_OK.load(Ordering::Acquire) {
        return true;
    }

    let idx = match pci::find_device(PCI_VENDOR_GVE, PCI_DEVICE_GVE) {
        Some(i) => i,
        None => {
            log(b"[gvnic] device not found on PCI bus\n");
            return false;
        }
    };
    let dev = pci::pci_device(idx);
    log(b"[gvnic] found device on PCI bus\n");

    // Enable bus master + memory space (bits 1 + 2 of Command). The
    // firmware on GCE's kernel-mode VM already programs BAR0, so we
    // only need to flip the enables.
    pci::enable_bus_mastering(dev.slot);
    // Memory Space enable (bit 1) isn't covered by enable_bus_mastering;
    // read Command and OR in 0x02. Do it via the 32-bit path since
    // GCE is x86_64.
    #[cfg(target_arch = "x86_64")]
    {
        let cmd = pci::read_config(dev.bus, dev.slot, dev.func, 0x04);
        pci::write_config(dev.bus, dev.slot, dev.func, 0x04, cmd | 0x06);
    }

    let bar_phys = pci::read_bar64(&dev, 0);
    if bar_phys == 0 {
        log(b"[gvnic] BAR0 is zero - firmware didn't assign it\n");
        return false;
    }
    let bar_virt = phys_to_virt(bar_phys) as u64;
    BAR0.store(bar_virt, Ordering::Release);

    // ── Read device advertising ──────────────────────────────────────────
    let dev_status = unsafe { reg_read32(REG_DEVICE_STATUS) };
    let max_tx = unsafe { reg_read32(REG_MAX_TX_QUEUES) };
    let max_rx = unsafe { reg_read32(REG_MAX_RX_QUEUES) };
    log(b"[gvnic] device_status=");
    log_hex32(dev_status);
    log(b" max_tx=");
    log_u32(max_tx);
    log(b" max_rx=");
    log_u32(max_rx);
    log(b"\n");

    // ── Allocate admin queue (one contiguous 4 KiB page) ─────────────────
    //
    // Legacy PFN addressing: we hand the device `phys >> 12` in the
    // ADMINQ_PFN register, so the ring MUST start on a 4 KiB boundary
    // and be exactly one page. `alloc_pages(1)` satisfies both and
    // returns a physical address on both architectures.
    let adminq_phys = alloc_pages(1);
    if adminq_phys == 0 {
        log(b"[gvnic] failed to allocate admin queue page\n");
        return false;
    }
    let adminq_va = phys_to_virt(adminq_phys) as u64;
    unsafe { ptr::write_bytes(adminq_va as *mut u8, 0, ADMINQ_SIZE); }

    // Publish the ring PFN. `adminq_phys >> 12` is what the device
    // expects. Reading it back is how Linux / FreeBSD check the
    // device accepted it.
    unsafe {
        reg_write32(REG_ADMINQ_PFN, (adminq_phys >> 12) as u32);
    }

    {
        let mut st = STATE.lock();
        *st = Some(State {
            adminq_va,
            prod_cnt: 0,
            queue_format: None,
            mac: [0; 6],
            max_tx_queues: max_tx,
            max_rx_queues: max_rx,
            tx_queue_entries: 0,
            rx_queue_entries: 0,
            default_num_queues: 0,
            mtu: 0,
        });
    }

    // ── DESCRIBE_DEVICE ─────────────────────────────────────────────────
    if !describe_device() {
        log(b"[gvnic] DESCRIBE_DEVICE failed - aborting bring-up\n");
        return false;
    }

    GVNIC_OK.store(true, Ordering::Release);
    log(b"[gvnic] admin queue up, DESCRIBE_DEVICE ok\n");
    true
}

/// Returns true if `init()` has completed successfully.
pub fn probe_ok() -> bool {
    GVNIC_OK.load(Ordering::Acquire)
}

// ---- DESCRIBE_DEVICE implementation ---------------------------------------
//
// One admin-queue command, one response DMA page. Submit, poll the
// event counter, parse the device descriptor, walk its option list,
// and remember everything Phase 2+ will need.

fn describe_device() -> bool {
    // Allocate a response page. The device writes the device
    // descriptor + option list into this buffer.
    let desc_phys = alloc_pages(1);
    if desc_phys == 0 {
        log(b"[gvnic] failed to allocate DESCRIBE_DEVICE response page\n");
        return false;
    }
    let desc_virt = phys_to_virt(desc_phys);
    unsafe { ptr::write_bytes(desc_virt, 0, 4096); }

    // Build the command. AdminqCommand is laid out as:
    //   u8[0..4]   opcode  (be32)
    //   u8[4..8]   status  (be32, written by device)
    //   u8[8..]    per-opcode payload
    //
    // For DESCRIBE_DEVICE the payload is:
    //   u8[8..16]  device_descriptor_addr (be64, physical)
    //   u8[16..20] device_descriptor_version (be32, = 1)
    //   u8[20..24] available_length (be32, = page size)
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_DESCRIBE_DEVICE);
    put_be64(&mut cmd.bytes, 8, desc_phys);
    put_be32(&mut cmd.bytes, 16, DEVICE_DESCRIPTOR_VERSION);
    put_be32(&mut cmd.bytes, 20, ADMINQ_SIZE as u32);

    if !submit_and_wait(&cmd) {
        return false;
    }

    // Re-read the slot — the device writes `status` back in-place.
    // Any slot in the ring would do; we submitted into slot
    // (prod_cnt-1) & mask.
    let status = unsafe { read_slot_status(current_slot_before_kick()) };
    if status != STATUS_PASSED {
        log(b"[gvnic] DESCRIBE_DEVICE status=");
        log_hex32(status);
        log(b"\n");
        return false;
    }

    parse_device_descriptor(desc_virt)
}

fn parse_device_descriptor(desc_virt: *mut u8) -> bool {
    // Device descriptor layout (40 bytes, all big-endian):
    //
    //   u64 max_registered_pages
    //   u16 reserved1
    //   u16 tx_queue_entries
    //   u16 rx_queue_entries
    //   u16 default_num_queues
    //   u16 mtu
    //   u16 counters
    //   u16 reserved2
    //   u16 rx_pages_per_qpl
    //   u8[6] mac
    //   u16 num_device_options
    //   u16 total_length
    //   u8[6] reserved3
    //
    // followed by `num_device_options` copies of `{ u16 id, u16 len,
    // u32 req_features }` plus a per-option payload of `len` bytes.

    let header_len = 40;
    let header: &[u8] = unsafe { core::slice::from_raw_parts(desc_virt, header_len) };

    let tx_entries = get_be16(header, 10);
    let rx_entries = get_be16(header, 12);
    let default_num_queues = get_be16(header, 14);
    let mtu = get_be16(header, 16);
    let rx_pages_per_qpl = get_be16(header, 22);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&header[24..30]);
    let num_options = get_be16(header, 30);
    let total_len = get_be16(header, 32) as usize;

    log(b"[gvnic] mtu=");
    log_u32(mtu as u32);
    log(b" default_num_queues=");
    log_u32(default_num_queues as u32);
    log(b" tx_entries=");
    log_u32(tx_entries as u32);
    log(b" rx_entries=");
    log_u32(rx_entries as u32);
    log(b" rx_pages_per_qpl=");
    log_u32(rx_pages_per_qpl as u32);
    log(b"\n");
    log(b"[gvnic] mac=");
    log_mac(&mac);
    log(b" num_options=");
    log_u32(num_options as u32);
    log(b"\n");

    // Walk the option list. For each option, print its id + length
    // and record the best queue-format we see. Preference order
    // matches Linux: DQO_RDA > DQO_QPL > GQI_RDA > GQI_QPL. We only
    // commit to one; Phase 2 will use it to pick a datapath.
    let mut best: Option<QueueFormat> = None;
    let mut offset = header_len;
    let end = if total_len > 0 && total_len <= ADMINQ_SIZE {
        total_len
    } else {
        ADMINQ_SIZE
    };
    for _ in 0..num_options {
        if offset + 8 > end { break; }
        let opt_hdr: &[u8] =
            unsafe { core::slice::from_raw_parts(desc_virt.add(offset), 8) };
        let id = get_be16(opt_hdr, 0);
        let len = get_be16(opt_hdr, 2) as usize;
        log(b"[gvnic]  option id=");
        log_u32(id as u32);
        log(b" len=");
        log_u32(len as u32);
        log(b"\n");

        // Promote `best` if this option is higher priority than what
        // we've seen so far. We target GQI_RDA for Phase 2 (simplest
        // from-scratch datapath), but Phase 1 just records what the
        // device advertised.
        let fmt = match id {
            OPT_ID_DQO_RDA => Some(QueueFormat::DqoRda),
            OPT_ID_DQO_QPL => Some(QueueFormat::DqoQpl),
            OPT_ID_GQI_RDA => Some(QueueFormat::GqiRda),
            OPT_ID_GQI_QPL => Some(QueueFormat::GqiQpl),
            _ => None,
        };
        if let Some(new) = fmt {
            best = Some(match best {
                None => new,
                Some(cur) => higher_priority(cur, new),
            });
        }

        offset += 8 + len;
    }

    if let Some(fmt) = best {
        log(b"[gvnic] queue_format=");
        log(fmt.name());
        log(b"\n");
    } else {
        log(b"[gvnic] no known queue format advertised - incompatible device\n");
        return false;
    }

    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.mac = mac;
        s.tx_queue_entries = tx_entries;
        s.rx_queue_entries = rx_entries;
        s.default_num_queues = default_num_queues;
        s.mtu = mtu;
        s.queue_format = best;
    }
    true
}

fn higher_priority(a: QueueFormat, b: QueueFormat) -> QueueFormat {
    fn rank(f: QueueFormat) -> u8 {
        match f {
            QueueFormat::DqoRda => 4,
            QueueFormat::DqoQpl => 3,
            QueueFormat::GqiRda => 2,
            QueueFormat::GqiQpl => 1,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

// ---- Admin-queue plumbing -------------------------------------------------

fn submit_and_wait(cmd: &AdminqCommand) -> bool {
    let expected_event_count;
    {
        let mut st = STATE.lock();
        let s = match st.as_mut() {
            Some(s) => s,
            None => return false,
        };
        let slot_idx = (s.prod_cnt as usize) & (ADMINQ_SLOTS - 1);
        let slot_ptr = (s.adminq_va as *mut AdminqCommand).wrapping_add(slot_idx);
        unsafe {
            ptr::write_volatile(slot_ptr, *cmd);
        }
        s.prod_cnt = s.prod_cnt.wrapping_add(1);
        expected_event_count = s.prod_cnt;
    }

    // Kick the device — write the new producer count to the doorbell.
    unsafe { reg_write32(REG_ADMINQ_DOORBELL, expected_event_count); }

    // Poll the event counter. When it catches up, our command has
    // completed. There's no HLT / WFE here yet — this is init-path
    // and spinning is fine.
    for _ in 0..ADMINQ_WAIT_SPINS {
        let ev = unsafe { reg_read32(REG_ADMINQ_EVENT_COUNTER) };
        if ev == expected_event_count {
            return true;
        }
        core::hint::spin_loop();
    }
    log(b"[gvnic] admin queue timeout\n");
    false
}

fn current_slot_before_kick() -> usize {
    // After submit_and_wait returns, the slot we just used is
    // (prod_cnt - 1) & mask. Read it back to pick up the device's
    // status write.
    let st = STATE.lock();
    let s = st.as_ref().expect("state");
    ((s.prod_cnt - 1) as usize) & (ADMINQ_SLOTS - 1)
}

unsafe fn read_slot_status(slot_idx: usize) -> u32 {
    let st = STATE.lock();
    let s = st.as_ref().expect("state");
    let slot_ptr = (s.adminq_va as *const AdminqCommand).wrapping_add(slot_idx);
    let slot = unsafe { &*slot_ptr };
    get_be32(&slot.bytes, 4)
}

// ---- Serial logging helpers ------------------------------------------------

fn log_u32(mut v: u32) {
    if v == 0 { log(b"0"); return; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut out = [0u8; 10];
    for i in 0..len { out[i] = tmp[len - 1 - i]; }
    log(&out[..len]);
}

fn log_hex32(v: u32) {
    let mut buf = [0u8; 10];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..8 {
        let nib = (v >> ((7 - i) * 4)) & 0xF;
        buf[2 + i] = if nib < 10 {
            b'0' + nib as u8
        } else {
            b'a' + (nib - 10) as u8
        };
    }
    log(&buf);
}

fn log_mac(mac: &[u8; 6]) {
    let hex = |n: u8, out: &mut [u8; 2]| {
        let h = |x: u8| if x < 10 { b'0' + x } else { b'a' + (x - 10) };
        out[0] = h(n >> 4);
        out[1] = h(n & 0xF);
    };
    let mut buf = [0u8; 17];
    for i in 0..6 {
        let mut pair = [0u8; 2];
        hex(mac[i], &mut pair);
        buf[i * 3] = pair[0];
        buf[i * 3 + 1] = pair[1];
        if i < 5 { buf[i * 3 + 2] = b':'; }
    }
    log(&buf);
}

// ---- Keep the compiler honest about unused bits ----------------------------
//
// `DEVICE_STATUS_RESET`, `STATUS_UNSET`, and `size_of::<AdminqCommand>`
// are only touched by later phases / diagnostics; reference them
// once here so Phase 1 still compiles with `-D unused`.
const _: () = {
    let _ = DEVICE_STATUS_RESET;
    let _ = STATUS_UNSET;
    let _ = OP_DESCRIBE_DEVICE; // already used but keep it explicit
    assert!(size_of::<AdminqCommand>() == CMD_SIZE);
    assert!(ADMINQ_SIZE / CMD_SIZE == ADMINQ_SLOTS);
};
