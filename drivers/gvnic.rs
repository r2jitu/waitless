// drivers/gvnic.rs — Google Virtual NIC (gVNIC) driver.
//
// Brings up one TX + one RX queue pair in GQI_QPL mode on GCE and
// serves packets on it. The driver is split into three levels:
//
//   1. Admin queue: PCI probe, DESCRIBE_DEVICE, parse device
//      descriptor + options.
//   2. Resource setup: CONFIGURE_DEVICE_RESOURCES, REGISTER_PAGE_LIST
//      (TX + RX), CREATE_TX_QUEUE, CREATE_RX_QUEUE.
//   3. Datapath: post RX buffers, drain completion ring, submit TX
//      descriptors, reclaim completed TX slots.
//
// Multi-queue + RSS is out of scope here — it's layered on top in
// a follow-up phase (one TxQueue / RxQueue per core, CONFIGURE_RSS
// at init).
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
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
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

// Admin queue opcodes (names match the enum in the reference
// driver's `gve_adminq.h`). We only use a subset.
const OP_DESCRIBE_DEVICE: u32 = 0x1;
const OP_CONFIGURE_DEVICE_RESOURCES: u32 = 0x2;
const OP_REGISTER_PAGE_LIST: u32 = 0x3;
const OP_CREATE_TX_QUEUE: u32 = 0x5;
const OP_CREATE_RX_QUEUE: u32 = 0x6;
const OP_CONFIGURE_RSS: u32 = 0xA;

/// RSS hash algorithm value (Toeplitz). Matches Linux's
/// `ETH_RSS_HASH_TOP = 1`. The device only implements Toeplitz.
const RSS_HASH_ALG_TOEPLITZ: u8 = 1;

/// `enum gve_rss_hash_type` bit positions (from the Linux header).
/// Our mask enables 4-tuple hashing for TCP + UDP on v4 and v6 —
/// that's what real traffic hits. Anything else falls back to
/// whatever LUT slot 0 maps to.
const RSS_HASH_TCPV4: u16 = 1 << 1;
const RSS_HASH_TCPV6: u16 = 1 << 4;
const RSS_HASH_UDPV4: u16 = 1 << 6;
const RSS_HASH_UDPV6: u16 = 1 << 7;

const RSS_KEY_SIZE: usize = 40;
const RSS_LUT_SIZE: usize = 128;

/// Marker for GQI_RDA mode (raw DMA addressing). In QPL mode the
/// `queue_page_list_id` field of CREATE_*_QUEUE is the real QPL id
/// we got from REGISTER_PAGE_LIST.
const GVE_RAW_ADDRESSING_QPL_ID: u32 = 0xFFFFFFFF;

/// Values for `CONFIGURE_DEVICE_RESOURCES.queue_format`.
const QF_GQI_RDA: u8 = 0x1;
const QF_GQI_QPL: u8 = 0x2;
const QF_DQO_RDA: u8 = 0x3;
const QF_DQO_QPL: u8 = 0x4;

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
    /// Number of event counters the device advertises. Sized by
    /// DESCRIBE_DEVICE's `counters` field. CONFIGURE_DEVICE_RESOURCES
    /// allocates a DMA array of this size that the device writes
    /// TX-completion counters into.
    num_event_counters: u16,
    /// Phase 2 resources — filled once CONFIGURE_DEVICE_RESOURCES
    /// succeeds. `None` between DESCRIBE_DEVICE and that point.
    resources: Option<DeviceResources>,
    /// Number of active queue pairs. <= MAX_QUEUE_PAIRS. Set by
    /// `init()` after all queues come up. Tier 1 polling in
    /// `net::poll_tier1` walks `0..num_qp`.
    num_qp: u16,
    /// TX / RX queues. Indexed by queue-pair number 0..num_qp.
    /// Phase 4 uses one pair per vCPU; multi-queue RX distribution
    /// happens inside the NIC via CONFIGURE_RSS.
    tx: [Option<TxQueue>; MAX_QUEUE_PAIRS],
    rx: [Option<RxQueue>; MAX_QUEUE_PAIRS],
}

/// Matches `drivers::virtio_net::MAX_QUEUE_PAIRS`. Upper bound for
/// `net_rx_counts()` / `net_rx_used_cursors()` array sizes so the
/// two drivers stay signature-compatible.
const MAX_QUEUE_PAIRS: usize = 8;

/// Device-wide resources negotiated via CONFIGURE_DEVICE_RESOURCES.
/// The device owns these DMA regions for its lifetime; the driver
/// just tells it where they live.
struct DeviceResources {
    /// Counter array (device writes per-TX-queue completion counts
    /// and other stats here). One 32-bit counter per slot.
    counter_array_va: u64,
    counter_array_phys: u64,
    /// IRQ doorbell block. Even though we're polling, the device
    /// requires a valid IRQ doorbell region and per-queue index.
    /// Each entry is a cache-line-aligned `u32` the device reads to
    /// decide whether to raise MSI-X.
    irq_db_va: u64,
    irq_db_phys: u64,
    /// Virtual address of BAR2 (per-queue doorbell register window).
    /// `queue_resources->db_index * 4` is the byte offset of a given
    /// queue's doorbell here.
    bar2_va: u64,
}

/// Per-queue TX metadata. GQI_QPL format: outbound packets are
/// memcpy'd into a pre-registered Queue Page List, and the
/// descriptor carries an offset into that list (not a DMA address).
struct TxQueue {
    /// Descriptor ring — one page of 256 × 16-byte `gve_tx_pkt_desc`.
    /// (We size at `min(tx_queue_entries, 256)` so it fits in 4 KiB.)
    /// Stored as a VA; the device holds the physical address it was
    /// given via CREATE_TX_QUEUE.
    ring_va: u64,
    ring_entries: u16,
    /// Queue-resources page. The device populates
    /// `{db_index, counter_index}` here right after CREATE_TX_QUEUE
    /// returns so the driver can find its doorbell / counter slot.
    qres_va: u64,
    /// QPL backing storage — contiguous pages the device sees as a
    /// linear byte range; our TX packets live here for the device to
    /// read. Phase 2 uses a single contiguous alloc for simplicity.
    qpl_base_va: u64,
    qpl_base_phys: u64,
    qpl_size: u32, // bytes
    qpl_id: u32,   // returned by REGISTER_PAGE_LIST
    /// Doorbell offset into BAR2 (bytes). Set once we read back the
    /// `db_index` the device wrote into `qres_va`.
    db_offset: u32,
    counter_index: u32,
    /// Monotonically-increasing packet producer counter. Written to
    /// the TX doorbell after submitting. Atomic so one core can
    /// publish (send path) while any other core reads it (e.g. for
    /// a deferred-kick check or a `/stats` snapshot).
    fill_cnt: AtomicU32,
    /// Last-seen value of `counter_array[counter_index]`. Drives
    /// TX slot recycling (a slot is reusable once done_cnt passes
    /// its fill_cnt).
    done_cnt: AtomicU32,
    /// Last value written to this queue's TX doorbell. Used by the
    /// deferred-kick path — `send_on_qp` updates `fill_cnt` but
    /// only writes the doorbell if the caller explicitly asks
    /// (via `flush_tx_kick_if_dirty_qp`) or if the ring is about
    /// to stall. Batching doorbell writes across a poll iteration
    /// cuts the per-packet MMIO-exit count on GCE.
    last_kicked: AtomicU32,
}

/// Per-queue RX metadata. Also QPL-backed: incoming frames are
/// DMA'd into pre-registered pages; the completion descriptor
/// tells us which offset.
struct RxQueue {
    /// Completion descriptor ring — `ring_entries × 64` bytes.
    compl_va: u64,
    /// Data-slot ring — `ring_entries × 8` bytes. Slot `i` holds
    /// a big-endian QPL offset the device will write buffer `i` to.
    data_va: u64,
    ring_entries: u16,
    /// Queue-resources page (same layout as TX).
    qres_va: u64,
    /// RX QPL backing storage. Big: 1024 pages = 4 MiB on GCE.
    qpl_base_va: u64,
    qpl_base_phys: u64,
    qpl_size: u32,
    qpl_id: u32,
    /// Doorbell for advancing the RX data-ring fill counter — we
    /// write the total number of posted slots here (monotonic).
    db_offset: u32,
    counter_index: u32,
    /// How many slots have been advertised to the device (matches
    /// the value last written to the RX doorbell).
    fill_cnt: AtomicU32,
    /// How many completions we've consumed. Only written by the
    /// core that polls this queue in Tier 1 mode; atomic so
    /// `/stats` can snapshot from any other core without a lock.
    cons_cnt: AtomicU32,
    /// Expected `flags_seq` sequence byte (low 3 bits, cycles 1..7;
    /// 0 is reserved). Used to detect new completions without
    /// reading a separate producer index.
    expected_seq: AtomicU8,
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

// Lock-free hot-path state — published at init time, then read
// without the big `STATE` spinlock so `poll_qp` / `send_on_qp` can
// run on multiple cores concurrently without serialising through
// a shared lock. Each of these atomics is written exactly once at
// init and only read afterward (except the queue-cursor fields
// inside TxQueue/RxQueue, which are their own atomics).

// BAR0 virtual address (admin-queue register window).
static BAR0: AtomicU64 = AtomicU64::new(0);
// BAR2 virtual address (per-queue doorbell register window).
static BAR2_VA: AtomicU64 = AtomicU64::new(0);
// DMA counter array VA (device writes TX completion counts here).
static COUNTER_ARRAY_VA: AtomicU64 = AtomicU64::new(0);
// Active queue pair count. Published once init is done so
// `num_queue_pairs()` can read it without taking STATE.
static NUM_QP: AtomicU16 = AtomicU16::new(0);
// Deferred-kick enable. When true, `send_on_qp` skips the TX
// doorbell write; callers must periodically call
// `flush_tx_kick_if_dirty()` (the kernel event loop does this
// once per iteration after the service callback). Cuts MMIO
// exits by ~Nx where N is average packets per poll batch.
static DEFERRED_KICK: AtomicBool = AtomicBool::new(false);
// Per-queue-pair TxQueue / RxQueue pointers. Each queue struct is
// allocated on the heap (`Box::leak`) and never freed; the
// pointer is published here once CREATE_*_QUEUE succeeds.
static TX_QUEUES: [AtomicPtr<TxQueue>; MAX_QUEUE_PAIRS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_QUEUE_PAIRS];
static RX_QUEUES: [AtomicPtr<RxQueue>; MAX_QUEUE_PAIRS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_QUEUE_PAIRS];

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
            num_event_counters: 0,
            resources: None,
            num_qp: 0,
            tx: [const { None }; MAX_QUEUE_PAIRS],
            rx: [const { None }; MAX_QUEUE_PAIRS],
        });
    }

    // ── DESCRIBE_DEVICE ─────────────────────────────────────────────────
    if !describe_device() {
        log(b"[gvnic] DESCRIBE_DEVICE failed - aborting bring-up\n");
        return false;
    }

    // ── Phase 2: bring up one TX + one RX queue in GQI_QPL mode ──────────
    //
    // Everything below is speculative until we've confirmed the
    // advertised queue format is one we support. GCE currently
    // advertises GQI_QPL only (see reference_gce_gvnic.md); we
    // error out for anything else.
    let fmt = STATE.lock().as_ref().and_then(|s| s.queue_format);
    match fmt {
        Some(QueueFormat::GqiQpl) => {}
        Some(_) => {
            log(b"[gvnic] only GQI_QPL supported in Phase 2 - aborting\n");
            return false;
        }
        None => return false,
    }

    let bar2_phys = pci::read_bar64(&dev, 2);
    if bar2_phys == 0 {
        log(b"[gvnic] BAR2 is zero - cannot reach per-queue doorbells\n");
        return false;
    }
    let bar2_va = phys_to_virt(bar2_phys) as u64;

    // Decide how many queue pairs to bring up. `default_num_queues`
    // is what GCE advertises for this machine type (2 on
    // n2-standard-2); `max_tx/rx_queues` is the hardware ceiling.
    // We cap at MAX_QUEUE_PAIRS because the /stats + net layer
    // APIs are sized to that constant.
    let (default_nq, max_tx, max_rx) = {
        let st = STATE.lock();
        let s = st.as_ref().unwrap();
        (s.default_num_queues as u32, s.max_tx_queues, s.max_rx_queues)
    };
    let num_qp = default_nq
        .min(max_tx)
        .min(max_rx)
        .min(MAX_QUEUE_PAIRS as u32)
        .max(1);

    if !configure_device_resources(bar2_va, num_qp) {
        return false;
    }

    for qp in 0..num_qp {
        if !create_tx_qp(qp) {
            log(b"[gvnic] TX queue create failed at qp=");
            log_u32(qp);
            log(b"\n");
            return false;
        }
    }
    for qp in 0..num_qp {
        if !create_rx_qp(qp, num_qp) {
            log(b"[gvnic] RX queue create failed at qp=");
            log_u32(qp);
            log(b"\n");
            return false;
        }
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.num_qp = num_qp as u16;
        }
    }
    NUM_QP.store(num_qp as u16, Ordering::Release);

    post_initial_rx();

    // Attempt to configure RSS so the device distributes incoming
    // flows across our queue pairs by 4-tuple hash. Not fatal if
    // rejected — the driver can still run on qp 0 — but we log it
    // so the /stats output makes sense.
    if num_qp > 1 {
        configure_rss(num_qp);
    }

    GVNIC_OK.store(true, Ordering::Release);
    log(b"[gvnic] ready (");
    log_u32(num_qp);
    log(b" queue pairs)\n");
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

    let max_registered_pages = u64::from_be_bytes([
        header[0], header[1], header[2], header[3],
        header[4], header[5], header[6], header[7],
    ]);
    let tx_entries = get_be16(header, 10);
    let rx_entries = get_be16(header, 12);
    let default_num_queues = get_be16(header, 14);
    let mtu = get_be16(header, 16);
    let counters = get_be16(header, 18);
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
    log(b" counters=");
    log_u32(counters as u32);
    log(b" rx_pages_per_qpl=");
    log_u32(rx_pages_per_qpl as u32);
    log(b" max_registered_pages=");
    log_u32(max_registered_pages as u32);
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

        // MODIFY_RING (option id 6, len 12): tells us the allowed
        // min/max ring sizes. The device rejects CREATE_*_QUEUE
        // with INVALID_ARGUMENT when the ring size is out of this
        // range, so log it so sizing decisions have numbers behind
        // them. Payload layout:
        //   u32 supported_features_mask
        //   u16 max_rx, u16 max_tx
        //   u16 min_rx, u16 min_tx
        if id == 6 && len == 12 && offset + 8 + 12 <= end {
            let payload: &[u8] =
                unsafe { core::slice::from_raw_parts(desc_virt.add(offset + 8), 12) };
            let max_rx = get_be16(payload, 4);
            let max_tx = get_be16(payload, 6);
            let min_rx = get_be16(payload, 8);
            let min_tx = get_be16(payload, 10);
            log(b"[gvnic]   MODIFY_RING min_rx=");
            log_u32(min_rx as u32);
            log(b" max_rx=");
            log_u32(max_rx as u32);
            log(b" min_tx=");
            log_u32(min_tx as u32);
            log(b" max_tx=");
            log_u32(max_tx as u32);
            log(b"\n");
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
        s.num_event_counters = counters;
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

/// Submit `cmd`, wait for the device, and check that the
/// per-command status is PASSED. Logs and returns false on any
/// failure (timeout or non-zero status). Used by every admin-queue
/// command after DESCRIBE_DEVICE.
fn execute_cmd(opcode_label: &[u8], cmd: &AdminqCommand) -> bool {
    if !submit_and_wait(cmd) {
        log(b"[gvnic] ");
        log(opcode_label);
        log(b": timeout\n");
        return false;
    }
    let slot = current_slot_before_kick();
    let status = unsafe { read_slot_status(slot) };
    if status != STATUS_PASSED {
        log(b"[gvnic] ");
        log(opcode_label);
        log(b": status=");
        log_hex32(status);
        log(b"\n");
        return false;
    }
    true
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

/// Read a field the device wrote into a DMA-coherent buffer the
/// driver allocated. Equivalent to `ptr::read_volatile` on the byte
/// range. Having this as a named helper makes the descriptor-
/// parsing sites easier to audit — each one is "device wrote here".
#[inline]
unsafe fn slice_at<'a>(va: u64, len: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(va as *const u8, len) }
}

// ---- Phase 2: resource + queue bring-up -----------------------------------
//
// These issue the sequence of admin-queue commands that takes the
// device from "admin queue up" to "one TX + one RX queue usable".
// No packets flow yet; Phase 2b adds the datapath.
//
// Wire-level command layouts are documented inline at each builder
// so the admin-queue reference file doesn't have to be open to
// follow along. Sizes + field offsets are from the FreeBSD
// `gve_adminq.h`; the payload lives at offset 8 within the 64-byte
// command (opcode + status + 56 bytes of per-command data).

/// IRQ doorbell entry stride. The device treats each doorbell as a
/// cache-line-aligned `u32`, which on all our targets is 64 bytes.
const IRQ_DB_STRIDE: u32 = 64;

/// TX + RX ring sizes — must be within the MODIFY_RING option's
/// advertised [min, max]. On GCE n2-standard-2 that's [256, 2048]
/// for TX and [512, 2048] for RX. Picking the minimum keeps the
/// per-queue DMA footprint small: with a GQI_QPL RX QPL at one
/// page per entry, 1024 entries means 4 MiB of RX buffers (and the
/// device rejected that registration with FAILED_PRECONDITION on
/// our side). 512 / 256 keeps the driver happy and is plenty for
/// a single-queue bring-up.
const TX_RING_ENTRIES: u16 = 256;
const RX_RING_ENTRIES: u16 = 512;
/// RX buffer size in bytes (matches GVE_DEFAULT_RX_BUFFER_SIZE =
/// 2048 from the reference driver; one packet per buffer).
const RX_BUFFER_SIZE: u16 = 2048;
/// 2-byte padding the device inserts before the Ethernet frame so
/// the IP header lands 4-byte-aligned in the RX buffer.
const _GVE_RX_PAD: u16 = 2;

/// TX QPL size in pages. One 4 KiB page per ring slot — slot `i`
/// always writes to QPL offset `i * PAGE_SIZE`, mirroring the RX
/// layout. This lets us skip a real FIFO allocator: ring slot
/// reuse waits on the device's `counter_array[counter_index]`,
/// and the page for that slot is only written while the slot is
/// free (`fill_cnt - done_cnt < ring_entries` gate in `send()`).
/// Reference driver's `tx_desc_cnt / GVE_QPL_DIVISOR = 64` packs
/// multiple packets per page and needs a full FIFO packer; not
/// worth the code for Phase 2 when RAM is cheap.
const TX_QPL_PAGES: u32 = TX_RING_ENTRIES as u32;
/// RX QPL size in pages. The reference driver allocates
/// `rx_desc_cnt` pages — one full page per ring entry, even though
/// each packet only uses the first 2 KiB of that page. Smaller
/// allocations are silently rejected by the device with
/// FAILED_PRECONDITION. `rx_pages_per_qpl = 1024` in the device
/// descriptor matches `rx_desc_cnt`, confirming this 1:1 sizing.
const RX_QPL_PAGES: u32 = RX_RING_ENTRIES as u32;

const PAGE_SIZE: u32 = 4096;

/// QPL IDs the driver assigns to itself. The spec just requires
/// uniqueness across live QPLs, so we pack TX ids into the low
/// half and RX ids above them. `tx_qpl_id(i)` = i, `rx_qpl_id(i)`
/// = MAX_QUEUE_PAIRS + i.
#[inline] fn tx_qpl_id(qp: u32) -> u32 { qp }
#[inline] fn rx_qpl_id(qp: u32) -> u32 { qp + MAX_QUEUE_PAIRS as u32 }

/// Notification-block ids. TX queues claim the first `num_qp`
/// slots, RX queues the next `num_qp`. Matches the reference
/// driver's layout and avoids the "two queues can't share an
/// ntfy_id" rejection.
#[inline] fn tx_ntfy_id(qp: u32) -> u32 { qp }
#[inline] fn rx_ntfy_id(num_qp: u32, qp: u32) -> u32 { num_qp + qp }

fn configure_device_resources(bar2_va: u64, num_qp: u32) -> bool {
    // Pull the device-advertised counter count out of state. This is
    // the value we must match — Linux passes this straight through
    // to the admin-queue command. Hardcoding a number here once
    // caused the device to reject the command with INVALID_ARGUMENT.
    let num_event_counters = {
        let st = STATE.lock();
        st.as_ref().map(|s| s.num_event_counters).unwrap_or(0)
    } as u32;
    if num_event_counters == 0 {
        log(b"[gvnic] device advertised zero event counters\n");
        return false;
    }

    // Allocate counter array + irq-db array. Both live for the
    // lifetime of the driver; we never unregister them.
    let counter_phys = alloc_pages(1);
    if counter_phys == 0 {
        log(b"[gvnic] failed to alloc counter array\n");
        return false;
    }
    let counter_va = phys_to_virt(counter_phys) as u64;
    unsafe { ptr::write_bytes(counter_va as *mut u8, 0, PAGE_SIZE as usize); }

    // IRQ-db array: one entry per notification block. Each entry is
    // IRQ_DB_STRIDE bytes (a full cache line) to avoid false sharing
    // between the device's writes. Size at 2 × 64 = 128 B; rounds
    // up to one page.
    let irq_db_phys = alloc_pages(1);
    if irq_db_phys == 0 {
        log(b"[gvnic] failed to alloc irq-db array\n");
        return false;
    }
    let irq_db_va = phys_to_virt(irq_db_phys) as u64;
    unsafe { ptr::write_bytes(irq_db_va as *mut u8, 0, PAGE_SIZE as usize); }

    // Build CONFIGURE_DEVICE_RESOURCES. Payload layout (40 bytes
    // at offset 8 of the command):
    //
    //   u64  counter_array (be, DMA)
    //   u64  irq_db_addr   (be, DMA)
    //   u32  num_counters  (be)
    //   u32  num_irq_dbs   (be)
    //   u32  irq_db_stride (be, 64 for our cache-line layout)
    //   u32  ntfy_blk_msix_base_idx (be, = 0 when we don't use MSI-X)
    //   u8   queue_format
    //   u8[7] padding
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CONFIGURE_DEVICE_RESOURCES);
    put_be64(&mut cmd.bytes, 8, counter_phys);
    put_be64(&mut cmd.bytes, 16, irq_db_phys);
    put_be32(&mut cmd.bytes, 24, num_event_counters);
    // num_irq_dbs = one notification block per active queue.
    // `num_qp * 2` covers both TX and RX queue pairs. Linux derives
    // this from the MSI-X count; we poll-only but the device still
    // wants a valid count here matching what the CREATE_*_QUEUE
    // ntfy_ids will reference.
    put_be32(&mut cmd.bytes, 28, num_qp * 2);
    put_be32(&mut cmd.bytes, 32, IRQ_DB_STRIDE);
    put_be32(&mut cmd.bytes, 36, 0);
    cmd.bytes[40] = QF_GQI_QPL;

    if !execute_cmd(b"CONFIGURE_DEVICE_RESOURCES", &cmd) {
        return false;
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.resources = Some(DeviceResources {
                counter_array_va: counter_va,
                counter_array_phys: counter_phys,
                irq_db_va,
                irq_db_phys,
                bar2_va,
            });
        }
    }
    // Publish for the lock-free hot path. These values are read by
    // `send_on_qp` / `tx_drain_qp` on every packet; going through
    // `STATE.lock()` on a shared spinlock would serialise all TX
    // across cores.
    BAR2_VA.store(bar2_va, Ordering::Release);
    COUNTER_ARRAY_VA.store(counter_va, Ordering::Release);
    log(b"[gvnic] device resources configured\n");
    true
}

/// Register `num_pages` physically-contiguous pages starting at
/// `base_phys` as a new QPL with `page_list_id`. Returns false if
/// the device rejects the registration.
fn register_page_list(page_list_id: u32, base_phys: u64, num_pages: u32) -> bool {
    // The device wants an array of per-page DMA addresses (be64
    // each) in a separate DMA-coherent buffer. 8 bytes per page,
    // rounded up. A 1024-page RX QPL needs 2 pages here.
    let list_bytes = (num_pages as usize) * 8;
    let list_pages = (list_bytes + (PAGE_SIZE as usize) - 1) / (PAGE_SIZE as usize);
    let page_addrs_phys = alloc_pages(list_pages);
    if page_addrs_phys == 0 {
        log(b"[gvnic] failed to alloc page-address list\n");
        return false;
    }
    let page_addrs_va = phys_to_virt(page_addrs_phys);
    unsafe { ptr::write_bytes(page_addrs_va, 0, list_pages * PAGE_SIZE as usize); }

    // Fill in the per-page addresses. The QPL is contiguous, so
    // the i-th page is at base_phys + i*4096.
    for i in 0..num_pages as usize {
        let page_addr = base_phys + (i as u64) * (PAGE_SIZE as u64);
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&page_addr.to_be_bytes());
        unsafe {
            ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (page_addrs_va as *mut u8).add(i * 8),
                8,
            );
        }
    }

    // Payload layout (24 bytes at offset 8):
    //   u32  page_list_id (be)
    //   u32  num_pages    (be)
    //   u64  page_address_list_addr (be, DMA)
    //   u64  page_size    (be, 4096)
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_REGISTER_PAGE_LIST);
    put_be32(&mut cmd.bytes, 8, page_list_id);
    put_be32(&mut cmd.bytes, 12, num_pages);
    put_be64(&mut cmd.bytes, 16, page_addrs_phys);
    put_be64(&mut cmd.bytes, 24, PAGE_SIZE as u64);

    if !execute_cmd(b"REGISTER_PAGE_LIST", &cmd) {
        return false;
    }
    true
}

/// Issue CONFIGURE_RSS so the device hashes incoming flows across
/// the `num_qp` active queue pairs. We build a 128-entry
/// indirection table that cycles `qp = i % num_qp` and a static
/// 40-byte Toeplitz key (any bit-diverse constant works for
/// driver-controlled hashing; Microsoft's classic MS-DRSH test
/// key would be overkill for this use case).
///
/// Returns true on success. On failure we log and continue —
/// the driver still works with queue 0 handling all traffic.
fn configure_rss(num_qp: u32) -> bool {
    // Use Microsoft's standard Toeplitz RSS key. It's the
    // well-tested 40-byte key every Linux / Windows NIC driver
    // defaults to, and produces well-distributed hashes for
    // realistic 4-tuples. Our first attempt used a synthetic key
    // (`i * 0x9E3779B1 >> 24`) which happened to hash ~99 % of
    // wrk's flows onto qp 0 on n2-highcpu-4.
    let key: [u8; RSS_KEY_SIZE] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    // LUT: 128 entries of be32 queue index. Cycle through the
    // active qps so 4-tuple hash distribution maps evenly.
    let mut lut_bytes = [0u8; RSS_LUT_SIZE * 4];
    for i in 0..RSS_LUT_SIZE {
        let q = (i as u32) % num_qp;
        lut_bytes[i * 4..i * 4 + 4].copy_from_slice(&q.to_be_bytes());
    }

    let key_phys = alloc_pages(1);
    let lut_phys = alloc_pages(1);
    if key_phys == 0 || lut_phys == 0 {
        log(b"[gvnic] RSS alloc failed\n");
        return false;
    }
    unsafe {
        let key_va = phys_to_virt(key_phys);
        ptr::copy_nonoverlapping(key.as_ptr(), key_va, RSS_KEY_SIZE);
        let lut_va = phys_to_virt(lut_phys);
        ptr::copy_nonoverlapping(lut_bytes.as_ptr(), lut_va, lut_bytes.len());
    }

    // Payload (24 bytes at offset 8):
    //   u16 hash_types    (be)
    //   u8  hash_alg      (1 = Toeplitz)
    //   u8  reserved
    //   u16 hash_key_size (be)
    //   u16 hash_lut_size (be)
    //   u64 hash_key_addr (be, DMA)
    //   u64 hash_lut_addr (be, DMA)
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CONFIGURE_RSS);
    let hash_types = RSS_HASH_TCPV4 | RSS_HASH_TCPV6 | RSS_HASH_UDPV4 | RSS_HASH_UDPV6;
    put_be16(&mut cmd.bytes, 8, hash_types);
    cmd.bytes[10] = RSS_HASH_ALG_TOEPLITZ;
    put_be16(&mut cmd.bytes, 12, RSS_KEY_SIZE as u16);
    put_be16(&mut cmd.bytes, 14, RSS_LUT_SIZE as u16);
    put_be64(&mut cmd.bytes, 16, key_phys);
    put_be64(&mut cmd.bytes, 24, lut_phys);

    if !execute_cmd(b"CONFIGURE_RSS", &cmd) {
        log(b"[gvnic] RSS not configured (falling back to single-queue delivery)\n");
        return false;
    }
    log(b"[gvnic] RSS configured across ");
    log_u32(num_qp);
    log(b" queue pairs\n");
    true
}

/// Allocate a contiguous physical region of `num_pages` 4 KiB pages.
/// Returns (phys, va). Both will be nonzero on success; logs + returns
/// (0, 0) on failure.
fn alloc_contig(num_pages: usize) -> (u64, u64) {
    let phys = alloc_pages(num_pages);
    if phys == 0 {
        return (0, 0);
    }
    let va = phys_to_virt(phys) as u64;
    unsafe { ptr::write_bytes(va as *mut u8, 0, num_pages * PAGE_SIZE as usize); }
    (phys, va)
}

fn create_tx_qp(qp: u32) -> bool {
    // ── Allocate TX ring (one page of 16-byte descriptors) ──────────────
    let (ring_phys, ring_va) = alloc_contig(1);
    if ring_phys == 0 {
        log(b"[gvnic] failed to alloc TX ring\n");
        return false;
    }

    // ── Allocate queue_resources page (device writes db_index +
    //    counter_index here once CREATE_TX_QUEUE returns) ─────────────────
    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 {
        log(b"[gvnic] failed to alloc TX queue_resources\n");
        return false;
    }

    // ── Allocate + register the TX QPL ───────────────────────────────────
    let (qpl_phys, qpl_va) = alloc_contig(TX_QPL_PAGES as usize);
    if qpl_phys == 0 {
        log(b"[gvnic] failed to alloc TX QPL pages\n");
        return false;
    }
    if !register_page_list(tx_qpl_id(qp), qpl_phys, TX_QPL_PAGES) {
        return false;
    }

    // ── CREATE_TX_QUEUE command ─────────────────────────────────────────
    //
    // Payload layout (48 bytes at offset 8):
    //   u32  queue_id
    //   u32  reserved
    //   u64  queue_resources_addr (be, DMA)
    //   u64  tx_ring_addr (be, DMA)
    //   u32  queue_page_list_id (be)
    //   u32  ntfy_id (be)
    //   u64  tx_comp_ring_addr (DQO only — zero here)
    //   u16  tx_ring_size (be)
    //   u16  tx_comp_ring_size (DQO only — zero)
    //   u8[4] padding
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CREATE_TX_QUEUE);
    put_be32(&mut cmd.bytes, 8, qp);
    put_be64(&mut cmd.bytes, 16, qres_phys);
    put_be64(&mut cmd.bytes, 24, ring_phys);
    put_be32(&mut cmd.bytes, 32, tx_qpl_id(qp));
    put_be32(&mut cmd.bytes, 36, tx_ntfy_id(qp));
    put_be16(&mut cmd.bytes, 48, TX_RING_ENTRIES);

    if !execute_cmd(b"CREATE_TX_QUEUE", &cmd) {
        return false;
    }

    // Read back db_index + counter_index. Layout of
    // `gve_queue_resources`:
    //   u32 db_index (be, device -> guest)
    //   u32 counter_index (be, device -> guest)
    //   u8[56] reserved
    let db_index;
    let counter_index;
    unsafe {
        let bytes = slice_at(qres_va, 8);
        db_index = get_be32(bytes, 0);
        counter_index = get_be32(bytes, 4);
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.tx[qp as usize] = Some(TxQueue {
                ring_va,
                ring_entries: TX_RING_ENTRIES,
                qres_va,
                qpl_base_va: qpl_va,
                qpl_base_phys: qpl_phys,
                qpl_size: TX_QPL_PAGES * PAGE_SIZE,
                qpl_id: tx_qpl_id(qp),
                db_offset: db_index * 4,
                counter_index,
                fill_cnt: AtomicU32::new(0),
                done_cnt: AtomicU32::new(0),
                last_kicked: AtomicU32::new(0),
            });
            // Publish a raw pointer to the TxQueue living inside State
            // so the hot path (`send_on_qp`) can reach it without
            // taking the STATE spinlock. State is only ever written
            // to once, so the Option's `Some` variant sits at a
            // stable address for the rest of the driver's life.
            let ptr = s.tx[qp as usize].as_ref().unwrap() as *const TxQueue as *mut TxQueue;
            TX_QUEUES[qp as usize].store(ptr, Ordering::Release);
        }
    }
    log(b"[gvnic] TX queue ");
    log_u32(qp);
    log(b" created, db_offset=");
    log_u32(db_index * 4);
    log(b" counter_index=");
    log_u32(counter_index);
    log(b"\n");
    true
}

fn create_rx_qp(qp: u32, num_qp: u32) -> bool {
    // ── Completion ring (64-byte descriptors, device-written) ───────────
    let compl_pages = ((RX_RING_ENTRIES as u32) * 64 + PAGE_SIZE - 1) / PAGE_SIZE;
    let (compl_phys, compl_va) = alloc_contig(compl_pages as usize);
    if compl_phys == 0 {
        log(b"[gvnic] failed to alloc RX completion ring\n");
        return false;
    }

    // ── Data-slot ring (8 bytes each, driver-written QPL offsets) ──────
    let data_pages = ((RX_RING_ENTRIES as u32) * 8 + PAGE_SIZE - 1) / PAGE_SIZE;
    let (data_phys, data_va) = alloc_contig(data_pages as usize);
    if data_phys == 0 {
        log(b"[gvnic] failed to alloc RX data ring\n");
        return false;
    }

    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 {
        log(b"[gvnic] failed to alloc RX queue_resources\n");
        return false;
    }

    // ── RX QPL ───────────────────────────────────────────────────────────
    let (qpl_phys, qpl_va) = alloc_contig(RX_QPL_PAGES as usize);
    if qpl_phys == 0 {
        log(b"[gvnic] failed to alloc RX QPL pages\n");
        return false;
    }
    if !register_page_list(rx_qpl_id(qp), qpl_phys, RX_QPL_PAGES) {
        return false;
    }

    // Pre-fill the data-slot ring: slot `i` points at QPL offset
    // `i * PAGE_SIZE`. Each ring entry gets a whole 4 KiB page even
    // though packets only use the first 2 KiB — that's how the
    // reference driver lays it out and what the device expects
    // (rx_pages_per_qpl == rx_desc_cnt).
    for i in 0..RX_RING_ENTRIES as usize {
        let offset: u64 = (i as u64) * (PAGE_SIZE as u64);
        let bytes = offset.to_be_bytes();
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (data_va as *mut u8).add(i * 8),
                8,
            );
        }
    }

    // ── CREATE_RX_QUEUE ─────────────────────────────────────────────────
    //
    // Payload (56 bytes at offset 8):
    //   u32  queue_id
    //   u32  index
    //   u32  reserved
    //   u32  ntfy_id
    //   u64  queue_resources_addr (DMA)
    //   u64  rx_desc_ring_addr (DMA — completion ring in GQI)
    //   u64  rx_data_ring_addr (DMA — slot ring in GQI)
    //   u32  queue_page_list_id
    //   u16  rx_ring_size
    //   u16  packet_buffer_size
    //   u16  rx_buff_ring_size (DQO only — zero)
    //   u8   enable_rsc
    //   u8[5] padding
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CREATE_RX_QUEUE);
    put_be32(&mut cmd.bytes, 8, qp);
    put_be32(&mut cmd.bytes, 12, qp);
    put_be32(&mut cmd.bytes, 20, rx_ntfy_id(num_qp, qp));
    put_be64(&mut cmd.bytes, 24, qres_phys);
    put_be64(&mut cmd.bytes, 32, compl_phys);
    put_be64(&mut cmd.bytes, 40, data_phys);
    put_be32(&mut cmd.bytes, 48, rx_qpl_id(qp));
    put_be16(&mut cmd.bytes, 52, RX_RING_ENTRIES);
    put_be16(&mut cmd.bytes, 54, RX_BUFFER_SIZE);

    if !execute_cmd(b"CREATE_RX_QUEUE", &cmd) {
        return false;
    }

    let db_index;
    let counter_index;
    unsafe {
        let bytes = slice_at(qres_va, 8);
        db_index = get_be32(bytes, 0);
        counter_index = get_be32(bytes, 4);
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.rx[qp as usize] = Some(RxQueue {
                compl_va,
                data_va,
                ring_entries: RX_RING_ENTRIES,
                qres_va,
                qpl_base_va: qpl_va,
                qpl_base_phys: qpl_phys,
                qpl_size: RX_QPL_PAGES * PAGE_SIZE,
                qpl_id: rx_qpl_id(qp),
                db_offset: db_index * 4,
                counter_index,
                fill_cnt: AtomicU32::new(0),
                cons_cnt: AtomicU32::new(0),
                expected_seq: AtomicU8::new(1),
            });
            let ptr = s.rx[qp as usize].as_ref().unwrap() as *const RxQueue as *mut RxQueue;
            RX_QUEUES[qp as usize].store(ptr, Ordering::Release);
        }
    }
    log(b"[gvnic] RX queue ");
    log_u32(qp);
    log(b" created, db_offset=");
    log_u32(db_index * 4);
    log(b" counter_index=");
    log_u32(counter_index);
    log(b"\n");
    true
}

// ---- Datapath ------------------------------------------------------------
//
// Single-queue GQI_QPL flow, one RX queue + one TX queue. Both
// sides are polled — no interrupts; the kernel's event loop calls
// `poll_qp(0, cb)` regularly, which drains the RX completion ring
// and re-posts consumed slots. `send()` copies one packet into
// the TX QPL FIFO, writes one descriptor, and kicks the doorbell.

/// RSS hash layout in the GQI_RX completion descriptor is the last
/// 64 bytes worth of the 64-byte descriptor. Offsets within it:
///
///   u8[0..48]   padding (device implementation detail)
///   u8[48..52]  rss_hash (be32)
///   u8[52..54]  mss (be16)
///   u8[54..56]  reserved
///   u8[56]      hdr_len
///   u8[57]      hdr_off (64-byte-scaled)
///   u8[58..60]  csum (host-endian per the reference driver)
///   u8[60..62]  len (be16)
///   u8[62..64]  flags_seq (be16)
///
/// Only `len` and `flags_seq` are needed for Phase 2 — csum +
/// hash are hints for the stack and can be ignored here.
const RX_DESC_SIZE: usize = 64;
const RX_DESC_LEN_OFF: usize = 60;
const RX_DESC_FLAGS_SEQ_OFF: usize = 62;
const RX_DESC_HDR_OFF_OFF: usize = 57;

/// Start-of-frame offset inside each 4 KiB RX page. The device
/// prepends `_GVE_RX_PAD = 2` bytes of padding before the Ethernet
/// header so IPv4 header bytes land 4-byte aligned. The *actual*
/// offset the device writes into `hdr_off` is scaled by 64 — for
/// Phase 2 with one packet per page there's only one valid value
/// (hdr_off = 0, actual start = `_GVE_RX_PAD`).
const RX_DATA_OFFSET_IN_PAGE: usize = _GVE_RX_PAD as usize;

/// TX descriptor size (gve_tx_pkt_desc, packed, 16 bytes).
const TX_DESC_SIZE: usize = 16;

/// Highest packet length we're willing to stage at once. Matches
/// the device-advertised MTU + Ethernet + safety slack; see
/// `send()` below for the actual check.
const TX_MAX_PKT_LEN: usize = 2048;

fn post_initial_rx() {
    // After CREATE_RX_QUEUE the data-slot ring is pre-populated with
    // (slot → QPL offset) but the device doesn't consider any slot
    // "available" until the driver bumps the data doorbell. Writing
    // `ring_entries` per queue hands every slot to the device in one
    // shot so it can start depositing frames immediately. Walk all
    // queue pairs we've brought up.
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    for qp in 0..MAX_QUEUE_PAIRS {
        let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
        if rx_ptr.is_null() { continue; }
        // SAFETY: pointer published with Release, only null means
        // "not installed". RxQueue's non-atomic fields are only
        // written during init (before this Release); reading them
        // here through Acquire is a valid synchronisation.
        let rx = unsafe { &*rx_ptr };
        let fill = rx.ring_entries as u32;
        rx.fill_cnt.store(fill, Ordering::Release);
        doorbell_write(bar2_va, rx.db_offset, fill);
    }
    log(b"[gvnic] posted initial RX buffers\n");
}

/// Write a big-endian `value` to BAR2 at byte-offset `offset`.
/// GQI doorbells are all BE on the wire — the FreeBSD reference
/// uses `htobe32` before `bus_write_4` for the same reason.
#[inline]
fn doorbell_write(bar2_va: u64, offset: u32, value: u32) {
    unsafe {
        mmio_write32(bar2_va + offset as u64, value.to_be());
    }
}

// ---- RX ------------------------------------------------------------------

/// Drain the RX completion ring for the given queue pair,
/// invoking `callback` for each frame. Returns number of frames
/// delivered.
///
/// Progress is detected by sequence number, not producer index:
/// each completion descriptor carries `flags_seq` whose low 3 bits
/// cycle 1..7. When the next descriptor's sequence matches what
/// we're expecting, it's a new completion.
pub fn poll_qp_inner(qp: usize, callback: fn(&[u8])) -> u32 {
    if qp >= MAX_QUEUE_PAIRS {
        return 0;
    }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() {
        return 0;
    }
    // SAFETY: pointer is published once after init. RxQueue's
    // non-atomic fields (ring_va, db_offset, …) are only written
    // during init under STATE lock, before the Release publish;
    // Acquire above synchronises with that. Mutable fields
    // (cons_cnt, expected_seq, fill_cnt) are AtomicU32/U8, which
    // tolerate concurrent access if another core ever calls in —
    // though in Tier 1 each queue is polled by exactly one core.
    let rx = unsafe { &*rx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let mask = (rx.ring_entries - 1) as u32;
    let mut cons = rx.cons_cnt.load(Ordering::Relaxed);
    let mut expected = rx.expected_seq.load(Ordering::Relaxed);
    let mut delivered: u32 = 0;

    // Batch limit. A runaway (matching-seq loop, or huge single
    // burst) could otherwise monopolise this core; the event loop
    // wouldn't get a chance to flush TX, check shutdown, etc. 64
    // packets per poll call is plenty for throughput and keeps us
    // responsive.
    const MAX_BATCH: u32 = 64;

    while delivered < MAX_BATCH {
        let idx = (cons & mask) as usize;
        let desc_ptr = (rx.compl_va as *const u8).wrapping_add(idx * RX_DESC_SIZE);
        // SAFETY: descriptor is 64 bytes inside a DMA-coherent page.
        // x86 is cache-coherent so a volatile read is sufficient
        // to see the device's writes.
        let desc: &[u8] = unsafe { core::slice::from_raw_parts(desc_ptr, RX_DESC_SIZE) };

        let flags_seq = get_be16(desc, RX_DESC_FLAGS_SEQ_OFF);
        let seq = (flags_seq & 0x7) as u8;
        if seq != expected {
            break;
        }

        let len = get_be16(desc, RX_DESC_LEN_OFF) as usize;
        let frame_start = rx.qpl_base_va as usize + idx * (PAGE_SIZE as usize)
            + RX_DATA_OFFSET_IN_PAGE;
        let frame: &[u8] = unsafe {
            core::slice::from_raw_parts(frame_start as *const u8, len)
        };
        callback(frame);

        delivered += 1;
        cons = cons.wrapping_add(1);
        expected = if expected == 7 { 1 } else { expected + 1 };
    }

    if delivered > 0 {
        let new_fill = rx.fill_cnt.load(Ordering::Relaxed).wrapping_add(delivered);
        rx.cons_cnt.store(cons, Ordering::Relaxed);
        rx.expected_seq.store(expected, Ordering::Relaxed);
        rx.fill_cnt.store(new_fill, Ordering::Relaxed);
        doorbell_write(bar2_va, rx.db_offset, new_fill);
    }

    delivered
}

// ---- TX ------------------------------------------------------------------

/// Reclaim TX slots on `qp` from the device's completion counter.
/// Lock-free fast path — reads TxQueue via the pre-published
/// pointer + device counter via an atomic.
#[inline]
fn tx_drain(tx: &TxQueue) {
    let counter_va = COUNTER_ARRAY_VA.load(Ordering::Acquire);
    if counter_va == 0 { return; }
    let counter_ptr = counter_va as *const u32;
    let raw = unsafe { ptr::read_volatile(counter_ptr.add(tx.counter_index as usize)) };
    let nic_done = u32::from_be(raw);
    let prev = tx.done_cnt.load(Ordering::Relaxed);
    if nic_done.wrapping_sub(prev) != 0 {
        tx.done_cnt.store(nic_done, Ordering::Relaxed);
    }
}

/// Submit a single-segment packet on queue pair `qp`. Returns
/// `true` on success, `false` when the ring has no free slots
/// (device hasn't caught up) or the frame exceeds `TX_MAX_PKT_LEN`.
pub fn send_on_qp(qp: usize, data: &[u8]) -> bool {
    if qp >= MAX_QUEUE_PAIRS || data.is_empty() || data.len() > TX_MAX_PKT_LEN {
        return false;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return false; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    tx_drain(tx);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let done_cnt = tx.done_cnt.load(Ordering::Relaxed);

    // Gate on ring capacity. Without this check, a flood of sends
    // wraps past `done_cnt` and rewrites descriptors the device is
    // still processing — the root cause of the ~50 % drop rate
    // observed on GCE before this fix.
    let in_flight = fill_cnt.wrapping_sub(done_cnt);
    if in_flight >= tx.ring_entries as u32 {
        return false;
    }

    let mask = (tx.ring_entries - 1) as u32;
    let slot = (fill_cnt & mask) as usize;

    // Each slot owns a single 4 KiB QPL page; its byte offset is
    // `slot * PAGE_SIZE`. Since the slot is only reused after the
    // device signals completion (the in_flight gate above), the
    // device can't be reading this page while we memcpy a new
    // packet into it.
    let qpl_offset = (slot as u32) * PAGE_SIZE;
    let dst = (tx.qpl_base_va + qpl_offset as u64) as *mut u8;
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
    }

    // Build the TX descriptor. gve_tx_pkt_desc layout:
    //   u8  type_flags       (GVE_TXD_STD = 0)
    //   u8  l4_csum_offset   (0 — no offload in Phase 2)
    //   u8  l4_hdr_offset    (0)
    //   u8  desc_cnt         (1 — single-segment packet)
    //   u16 len              (be, total packet length)
    //   u16 seg_len          (be, this segment length)
    //   u64 seg_addr         (be, QPL byte offset in QPL mode)
    let desc_ptr = (tx.ring_va as *mut u8).wrapping_add(slot * TX_DESC_SIZE);
    let mut desc = [0u8; TX_DESC_SIZE];
    desc[3] = 1;
    put_be16(&mut desc, 4, data.len() as u16);
    put_be16(&mut desc, 6, data.len() as u16);
    put_be64(&mut desc, 8, qpl_offset as u64);
    unsafe {
        core::ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, TX_DESC_SIZE);
    }

    let new_fill = fill_cnt.wrapping_add(1);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    // Deferred-kick path: the doorbell write costs a VM-exit on
    // GCE's gVNIC backend. If the event-loop integration promises
    // to call `flush_tx_kick_if_dirty()` before idling, we can
    // batch many sends into one doorbell. Force a kick anyway when
    // the ring is near full — otherwise a sustained burst with no
    // flush would stall waiting for completions the device hasn't
    // been told about.
    let near_full = new_fill.wrapping_sub(done_cnt) >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }
    true
}

/// Flush the deferred TX kick for the given queue pair. Returns
/// true if a doorbell write was issued. Called by the event loop
/// after each service pass to push whatever `send_on_qp` batched
/// onto the wire before the CPU sits idle.
pub fn flush_tx_kick_if_dirty_qp(qp: usize) -> bool {
    if qp >= MAX_QUEUE_PAIRS { return false; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return false; }
    let tx = unsafe { &*tx_ptr };
    let fill = tx.fill_cnt.load(Ordering::Relaxed);
    let kicked = tx.last_kicked.load(Ordering::Relaxed);
    if fill == kicked {
        return false;
    }
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    doorbell_write(bar2_va, tx.db_offset, fill);
    tx.last_kicked.store(fill, Ordering::Relaxed);
    true
}

/// Flush the current core's TX queue if dirty. Mirrors
/// `drivers::virtio_net::flush_tx_kick_if_dirty` so the shim in
/// `drivers::net` can dispatch through the same signature.
pub fn flush_tx_kick_if_dirty() -> bool {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 { return false; }
    let core = kernel::cpu_id();
    let qp = if core < num_qp { core as usize } else { 0 };
    flush_tx_kick_if_dirty_qp(qp)
}

/// Flush every TX queue's pending kick. Not strictly needed in
/// per-core-queue Tier 1 mode (each core's `flush_tx_kick_if_dirty`
/// covers its own queue), but useful if something batches sends
/// across cores. Called from the shim's `flush_tx_staging()`.
pub fn flush_all_tx_kicks() {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        flush_tx_kick_if_dirty_qp(qp);
    }
}

/// Turn on batched TX doorbells. Called once by the kernel after
/// it has wired `flush_tx_kick_if_dirty` into the event loop —
/// without that guarantee the device would never see the doorbell
/// writes and TX would stall once the ring fills.
pub fn enable_deferred_tx_kick() {
    DEFERRED_KICK.store(true, Ordering::Release);
}

/// Per-core TX. Picks the queue pair matching `cpu_id()` when that
/// fits within `num_qp`, else falls back to qp 0. Matches the
/// virtio-net "send on your own core's queue" semantics so Tier 1
/// scaling keeps working.
pub fn send(data: &[u8]) -> bool {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 {
        return false;
    }
    let core = kernel::cpu_id();
    let qp = if core < num_qp { core as usize } else { 0 };
    send_on_qp(qp, data)
}

// ---- virtio-net-compatible public surface --------------------------------

/// Copy the device MAC into `mac_out` (6 bytes). Matches the
/// signature of `drivers::virtio_net::get_mac` so the dispatch
/// shim can call either driver the same way. The caller is
/// responsible for `mac_out` pointing at 6 writable bytes — same
/// unwritten contract virtio-net's version has.
pub fn get_mac(mac_out: *mut u8) {
    let st = STATE.lock();
    let src = st.as_ref().map(|s| s.mac).unwrap_or([0u8; 6]);
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), mac_out, 6);
    }
}

/// Active queue pair count. Drives `net::poll_tier1` — when > 1
/// the kernel switches to per-core queue polling.
#[inline]
pub fn num_queue_pairs() -> u16 {
    NUM_QP.load(Ordering::Acquire)
}

/// Per-queue RX frame count. Lock-free snapshot — uses the atomic
/// cons_cnt on each live queue.
pub fn rx_counts() -> [u64; 8] {
    let mut out = [0u64; 8];
    for qp in 0..MAX_QUEUE_PAIRS.min(out.len()) {
        let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
        if !rx_ptr.is_null() {
            out[qp] = unsafe { (*rx_ptr).cons_cnt.load(Ordering::Relaxed) as u64 };
        }
    }
    out
}

/// Per-queue used-ring cursors. For gvnic we don't have a
/// virtio-style "used ring" — the closest analogs are the
/// completion ring's fill count (posted to device) and cons count
/// (consumed by driver). Return `(fill_cnt, cons_cnt)` which maps
/// naturally onto virtio's `(device_idx, driver_cursor)`
/// interpretation in `/stats`.
pub fn rx_used_cursors() -> [(u16, u16); 8] {
    let mut out = [(0u16, 0u16); 8];
    for qp in 0..MAX_QUEUE_PAIRS.min(out.len()) {
        let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
        if !rx_ptr.is_null() {
            let rx = unsafe { &*rx_ptr };
            out[qp] = (
                rx.fill_cnt.load(Ordering::Relaxed) as u16,
                rx.cons_cnt.load(Ordering::Relaxed) as u16,
            );
        }
    }
    out
}

/// Per-queue RX poll. Mirrors `drivers::virtio_net::poll_qp(qp, cb)`
/// so Tier 1 per-core polling in `net::poll_tier1` works unchanged.
pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    poll_qp_inner(qp, callback) as i32
}

/// Non-per-core poll. Callers (DHCP bring-up, Tier 2 distribute)
/// don't know which RX queue a given packet landed on, so walk
/// every live queue. RSS is active by the time `init()` returns,
/// and DHCP's reply may hash onto any queue — not just qp 0.
pub fn poll(callback: fn(&[u8])) -> i32 {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    let mut total: u32 = 0;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        total = total.saturating_add(poll_qp_inner(qp, callback));
    }
    total as i32
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
