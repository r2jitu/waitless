// uni-driver-gve/src/lib.rs — Google Virtual Ethernet (gve) driver.
//
// Naming: "gVNIC" is GCE's branding for the virtual NIC product;
// the driver itself is `gve` (matches Linux / the upstream Google
// driver name). The module name and symbols all say `gve`; comments
// reference "gVNIC" when talking about the GCE product surface
// (e.g., instance flags).
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

#![no_std]
#![allow(dead_code, unused_imports)]

extern crate drivers_infra;
extern crate uni_kernel;
extern crate uni_net_driver;

use drivers_infra::{log, mmio_read32, mmio_write32};
use drivers_infra::pci;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{
    compiler_fence, AtomicBool, AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering,
};
use uni_kernel::mm::{alloc_pages, phys_to_virt};
use uni_kernel::sync::Spinlock;

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

/// Values for `CONFIGURE_DEVICE_RESOURCES.queue_format`. Only the
/// two we actually negotiate are listed; see the comment on
/// `QueueFormat` for why `QF_GQI_RDA` (0x1) and `QF_DQO_QPL` (0x4)
/// were removed.
const QF_GQI_QPL: u8 = 0x2;
const QF_DQO_RDA: u8 = 0x3;

// Adminq completion statuses.
const STATUS_UNSET: u32 = 0x0;
const STATUS_PASSED: u32 = 0x1;

// Version field the device expects in DESCRIBE_DEVICE.
const DEVICE_DESCRIPTOR_VERSION: u32 = 1;

// Maximum time we'll poll the event counter for a single command.
// Linux allows many seconds here; we need generous room for the
// device to service DESCRIBE_DEVICE in a freshly-booted VM.
const ADMINQ_WAIT_SPINS: u32 = 10_000_000;

// Device-option ids — only the queue formats this driver knows
// how to bring up. `OPT_ID_GQI_RDA` (0x2) and `OPT_ID_DQO_QPL`
// (0x7) are also defined in the spec but are never advertised
// by GCE in any generation we've tested + we have no driver
// support for them, so they're not parsed here. Unknown ids in
// the device descriptor are skipped silently.
const OPT_ID_GQI_QPL: u16 = 0x3;
const OPT_ID_DQO_RDA: u16 = 0x4;

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
    /// `None` until init runs. Read by queue bring-up to pick a datapath.
    queue_format: Option<QueueFormat>,
    /// MAC from the device descriptor. Populated by DESCRIBE_DEVICE.
    mac: [u8; 6],
    /// Device-advertised caps from the device descriptor. Logged
    /// from init; consumed by queue bring-up when sizing rings.
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
    /// Device-wide resources — filled once CONFIGURE_DEVICE_RESOURCES
    /// succeeds. `None` between DESCRIBE_DEVICE and that point.
    resources: Option<DeviceResources>,
    /// Number of active queue pairs. <= MAX_QUEUE_PAIRS. Set by
    /// `init()` after all queues come up. Tier 1 polling in
    /// `net::poll_tier1` walks `0..num_qp`.
    num_qp: u16,
    /// TX / RX queues. Indexed by queue-pair number 0..num_qp.
    /// One pair per vCPU; multi-queue RX distribution happens
    /// inside the NIC via CONFIGURE_RSS.
    tx: [Option<TxQueue>; MAX_QUEUE_PAIRS],
    rx: [Option<RxQueue>; MAX_QUEUE_PAIRS],
}

/// Matches `uni_drivers::virtio_net::MAX_QUEUE_PAIRS`. Upper bound for
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
    /// read. Single contiguous alloc — simpler than page-by-page.
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

    // ---- DQO_RDA-only fields ----
    /// TX completion ring (DQO only). Each entry is 8 bytes,
    /// device-written; driver polls for the generation bit to
    /// flip on each ring wraparound. 0 in GQI_QPL mode.
    tx_compl_va: u64,
    tx_compl_entries: u16,
    /// Cursor into the TX completion ring (DQO only). 0 in GQI mode.
    tx_compl_head: AtomicU32,
    /// Expected generation bit value for the next completion entry.
    /// Flips each time `tx_compl_head` wraps. 0 in GQI mode.
    tx_compl_gen: AtomicU8,

    /// Cumulative `fill_cnt` value at which we last set
    /// `report_event` on a DQO descriptor. Used to gate the
    /// 32-descriptor minimum spacing between RE flags
    /// (`DQO_TX_RE_INTERVAL`) — required by the device per
    /// `gve_desc_dqo.h`. GQI doesn't have RE; field is unused
    /// in that mode.
    last_re_at_fill: AtomicU32,

    // ---- Direct-fill (zero-copy) TX path (GQI_QPL only today) ----
    //
    // The QPL is indexed by `slot * PAGE_SIZE`; each slot is one
    // 4 KiB page. `slot_used[i]` tracks whether slot `i`'s page is
    // currently filled-and-in-flight. acquire scans for the first
    // `false`, sets `true`, hands the caller a handle pointing at
    // QPL[slot]. submit writes a descriptor at the next ring
    // position whose `seg_addr` references QPL[slot] (decoupled
    // from ring index — the descriptor carries the seg_addr
    // explicitly, so any slot can be referenced from any ring
    // position). On completion the drain path reads `seg_addr`
    // out of the descriptor to recover the slot index and clear
    // `_used`.
    //
    // AtomicBool because the drain runs on the qp's owning core
    // (Tier 1) but slot-allocation is also on that core — single-
    // writer per worker. AtomicBool is a clean primitive here even
    // though a plain `bool` would suffice on Tier 1; matches
    // virtio-net's pattern and keeps cross-core drain (Tier 2 if
    // we ever add it) sound for free.
    slot_used: [core::sync::atomic::AtomicBool; TX_RING_ENTRIES as usize],
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
    /// Expected `flags_seq` sequence byte in GQI_QPL mode (low 3 bits,
    /// cycles 1..7; 0 is reserved); doubles as the expected
    /// generation bit (0 or 1) in DQO_RDA mode. Both signal "this
    /// completion entry was just written by the device" without a
    /// separate producer-index read.
    expected_seq: AtomicU8,
}

/// The two queue formats we actually support. GCE today advertises
/// `GqiQpl` on n2/n2d/e2 and both `GqiQpl` + `DqoRda` on c3/c4. The
/// driver historically also enumerated `GqiRda` and `DqoQpl` for
/// completeness, but neither is ever advertised by GCE in any
/// generation we've tested, and neither has driver-side support
/// (CREATE_*_QUEUE shape, descriptor format, completion handling),
/// so the variants were pure dead code — removed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QueueFormat {
    GqiQpl,
    DqoRda,
}

impl QueueFormat {
    fn name(self) -> &'static [u8] {
        match self {
            QueueFormat::GqiQpl => b"GQI_QPL",
            QueueFormat::DqoRda => b"DQO_RDA",
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
// Hot-path dispatch flag: true once init() has committed to DQO_RDA
// (modern descriptor format on c3 / c4 / future GCE generations).
// Read by `send_on_qp` / `poll_qp_inner` / `tx_drain` / etc. — one
// Acquire load + branch, no STATE.lock(). False in GQI_QPL mode.
static QUEUE_FORMAT_DQO: AtomicBool = AtomicBool::new(false);
// Deferred-kick enable. When true, `send_on_qp` skips the TX
// doorbell write; callers must periodically call
// `flush_tx_kick_if_dirty()` (the kernel event loop does this
// once per iteration after the service callback). Cuts MMIO
// exits by ~Nx where N is average packets per poll batch.
static DEFERRED_KICK: AtomicBool = AtomicBool::new(false);
// Per-queue-pair TxQueue / RxQueue pointers. Each queue struct
// lives inside the driver's `static Spinlock<State>` — `State.tx[qp]` /
// `State.rx[qp]` is a `Some(...)` slot at a stable address for the
// lifetime of the driver. These AtomicPtrs publish raw pointers into
// those slots once `CREATE_*_QUEUE` succeeds, so the hot path
// (`send_on_qp`, `rx_poll_qp`) can reach the queue without taking the
// STATE spinlock.
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
fn read_be16(src: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([src[offset], src[offset + 1]])
}

#[inline]
fn read_be32(src: &[u8], offset: usize) -> u32 {
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
fn init() -> bool {
    if GVNIC_OK.load(Ordering::Acquire) {
        return true;
    }

    // gvnic-not-present is the common case on every platform that
    // isn't GCE — silent miss; the higher-level boot doesn't print
    // a NIC line and the next driver in the registry gets a turn.
    let idx = match pci::find_device(PCI_VENDOR_GVE, PCI_DEVICE_GVE) {
        Some(i) => i,
        None => return false,
    };
    let dev = pci::pci_device(idx);

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
    // dev_status / max_tx / max_rx are sanity reads only — values are
    // identical across every healthy GCE n2 boot and the per-queue
    // count we actually use lands in the `nic` line at end of init.
    let _dev_status = unsafe { reg_read32(REG_DEVICE_STATUS) };
    let max_tx = unsafe { reg_read32(REG_MAX_TX_QUEUES) };
    let max_rx = unsafe { reg_read32(REG_MAX_RX_QUEUES) };

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

    // ── Queue bring-up ──────────────────────────────────────────────────
    //
    // Negotiated queue format. n2 / n2d / e2 advertise GQI_QPL;
    // c3 / c4 / future generations advertise both GQI_QPL and
    // DQO_RDA — `higher_priority` picks GQI_QPL today (DQO direct-
    // fill debug is parked on the c3 stall). The match is now
    // exhaustive: `QueueFormat` only enumerates the two formats
    // the driver actually supports.
    let fmt = match STATE.lock().as_ref().and_then(|s| s.queue_format) {
        Some(f) => f,
        None => return false,
    };
    QUEUE_FORMAT_DQO.store(matches!(fmt, QueueFormat::DqoRda), Ordering::Release);

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

    if !configure_device_resources(bar2_va, num_qp, fmt) {
        return false;
    }

    if !create_all_queues_batched(num_qp, fmt) {
        return false;
    }

    {
        let mut st = STATE.lock();
        if let Some(s) = st.as_mut() {
            s.num_qp = num_qp as u16;
        }
    }
    NUM_QP.store(num_qp as u16, Ordering::Release);

    post_initial_rx();
    // CONFIGURE_RSS already submitted into Phase B's batch by
    // `create_all_queues_batched` and verified with the others;
    // no separate admin-queue round-trip here.

    GVNIC_OK.store(true, Ordering::Release);
    log(b"[gvnic] ready (");
    log_u32(num_qp);
    log(b" queue pairs)\n");
    true
}

/// Returns true if `init()` has completed successfully.
fn probe_ok() -> bool {
    GVNIC_OK.load(Ordering::Acquire)
}

// ---- DESCRIBE_DEVICE implementation ---------------------------------------
//
// One admin-queue command, one response DMA page. Submit, poll the
// event counter, parse the device descriptor, walk its option list,
// and remember everything queue bring-up will need.

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
    // Device descriptor layout (40 bytes, all big-endian), per
    // Linux's `struct gve_device_descriptor` in `gve_adminq.h`:
    //
    //   u64 max_registered_pages   // offset  0
    //   u16 reserved1              //         8
    //   u16 tx_queue_entries       //        10
    //   u16 rx_queue_entries       //        12
    //   u16 default_num_queues     //        14
    //   u16 mtu                    //        16
    //   u16 counters               //        18
    //   u16 tx_pages_per_qpl       //        20
    //   u16 rx_pages_per_qpl       //        22
    //   u8[6] mac                  //        24
    //   u16 num_device_options     //        30
    //   u16 total_length           //        32
    //   u8[6] reserved3            //        34
    //
    // followed by `num_device_options` copies of `{ u16 id, u16 len,
    // u32 req_features }` plus a per-option payload of `len` bytes.

    let header_len = 40;
    let header: &[u8] = unsafe { core::slice::from_raw_parts(desc_virt, header_len) };

    let tx_entries = read_be16(header, 10);
    let rx_entries = read_be16(header, 12);
    let default_num_queues = read_be16(header, 14);
    let tx_pages_per_qpl = read_be16(header, 20);
    let mtu = read_be16(header, 16);
    let counters = read_be16(header, 18);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&header[24..30]);
    let num_options = read_be16(header, 30);
    let total_len = read_be16(header, 32) as usize;

    // Walk the option list to negotiate the queue format. Preference
    // order matches Linux: DQO_RDA > DQO_QPL > GQI_RDA > GQI_QPL.
    // No per-option logging: GCE currently advertises GQI_QPL plus
    // a fixed set of decoration options (MODIFY_RING etc.) that
    // never vary across boots.
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
        let id = read_be16(opt_hdr, 0);
        let len = read_be16(opt_hdr, 2) as usize;

        let fmt = match id {
            OPT_ID_DQO_RDA => Some(QueueFormat::DqoRda),
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

    let fmt_name = match best {
        Some(f) => f.name(),
        None => {
            log(b"[gvnic] no known queue format advertised - incompatible device\n");
            return false;
        }
    };

    // One summary line covering everything an operator actually
    // wants to see at boot. Static device caps (counters, max regs,
    // entry sizes etc.) live in the source — only `mtu`, `qps`,
    // `mac`, and the negotiated format vary in practice.
    log(b"[gvnic] device ");
    log(fmt_name);
    log(b" mtu=");
    log_u32(mtu as u32);
    log(b" qps=");
    log_u32(default_num_queues as u32);
    // Device's advertised TX/RX ring sizes. Currently we use static
    // `TX_RING_ENTRIES = 256` / `RX_RING_ENTRIES = 512` regardless;
    // if these advertised numbers diverge (especially on a future
    // GCE SKU), the gap is visible here for a follow-up that
    // heap-allocates `TxQueue.slot_used` from the runtime value.
    log(b" tx_entries=");
    log_u32(tx_entries as u32);
    log(b" rx_entries=");
    log_u32(rx_entries as u32);
    log(b" tx_pages_per_qpl=");
    log_u32(tx_pages_per_qpl as u32);
    log(b" mac=");
    log_mac(&mac);
    log(b"\n");

    // The device advertises `tx_pages_per_qpl` (Linux's
    // `gve_device_descriptor.tx_pages_per_qpl`) as the MAXIMUM
    // tx pages per registered QPL. Linux uses `tx_desc_cnt /
    // GVE_QPL_DIVISOR = 256/64 = 4` and packs many packets into
    // each page via a FIFO. We deliberately use `1 page per ring
    // slot` (TX_QPL_PAGES = 256), which exceeds the advertised
    // cap on most GCE generations, but our REGISTER_PAGE_LIST
    // command has been working in practice. Log if we exceed and
    // proceed; if a future device strictly enforces this cap and
    // rejects our registration, we'll see it in a CREATE_TX_QUEUE
    // failure later.
    let _ = tx_pages_per_qpl;

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
    // Linux ranks DQO_RDA highest (it's the modern format, better
    // perf on supporting hardware). Our DQO TX path stalls under
    // sustained parallel load on c3-standard-4, while GQI_QPL is
    // validated working on n2. Until DQO is debugged on host,
    // prefer GQI_QPL so c3 deployments fall back to a known-good
    // format. C3 advertises both per Google's gVNIC docs; older
    // n2/n2d/e2 advertise only GQI_QPL.
    use QueueFormat::{DqoRda, GqiQpl};
    match (a, b) {
        (GqiQpl, _) | (_, GqiQpl) => GqiQpl,
        (DqoRda, DqoRda) => DqoRda,
    }
}

// ---- Admin-queue plumbing -------------------------------------------------

/// Enqueue `cmd` into the next admin-queue slot without ringing
/// the doorbell. Returns `(slot_idx, new_prod_cnt)`. Caller is
/// expected to either:
///   - submit additional commands and then call
///     `kick_and_wait_to(prod_cnt)` once to flush the whole batch,
///     followed by `check_slot_status` per command, or
///   - call `kick_and_wait_to` immediately for a one-off (the
///     `submit_and_wait` / `execute_cmd` wrappers do this).
///
/// Batching matches the upstream Linux gve driver's
/// `gve_adminq_issue_cmd` + `gve_adminq_kick_and_wait` pattern —
/// instead of paying per-command device-side processing latency
/// (~3 ms each on GCE) sequentially, we let the device pipeline a
/// run of queued commands and wait for the final completion only.
fn submit_no_wait(cmd: &AdminqCommand) -> Option<(usize, u32)> {
    let mut st = STATE.lock();
    let s = st.as_mut()?;
    let slot_idx = (s.prod_cnt as usize) & (ADMINQ_SLOTS - 1);
    let slot_ptr = (s.adminq_va as *mut AdminqCommand).wrapping_add(slot_idx);
    unsafe { ptr::write_volatile(slot_ptr, *cmd); }
    let new_prod = s.prod_cnt.wrapping_add(1);
    s.prod_cnt = new_prod;
    Some((slot_idx, new_prod))
}

/// Doorbell with the producer count and spin until the device's
/// event counter catches up. Returns false on timeout. Status of
/// each individual command must be checked separately via
/// `read_slot_status` / `check_slot_status`.
fn kick_and_wait_to(expected_event_count: u32) -> bool {
    unsafe { reg_write32(REG_ADMINQ_DOORBELL, expected_event_count); }
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

/// Verify a previously-submitted slot's status word is `STATUS_PASSED`.
/// `label` is logged on failure to identify the failing command.
fn check_slot_status(slot_idx: usize, label: &[u8]) -> bool {
    let status = unsafe { read_slot_status(slot_idx) };
    if status != STATUS_PASSED {
        log(b"[gvnic] ");
        log(label);
        log(b": status=");
        log_hex32(status);
        log(b"\n");
        return false;
    }
    true
}

fn submit_and_wait(cmd: &AdminqCommand) -> bool {
    let (_slot, prod) = match submit_no_wait(cmd) {
        Some(x) => x,
        None => return false,
    };
    kick_and_wait_to(prod)
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
    read_be32(&slot.bytes, 4)
}

/// Read a field the device wrote into a DMA-coherent buffer the
/// driver allocated. Equivalent to `ptr::read_volatile` on the byte
/// range. Having this as a named helper makes the descriptor-
/// parsing sites easier to audit — each one is "device wrote here".
#[inline]
unsafe fn slice_at<'a>(va: u64, len: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(va as *const u8, len) }
}

// ---- Resource + queue bring-up --------------------------------------------
//
// These issue the sequence of admin-queue commands that takes the
// device from "admin queue up" to "one TX + one RX queue usable".
// The datapath (packet send/receive) is further down.
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
/// worth the code when RAM is cheap.
const TX_QPL_PAGES: u32 = TX_RING_ENTRIES as u32;
/// RX QPL size in pages. The reference driver allocates
/// `rx_desc_cnt` pages — one full page per ring entry, even though
/// each packet only uses the first 2 KiB of that page. Smaller
/// allocations are silently rejected by the device with
/// FAILED_PRECONDITION. `rx_pages_per_qpl = 1024` in the device
/// descriptor matches `rx_desc_cnt`, confirming this 1:1 sizing.
const RX_QPL_PAGES: u32 = RX_RING_ENTRIES as u32;

// ---- DQO_RDA descriptor formats -------------------------------------------
// Modern queue format on c3 / c4 / future GCE generations. All
// multi-byte fields are little-endian (matches Linux's gve_desc_dqo.h
// "Only little endian supported"). Generation-bit polling replaces
// GQI's flags_seq pattern: the device flips a generation bit on each
// completion-ring wraparound, and the driver alternates its expected
// generation each time its head wraps.

/// DQO TX packet descriptor — 16 bytes.
///   0..8   buf_addr     (LE64)            DMA addr of packet buffer
///   8      type_flags                     bits[4:0]=dtype (0xC), bit5=end_of_packet,
///                                         bit6=checksum_offload, bit7=report_event
///   9      reserved0
///   10..12 reserved1                      (LE16)
///   12..14 compl_tag                      (LE16)  device echoes in TX completion
///   14..16 buf_size_and_resv              bits[13:0]=buf_size (max 16383)
const DQO_TX_DESC_SIZE: usize = 16;
const DQO_TX_DTYPE_PKT: u8 = 0xC;
/// General context descriptor type, per `gve_desc_dqo.h`'s
/// `GVE_TX_GENERAL_CTX_DESC_DTYPE_DQO`. Linux emits one of
/// these IMMEDIATELY before each data descriptor; without it,
/// our packets miss the metadata preamble the device expects.
const DQO_TX_DTYPE_GENERAL_CTX: u8 = 0x4;
const DQO_TX_FLAG_EOP: u8 = 1 << 5;
/// `checksum_offload_enable` (byte 8 bit 6) — instructs the device
/// to compute the L4 checksum host-side. Equivalent of virtio's
/// NEEDS_CSUM. Per gve_desc_dqo.h.
const DQO_TX_FLAG_CSUM: u8 = 1 << 6;
const DQO_TX_FLAG_REPORT_EVENT: u8 = 1 << 7;
/// `report_event` flags MUST be spaced at least this many TX
/// descriptors apart per `gve_desc_dqo.h`'s GVE_TX_MIN_RE_INTERVAL
/// (= 32). Linux's gve_tx_dqo bumps `last_re_idx` after setting RE
/// and only sets it again once `interval >= 32`. Setting RE on
/// every descriptor (which an earlier version of this driver did)
/// stalls the device under sustained load: completions stop
/// arriving and the per-qp ring saturates at fill_cnt - done_cnt
/// = ring_entries.
const DQO_TX_RE_INTERVAL: u32 = 32;

/// DQO TX completion descriptor — 8 bytes (device-written).
///   0..2   header                         bits[10:0]=id, [13:11]=type,
///                                         bit14=reserved, bit15=generation
///   2..4   tx_head_or_tag                 (LE16)  packet=compl_tag, descriptor=head+1
///   4..8   reserved                       (LE32)
const DQO_TX_COMPL_SIZE: usize = 8;
const DQO_TX_COMPL_TYPE_PACKET: u8 = 0x2;
/// Descriptor completion. Carries `tx_head` (= last desc fetched
/// by HW + 1) at compl bytes 2-3 — the authoritative driver
/// `done_cnt` value. Emitted in response to a `report_event` bit
/// in the TX descriptor.
const DQO_TX_COMPL_TYPE_DESC: u8 = 0x4;

/// DQO RX buffer descriptor — 32 bytes (driver-written, points to a
/// device-readable packet buffer).
///   0..2   buf_id                         (LE16)  echoed back in RX completion
///   2..4   reserved0                      (LE16)
///   4..8   reserved1                      (LE32)
///   8..16  buf_addr                       (LE64)  DMA addr of packet buffer
///   16..24 header_buf_addr                (LE64)  DMA addr of header buffer (we use 0)
///   24..32 reserved2
const DQO_RX_DESC_SIZE: usize = 32;

/// DQO RX completion descriptor — 32 bytes (device-written).
///   Layout per Linux gve_desc_dqo.h. We only use a few fields:
///     offset 0  (1 byte)  rxdid (low 4 bits, must be 1) + reserved
///     offset 4..6 (LE16)  packet_len (low 14 bits) + generation (bit 14) + bq_id (bit 15)
///     offset 8  (1 byte)  status flags: bit0=descriptor_done, bit1=end_of_packet, ...
///     offset 12..14 (LE16) buf_id
const DQO_RX_COMPL_SIZE: usize = 32;
const DQO_RX_COMPL_STATUS_EOP: u8 = 1 << 1;

/// DQO RX buffer pool. Each pre-allocated 2 KiB packet buffer maps to
/// a `buf_id` (the index in this pool). On post we tell the device
/// "buffer at DMA addr X has buf_id Y"; on completion the device
/// returns "buffer Y holds a packet of N bytes" and we look up the VA
/// at `pool_base_va + Y * RX_BUFFER_SIZE` to deliver to the callback.
const DQO_RX_POOL_BUFS: u32 = RX_RING_ENTRIES as u32;
/// DQO TX bounce buffer pool. Mirrors GQI's QPL pages — one buffer
/// per TX ring slot, indexed by ring slot. send() copies the packet
/// in; completion frees the slot.
const DQO_TX_POOL_BUFS: u32 = TX_RING_ENTRIES as u32;

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

fn configure_device_resources(bar2_va: u64, num_qp: u32, fmt: QueueFormat) -> bool {
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
    cmd.bytes[40] = match fmt {
        QueueFormat::GqiQpl => QF_GQI_QPL,
        QueueFormat::DqoRda => QF_DQO_RDA,
    };

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

/// Build a REGISTER_PAGE_LIST command for `num_pages` physically-
/// contiguous pages starting at `base_phys`, identified by
/// `page_list_id`. Allocates the per-page DMA address list (8 bytes
/// per page, in its own page-aligned DMA-coherent buffer) and fills
/// it with big-endian page addresses. Returns the command ready to
/// submit (sync via `execute_cmd` or batched via `submit_no_wait`),
/// or None if the address-list allocation failed.
fn build_register_page_list_cmd(
    page_list_id: u32,
    base_phys: u64,
    num_pages: u32,
) -> Option<AdminqCommand> {
    // The device wants an array of per-page DMA addresses (be64
    // each) in a separate DMA-coherent buffer. 8 bytes per page,
    // rounded up. A 1024-page RX QPL needs 2 pages here.
    let list_bytes = (num_pages as usize) * 8;
    let list_pages = (list_bytes + (PAGE_SIZE as usize) - 1) / (PAGE_SIZE as usize);
    let page_addrs_phys = alloc_pages(list_pages);
    if page_addrs_phys == 0 {
        log(b"[gvnic] failed to alloc page-address list\n");
        return None;
    }
    let page_addrs_va = phys_to_virt(page_addrs_phys);
    unsafe { ptr::write_bytes(page_addrs_va, 0, list_pages * PAGE_SIZE as usize); }

    // Fill in the per-page addresses. The QPL is contiguous, so
    // the i-th page is at base_phys + i*4096.
    for i in 0..num_pages as usize {
        let page_addr = base_phys + (i as u64) * (PAGE_SIZE as u64);
        let buf = page_addr.to_be_bytes();
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
    Some(cmd)
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
/// Build a CONFIGURE_RSS command + its DMA-coherent backing
/// allocations (Toeplitz key + 128-entry indirection LUT). The
/// device processes admin commands in order, so this can be
/// queued in the same `kick_and_wait` batch as the CREATE_*_QUEUE
/// commands — the device sees CREATE_RX_QUEUE × N first, then
/// reads the LUT pointing into queues that now exist. Saves ~3 ms
/// of separate-batch wait time.
///
/// Payload (24 bytes at offset 8):
///   u16 hash_types    (be)
///   u8  hash_alg      (1 = Toeplitz)
///   u8  reserved
///   u16 hash_key_size (be)
///   u16 hash_lut_size (be)
///   u64 hash_key_addr (be, DMA)
///   u64 hash_lut_addr (be, DMA)
fn build_configure_rss_cmd(num_qp: u32) -> Option<AdminqCommand> {
    // 40-byte Toeplitz RSS key. The default is Microsoft's
    // standard key (every Linux / Windows NIC driver uses it),
    // well-tested for realistic 4-tuples. Override at compile
    // time with `--cfg=rss_key=symmetric` to use the symmetric
    // form (`0x6d5a` repeated 20 times) — useful when the
    // bench-client traffic shape is single-source-IP +
    // many-ephemeral-ports, where the asymmetric MS key has
    // surfaced 2× imbalance between hottest and coldest qp on
    // c3 (see /stats `rx_chi_squared_x100`). The symmetric key
    // gives identical hashes for both directions of a 4-tuple,
    // which decorrelates the bias when one peer's port range
    // is fixed.
    //
    // Our first attempt used a synthetic key
    // (`i * 0x9E3779B1 >> 24`) which happened to hash ~99 % of
    // wrk's flows onto qp 0 on n2-highcpu-4 — kept as a
    // cautionary tale in this comment.
    #[cfg(rss_key = "symmetric")]
    let key: [u8; RSS_KEY_SIZE] = [
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    ];
    #[cfg(not(rss_key = "symmetric"))]
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
        return None;
    }
    unsafe {
        let key_va = phys_to_virt(key_phys);
        ptr::copy_nonoverlapping(key.as_ptr(), key_va, RSS_KEY_SIZE);
        let lut_va = phys_to_virt(lut_phys);
        ptr::copy_nonoverlapping(lut_bytes.as_ptr(), lut_va, lut_bytes.len());
    }

    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CONFIGURE_RSS);
    let hash_types = RSS_HASH_TCPV4 | RSS_HASH_TCPV6 | RSS_HASH_UDPV4 | RSS_HASH_UDPV6;
    put_be16(&mut cmd.bytes, 8, hash_types);
    cmd.bytes[10] = RSS_HASH_ALG_TOEPLITZ;
    put_be16(&mut cmd.bytes, 12, RSS_KEY_SIZE as u16);
    put_be16(&mut cmd.bytes, 14, RSS_LUT_SIZE as u16);
    put_be64(&mut cmd.bytes, 16, key_phys);
    put_be64(&mut cmd.bytes, 24, lut_phys);
    Some(cmd)
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

// ---- Per-queue resource allocation ----------------------------------------
//
// Bring-up is split into "alloc resources" → "submit admin commands"
// → "wait once" → "finalize" so that all per-queue admin commands
// can be batched (Linux's `gve_adminq_kick_and_wait` pattern). The
// bottleneck on GCE is admin-queue device latency (~3 ms per command);
// 18 commands run sequentially is ~54 ms, batched into 2 phases is
// ~6 ms in the best case.

#[derive(Clone, Copy)]
struct TxAlloc {
    ring_phys: u64, ring_va: u64,
    qres_phys: u64, qres_va: u64,
    /// In GQI_QPL mode this is the QPL backing pages
    /// (TX_QPL_PAGES × 4 KiB). In DQO_RDA mode this is the TX
    /// bounce-buffer pool (DQO_TX_POOL_BUFS × RX_BUFFER_SIZE
    /// rounded up to pages); send() copies the packet here, the
    /// device DMA-reads it via the descriptor's `buf_addr`.
    qpl_phys: u64, qpl_va: u64,
    /// DQO_RDA only — TX completion ring backing
    /// (DQO_TX_COMPL_SIZE × ring_entries). 0 in GQI_QPL mode.
    tx_compl_phys: u64, tx_compl_va: u64,
}

#[derive(Clone, Copy)]
struct RxAlloc {
    compl_phys: u64, compl_va: u64,
    data_phys: u64, data_va: u64,
    qres_phys: u64, qres_va: u64,
    /// In GQI_QPL mode this is the QPL backing pages
    /// (RX_QPL_PAGES × 4 KiB) — the device DMA-writes packet
    /// payloads here. In DQO_RDA mode this is the RX buffer pool
    /// (DQO_RX_POOL_BUFS × RX_BUFFER_SIZE rounded up to pages); the
    /// driver posts each buffer's DMA addr to the buffer ring at
    /// `data_va` and the device returns the matching `buf_id` in
    /// the completion at `compl_va`.
    qpl_phys: u64, qpl_va: u64,
}

fn alloc_tx_resources(fmt: QueueFormat) -> Option<TxAlloc> {
    // TX descriptor ring: one page of 16-byte descriptors
    // (TX_RING_ENTRIES = 256). Same shape in both formats.
    let (ring_phys, ring_va) = alloc_contig(1);
    if ring_phys == 0 { log(b"[gvnic] failed to alloc TX ring\n"); return None; }
    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 { log(b"[gvnic] failed to alloc TX queue_resources\n"); return None; }

    let (qpl_phys, qpl_va) = match fmt {
        QueueFormat::GqiQpl => {
            // Backing QPL pages — TX_QPL_PAGES contiguous 4 KiB.
            // The device DMA-reads packet payloads via QPL offsets.
            alloc_contig(TX_QPL_PAGES as usize)
        }
        QueueFormat::DqoRda => {
            // TX bounce-buffer pool: one packet buffer per ring slot.
            // send() copies the packet here so the descriptor can
            // hand the device a stable DMA address.
            let bytes = (DQO_TX_POOL_BUFS as u32) * (RX_BUFFER_SIZE as u32);
            let pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
            alloc_contig(pages as usize)
        }
    };
    if qpl_phys == 0 { log(b"[gvnic] failed to alloc TX backing pages\n"); return None; }

    let (tx_compl_phys, tx_compl_va) = match fmt {
        QueueFormat::DqoRda => {
            // TX completion ring — 8 bytes per entry, sized to
            // tx_compl_ring_size (use ring_entries for symmetry).
            let bytes = (TX_RING_ENTRIES as u32) * (DQO_TX_COMPL_SIZE as u32);
            let pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
            let (p, v) = alloc_contig(pages as usize);
            if p == 0 { log(b"[gvnic] failed to alloc TX compl ring\n"); return None; }
            (p, v)
        }
        _ => (0, 0),
    };

    Some(TxAlloc { ring_phys, ring_va, qres_phys, qres_va, qpl_phys, qpl_va, tx_compl_phys, tx_compl_va })
}

fn alloc_rx_resources(fmt: QueueFormat) -> Option<RxAlloc> {
    // RX completion ring: GQI uses 64 B descriptors, DQO uses 32 B.
    let compl_desc_size: u32 = match fmt {
        QueueFormat::GqiQpl => 64,
        QueueFormat::DqoRda => DQO_RX_COMPL_SIZE as u32,
    };
    let compl_pages = ((RX_RING_ENTRIES as u32) * compl_desc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let (compl_phys, compl_va) = alloc_contig(compl_pages as usize);
    if compl_phys == 0 { log(b"[gvnic] failed to alloc RX completion ring\n"); return None; }

    // RX data ring:
    //   GQI: 8-byte slot ring of QPL offsets.
    //   DQO: 32-byte buffer descriptors carrying buf_id + buf_addr.
    let data_desc_size: u32 = match fmt {
        QueueFormat::GqiQpl => 8,
        QueueFormat::DqoRda => DQO_RX_DESC_SIZE as u32,
    };
    let data_pages = ((RX_RING_ENTRIES as u32) * data_desc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let (data_phys, data_va) = alloc_contig(data_pages as usize);
    if data_phys == 0 { log(b"[gvnic] failed to alloc RX data ring\n"); return None; }

    let (qres_phys, qres_va) = alloc_contig(1);
    if qres_phys == 0 { log(b"[gvnic] failed to alloc RX queue_resources\n"); return None; }

    let (qpl_phys, qpl_va) = match fmt {
        QueueFormat::GqiQpl => alloc_contig(RX_QPL_PAGES as usize),
        QueueFormat::DqoRda => {
            // RX buffer pool: one 2 KiB packet buffer per pool slot.
            // The device DMA-writes received frames into these and
            // returns the matching buf_id in the completion.
            let bytes = (DQO_RX_POOL_BUFS as u32) * (RX_BUFFER_SIZE as u32);
            let pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
            alloc_contig(pages as usize)
        }
    };
    if qpl_phys == 0 { log(b"[gvnic] failed to alloc RX backing pages\n"); return None; }

    if matches!(fmt, QueueFormat::GqiQpl) {
        // Pre-fill the GQI data-slot ring: slot `i` points at QPL
        // offset `i * PAGE_SIZE`. Each ring entry gets a whole 4 KiB
        // page even though packets only use the first 2 KiB — matches
        // the reference driver layout (rx_pages_per_qpl == rx_desc_cnt).
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
    }
    // DQO data ring is populated lazily by post_initial_rx_for_qp_dqo
    // after CREATE_RX_QUEUE returns the db_offset (the buffer-ring
    // doorbell is what tells the device "buffers are available").

    Some(RxAlloc { compl_phys, compl_va, data_phys, data_va, qres_phys, qres_va, qpl_phys, qpl_va })
}

/// CREATE_TX_QUEUE command builder. Payload layout (48 bytes at offset 8):
///   u32  queue_id
///   u32  reserved
///   u64  queue_resources_addr (be, DMA)
///   u64  tx_ring_addr (be, DMA)
///   u32  queue_page_list_id (be)        — GQI only; 0 in DQO_RDA
///   u32  ntfy_id (be)
///   u64  tx_comp_ring_addr               — DQO only; 0 in GQI
///   u16  tx_ring_size (be)
///   u16  tx_comp_ring_size (be)          — DQO only; 0 in GQI
///   u8[4] padding
fn build_create_tx_queue_cmd(qp: u32, alloc: &TxAlloc, fmt: QueueFormat) -> AdminqCommand {
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CREATE_TX_QUEUE);
    put_be32(&mut cmd.bytes, 8, qp);
    put_be64(&mut cmd.bytes, 16, alloc.qres_phys);
    put_be64(&mut cmd.bytes, 24, alloc.ring_phys);
    put_be32(&mut cmd.bytes, 32, match fmt {
        QueueFormat::GqiQpl => tx_qpl_id(qp),
        _ => 0,
    });
    put_be32(&mut cmd.bytes, 36, tx_ntfy_id(qp));
    if matches!(fmt, QueueFormat::DqoRda) {
        put_be64(&mut cmd.bytes, 40, alloc.tx_compl_phys);
    }
    put_be16(&mut cmd.bytes, 48, TX_RING_ENTRIES);
    if matches!(fmt, QueueFormat::DqoRda) {
        put_be16(&mut cmd.bytes, 50, TX_RING_ENTRIES);
    }
    cmd
}

/// CREATE_RX_QUEUE command builder. Payload (56 bytes at offset 8):
///   u32  queue_id
///   u32  index
///   u32  reserved
///   u32  ntfy_id
///   u64  queue_resources_addr (DMA)
///   u64  rx_desc_ring_addr (DMA — completion ring; 64 B desc on GQI, 32 B on DQO)
///   u64  rx_data_ring_addr (DMA — slot ring on GQI, buffer ring on DQO)
///   u32  queue_page_list_id              — GQI only; 0 in DQO_RDA
///   u16  rx_ring_size
///   u16  packet_buffer_size
///   u16  rx_buff_ring_size               — DQO only; 0 in GQI
///   u8   enable_rsc
///   u8[5] padding
fn build_create_rx_queue_cmd(qp: u32, alloc: &RxAlloc, num_qp: u32, fmt: QueueFormat) -> AdminqCommand {
    let mut cmd = AdminqCommand::ZERO;
    put_be32(&mut cmd.bytes, 0, OP_CREATE_RX_QUEUE);
    put_be32(&mut cmd.bytes, 8, qp);
    put_be32(&mut cmd.bytes, 12, qp);
    put_be32(&mut cmd.bytes, 20, rx_ntfy_id(num_qp, qp));
    put_be64(&mut cmd.bytes, 24, alloc.qres_phys);
    put_be64(&mut cmd.bytes, 32, alloc.compl_phys);
    put_be64(&mut cmd.bytes, 40, alloc.data_phys);
    put_be32(&mut cmd.bytes, 48, match fmt {
        QueueFormat::GqiQpl => rx_qpl_id(qp),
        _ => 0,
    });
    put_be16(&mut cmd.bytes, 52, RX_RING_ENTRIES);
    put_be16(&mut cmd.bytes, 54, RX_BUFFER_SIZE);
    if matches!(fmt, QueueFormat::DqoRda) {
        put_be16(&mut cmd.bytes, 56, RX_RING_ENTRIES);
    }
    cmd
}

/// Read the device's CREATE_TX_QUEUE response from the qres page and
/// install the resulting `TxQueue` into `STATE` + publish via
/// `TX_QUEUES`. Must run after the corresponding CREATE_TX_QUEUE
/// command has completed (i.e. after `kick_and_wait_to`). Format-
/// specific fields are zeroed for the inactive mode.
fn finalize_tx_queue(qp: u32, alloc: &TxAlloc, fmt: QueueFormat) {
    // gve_queue_resources: u32 db_index (be) + u32 counter_index (be).
    let db_index;
    let counter_index;
    unsafe {
        let bytes = slice_at(alloc.qres_va, 8);
        db_index = read_be32(bytes, 0);
        counter_index = read_be32(bytes, 4);
    }
    let qpl_size = match fmt {
        QueueFormat::GqiQpl => TX_QPL_PAGES * PAGE_SIZE,
        QueueFormat::DqoRda => DQO_TX_POOL_BUFS * RX_BUFFER_SIZE as u32,
    };
    let qpl_id = match fmt {
        QueueFormat::GqiQpl => tx_qpl_id(qp),
        QueueFormat::DqoRda => 0, // RDA → no QPL; CREATE_TX_QUEUE uses GVE_RAW_ADDRESSING_QPL_ID
    };
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.tx[qp as usize] = Some(TxQueue {
            ring_va: alloc.ring_va,
            ring_entries: TX_RING_ENTRIES,
            qres_va: alloc.qres_va,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
            qpl_size,
            qpl_id,
            db_offset: db_index * 4,
            counter_index,
            fill_cnt: AtomicU32::new(0),
            done_cnt: AtomicU32::new(0),
            last_kicked: AtomicU32::new(0),
            tx_compl_va: alloc.tx_compl_va,
            tx_compl_entries: match fmt { QueueFormat::DqoRda => TX_RING_ENTRIES, _ => 0 },
            tx_compl_head: AtomicU32::new(0),
            // Generation starts at 1: the device fills entries with
            // the current generation on each completion, then flips
            // each ring wrap. Ring is initially zeroed (gen=0), so we
            // expect the first entry to read with gen=1.
            tx_compl_gen: AtomicU8::new(1),
            // Initialise last_re_at_fill = -DQO_TX_RE_INTERVAL
            // (wrapping). With fill_cnt starting at 0, the first
            // submit's `interval = 0 - (-32) = 32` fires the
            // `>= 32` check and sets RE — so the device's
            // completion stream bootstraps on the first packet.
            last_re_at_fill: AtomicU32::new(0u32.wrapping_sub(DQO_TX_RE_INTERVAL)),
            slot_used: [const { core::sync::atomic::AtomicBool::new(false) };
                TX_RING_ENTRIES as usize],
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

fn finalize_rx_queue(qp: u32, alloc: &RxAlloc, fmt: QueueFormat) {
    let db_index;
    let counter_index;
    unsafe {
        let bytes = slice_at(alloc.qres_va, 8);
        db_index = read_be32(bytes, 0);
        counter_index = read_be32(bytes, 4);
    }
    let qpl_size = match fmt {
        QueueFormat::GqiQpl => RX_QPL_PAGES * PAGE_SIZE,
        QueueFormat::DqoRda => DQO_RX_POOL_BUFS * RX_BUFFER_SIZE as u32,
    };
    let qpl_id = match fmt {
        QueueFormat::GqiQpl => rx_qpl_id(qp),
        QueueFormat::DqoRda => 0, // RDA → CREATE_RX_QUEUE uses GVE_RAW_ADDRESSING_QPL_ID
    };
    // GQI uses flags_seq starting at 1; DQO uses generation bit
    // starting at 1 (ring is zeroed, device fills with current gen,
    // flips each wrap).
    let initial_seq: u8 = 1;
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.rx[qp as usize] = Some(RxQueue {
            compl_va: alloc.compl_va,
            data_va: alloc.data_va,
            ring_entries: RX_RING_ENTRIES,
            qres_va: alloc.qres_va,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
            qpl_size,
            qpl_id,
            db_offset: db_index * 4,
            counter_index,
            fill_cnt: AtomicU32::new(0),
            cons_cnt: AtomicU32::new(0),
            expected_seq: AtomicU8::new(initial_seq),
        });
        let ptr = s.rx[qp as usize].as_ref().unwrap() as *const RxQueue as *mut RxQueue;
        RX_QUEUES[qp as usize].store(ptr, Ordering::Release);
    }
}

/// Bring up all `num_qp` queue pairs in two batched admin-queue
/// phases: REGISTER_PAGE_LIST × 2*num_qp, then CREATE_*_QUEUE
/// × 2*num_qp. Each phase doorbells once and waits once. On a
/// device that pipelines admin commands this collapses ~16 sync
/// waits (~3 ms each on GCE) into 2.
fn create_all_queues_batched(num_qp: u32, fmt: QueueFormat) -> bool {
    let n = num_qp as usize;
    if n == 0 || n > MAX_QUEUE_PAIRS { return false; }

    // Phase 0: allocate all per-queue local resources (no admin
    // commands). Order doesn't matter; do TX then RX.
    let mut tx_allocs: [Option<TxAlloc>; MAX_QUEUE_PAIRS] = [None; MAX_QUEUE_PAIRS];
    let mut rx_allocs: [Option<RxAlloc>; MAX_QUEUE_PAIRS] = [None; MAX_QUEUE_PAIRS];
    for qp in 0..n {
        tx_allocs[qp] = alloc_tx_resources(fmt);
        if tx_allocs[qp].is_none() { return false; }
    }
    for qp in 0..n {
        rx_allocs[qp] = alloc_rx_resources(fmt);
        if rx_allocs[qp].is_none() { return false; }
    }

    let mut last_prod = 0u32;

    // Phase A: REGISTER_PAGE_LIST × 2n (TX then RX), batched. Only
    // needed in GQI_QPL mode — DQO_RDA descriptors carry raw DMA
    // addresses so there are no QPLs to register, and we skip the
    // entire phase (~5 ms wait).
    if matches!(fmt, QueueFormat::GqiQpl) {
        let mut tx_rpl_slots = [0usize; MAX_QUEUE_PAIRS];
        let mut rx_rpl_slots = [0usize; MAX_QUEUE_PAIRS];
        for qp in 0..n {
            let alloc = tx_allocs[qp].as_ref().unwrap();
            let cmd = match build_register_page_list_cmd(tx_qpl_id(qp as u32), alloc.qpl_phys, TX_QPL_PAGES) {
                Some(c) => c,
                None => return false,
            };
            match submit_no_wait(&cmd) {
                Some((slot, prod)) => { tx_rpl_slots[qp] = slot; last_prod = prod; }
                None => return false,
            }
        }
        for qp in 0..n {
            let alloc = rx_allocs[qp].as_ref().unwrap();
            let cmd = match build_register_page_list_cmd(rx_qpl_id(qp as u32), alloc.qpl_phys, RX_QPL_PAGES) {
                Some(c) => c,
                None => return false,
            };
            match submit_no_wait(&cmd) {
                Some((slot, prod)) => { rx_rpl_slots[qp] = slot; last_prod = prod; }
                None => return false,
            }
        }
        if !kick_and_wait_to(last_prod) { return false; }
        for qp in 0..n {
            if !check_slot_status(tx_rpl_slots[qp], b"REGISTER_PAGE_LIST tx") { return false; }
            if !check_slot_status(rx_rpl_slots[qp], b"REGISTER_PAGE_LIST rx") { return false; }
        }
    }

    // Phase B: CREATE_*_QUEUE × 2n (TX then RX) + CONFIGURE_RSS,
    // batched. The qres page contents are device-written, so
    // finalize must run after the wait completes. CONFIGURE_RSS
    // goes last in the batch so it processes after all the
    // CREATE_RX_QUEUE commands that its LUT references.
    let mut tx_create_slots = [0usize; MAX_QUEUE_PAIRS];
    let mut rx_create_slots = [0usize; MAX_QUEUE_PAIRS];
    for qp in 0..n {
        let cmd = build_create_tx_queue_cmd(qp as u32, tx_allocs[qp].as_ref().unwrap(), fmt);
        match submit_no_wait(&cmd) {
            Some((slot, prod)) => { tx_create_slots[qp] = slot; last_prod = prod; }
            None => return false,
        }
    }
    for qp in 0..n {
        let cmd = build_create_rx_queue_cmd(qp as u32, rx_allocs[qp].as_ref().unwrap(), num_qp, fmt);
        match submit_no_wait(&cmd) {
            Some((slot, prod)) => { rx_create_slots[qp] = slot; last_prod = prod; }
            None => return false,
        }
    }
    let rss_slot = if num_qp > 1 {
        let cmd = match build_configure_rss_cmd(num_qp) {
            Some(c) => c,
            None => return false,
        };
        match submit_no_wait(&cmd) {
            Some((slot, prod)) => { last_prod = prod; Some(slot) }
            None => return false,
        }
    } else {
        None
    };
    if !kick_and_wait_to(last_prod) { return false; }
    for qp in 0..n {
        if !check_slot_status(tx_create_slots[qp], b"CREATE_TX_QUEUE") { return false; }
        finalize_tx_queue(qp as u32, tx_allocs[qp].as_ref().unwrap(), fmt);
    }
    for qp in 0..n {
        if !check_slot_status(rx_create_slots[qp], b"CREATE_RX_QUEUE") { return false; }
        finalize_rx_queue(qp as u32, rx_allocs[qp].as_ref().unwrap(), fmt);
    }
    if let Some(slot) = rss_slot {
        // RSS failure is non-fatal — log and fall through to qp 0
        // single-queue delivery, matching the previous behaviour.
        if !check_slot_status(slot, b"CONFIGURE_RSS") {
            log(b"[gvnic] RSS not configured (falling back to single-queue delivery)\n");
        }
    }

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
/// Only `len` and `flags_seq` are needed by this driver — csum +
/// hash are hints for the stack and can be ignored here.
const RX_DESC_SIZE: usize = 64;
const RX_DESC_LEN_OFF: usize = 60;
const RX_DESC_FLAGS_SEQ_OFF: usize = 62;
const RX_DESC_HDR_OFF_OFF: usize = 57;

/// Start-of-frame offset inside each 4 KiB RX page. The device
/// prepends `_GVE_RX_PAD = 2` bytes of padding before the Ethernet
/// header so IPv4 header bytes land 4-byte aligned. The *actual*
/// offset the device writes into `hdr_off` is scaled by 64 — with
/// one packet per page there's only one valid value
/// (hdr_off = 0, actual start = `_GVE_RX_PAD`).
const RX_DATA_OFFSET_IN_PAGE: usize = _GVE_RX_PAD as usize;

/// TX descriptor size (gve_tx_pkt_desc, packed, 16 bytes).
const TX_DESC_SIZE: usize = 16;

/// Highest packet length we're willing to stage at once. Matches
/// the device-advertised MTU + Ethernet + safety slack; see
/// `send()` below for the actual check.
const TX_MAX_PKT_LEN: usize = 2048;

fn post_initial_rx() {
    // After CREATE_RX_QUEUE the data ring needs a doorbell so the
    // device starts using the posted buffers/slots. GQI: data-slot
    // ring is already pre-filled with QPL offsets; write the full
    // ring count to the doorbell. DQO: write 32-byte buffer
    // descriptors carrying buf_id+buf_addr, then doorbell.
    let dqo = QUEUE_FORMAT_DQO.load(Ordering::Acquire);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    for qp in 0..MAX_QUEUE_PAIRS {
        let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
        if rx_ptr.is_null() { continue; }
        // SAFETY: pointer published with Release, only null means
        // "not installed". RxQueue's non-atomic fields are only
        // written during init (before this Release); reading them
        // here through Acquire is a valid synchronisation.
        let rx = unsafe { &*rx_ptr };
        if dqo {
            post_initial_rx_for_qp_dqo(rx);
        } else {
            let fill = rx.ring_entries as u32;
            rx.fill_cnt.store(fill, Ordering::Release);
            doorbell_write(bar2_va, rx.db_offset, fill);
        }
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
fn poll_qp_inner<F: FnMut(&[u8])>(qp: usize, mut callback: F) -> u32 {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return poll_qp_inner_dqo(qp, callback);
    }
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

        let flags_seq = read_be16(desc, RX_DESC_FLAGS_SEQ_OFF);
        let seq = (flags_seq & 0x7) as u8;
        if seq != expected {
            break;
        }

        let len = read_be16(desc, RX_DESC_LEN_OFF) as usize;
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
/// pointer + device counter via an atomic. For each completed
/// descriptor in the range `[done_cnt, nic_done)`, reads the
/// descriptor's `seg_addr` to recover which slot's QPL page it
/// referenced and marks that slot free. Cheap: each completion
/// is a 16-byte descriptor read + an atomic store.
#[inline]
fn tx_drain(tx: &TxQueue) {
    let counter_va = COUNTER_ARRAY_VA.load(Ordering::Acquire);
    if counter_va == 0 { return; }
    let counter_ptr = counter_va as *const u32;
    let raw = unsafe { ptr::read_volatile(counter_ptr.add(tx.counter_index as usize)) };
    let nic_done = u32::from_be(raw);
    let prev = tx.done_cnt.load(Ordering::Relaxed);
    if nic_done == prev { return; }

    // Walk completed descriptors and free their slots.
    let mask = (tx.ring_entries - 1) as u32;
    let mut k = prev;
    while k != nic_done {
        let ring_idx = (k & mask) as usize;
        let desc_ptr = (tx.ring_va as *const u8).wrapping_add(ring_idx * TX_DESC_SIZE);
        // gve_tx_pkt_desc: seg_addr is at offset 8, big-endian u64.
        // SAFETY: ring_va is a registered DMA-mapped page; idx is in
        // bounds via `& mask`; descriptor is 16 bytes wide.
        let seg_addr_be = unsafe {
            ptr::read_unaligned(desc_ptr.add(8) as *const u64)
        };
        let seg_addr = u64::from_be(seg_addr_be);
        let slot = (seg_addr / PAGE_SIZE as u64) as usize;
        if slot < TX_RING_ENTRIES as usize {
            tx.slot_used[slot].store(false, Ordering::Release);
        }
        k = k.wrapping_add(1);
    }
    tx.done_cnt.store(nic_done, Ordering::Relaxed);
}

/// Submit a single-segment packet on queue pair `qp`. Returns
/// `true` on success, `false` when the ring has no free slots
/// (device hasn't caught up) or the frame exceeds `TX_MAX_PKT_LEN`.
/// Dispatches to the GQI_QPL or DQO_RDA implementation based on
/// the queue format committed at init time.
fn send_on_qp(qp: usize, data: &[u8]) -> bool {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return send_on_qp_dqo(qp, data);
    }
    if data.is_empty() || data.len() > TX_MAX_PKT_LEN {
        return false;
    }
    // Slice-shaped wrapper over the direct-fill path: acquire a
    // slot from the QP's pool, memcpy data into it, submit. The
    // caller's stack-staged buffer + this memcpy is exactly the
    // cost the direct-fill path saves for callers willing to fill
    // in place.
    let mut handle = match acquire_tx_buf_for_qp(qp) {
        Some(h) => h,
        None => return false,
    };
    let n = data.len();
    handle.data_mut()[..n].copy_from_slice(data);
    submit_tx_inner(handle, n, uni_net_driver::CsumOffload::NONE);
    true
}

/// Acquire a TX slot for a specific qp. Used by `send_on_qp` (which
/// has already picked the qp by core or fallback) and by the
/// public `acquire_tx_buf` (which picks the worker's qp). Spin-
/// drains on full pool — the caller is the qp's owning worker
/// (Tier 1) so this is cooperative scheduling, not deadlock-prone.
fn acquire_tx_buf_for_qp(qp: usize) -> Option<uni_net_driver::TxBufHandle> {
    if qp >= MAX_QUEUE_PAIRS { return None; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return None; }
    let tx = unsafe { &*tx_ptr };

    let mut local_iters: u64 = 0;
    loop {
        // Need both: a free slot in the pool AND ring-fill capacity
        // (fill_cnt - done_cnt < ring_entries). With slot_count ==
        // ring_entries, "free slot" implies "ring capacity" once
        // drain runs; check both for clarity.
        tx_drain(tx);
        let fill = tx.fill_cnt.load(Ordering::Relaxed);
        let done = tx.done_cnt.load(Ordering::Relaxed);
        if fill.wrapping_sub(done) < tx.ring_entries as u32 {
            for slot in 0..(tx.ring_entries as usize) {
                local_iters += 1;
                if !tx.slot_used[slot].load(Ordering::Acquire) {
                    tx.slot_used[slot].store(true, Ordering::Relaxed);
                    // Diag: record cumulative scan-iters + acquire
                    // count so the reader can compute the average
                    // scan depth. Single relaxed atomic each — off
                    // the per-packet hot path's critical chain.
                    TX_SMALL_SCAN_ITERS.fetch_add(local_iters, Ordering::Relaxed);
                    TX_SMALL_ACQUIRES.fetch_add(1, Ordering::Relaxed);
                    let qpl_offset = (slot as u32) * PAGE_SIZE;
                    let data_ptr = (tx.qpl_base_va + qpl_offset as u64) as *mut u8;
                    return Some(uni_net_driver::TxBufHandle {
                        data_ptr,
                        data_cap: TX_MAX_PKT_LEN as u32,
                        driver_token: encode_token(qp, slot),
                        release_fn: release_tx_slot,
                    });
                }
            }
        }
        // No capacity. Force any deferred kick so the host sees
        // pending descriptors and can produce completions. Each
        // wrap-around counts as one saturation event.
        TX_SMALL_FULL_SPINS.fetch_add(1, Ordering::Relaxed);
        let bar2_va = BAR2_VA.load(Ordering::Acquire);
        if bar2_va != 0 {
            let last = tx.last_kicked.load(Ordering::Relaxed);
            if fill != last {
                doorbell_write(bar2_va, tx.db_offset, fill);
                tx.last_kicked.store(fill, Ordering::Relaxed);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Encode `(qp, slot)` into the opaque `driver_token` of a
/// [`uni_net_driver::TxBufHandle`]. Layout:
///   * bits 32..62: qp index
///   * bits  0..32: slot index
#[inline]
fn encode_token(qp: usize, slot: usize) -> u64 {
    (((qp as u64) & 0x7FFF_FFFF) << 32) | (slot as u64 & 0xFFFF_FFFF)
}

#[inline]
fn decode_token(token: u64) -> (usize, usize) {
    let qp = ((token >> 32) & 0x7FFF_FFFF) as usize;
    let slot = (token & 0xFFFF_FFFF) as usize;
    (qp, slot)
}

/// Drop callback for an unsubmitted handle: returns the slot to
/// the pool. `submit_tx_inner` mem-forgets the handle to skip this
/// path on the success leg.
fn release_tx_slot(token: u64) {
    let (qp, slot) = decode_token(token);
    if qp >= MAX_QUEUE_PAIRS { return; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    if slot < TX_RING_ENTRIES as usize {
        tx.slot_used[slot].store(false, Ordering::Release);
    }
}

/// Build the gve_tx_pkt_desc at the next ring position, advance
/// `fill_cnt`, and (unless deferred) write the doorbell. Caller
/// has already filled `handle.data_mut()[..frame_len]` with the
/// frame bytes; the descriptor's `seg_addr` references the slot's
/// QPL page so the device DMAs from there.
///
/// gve_tx_pkt_desc layout (16 bytes), per Linux gve_desc.h:
///   u8  type_flags     (low 4 bits = type, upper 4 bits = flags;
///                       type = GVE_TXD_STD (0x00); flags include
///                       GVE_TXF_L4CSUM (bit 0))
///   u8  l4_csum_offset (16-bit-WORD offset within L4 header to
///                       the checksum field — TCP=8, UDP=3)
///   u8  l4_hdr_offset  (16-bit-WORD offset of L4 header in
///                       packet — Eth+IPv4 = 34/2 = 17)
///   u8  desc_cnt       (1 — single-segment packet)
///   u16 len            (be, total packet length)
///   u16 seg_len        (be, this segment length)
///   u64 seg_addr       (be, QPL byte offset in QPL mode)
///
/// `csum.is_some()` activates L4-CSUM offload: the device
/// computes the L4 checksum at byte
/// `l4_hdr_offset*2 + l4_csum_offset*2` of the frame.
fn submit_tx_inner(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    let (qp, slot) = decode_token(handle.driver_token);
    // mem::forget skips Drop's `release_fn` — the slot is about
    // to be in-flight, not unused. `tx_drain` returns it to the
    // pool when the device signals descriptor completion.
    core::mem::forget(handle);

    if qp >= MAX_QUEUE_PAIRS || slot >= TX_RING_ENTRIES as usize {
        return;
    }
    if frame_len == 0 || frame_len > TX_MAX_PKT_LEN {
        let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            unsafe { (*tx_ptr).slot_used[slot].store(false, Ordering::Release); }
        }
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let mask = (tx.ring_entries - 1) as u32;
    let ring_idx = (fill_cnt & mask) as usize;

    let qpl_offset = (slot as u32) * PAGE_SIZE;
    let desc_ptr = (tx.ring_va as *mut u8).wrapping_add(ring_idx * TX_DESC_SIZE);
    let mut desc = [0u8; TX_DESC_SIZE];
    // type_flags: GVE_TXD_STD (= 0x00) | GVE_TXF_L4CSUM (= 0x01)
    // when offload is on. Linux uses the upper-4-bit type encoding
    // (`(0x0 << 4) = GVE_TXD_STD`) plus low-bit flags.
    desc[0] = if csum.is_some() { 0x01 /* GVE_TXF_L4CSUM */ } else { 0x00 };
    if csum.is_some() {
        // Both fields are in 16-bit-word units per the spec
        // (`csum_offset >> 1`, `l4_hdr_offset >> 1` in Linux).
        // The caller's `csum.start` is the byte offset of the L4
        // header in the frame; `csum.offset` is the byte offset
        // of the checksum field within the L4 header.
        desc[1] = (csum.offset >> 1) as u8;
        desc[2] = (csum.start >> 1) as u8;
    }
    desc[3] = 1; // desc_cnt
    put_be16(&mut desc, 4, frame_len as u16);
    put_be16(&mut desc, 6, frame_len as u16);
    put_be64(&mut desc, 8, qpl_offset as u64);
    unsafe {
        ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, TX_DESC_SIZE);
    }
    record_tx_desc(qp as u8, tx_desc_kind::STD, &desc);

    let new_fill = fill_cnt.wrapping_add(1);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(tx.done_cnt.load(Ordering::Relaxed))
        >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }

    // Per-qp TX packet count for load-distribution diagnostics.
    if qp < TX_PACKETS_PER_QP.len() {
        TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
    }
}

/// Public direct-fill TX entry — picks the calling worker's qp,
/// scans for a free slot, returns a handle into the per-slot
/// QPL page (GQI_QPL).
///
/// On DQO_RDA returns `None` so callers fall through to the
/// slice-shaped `send_on_qp_dqo` path. The DQO direct-fill
/// implementation (`acquire_tx_buf_dqo_for_qp` /
/// `submit_tx_inner_dqo`) is in place and applies all the
/// spec-correct fixes derived from Linux's `gve_tx_dqo` (RE
/// spaced ≥ 32 descriptors, DESC completion's `tx_head` drives
/// `done_cnt`, `checksum_offload_enable` bit), but real-device
/// validation on c3 still shows a stall under sustained
/// parallel load even with these fixes — there's at least one
/// more issue that needs on-host debugging (likely doorbell or
/// completion-ring related) before we can ship DQO direct-fill.
/// Tracked as a follow-up.
fn acquire_tx_buf() -> Option<uni_net_driver::TxBufHandle> {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return None;
    }
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 { return None; }
    let core = uni_kernel::cpu_id();
    let qp = if core < num_qp { core as usize } else { 0 };
    acquire_tx_buf_for_qp(qp)
}

/// Public submit — paired with [`acquire_tx_buf`]. Consumes the
/// handle (slot returns to pool on device completion). `csum`
/// is not yet wired through gve's descriptor — caller's stamped
/// checksum is shipped verbatim today.
fn submit_tx(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        submit_tx_inner_dqo(handle, frame_len, csum);
    } else {
        submit_tx_inner(handle, frame_len, csum);
    }
}

/// Flush the deferred TX kick for the given queue pair. Returns
/// true if a doorbell write was issued. Called by the event loop
/// after each service pass to push whatever `send_on_qp` batched
/// onto the wire before the CPU sits idle.
fn flush_tx_kick_if_dirty_qp(qp: usize) -> bool {
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
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        doorbell_write_le(bar2_va, tx.db_offset, fill);
    } else {
        doorbell_write(bar2_va, tx.db_offset, fill);
    }
    tx.last_kicked.store(fill, Ordering::Relaxed);
    true
}

/// Flush the current core's TX queue if dirty. Mirrors
/// `uni_drivers::virtio_net::flush_tx_kick_if_dirty` so the shim in
/// `uni_drivers::net` can dispatch through the same signature.
fn flush_tx_kick_if_dirty() -> bool {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 { return false; }
    let core = uni_kernel::cpu_id();
    let qp = if core < num_qp { core as usize } else { 0 };
    flush_tx_kick_if_dirty_qp(qp)
}

/// Flush every TX queue's pending kick. Not strictly needed in
/// per-core-queue Tier 1 mode (each core's `flush_tx_kick_if_dirty`
/// covers its own queue), but useful if something batches sends
/// across cores. Called from the shim's `flush_tx_staging()`.
fn flush_all_tx_kicks() {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        flush_tx_kick_if_dirty_qp(qp);
    }
}

// ---- DQO_RDA datapath ------------------------------------------------------
//
// Modern descriptor format used on c3 / c4 / future GCE generations.
// Differences from GQI_QPL: little-endian wire format throughout, raw
// DMA addresses in TX descriptors (no QPL offsets — we still bounce
// through a per-slot buffer to keep memory layout simple), separate
// TX completion ring and RX buffer ring, and "generation bit" polling
// instead of GQI's flags_seq cycle.

/// DQO doorbell write. Unlike GQI_QPL (big-endian), DQO doorbells are
/// little-endian on the wire — Linux's `gve_*_write_doorbell_dqo` use
/// `writel` (LE on x86) vs GQI's `iowrite32be`.
#[inline]
fn doorbell_write_le(bar2_va: u64, offset: u32, value: u32) {
    unsafe {
        mmio_write32(bar2_va + offset as u64, value);
    }
}

/// Drain the DQO TX completion ring up to the first entry whose
/// generation bit doesn't match what we expect, then advance
/// `done_cnt` to the device-reported `tx_head` from the last
/// observed DESC completion.
///
/// DQO TX-completion descriptor layout (8 bytes), per Linux's
/// `gve_tx_compl_desc` (gve_desc_dqo.h):
///
///   bytes 0-1: LE-bitfield u16
///     bits  0..10 = id (compl_tag, for PKT/MISS/REINJECT compls;
///                   queue ID for DESC compls — informational)
///     bits 11..13 = type (DQO_TX_COMPL_TYPE_*)
///     bit 14      = reserved
///     bit 15      = generation
///   bytes 2-3: union — `tx_head` (DESC compl) or
///              `completion_tag` (PKT compl), LE u16
///   bytes 4-7: reserved
///
/// `tx_head` from a DESC completion is "the last descriptor
/// fetched by HW plus one" (the authoritative driver `done_cnt`
/// value). PKT/MISS/REINJECT completions only convey per-packet
/// status — we don't need them for slot reuse since this driver
/// uses the slot==ring_idx convention; ring positions cycle
/// implicitly as `done_cnt` advances.
fn tx_drain_dqo(tx: &TxQueue) {
    if tx.tx_compl_va == 0 || tx.tx_compl_entries == 0 { return; }
    let cmask = (tx.tx_compl_entries - 1) as u32;
    let rmask = (tx.ring_entries - 1) as u32;
    let mut head = tx.tx_compl_head.load(Ordering::Relaxed);
    let mut cur_gen = tx.tx_compl_gen.load(Ordering::Relaxed);
    let mut latest_tx_head: Option<u16> = None;
    loop {
        let idx = (head & cmask) as usize;
        let desc_ptr = (tx.tx_compl_va as *const u8).wrapping_add(idx * DQO_TX_COMPL_SIZE);
        let hdr_word = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr) },
            unsafe { ptr::read_volatile(desc_ptr.add(1)) },
        ]);
        let desc_gen = ((hdr_word >> 15) & 1) as u8;
        if desc_gen != cur_gen { break; }
        let cmpl_type = ((hdr_word >> 11) & 0x7) as u8;
        if cmpl_type == DQO_TX_COMPL_TYPE_DESC {
            let tx_head = u16::from_le_bytes([
                unsafe { ptr::read_volatile(desc_ptr.add(2)) },
                unsafe { ptr::read_volatile(desc_ptr.add(3)) },
            ]);
            latest_tx_head = Some(tx_head);
        }
        // PKT / MISS / REINJECTION completions: consume but
        // don't act on them — slot reuse is keyed off DESC
        // completions' tx_head.
        head = head.wrapping_add(1);
        if (head & cmask) == 0 {
            cur_gen ^= 1;
        }
    }
    tx.tx_compl_head.store(head, Ordering::Relaxed);
    tx.tx_compl_gen.store(cur_gen, Ordering::Relaxed);
    if let Some(tx_head) = latest_tx_head {
        // Translate the device's u16 ring-position `tx_head` into
        // an advance for our cumulative `done_cnt` (u32). Both
        // `done_cnt`'s low ring-mask bits and `tx_head` index into
        // the same ring; the delta between them (mod ring_entries)
        // is the number of descriptors the device has fetched
        // since our last drain.
        let mask16 = rmask as u16;
        let prev = tx.done_cnt.load(Ordering::Relaxed);
        let prev_low = (prev as u16) & mask16;
        let tx_head_low = tx_head & mask16;
        let delta = (tx_head_low.wrapping_sub(prev_low)) & mask16;
        if delta > 0 {
            tx.done_cnt.store(prev.wrapping_add(delta as u32), Ordering::Relaxed);
        }
    }
}

fn send_on_qp_dqo(qp: usize, data: &[u8]) -> bool {
    if qp >= MAX_QUEUE_PAIRS || data.is_empty() || data.len() > (RX_BUFFER_SIZE as usize) {
        return false;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return false; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    tx_drain_dqo(tx);

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let done_cnt = tx.done_cnt.load(Ordering::Relaxed);
    let in_flight = fill_cnt.wrapping_sub(done_cnt);
    if in_flight >= tx.ring_entries as u32 {
        return false;
    }

    let mask = (tx.ring_entries - 1) as u32;
    let slot = (fill_cnt & mask) as usize;

    // Per-slot bounce buffer: send copies the packet here so the
    // descriptor can hand the device a stable DMA address.
    let buf_offset = (slot as u32) * (RX_BUFFER_SIZE as u32);
    let buf_va = (tx.qpl_base_va + buf_offset as u64) as *mut u8;
    let buf_phys = tx.qpl_base_phys + buf_offset as u64;
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf_va, data.len()); }

    // gve_tx_pkt_desc_dqo, 16 bytes, all LE. RE only every 32nd
    // descriptor per the device's spec (`GVE_TX_MIN_RE_INTERVAL`).
    //
    // NOTE: Linux's `gve_tx_add_skb_dqo` ALWAYS emits a general
    // context descriptor (DTYPE 0x4) before each data desc.
    // I tried that — c3-standard-4 throughput got worse, not
    // better, suggesting either my context-desc layout is wrong
    // or there's an interaction with the RE/completion path I
    // can't see from outside the bench loop. Reverted to the
    // single-data-desc shape; needs on-host instrumentation to
    // root-cause why the device wedges under sustained load.
    let last_re = tx.last_re_at_fill.load(Ordering::Relaxed);
    let want_re = fill_cnt.wrapping_sub(last_re) >= DQO_TX_RE_INTERVAL;
    let mut flags = DQO_TX_DTYPE_PKT | DQO_TX_FLAG_EOP;
    if want_re {
        flags |= DQO_TX_FLAG_REPORT_EVENT;
        tx.last_re_at_fill.store(fill_cnt, Ordering::Relaxed);
    }
    let desc_ptr = (tx.ring_va as *mut u8).wrapping_add(slot * DQO_TX_DESC_SIZE);
    let mut desc = [0u8; DQO_TX_DESC_SIZE];
    desc[0..8].copy_from_slice(&buf_phys.to_le_bytes());
    desc[8] = flags;
    desc[12..14].copy_from_slice(&(slot as u16).to_le_bytes());
    let size_word = (data.len() as u16) & 0x3FFF;
    desc[14..16].copy_from_slice(&size_word.to_le_bytes());
    unsafe { ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, DQO_TX_DESC_SIZE); }

    let new_fill = fill_cnt.wrapping_add(1);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(done_cnt) >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write_le(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }
    true
}

/// DQO direct-fill: claim the next ring position (slot index ==
/// `fill_cnt & mask`) and return a handle pointing at the
/// matching bounce-buffer page. Spin-drains on full.
///
/// Unlike GQI's pool-decoupled allocator, DQO uses the
/// slot==ring_idx convention — same shape as the legacy
/// `send_on_qp_dqo` that this path replaces. The pool decoupling
/// turned out not to work on real DQO devices: the completion
/// descriptor's `compl_tag` field doesn't reliably round-trip
/// through the device on every instance type, so we can't
/// recover an arbitrary slot index at drain time. Sticking with
/// slot==ring_idx means drain just needs to advance `done_cnt`;
/// slot reuse is implicit (ring position cycles).
///
/// Contract: the caller must pair acquire+submit synchronously
/// (one outstanding handle per worker). Dropping a handle
/// without submitting is a no-op — the next acquire returns the
/// same slot since `fill_cnt` didn't move.
fn acquire_tx_buf_dqo_for_qp(qp: usize) -> Option<uni_net_driver::TxBufHandle> {
    if qp >= MAX_QUEUE_PAIRS { return None; }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return None; }
    let tx = unsafe { &*tx_ptr };

    loop {
        tx_drain_dqo(tx);
        let fill = tx.fill_cnt.load(Ordering::Relaxed);
        let done = tx.done_cnt.load(Ordering::Relaxed);
        if fill.wrapping_sub(done) < tx.ring_entries as u32 {
            let mask = (tx.ring_entries - 1) as u32;
            let slot = (fill & mask) as usize;
            let buf_offset = (slot as u32) * (RX_BUFFER_SIZE as u32);
            let data_ptr = (tx.qpl_base_va + buf_offset as u64) as *mut u8;
            return Some(uni_net_driver::TxBufHandle {
                data_ptr,
                data_cap: RX_BUFFER_SIZE as u32,
                driver_token: encode_token(qp, slot),
                release_fn: release_tx_slot_noop,
            });
        }
        // Force any deferred kick so the device drains and produces
        // completions; spin-drain.
        let bar2_va = BAR2_VA.load(Ordering::Acquire);
        if bar2_va != 0 {
            let last = tx.last_kicked.load(Ordering::Relaxed);
            if fill != last {
                doorbell_write_le(bar2_va, tx.db_offset, fill);
                tx.last_kicked.store(fill, Ordering::Relaxed);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// No-op release for the slot==ring_idx convention: dropping a
/// handle without submit doesn't advance `fill_cnt`, so the same
/// slot is returned by the next acquire. No bookkeeping needed.
fn release_tx_slot_noop(_token: u64) {}

/// DQO submit: build the gve_tx_pkt_desc_dqo at ring[slot]
/// (slot==ring_idx convention from acquire), advance fill_cnt,
/// (unless deferred) write doorbell.
///
/// gve_tx_pkt_desc_dqo (16 bytes, all LE):
///   0..8   buf_addr (DMA address)
///   8      dtype:5 | end_of_packet:1 | checksum_offload_enable:1 | report_event:1
///   9      reserved
///   10..12 reserved
///   12..14 compl_tag (we use the slot index — informational)
///   14..16 buf_size (low 14 bits)
///
/// `report_event` is gated to fire at most every
/// `DQO_TX_RE_INTERVAL` (= 32) descriptors per the device's spec.
/// `checksum_offload_enable` is set when the caller passed a
/// non-NONE `CsumOffload` (caller stamped the pseudo-header
/// partial sum at the L4 checksum field).
fn submit_tx_inner_dqo(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    let (qp, slot) = decode_token(handle.driver_token);
    core::mem::forget(handle);
    if qp >= MAX_QUEUE_PAIRS || slot >= TX_RING_ENTRIES as usize {
        return;
    }
    if frame_len == 0 || frame_len > RX_BUFFER_SIZE as usize {
        return;
    }
    let tx_ptr = TX_QUEUES[qp].load(Ordering::Acquire);
    if tx_ptr.is_null() { return; }
    let tx = unsafe { &*tx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    // slot == fill_cnt & mask by acquire's contract; use it
    // directly as the ring position (and the QPL bounce-buffer
    // index — they coincide).
    let buf_offset = (slot as u32) * (RX_BUFFER_SIZE as u32);
    let buf_phys = tx.qpl_base_phys + buf_offset as u64;

    let fill_cnt = tx.fill_cnt.load(Ordering::Relaxed);
    let last_re = tx.last_re_at_fill.load(Ordering::Relaxed);
    let want_re = fill_cnt.wrapping_sub(last_re) >= DQO_TX_RE_INTERVAL;
    let mut flags = DQO_TX_DTYPE_PKT | DQO_TX_FLAG_EOP;
    if want_re {
        flags |= DQO_TX_FLAG_REPORT_EVENT;
        tx.last_re_at_fill.store(fill_cnt, Ordering::Relaxed);
    }
    if csum.is_some() {
        flags |= DQO_TX_FLAG_CSUM;
    }

    let desc_ptr = (tx.ring_va as *mut u8).wrapping_add(slot * DQO_TX_DESC_SIZE);
    let mut desc = [0u8; DQO_TX_DESC_SIZE];
    desc[0..8].copy_from_slice(&buf_phys.to_le_bytes());
    desc[8] = flags;
    desc[12..14].copy_from_slice(&(slot as u16).to_le_bytes());
    let size_word = (frame_len as u16) & 0x3FFF;
    desc[14..16].copy_from_slice(&size_word.to_le_bytes());
    unsafe { ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, DQO_TX_DESC_SIZE); }

    let new_fill = fill_cnt.wrapping_add(1);
    tx.fill_cnt.store(new_fill, Ordering::Release);

    let near_full = new_fill.wrapping_sub(tx.done_cnt.load(Ordering::Relaxed))
        >= (tx.ring_entries as u32) - 16;
    if !DEFERRED_KICK.load(Ordering::Relaxed) || near_full {
        doorbell_write_le(bar2_va, tx.db_offset, new_fill);
        tx.last_kicked.store(new_fill, Ordering::Relaxed);
    }

    // Per-qp TX packet count, same field as the GQI path.
    if qp < TX_PACKETS_PER_QP.len() {
        TX_PACKETS_PER_QP[qp].fetch_add(1, Ordering::Relaxed);
    }
}

/// Post all DQO_RX_POOL_BUFS buffers on this queue's buffer ring and
/// kick the doorbell — equivalent to GQI's "fill the data-slot ring +
/// write fill_cnt to doorbell". Buffer i lives at
/// `qpl_base + i * RX_BUFFER_SIZE` and is identified by `buf_id = i`
/// when the device returns it via the completion ring.
fn post_initial_rx_for_qp_dqo(rx: &RxQueue) {
    let pool_base_phys = rx.qpl_base_phys;
    let mask = (rx.ring_entries - 1) as u32;
    for i in 0..DQO_RX_POOL_BUFS {
        let post_idx = ((i) & mask) as usize;
        let desc_ptr = (rx.data_va as *mut u8).wrapping_add(post_idx * DQO_RX_DESC_SIZE);
        let mut desc = [0u8; DQO_RX_DESC_SIZE];
        desc[0..2].copy_from_slice(&(i as u16).to_le_bytes());
        let buf_phys = pool_base_phys + (i as u64) * (RX_BUFFER_SIZE as u64);
        desc[8..16].copy_from_slice(&buf_phys.to_le_bytes());
        unsafe { ptr::copy_nonoverlapping(desc.as_ptr(), desc_ptr, DQO_RX_DESC_SIZE); }
    }
    rx.fill_cnt.store(DQO_RX_POOL_BUFS, Ordering::Release);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    doorbell_write_le(bar2_va, rx.db_offset, DQO_RX_POOL_BUFS);
}

fn poll_qp_inner_dqo<F: FnMut(&[u8])>(qp: usize, mut callback: F) -> u32 {
    if qp >= MAX_QUEUE_PAIRS { return 0; }
    let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
    if rx_ptr.is_null() { return 0; }
    let rx = unsafe { &*rx_ptr };
    let bar2_va = BAR2_VA.load(Ordering::Acquire);

    let mask = (rx.ring_entries - 1) as u32;
    let mut cons = rx.cons_cnt.load(Ordering::Relaxed);
    let mut cur_gen = rx.expected_seq.load(Ordering::Relaxed);
    let mut delivered: u32 = 0;
    const MAX_BATCH: u32 = 64;

    while delivered < MAX_BATCH {
        let idx = (cons & mask) as usize;
        let desc_ptr = (rx.compl_va as *const u8).wrapping_add(idx * DQO_RX_COMPL_SIZE);
        // packet_len LE16 at offset 4: bits[13:0]=len, bit14=generation.
        let pkt_word = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr.add(4)) },
            unsafe { ptr::read_volatile(desc_ptr.add(5)) },
        ]);
        let desc_gen = ((pkt_word >> 14) & 1) as u8;
        if desc_gen != cur_gen { break; }

        let pkt_len = (pkt_word & 0x3FFF) as usize;
        let status = unsafe { ptr::read_volatile(desc_ptr.add(8)) };
        let buf_id = u16::from_le_bytes([
            unsafe { ptr::read_volatile(desc_ptr.add(12)) },
            unsafe { ptr::read_volatile(desc_ptr.add(13)) },
        ]) as u32;

        if buf_id < DQO_RX_POOL_BUFS && (status & DQO_RX_COMPL_STATUS_EOP) != 0 && pkt_len > 0 {
            let buf_va = (rx.qpl_base_va + (buf_id as u64) * (RX_BUFFER_SIZE as u64)) as *const u8;
            let bytes = unsafe { core::slice::from_raw_parts(buf_va, pkt_len) };
            callback(bytes);

            // Repost the buffer at the buffer-ring's next free slot.
            // Same buf_id, same DMA addr — the device only needs the
            // descriptor written, plus a doorbell at the end.
            let fill = rx.fill_cnt.load(Ordering::Relaxed);
            let post_idx = (fill & mask) as usize;
            let post_ptr = (rx.data_va as *mut u8).wrapping_add(post_idx * DQO_RX_DESC_SIZE);
            let mut post_desc = [0u8; DQO_RX_DESC_SIZE];
            post_desc[0..2].copy_from_slice(&(buf_id as u16).to_le_bytes());
            let buf_phys = rx.qpl_base_phys + (buf_id as u64) * (RX_BUFFER_SIZE as u64);
            post_desc[8..16].copy_from_slice(&buf_phys.to_le_bytes());
            unsafe { ptr::copy_nonoverlapping(post_desc.as_ptr(), post_ptr, DQO_RX_DESC_SIZE); }
            rx.fill_cnt.store(fill.wrapping_add(1), Ordering::Release);

            rx.cons_cnt.store(cons.wrapping_add(1), Ordering::Relaxed);
            delivered += 1;
        }

        cons = cons.wrapping_add(1);
        if (cons & mask) == 0 {
            cur_gen ^= 1;
        }
    }

    rx.cons_cnt.store(cons, Ordering::Relaxed);
    rx.expected_seq.store(cur_gen, Ordering::Relaxed);

    if delivered > 0 {
        let fill = rx.fill_cnt.load(Ordering::Relaxed);
        doorbell_write_le(bar2_va, rx.db_offset, fill);
    }

    delivered
}

/// Turn on batched TX doorbells. Called once by the kernel after
/// it has wired `flush_tx_kick_if_dirty` into the event loop —
/// without that guarantee the device would never see the doorbell
/// writes and TX would stall once the ring fills.
fn enable_deferred_tx_kick() {
    DEFERRED_KICK.store(true, Ordering::Release);
}

/// Per-core TX. Picks the queue pair matching `cpu_id()` when that
/// fits within `num_qp`, else falls back to qp 0. Matches the
/// virtio-net "send on your own core's queue" semantics so Tier 1
/// scaling keeps working.
fn send(data: &[u8]) {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 {
        return;
    }
    let core = uni_kernel::cpu_id();
    let qp = if core < num_qp { core as usize } else { 0 };
    let _ = send_on_qp(qp, data);
}

// ---- virtio-net-compatible public surface --------------------------------

/// Copy the device MAC into `mac_out` (6 bytes). Matches the
/// signature of `uni_drivers::virtio_net::get_mac` so the dispatch
/// shim can call either driver the same way. The caller is
/// responsible for `mac_out` pointing at 6 writable bytes — same
/// unwritten contract virtio-net's version has.
fn get_mac(mac_out: *mut u8) {
    let st = STATE.lock();
    let src = st.as_ref().map(|s| s.mac).unwrap_or([0u8; 6]);
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), mac_out, 6);
    }
}

/// Active queue pair count. Drives `net::poll_tier1` — when > 1
/// the kernel switches to per-core queue polling.
#[inline]
fn num_queue_pairs() -> u16 {
    NUM_QP.load(Ordering::Acquire)
}

// ---- TX-side hot-path counters ----
//
// Bumped from `acquire_tx_buf_for_qp`, `acquire_tx_tso_buf_for_qp`,
// and the GQI / DQO submit functions. Surfaced via `tx_diag()` →
// `NicDiagOps::tx_diag` so the /stats endpoint can render them.
//
// Layout mirrors virtio-net's: per-qp packet counts (8-deep) plus
// scalar saturation + scan-depth counters that don't depend on qp
// (the small/big pools are per-qp here, but the scans run inside
// the owning worker so a single set of counters captures the
// driver's aggregate behaviour without needing a per-qp split).
static TX_PACKETS_PER_QP: [AtomicU64; 8] =
    [const { AtomicU64::new(0) }; 8];
static TX_SMALL_FULL_SPINS: AtomicU64 = AtomicU64::new(0);
static TX_SMALL_SCAN_ITERS: AtomicU64 = AtomicU64::new(0);
static TX_SMALL_ACQUIRES: AtomicU64 = AtomicU64::new(0);
static TX_BIG_FULL_RETURNS: AtomicU64 = AtomicU64::new(0);
static TX_BIG_ACQUIRES: AtomicU64 = AtomicU64::new(0);

// ---- TX descriptor capture ring ----
//
// Records every 16-byte descriptor handed to the device, latest
// `TX_DESC_LOG_DEPTH` retained. Surfaced via `tx_desc_log_snapshot`
// → /diag-gve so a remote operator can inspect what the driver
// actually wrote when the device misbehaves. Particularly load-
// bearing for TSO debug on GCE where serial-port output is gated
// by sandbox IAM.
//
// The ring is bounded so a steady-state production deploy doesn't
// pay unbounded memory; 32 entries × 24 bytes per entry × 1 lock
// ≈ 800 B + spinlock state. Each `submit_tx_*` call touches the
// lock once on the hot path, but the contended window is tiny
// (a few stores) so cross-core ping-pong is dwarfed by the
// surrounding allocator + descriptor work.

const TX_DESC_LOG_DEPTH: usize = 32;

#[derive(Clone, Copy)]
pub struct TxDescLogEntry {
    /// Monotonic sequence number — lets readers reconstruct the
    /// chronological order even when the ring has wrapped.
    pub seq: u32,
    /// Queue pair index (0..MAX_QUEUE_PAIRS). u8 is plenty: we never
    /// expose more than 8 qps to the kernel.
    pub qp: u8,
    /// Descriptor kind: 0 = STD pkt, 1 = TSO pkt, 2 = SEG. Lets
    /// `/diag-gve` annotate each row without re-parsing the type
    /// byte (which lives at byte 0 but with flag bits OR'd in).
    pub kind: u8,
    /// Raw 16-byte gve descriptor bytes as written into the ring.
    pub bytes: [u8; 16],
}

struct TxDescLog {
    entries: [TxDescLogEntry; TX_DESC_LOG_DEPTH],
    /// Next slot to overwrite (0..TX_DESC_LOG_DEPTH).
    head: usize,
    /// Monotonic counter; current value matches the most recently
    /// written entry's `seq`. Wraps on overflow but the relative
    /// order across ≤ TX_DESC_LOG_DEPTH live entries stays
    /// unambiguous in practice.
    seq: u32,
    /// Total entries written since boot. `valid_count = min(written,
    /// TX_DESC_LOG_DEPTH)` tells the snapshot reader how many slots
    /// to walk.
    written: u64,
}

impl TxDescLog {
    const EMPTY: Self = TxDescLog {
        entries: [TxDescLogEntry {
            seq: 0,
            qp: 0,
            kind: 0,
            bytes: [0; 16],
        }; TX_DESC_LOG_DEPTH],
        head: 0,
        seq: 0,
        written: 0,
    };
}

static TX_DESC_LOG: Spinlock<TxDescLog> = Spinlock::new(TxDescLog::EMPTY);

/// Descriptor kinds — use these (not raw integers) at call sites
/// so `/diag-gve`'s rendering stays in sync with what the driver
/// actually wrote.
pub mod tx_desc_kind {
    pub const STD: u8 = 0;
    pub const TSO: u8 = 1;
    pub const SEG: u8 = 2;
}

fn record_tx_desc(qp: u8, kind: u8, bytes: &[u8; 16]) {
    let mut log = TX_DESC_LOG.lock();
    log.seq = log.seq.wrapping_add(1);
    log.written = log.written.wrapping_add(1);
    let head = log.head;
    log.entries[head] = TxDescLogEntry {
        seq: log.seq,
        qp,
        kind,
        bytes: *bytes,
    };
    log.head = (head + 1) % TX_DESC_LOG_DEPTH;
}

/// Snapshot the descriptor log into `out` in chronological order
/// (oldest first). Returns the number of valid entries written
/// (≤ `out.len()` and ≤ `TX_DESC_LOG_DEPTH`). Lock-bounded; the
/// caller doesn't need to coordinate with `record_tx_desc`.
pub fn tx_desc_log_snapshot(out: &mut [TxDescLogEntry]) -> usize {
    let log = TX_DESC_LOG.lock();
    let valid = (log.written as usize).min(TX_DESC_LOG_DEPTH);
    let n = valid.min(out.len());
    if n == 0 {
        return 0;
    }
    // Oldest entry is at `head` when the ring is full, else at 0.
    let start = if log.written as usize >= TX_DESC_LOG_DEPTH {
        log.head
    } else {
        0
    };
    for i in 0..n {
        out[i] = log.entries[(start + i) % TX_DESC_LOG_DEPTH];
    }
    n
}

fn tx_diag() -> uni_net_driver::TxDiag {
    let mut packets = [0u64; uni_net_driver::DIAG_QP_CAP];
    let mut inflight = [0u32; uni_net_driver::DIAG_QP_CAP];
    for i in 0..uni_net_driver::DIAG_QP_CAP {
        packets[i] = TX_PACKETS_PER_QP[i].load(Ordering::Relaxed);
        // In-flight = fill_cnt - done_cnt for each live qp. Pinned
        // at `ring_entries` across multiple snapshots flags a
        // stall — the driver's queueing more, but the device
        // hasn't issued completions. Direct smoking gun for the
        // gve DQO-direct-fill stall on c3 (whichever qp shows
        // a saturated in-flight + zero advance over time is the
        // one to look at).
        let tx_ptr = TX_QUEUES[i].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            let tx = unsafe { &*tx_ptr };
            let fill = tx.fill_cnt.load(Ordering::Relaxed);
            let done = tx.done_cnt.load(Ordering::Relaxed);
            inflight[i] = fill.wrapping_sub(done);
        }
    }
    uni_net_driver::TxDiag {
        packets_per_qp: packets,
        inflight_per_qp: inflight,
        small_pool_full_spins: TX_SMALL_FULL_SPINS.load(Ordering::Relaxed),
        small_pool_scan_iters: TX_SMALL_SCAN_ITERS.load(Ordering::Relaxed),
        small_pool_acquires: TX_SMALL_ACQUIRES.load(Ordering::Relaxed),
        big_pool_full_returns: TX_BIG_FULL_RETURNS.load(Ordering::Relaxed),
        big_pool_acquires: TX_BIG_ACQUIRES.load(Ordering::Relaxed),
        small_pool_size: TX_RING_ENTRIES as u32,
        // Big pool isn't wired in production (TSO parked); report 0
        // until acquire_tx_tso_buf comes back online.
        big_pool_size: 0,
    }
}

/// Per-queue RX frame count. Lock-free snapshot — uses the atomic
/// cons_cnt on each live queue.
fn rx_counts() -> [u64; 8] {
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
fn rx_used_cursors() -> [(u16, u16); 8] {
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

// ---- RX (NicOps::poll_rx / poll_qp) --------------------------------------
//
// gve's QPL design pins a fixed set of pages between guest and
// device, so the device may overwrite a frame's QPL page once we
// re-fill its descriptor. A real zero-copy IOBuf path for gve
// would track which descriptors are out at consumers and gate
// `fill_cnt` advance on in-flight drops — that's substantial
// enough to be its own follow-up.
//
// For now this is a memcpy-wrap stub: per frame we kmalloc a fresh
// Heap IOBuf and copy the QPL bytes into it, then re-fill the
// descriptor immediately. Same memcpy count as a `&[u8]` callback
// would have done; the win is API uniformity — the net stack only
// has one RX surface to call into.

fn poll_qp(qp: usize, callback: fn(uni_net_driver::IOBuf)) -> usize {
    poll_qp_inner(qp, |frame| {
        let iobuf = uni_net_driver::IOBuf::from_slice_with_headroom(0, frame, 0);
        callback(iobuf);
    }) as usize
}

/// Non-per-core poll. Callers (DHCP bring-up, Tier 2 distribute)
/// don't know which RX queue a given packet landed on, so walk
/// every live queue. RSS is active by the time `init()` returns,
/// and DHCP's reply may hash onto any queue — not just qp 0.
fn poll(callback: fn(uni_net_driver::IOBuf)) -> usize {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    let mut total: usize = 0;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        total = total.saturating_add(poll_qp_inner(qp, |frame| {
            let iobuf = uni_net_driver::IOBuf::from_slice_with_headroom(0, frame, 0);
            callback(iobuf);
        }) as usize);
    }
    total
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
// are only touched by diagnostics; reference them once here so the
// crate still compiles with `-D unused`.
const _: () = {
    let _ = DEVICE_STATUS_RESET;
    let _ = STATUS_UNSET;
    let _ = OP_DESCRIBE_DEVICE; // already used but keep it explicit
    assert!(size_of::<AdminqCommand>() == CMD_SIZE);
    assert!(ADMINQ_SIZE / CMD_SIZE == ADMINQ_SLOTS);
};

// ============================================================================
// NicOps registration
// ============================================================================
//
// Registered into the `.uni_drivers_ethernet` section as a static
// `NicOps`. Every dispatcher call does one Acquire load + one direct
// call through the pointer. gve is polling-only — no NAPI, no MSI-X,
// so `idle` is `None` and the dispatcher's idle path skips it.

use uni_net_driver::{NicDiagOps, NicOps};

/// `init()` internally short-circuits on `GVNIC_OK`, but we also
/// check `probe_ok` here so multi-probe driver walks don't re-enter
/// bring-up. Matches virtio-net's shape.
fn probe() -> bool {
    probe_ok() || init()
}

/// Trampoline so the driver's local `TxDescLogEntry` (private
/// shape, lives in this module) bridges to the cross-crate
/// `uni_net_driver::TxDescLogEntry` the consumer reads. Same
/// fields, same layout — we copy field-by-field rather than
/// transmute to keep the boundary explicit.
fn tx_desc_log_snapshot_export(out: &mut [uni_net_driver::TxDescLogEntry]) -> usize {
    let mut local = [TxDescLogEntry {
        seq: 0,
        qp: 0,
        kind: 0,
        bytes: [0; 16],
    }; TX_DESC_LOG_DEPTH];
    let limit = out.len().min(TX_DESC_LOG_DEPTH);
    let n = tx_desc_log_snapshot(&mut local[..limit]);
    for i in 0..n {
        out[i] = uni_net_driver::TxDescLogEntry {
            seq: local[i].seq,
            qp: local[i].qp,
            kind: local[i].kind,
            bytes: local[i].bytes,
        };
    }
    n
}

static GVE_DIAG_OPS: NicDiagOps = NicDiagOps {
    rx_counts,
    rx_used_cursors,
    tx_diag: Some(tx_diag),
    tx_desc_log_snapshot: Some(tx_desc_log_snapshot_export),
};

static GVE_OPS: NicOps = NicOps {
    name: "gve",
    probe,
    send,
    // Direct-fill TX: GQI_QPL implemented; DQO_RDA returns None
    // and callers fall back to the slice-shaped `send` (one extra
    // memcpy per frame). Wiring DQO direct-fill is a follow-up.
    acquire_tx_buf: Some(acquire_tx_buf),
    submit_tx: Some(submit_tx),
    // GVE on GCE supports TSOv4 natively but we haven't wired the
    // descriptor-side support yet; report unavailable so callers
    // do per-MSS segmentation as today.
    tso_available: || false,
    // CSUM offload via GQI's `GVE_TXF_L4CSUM` + `l4_csum_offset` /
    // `l4_hdr_offset` (per Linux's `gve_tx_fill_pkt_desc`). Stamp
    // convention is `PseudoHeaderPartial` to match Linux's
    // `CHECKSUM_PARTIAL` skb path (caller pre-stamps the
    // pseudo-header sum at the L4 checksum field; device adds
    // data and folds).
    csum_tx_offload: || true,
    csum_stamp_convention:
        || uni_net_driver::CsumStampConvention::PseudoHeaderPartial,
    acquire_tx_tso_buf: None,
    submit_tx_tso: None,
    poll_rx: poll,
    poll_qp,
    get_mac,
    num_queue_pairs,
    enable_irq: noop,
    enable_deferred_tx_kick,
    flush_tx_staging: flush_all_tx_kicks,
    flush_tx_kick_if_dirty,
    poke_interrupt_status: noop,
    idle: None,
    diag: Some(&GVE_DIAG_OPS),
};

fn noop() {}

uni_net_driver::register_ethernet_driver!(GVE_OPS);
