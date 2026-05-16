// uni-driver-gve/src/lib.rs — Google Virtual Ethernet (gve) driver.
//
// Naming: "gVNIC" is GCE's branding for the virtual NIC product;
// the driver itself is `gve` (matches Linux / the upstream Google
// driver name). The module name and symbols all say `gve`; comments
// reference "gVNIC" when talking about the GCE product surface
// (e.g., instance flags).
//
// Brings up one TX + one RX queue pair on GCE and serves packets on
// it. n2/n2d/e2 advertise GQI_QPL only; c3/c4 advertise both GQI_QPL
// and DQO_RDA — we prefer DQO_RDA (modern 32 B descs, real RSS, the
// path Linux's gve uses on c3+). The driver is split into three levels:
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

extern crate drivers_infra;
extern crate uni_iobuf;
extern crate uni_kernel;
extern crate uni_net_driver;

mod adminq;
mod diag;
pub mod dqo;
mod gqi;

use uni_iobuf::{Chain, IOBufPool, OwnedIOBuf};

// Re-export diagnostic counters + descriptor-log helpers so the
// DQO/GQI submodules can `use crate::TX_PACKETS_PER_QP` etc.
// without knowing the diag module exists, and so the public
// `tx_desc_log_snapshot` keeps its `gve::tx_desc_log_snapshot`
// path. `RX_BUF_REPOST_COUNT` / `GQI_RECYCLE_POOL_EXHAUSTED` are
// `pub` (not `pub(crate)`) so the app's /stats endpoint can read
// them as `uni_driver_gve::…`.
pub use diag::{
    tx_desc_log_snapshot, GQI_RECYCLE_POOL_EXHAUSTED, RX_BUF_REPOST_COUNT, TxDescLogEntry,
};
pub(crate) use diag::{
    record_tx_desc, tx_desc_kind, RX_BYTES_PER_QP, TX_BIG_ACQUIRES, TX_BIG_FULL_RETURNS,
    TX_BYTES_PER_QP, TX_PACKETS_PER_QP, TX_SMALL_ACQUIRES, TX_SMALL_FULL_SPINS, TX_SMALL_SCAN_ITERS,
};

use adminq::{
    AdminqCommand, OP_CONFIGURE_DEVICE_RESOURCES, OP_CONFIGURE_RSS, OP_CREATE_RX_QUEUE,
    OP_CREATE_TX_QUEUE, OP_DESCRIBE_DEVICE, OP_REGISTER_PAGE_LIST,
};
use drivers_infra::{log, mmio_read32, mmio_write32};
use drivers_infra::pci;
use core::ptr;
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering,
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
// 0x04: REG_DRIVER_STATUS — defined by the device but unused here.
const REG_MAX_TX_QUEUES: u64 = 0x08;
const REG_MAX_RX_QUEUES: u64 = 0x0C;
// REG_ADMINQ_* registers are owned by `crate::adminq`.
// 0x1C..=0x1F: reserved (3) + driver_version (1)
// 0x20..=0x2B: modern adminq base_address_hi/lo + length (we don't use these)

const DEVICE_STATUS_RESET: u32 = 1 << 1;

// Admin queue constants, opcodes, command builder, and submission
// helpers live in `crate::adminq` (q.v.).

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

// Version field the device expects in DESCRIBE_DEVICE.
const DEVICE_DESCRIPTOR_VERSION: u32 = 1;

// Device-option ids — only the queue formats this driver knows
// how to bring up. `OPT_ID_GQI_RDA` (0x2) and `OPT_ID_DQO_QPL`
// (0x7) are also defined in the spec but are never advertised
// by GCE in any generation we've tested + we have no driver
// support for them, so they're not parsed here. Unknown ids in
// the device descriptor are skipped silently.
const OPT_ID_GQI_QPL: u16 = 0x3;
const OPT_ID_DQO_RDA: u16 = 0x4;
// MODIFY_RING (advertised by every GCE generation we test) tells
// the driver the [min, max] envelope for TX/RX ring sizes. The
// option payload is a u32 supported_features_mask followed by
// four big-endian u16s: max_rx, max_tx, min_rx, min_tx.
const OPT_ID_MODIFY_RING: u16 = 0x6;

// ---- Driver state ----------------------------------------------------------

/// Publication guard. Set at the end of a successful `init()`. Lets
/// the rest of the system probe whether gVNIC came up without
/// racing against the init path on another core.
static GVNIC_OK: AtomicBool = AtomicBool::new(false);

struct State {
    /// Negotiated queue format — filled in by DESCRIBE_DEVICE.
    /// `None` until init runs. Read by queue bring-up to pick a datapath.
    queue_format: Option<QueueFormat>,
    /// MAC from the device descriptor. Populated by DESCRIBE_DEVICE.
    mac: [u8; 6],
    /// Device-advertised caps from the device descriptor. Logged
    /// from init; consumed by queue bring-up when sizing rings.
    max_tx_queues: u32,
    max_rx_queues: u32,
    default_num_queues: u16,
    mtu: u16,
    /// Number of event counters the device advertises. Sized by
    /// DESCRIBE_DEVICE's `counters` field. CONFIGURE_DEVICE_RESOURCES
    /// allocates a DMA array of this size that the device writes
    /// TX-completion counters into.
    num_event_counters: u16,
    /// Ring-size bounds advertised via the MODIFY_RING device option
    /// (id=6). All zero if the option wasn't present in DESCRIBE_DEVICE
    /// (no known GCE SKU omits it, but the field defaults are inert).
    /// Our compile-time `TX_RING_ENTRIES` / `RX_RING_ENTRIES` are
    /// asserted to fall within these bounds in `build_create_*_queue_cmd`
    /// before the admin command goes out.
    max_tx_ring: u16,
    min_tx_ring: u16,
    max_rx_ring: u16,
    min_rx_ring: u16,
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
pub(crate) const MAX_QUEUE_PAIRS: usize = 8;

/// Per-queue TX metadata. GQI_QPL format: outbound packets are
/// memcpy'd into a pre-registered Queue Page List, and the
/// descriptor carries an offset into that list (not a DMA address).
pub(crate) struct TxQueue {
    /// Descriptor ring — one page of 256 × 16-byte `gve_tx_pkt_desc`.
    /// (We size at `min(tx_queue_entries, 256)` so it fits in 4 KiB.)
    /// Stored as a VA; the device holds the physical address it was
    /// given via CREATE_TX_QUEUE.
    pub(crate) ring_va: u64,
    pub(crate) ring_entries: u16,
    /// QPL backing storage — contiguous pages the device sees as a
    /// linear byte range; our TX packets live here for the device to
    /// read. Single contiguous alloc — simpler than page-by-page.
    pub(crate) qpl_base_va: u64,
    pub(crate) qpl_base_phys: u64,
    /// Doorbell offset into BAR2 (bytes). Set once we read back the
    /// device-populated `db_index` from the queue-resources page at
    /// queue-create time.
    pub(crate) db_offset: u32,
    pub(crate) counter_index: u32,
    /// Monotonically-increasing packet producer counter. Written to
    /// the TX doorbell after submitting. Atomic so one core can
    /// publish (send path) while any other core reads it (e.g. for
    /// a deferred-kick check or a `/stats` snapshot).
    pub(crate) fill_cnt: AtomicU32,
    /// Last-seen value of `counter_array[counter_index]`. Drives
    /// TX slot recycling (a slot is reusable once done_cnt passes
    /// its fill_cnt).
    pub(crate) done_cnt: AtomicU32,
    /// Last value written to this queue's TX doorbell. Used by the
    /// deferred-kick path — `send_on_qp` updates `fill_cnt` but
    /// only writes the doorbell if the caller explicitly asks
    /// (via `flush_tx_kick_if_dirty_qp`) or if the ring is about
    /// to stall. Batching doorbell writes across a poll iteration
    /// cuts the per-packet MMIO-exit count on GCE.
    pub(crate) last_kicked: AtomicU32,

    // ---- DQO_RDA-only fields ----
    /// TX completion ring (DQO only). Each entry is 8 bytes,
    /// device-written; driver polls for the generation bit to
    /// flip on each ring wraparound. 0 in GQI_QPL mode.
    pub(crate) tx_compl_va: u64,
    pub(crate) tx_compl_entries: u16,
    /// Cursor into the TX completion ring (DQO only). 0 in GQI mode.
    pub(crate) tx_compl_head: AtomicU32,
    /// Expected generation bit value for the next completion entry.
    /// Flips each time `tx_compl_head` wraps. 0 in GQI mode.
    pub(crate) tx_compl_gen: AtomicU8,

    /// Cumulative `fill_cnt` value at which we last set
    /// `report_event` on a DQO descriptor. Used to gate the
    /// 32-descriptor minimum spacing between RE flags
    /// (`DQO_TX_RE_INTERVAL`) — required by the device per
    /// `gve_desc_dqo.h`. GQI doesn't have RE; field is unused
    /// in that mode.
    pub(crate) last_re_at_fill: AtomicU32,

    // ---- Direct-fill (zero-copy) TX path (GQI_QPL only today) ----
    //
    // The QPL is split into two pools (see `TX_SMALL_POOL_SLOTS` /
    // `TX_BIG_POOL_SLOTS`): the small pool holds one packet per
    // 4 KiB page; the big pool holds one TSO super-segment per
    // 16 KiB block (4 contiguous pages).
    //
    // acquire scans `_used[]` for the first `false`, sets `true`,
    // hands the caller a handle pointing at QPL[slot]. submit writes
    // 1 (small) or 2 (TSO + SEG) descriptor(s) whose `seg_addr`
    // references the slot's page(s). On completion `tx_drain` reads
    // the descriptor's type+seg_addr to recover the pool + slot
    // index and clears `_used`.
    //
    // AtomicBool because the drain runs on the qp's owning core
    // (Tier 1) but slot-allocation is also on that core — single-
    // writer per worker. AtomicBool is a clean primitive here even
    // though a plain `bool` would suffice on Tier 1; matches
    // virtio-net's pattern and keeps cross-core drain (Tier 2 if
    // we ever add it) sound for free.
    pub(crate) small_slot_used: [core::sync::atomic::AtomicBool; TX_SMALL_POOL_SLOTS as usize],
    pub(crate) big_slot_used: [core::sync::atomic::AtomicBool; TX_BIG_POOL_SLOTS as usize],
}

/// Per-queue RX metadata. Also QPL-backed: incoming frames are
/// DMA'd into pre-registered pages; the completion descriptor
/// tells us which offset.
pub(crate) struct RxQueue {
    /// Completion descriptor ring — `ring_entries × 64` bytes.
    pub(crate) compl_va: u64,
    /// Data-slot ring — `ring_entries × 8` bytes. Slot `i` holds
    /// a big-endian QPL offset the device will write buffer `i` to.
    pub(crate) data_va: u64,
    pub(crate) ring_entries: u16,
    /// RX QPL backing storage.
    pub(crate) qpl_base_va: u64,
    pub(crate) qpl_base_phys: u64,
    /// Doorbell for advancing the RX data-ring fill counter — we
    /// write the total number of posted slots here (monotonic).
    pub(crate) db_offset: u32,
    /// How many slots have been advertised to the device (matches
    /// the value last written to the RX doorbell).
    pub(crate) fill_cnt: AtomicU32,
    /// How many completions we've consumed. Only written by the
    /// core that polls this queue in Tier 1 mode; atomic so
    /// `/stats` can snapshot from any other core without a lock.
    pub(crate) cons_cnt: AtomicU32,
    /// Expected `flags_seq` sequence byte in GQI_QPL mode (low 3 bits,
    /// cycles 1..7; 0 is reserved); doubles as the expected
    /// generation bit (0 or 1) in DQO_RDA mode. Both signal "this
    /// completion entry was just written by the device" without a
    /// separate producer-index read.
    pub(crate) expected_seq: AtomicU8,
    /// RX recycle pool — `Some` for GQI_QPL, `None` for DQO_RDA.
    /// GQI can't lend its device QPL pages up the stack (strict
    /// in-order repost), so `gqi::poll_qp_inner` copies each frame
    /// into a slab from this pool and delivers the slab; DQO lends
    /// its device buffers directly and needs no pool. Set once at
    /// init in `finalize_rx_queue`; an `IOBufPool` is a cheap
    /// clonable `Arc` handle, so each issued slab keeps the pool's
    /// backing region alive on its own.
    pub(crate) rx_pool: Option<IOBufPool>,
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
pub(crate) static BAR2_VA: AtomicU64 = AtomicU64::new(0);
// DMA counter array VA (device writes TX completion counts here).
pub(crate) static COUNTER_ARRAY_VA: AtomicU64 = AtomicU64::new(0);
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
pub(crate) static DEFERRED_KICK: AtomicBool = AtomicBool::new(false);
// Per-queue-pair TxQueue / RxQueue pointers. Each queue struct
// lives inside the driver's `static Spinlock<State>` — `State.tx[qp]` /
// `State.rx[qp]` is a `Some(...)` slot at a stable address for the
// lifetime of the driver. These AtomicPtrs publish raw pointers into
// those slots once `CREATE_*_QUEUE` succeeds, so the hot path
// (`send_on_qp`, `rx_poll_qp`) can reach the queue without taking the
// STATE spinlock.
pub(crate) static TX_QUEUES: [AtomicPtr<TxQueue>; MAX_QUEUE_PAIRS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_QUEUE_PAIRS];
pub(crate) static RX_QUEUES: [AtomicPtr<RxQueue>; MAX_QUEUE_PAIRS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_QUEUE_PAIRS];

// ---- Host-DMA store barrier -----------------------------------------------
//
// Drain the CPU's store buffer to the coherent cache hierarchy.
// Use this immediately before any MMIO doorbell write whose
// semantics tell the device to DMA-read host memory that we just
// modified (TX descriptor rings, RX buffer-queue replenishment,
// admin-queue commands).
//
// Without this, the doorbell TLP can arrive at the IPU before our
// descriptor stores have drained from the store buffer. PCIe DMA
// reads snoop the CPU's caches but cannot snoop the store buffer,
// so the device samples stale memory (valid=0) and silently strands
// the operation. No completion of any type is emitted.
//
// `sfence` is the minimum-strength architectural barrier sufficient
// here — drains prior stores without serializing loads. We use raw
// inline asm because `core::arch::x86_64::_mm_sfence` lowers to an
// out-of-line function call under `-Copt-level=2`.
//
// NOT required for: pure control-register writes (no DMA payload),
// consecutive MMIO writes (UC stores are TSO-ordered with each
// other), or RX completion reads on x86 (load ordering is intrinsic).
//
// Diagnostic story: see commit fa1ac4d.
#[inline(always)]
pub(crate) fn host_dma_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)); }
    #[cfg(not(target_arch = "x86_64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
}

// ---- Big-endian field helpers ---------------------------------------------

#[inline]
pub(crate) fn put_be16(dst: &mut [u8], offset: usize, v: u16) {
    dst[offset..offset + 2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
pub(crate) fn put_be32(dst: &mut [u8], offset: usize, v: u32) {
    dst[offset..offset + 4].copy_from_slice(&v.to_be_bytes());
}

#[inline]
pub(crate) fn put_be64(dst: &mut [u8], offset: usize, v: u64) {
    dst[offset..offset + 8].copy_from_slice(&v.to_be_bytes());
}

#[inline]
pub(crate) fn read_be16(src: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([src[offset], src[offset + 1]])
}

#[inline]
pub(crate) fn read_be32(src: &[u8], offset: usize) -> u32 {
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
pub(crate) unsafe fn reg_read32(offset: u64) -> u32 {
    let base = BAR0.load(Ordering::Acquire);
    u32::from_be(unsafe { mmio_read32(base + offset) })
}

#[inline]
pub(crate) unsafe fn reg_write32(offset: u64, val: u32) {
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
    unsafe { ptr::write_bytes(adminq_va as *mut u8, 0, adminq::ADMINQ_SIZE); }

    // Publish the ring PFN. `adminq_phys >> 12` is what the device
    // expects. Reading it back is how Linux / FreeBSD check the
    // device accepted it.
    if !adminq::init(adminq_va, adminq_phys) {
        return false;
    }

    {
        let mut st = STATE.lock();
        *st = Some(State {
            queue_format: None,
            mac: [0; 6],
            max_tx_queues: max_tx,
            max_rx_queues: max_rx,
            default_num_queues: 0,
            mtu: 0,
            num_event_counters: 0,
            max_tx_ring: 0,
            min_tx_ring: 0,
            max_rx_ring: 0,
            min_rx_ring: 0,
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
    // Negotiated queue format — see `higher_priority` for why we
    // prefer GQI_QPL on c3 even though DQO_RDA is offered.
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

    // Build the command. DESCRIBE_DEVICE payload (per `gve_adminq.h`):
    //   u8[8..16]  device_descriptor_addr (be64, physical)
    //   u8[16..20] device_descriptor_version (be32, = 1)
    //   u8[20..24] available_length (be32, = page size)
    let mut cmd = AdminqCommand::new(OP_DESCRIBE_DEVICE);
    cmd.put_be64(8, desc_phys);
    cmd.put_be32(16, DEVICE_DESCRIPTOR_VERSION);
    cmd.put_be32(20, adminq::ADMINQ_SIZE as u32);

    if !adminq::execute_cmd(b"DESCRIBE_DEVICE", &cmd) {
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
    // Log every option the device offers — the set varies between
    // n2/n2d/e2 (GQI_QPL only) and c3/c4 (GQI_QPL + DQO_RDA), and
    // future SKUs may add more. Visibility makes negotiation
    // mismatches diagnosable from serial alone.
    let mut best: Option<QueueFormat> = None;
    // MODIFY_RING bounds — left at 0 if the option isn't advertised
    // (no known GCE SKU omits it, but we don't want to assume).
    let mut max_tx_ring: u16 = 0;
    let mut min_tx_ring: u16 = 0;
    let mut max_rx_ring: u16 = 0;
    let mut min_rx_ring: u16 = 0;
    let mut offset = header_len;
    let end = if total_len > 0 && total_len <= adminq::ADMINQ_SIZE {
        total_len
    } else {
        adminq::ADMINQ_SIZE
    };
    for _ in 0..num_options {
        if offset + 8 > end { break; }
        let opt_hdr: &[u8] =
            unsafe { core::slice::from_raw_parts(desc_virt.add(offset), 8) };
        let id = read_be16(opt_hdr, 0);
        let len = read_be16(opt_hdr, 2) as usize;

        log(b"[gvnic]  option id=");
        log_u32(id as u32);
        log(b" len=");
        log_u32(len as u32);
        log(b"\n");

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

        // MODIFY_RING payload (per `gve_device_option_modify_ring`):
        //   u32 supported_features_mask  // currently unused
        //   u16 max_rx_ring_size         // offset 4 of payload
        //   u16 max_tx_ring_size         // offset 6
        //   u16 min_rx_ring_size         // offset 8
        //   u16 min_tx_ring_size         // offset 10
        // All big-endian. Total 12 bytes — older firmware may
        // advertise only the first 8 (just the maxes), so we guard
        // on `len >= 12` before reading mins.
        if id == OPT_ID_MODIFY_RING && offset + 8 + len <= end && len >= 8 {
            let payload: &[u8] =
                unsafe { core::slice::from_raw_parts(desc_virt.add(offset + 8), len) };
            max_rx_ring = read_be16(payload, 4);
            max_tx_ring = read_be16(payload, 6);
            if len >= 12 {
                min_rx_ring = read_be16(payload, 8);
                min_tx_ring = read_be16(payload, 10);
            }
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
    // MODIFY_RING bounds. Logged so a future ring-size experiment
    // can pick a runtime-valid value from this line alone. Zeros
    // mean the device didn't advertise the option.
    log(b" rx_ring=[");
    log_u32(min_rx_ring as u32);
    log(b"..");
    log_u32(max_rx_ring as u32);
    log(b"] tx_ring=[");
    log_u32(min_tx_ring as u32);
    log(b"..");
    log_u32(max_tx_ring as u32);
    log(b"] mac=");
    log_mac(&mac);
    log(b"\n");

    // The device advertises `tx_pages_per_qpl` as the MAXIMUM tx
    // pages per registered QPL. Linux packs many packets per page
    // via a FIFO (`tx_desc_cnt / GVE_QPL_DIVISOR = 4`). We
    // deliberately use `1 page per ring slot` (TX_QPL_PAGES = 256)
    // which exceeds the advertised cap on most GCE generations;
    // REGISTER_PAGE_LIST has accepted it on every SKU we've tested.
    // If a future device enforces the cap strictly, CREATE_TX_QUEUE
    // will fail and the log line above shows the gap.

    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.mac = mac;
        s.default_num_queues = default_num_queues;
        s.mtu = mtu;
        s.num_event_counters = counters;
        s.queue_format = best;
        s.max_tx_ring = max_tx_ring;
        s.min_tx_ring = min_tx_ring;
        s.max_rx_ring = max_rx_ring;
        s.min_rx_ring = min_rx_ring;
    }
    true
}

fn higher_priority(a: QueueFormat, b: QueueFormat) -> QueueFormat {
    // Linux's gve ranks DQO_RDA highest on c3+ — modern 32 B desc
    // shape, real Toeplitz RSS, better completion-ring layout.
    // n2/n2d/e2 only advertise GQI_QPL so they fall back naturally.
    use QueueFormat::{DqoRda, GqiQpl};
    match (a, b) {
        (DqoRda, _) | (_, DqoRda) => DqoRda,
        (GqiQpl, GqiQpl) => GqiQpl,
    }
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
/// advertised [min, max]. On GCE c3-highcpu-8 the advertised range
/// is [256, 4096] for TX and [512, 4096] for RX. We pick the
/// minimum: descriptor + buffer footprint is per-queue × 8 queues
/// on c3, and we measured no throughput gain from deeper rings
/// after the DQO RX read-race fix (see `dqo::poll_qp_inner`).
pub(crate) const TX_RING_ENTRIES: u16 = 256;
pub(crate) const RX_RING_ENTRIES: u16 = 512;
/// RX buffer size in bytes (matches GVE_DEFAULT_RX_BUFFER_SIZE =
/// 2048 from the reference driver; one packet per buffer).
pub(crate) const RX_BUFFER_SIZE: u16 = 2048;
/// 2-byte padding the device inserts before the Ethernet frame so
/// the IP header lands 4-byte-aligned in the RX buffer.
pub(crate) const _GVE_RX_PAD: u16 = 2;

/// TX QPL layout — split into two pools that share the same
/// pre-registered, contiguous range of pages.
///
/// **Small pool** (single-segment frames): one 4 KiB page per
/// slot, `slot_idx ∈ 0..TX_SMALL_POOL_SLOTS`. QPL offset for slot
/// `i` is `i * PAGE_SIZE`. Used by `send` / `acquire_tx_buf`.
///
/// **Big pool** (TSO super-segments): **five** contiguous 4 KiB
/// pages per slot, `slot_idx ∈ 0..TX_BIG_POOL_SLOTS`. QPL offset
/// for big slot `i` is `TX_BIG_POOL_QPL_OFFSET +
/// i * TX_BIG_SLOT_SIZE`. Used by `acquire_tx_tso_buf` /
/// `submit_tx_tso`. Sized at 20 KiB to fit one max-size TLS-1.3
/// record (16384 plaintext + 22 envelope = 16406 wire bytes) plus
/// 54-74 bytes of Eth+IP+TCP/UDP headers, with safety headroom.
/// The earlier 4-page (16 KiB) sizing was the same as the TLS
/// plaintext cap, leaving no room for the L2/L3/L4 prefix — fine
/// for `/diagnostics` (~9 KB body) but `OutputTooSmall` on any
/// request whose record fills the cap (e.g. `/static-16k`).
///
/// The 176 + 16×5 = 256 page total matches what we registered
/// before, so REGISTER_PAGE_LIST and CREATE_TX_QUEUE see no
/// change. Linux's reference driver packs multiple packets per
/// page via a FIFO; not worth that complexity when RAM is cheap.
/// The 16 big slots cap concurrent in-flight TSO super-segments
/// per qp; per-MSS fallback covers any saturation.
pub(crate) const TX_SMALL_POOL_SLOTS: u32 = 176;
pub(crate) const TX_BIG_POOL_SLOTS: u32 = 16;
pub(crate) const TX_BIG_SLOT_PAGES: u32 = 5;
pub(crate) const TX_BIG_SLOT_SIZE: u32 = TX_BIG_SLOT_PAGES * PAGE_SIZE; // 20 KiB
pub(crate) const TX_BIG_POOL_QPL_OFFSET: u32 = TX_SMALL_POOL_SLOTS * PAGE_SIZE;
const TX_QPL_PAGES: u32 = TX_SMALL_POOL_SLOTS + TX_BIG_POOL_SLOTS * TX_BIG_SLOT_PAGES;
/// RX QPL size in pages. The reference driver allocates
/// `rx_desc_cnt` pages — one full page per ring entry, even though
/// each packet only uses the first 2 KiB of that page. Smaller
/// allocations are silently rejected by the device with
/// FAILED_PRECONDITION. `rx_pages_per_qpl = 1024` in the device
/// descriptor matches `rx_desc_cnt`, confirming this 1:1 sizing.
const RX_QPL_PAGES: u32 = RX_RING_ENTRIES as u32;

pub(crate) const PAGE_SIZE: u32 = 4096;

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
    let mut cmd = AdminqCommand::new(OP_CONFIGURE_DEVICE_RESOURCES);
    cmd.put_be64(8, counter_phys);
    cmd.put_be64(16, irq_db_phys);
    cmd.put_be32(24, num_event_counters);
    // num_irq_dbs = one notification block per active queue.
    // `num_qp * 2` covers both TX and RX queue pairs. Linux derives
    // this from the MSI-X count; we poll-only but the device still
    // wants a valid count here matching what the CREATE_*_QUEUE
    // ntfy_ids will reference.
    cmd.put_be32(28, num_qp * 2);
    cmd.put_be32(32, IRQ_DB_STRIDE);
    cmd.put_be32(36, 0);
    cmd.set_byte(40, match fmt {
        QueueFormat::GqiQpl => QF_GQI_QPL,
        QueueFormat::DqoRda => QF_DQO_RDA,
    });

    if !adminq::execute_cmd(b"CONFIGURE_DEVICE_RESOURCES", &cmd) {
        return false;
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
    let mut cmd = AdminqCommand::new(OP_REGISTER_PAGE_LIST);
    cmd.put_be32(8, page_list_id);
    cmd.put_be32(12, num_pages);
    cmd.put_be64(16, page_addrs_phys);
    cmd.put_be64(24, PAGE_SIZE as u64);
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
    // 40-byte Toeplitz RSS key.
    //
    // **Default: symmetric `0x6d5a` × 20.** A symmetric key gives
    // identical hashes for both directions of a 4-tuple, which
    // is what we want when one peer (the bench client, in
    // particular) holds a single source IP with many ephemeral
    // ports — the asymmetric MS key hashes those flows to a tiny
    // subset of qps because the source-port LSBs feed the hash
    // weakly. Concrete observation (2026-05-11): `static_1m_tls_max`
    // (16 conns from kvm-vm) with the MS key pinned ~all conns to
    // core 1, leaving cores 0/2/3 at 28-29% real idle and capping
    // throughput at 1.07 Gbps; the symmetric key spreads evenly.
    //
    // `--cfg=rss_key=microsoft` flips back to the asymmetric MS key
    // (every Linux/Windows NIC driver's default), useful only when
    // production traffic is *not* single-source-IP — e.g. real
    // Internet-facing serving with many distinct source IPs, where
    // the asymmetric key's anti-correlation properties win.
    //
    // Our first attempt used a synthetic key
    // (`i * 0x9E3779B1 >> 24`) which happened to hash ~99 % of
    // wrk's flows onto qp 0 on n2-highcpu-4 — kept as a
    // cautionary tale in this comment.
    #[cfg(not(rss_key = "microsoft"))]
    let key: [u8; RSS_KEY_SIZE] = [
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
        0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    ];
    #[cfg(rss_key = "microsoft")]
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

    let mut cmd = AdminqCommand::new(OP_CONFIGURE_RSS);
    let hash_types = RSS_HASH_TCPV4 | RSS_HASH_TCPV6 | RSS_HASH_UDPV4 | RSS_HASH_UDPV6;
    cmd.put_be16(8, hash_types);
    cmd.set_byte(10, RSS_HASH_ALG_TOEPLITZ);
    cmd.put_be16(12, RSS_KEY_SIZE as u16);
    cmd.put_be16(14, RSS_LUT_SIZE as u16);
    cmd.put_be64(16, key_phys);
    cmd.put_be64(24, lut_phys);
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
            let bytes = (dqo::DQO_TX_POOL_BUFS as u32) * (RX_BUFFER_SIZE as u32);
            let pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
            alloc_contig(pages as usize)
        }
    };
    if qpl_phys == 0 { log(b"[gvnic] failed to alloc TX backing pages\n"); return None; }

    let (tx_compl_phys, tx_compl_va) = match fmt {
        QueueFormat::DqoRda => {
            // TX completion ring — 8 bytes per entry, sized to
            // tx_compl_ring_size (use ring_entries for symmetry).
            let bytes = (TX_RING_ENTRIES as u32) * (dqo::DQO_TX_COMPL_SIZE as u32);
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
        QueueFormat::DqoRda => dqo::DQO_RX_COMPL_SIZE as u32,
    };
    let compl_pages = ((RX_RING_ENTRIES as u32) * compl_desc_size + PAGE_SIZE - 1) / PAGE_SIZE;
    let (compl_phys, compl_va) = alloc_contig(compl_pages as usize);
    if compl_phys == 0 { log(b"[gvnic] failed to alloc RX completion ring\n"); return None; }

    // RX data ring:
    //   GQI: 8-byte slot ring of QPL offsets.
    //   DQO: 32-byte buffer descriptors carrying buf_id + buf_addr.
    let data_desc_size: u32 = match fmt {
        QueueFormat::GqiQpl => 8,
        QueueFormat::DqoRda => dqo::DQO_RX_DESC_SIZE as u32,
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
            let bytes = (dqo::DQO_RX_POOL_BUFS as u32) * (RX_BUFFER_SIZE as u32);
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
    // Honor the device-advertised MODIFY_RING bounds. If the option
    // wasn't seen (`max_tx_ring == 0`) we skip the check rather than
    // refusing to bring up older devices that didn't advertise it.
    {
        let st = STATE.lock();
        if let Some(s) = st.as_ref() {
            if s.max_tx_ring != 0 {
                assert!(
                    TX_RING_ENTRIES >= s.min_tx_ring && TX_RING_ENTRIES <= s.max_tx_ring,
                    "TX_RING_ENTRIES out of MODIFY_RING bounds"
                );
            }
        }
    }
    let mut cmd = AdminqCommand::new(OP_CREATE_TX_QUEUE);
    cmd.put_be32(8, qp);
    cmd.put_be64(16, alloc.qres_phys);
    cmd.put_be64(24, alloc.ring_phys);
    cmd.put_be32(32, match fmt {
        QueueFormat::GqiQpl => tx_qpl_id(qp),
        QueueFormat::DqoRda => GVE_RAW_ADDRESSING_QPL_ID,
    });
    cmd.put_be32(36, tx_ntfy_id(qp));
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be64(40, alloc.tx_compl_phys);
    }
    cmd.put_be16(48, TX_RING_ENTRIES);
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be16(50, TX_RING_ENTRIES);
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
    {
        let st = STATE.lock();
        if let Some(s) = st.as_ref() {
            if s.max_rx_ring != 0 {
                assert!(
                    RX_RING_ENTRIES >= s.min_rx_ring && RX_RING_ENTRIES <= s.max_rx_ring,
                    "RX_RING_ENTRIES out of MODIFY_RING bounds"
                );
            }
        }
    }
    let mut cmd = AdminqCommand::new(OP_CREATE_RX_QUEUE);
    cmd.put_be32(8, qp);
    // `index` field. Linux + FreeBSD set this only for GQI; for
    // DQO they leave it 0. We had it set unconditionally; the DQO
    // device may interpret a non-zero `index` differently from
    // `queue_id` and silently route packets oddly.
    if matches!(fmt, QueueFormat::GqiQpl) {
        cmd.put_be32(12, qp);
    }
    cmd.put_be32(20, rx_ntfy_id(num_qp, qp));
    cmd.put_be64(24, alloc.qres_phys);
    cmd.put_be64(32, alloc.compl_phys);
    cmd.put_be64(40, alloc.data_phys);
    cmd.put_be32(48, match fmt {
        QueueFormat::GqiQpl => rx_qpl_id(qp),
        QueueFormat::DqoRda => GVE_RAW_ADDRESSING_QPL_ID,
    });
    cmd.put_be16(52, RX_RING_ENTRIES);
    cmd.put_be16(54, RX_BUFFER_SIZE);
    if matches!(fmt, QueueFormat::DqoRda) {
        cmd.put_be16(56, RX_RING_ENTRIES);
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
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.tx[qp as usize] = Some(TxQueue {
            ring_va: alloc.ring_va,
            ring_entries: TX_RING_ENTRIES,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
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
            last_re_at_fill: AtomicU32::new(0u32.wrapping_sub(dqo::DQO_TX_RE_INTERVAL)),
            small_slot_used: [const { core::sync::atomic::AtomicBool::new(false) };
                TX_SMALL_POOL_SLOTS as usize],
            big_slot_used: [const { core::sync::atomic::AtomicBool::new(false) };
                TX_BIG_POOL_SLOTS as usize],
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
    unsafe {
        let bytes = slice_at(alloc.qres_va, 8);
        db_index = read_be32(bytes, 0);
        // counter_index at offset 4 — RX doesn't use it (we never
        // read the device's RX counter slot).
    }
    // GQI uses flags_seq starting at 1; DQO uses generation bit
    // starting at 1 (ring is zeroed, device fills with current gen,
    // flips each wrap).
    let initial_seq: u8 = 1;
    // GQI's RX poll copies each frame into a recycle-pool slab —
    // it can't lend device QPL pages up the stack. DQO lends its
    // device buffers directly (no pool). Build the pool before
    // taking `STATE` so the 512 KiB slab-region allocation +
    // zero-fill doesn't run under the spinlock.
    let rx_pool = match fmt {
        QueueFormat::GqiQpl => {
            Some(IOBufPool::new(gqi::GQI_RX_POOL_SLABS, gqi::GQI_RX_SLAB_SIZE))
        }
        QueueFormat::DqoRda => None,
    };
    let mut st = STATE.lock();
    if let Some(s) = st.as_mut() {
        s.rx[qp as usize] = Some(RxQueue {
            compl_va: alloc.compl_va,
            data_va: alloc.data_va,
            ring_entries: RX_RING_ENTRIES,
            qpl_base_va: alloc.qpl_va,
            qpl_base_phys: alloc.qpl_phys,
            db_offset: db_index * 4,
            fill_cnt: AtomicU32::new(0),
            cons_cnt: AtomicU32::new(0),
            expected_seq: AtomicU8::new(initial_seq),
            rx_pool,
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
            match adminq::submit_no_wait(&cmd) {
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
            match adminq::submit_no_wait(&cmd) {
                Some((slot, prod)) => { rx_rpl_slots[qp] = slot; last_prod = prod; }
                None => return false,
            }
        }
        if !adminq::kick_and_wait_to(last_prod) { return false; }
        for qp in 0..n {
            if !adminq::check_slot_status(tx_rpl_slots[qp], b"REGISTER_PAGE_LIST tx") { return false; }
            if !adminq::check_slot_status(rx_rpl_slots[qp], b"REGISTER_PAGE_LIST rx") { return false; }
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
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => { tx_create_slots[qp] = slot; last_prod = prod; }
            None => return false,
        }
    }
    for qp in 0..n {
        let cmd = build_create_rx_queue_cmd(qp as u32, rx_allocs[qp].as_ref().unwrap(), num_qp, fmt);
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => { rx_create_slots[qp] = slot; last_prod = prod; }
            None => return false,
        }
    }
    let rss_slot = if num_qp > 1 {
        let cmd = match build_configure_rss_cmd(num_qp) {
            Some(c) => c,
            None => return false,
        };
        match adminq::submit_no_wait(&cmd) {
            Some((slot, prod)) => { last_prod = prod; Some(slot) }
            None => return false,
        }
    } else {
        None
    };
    if !adminq::kick_and_wait_to(last_prod) { return false; }
    for qp in 0..n {
        if !adminq::check_slot_status(tx_create_slots[qp], b"CREATE_TX_QUEUE") { return false; }
        finalize_tx_queue(qp as u32, tx_allocs[qp].as_ref().unwrap(), fmt);
    }
    for qp in 0..n {
        if !adminq::check_slot_status(rx_create_slots[qp], b"CREATE_RX_QUEUE") { return false; }
        finalize_rx_queue(qp as u32, rx_allocs[qp].as_ref().unwrap(), fmt);
    }
    if let Some(slot) = rss_slot {
        // RSS failure is non-fatal — log and fall through to qp 0
        // single-queue delivery, matching the previous behaviour.
        if !adminq::check_slot_status(slot, b"CONFIGURE_RSS") {
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

fn post_initial_rx() {
    // After CREATE_RX_QUEUE the data ring needs a doorbell so the
    // device starts using the posted buffers/slots. GQI: data-slot
    // ring is already pre-filled with QPL offsets; write the full
    // ring count to the doorbell. DQO: write 32-byte buffer
    // descriptors carrying buf_id+buf_addr, then doorbell.
    let is_dqo = QUEUE_FORMAT_DQO.load(Ordering::Acquire);
    let bar2_va = BAR2_VA.load(Ordering::Acquire);
    for qp in 0..MAX_QUEUE_PAIRS {
        let rx_ptr = RX_QUEUES[qp].load(Ordering::Acquire);
        if rx_ptr.is_null() { continue; }
        // SAFETY: pointer published with Release, only null means
        // "not installed". RxQueue's non-atomic fields are only
        // written during init (before this Release); reading them
        // here through Acquire is a valid synchronisation.
        let rx = unsafe { &*rx_ptr };
        if is_dqo {
            dqo::post_initial_rx_for_qp(rx);
        } else {
            let fill = rx.ring_entries as u32;
            rx.fill_cnt.store(fill, Ordering::Release);
            gqi::doorbell_write(bar2_va, rx.db_offset, fill);
        }
    }
    log(b"[gvnic] posted initial RX buffers\n");
}

// ---- RX ------------------------------------------------------------------

/// Drain the RX completion ring for the given queue pair, dispatching
/// to the GQI or DQO datapath based on the negotiated queue format.
fn poll_qp_inner<F: FnMut(Chain<OwnedIOBuf>)>(qp: usize, callback: F) -> u32 {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::poll_qp_inner(qp, callback)
    } else {
        gqi::poll_qp_inner(qp, callback)
    }
}

/// Queue-pair index for the current core, or `None` if the driver
/// isn't ready (`num_qp == 0`). Tier 1 mode pins core N to qp N when
/// `N < num_qp`; cores beyond fall back to qp 0 (no NIC TX from them
/// in practice — they handle handlers, not the polling path).
#[inline]
fn current_qp() -> Option<usize> {
    let num_qp = NUM_QP.load(Ordering::Acquire) as u32;
    if num_qp == 0 { return None; }
    let core = uni_kernel::cpu_id();
    Some(if core < num_qp { core as usize } else { 0 })
}

fn acquire_tx_udp_gso_buf() -> Option<uni_net_driver::TxUdpGsoBufHandle> {
    // Share the big pool with TSO — same slot shape (16 KiB), same
    // pool_id encoding. We just rewrap as the type-distinct handle
    // so the API surface routes UDP-GSO slots through
    // `submit_tx_udp_gso` (different descriptor bytes vs TSO).
    let tso = acquire_tx_tso_buf()?;
    Some(uni_net_driver::TxUdpGsoBufHandle(tso.0))
}

fn submit_tx_udp_gso(
    handle: uni_net_driver::TxUdpGsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return;
    }
    gqi::submit_tx_udp_gso_inner(handle, frame_len, hdr_len, csum_start, gso_size);
}

/// Public direct-fill TX entry — picks the calling worker's qp,
/// scans for a free slot, returns a handle into the per-slot
/// QPL page (GQI_QPL only).
///
/// On DQO_RDA returns `None` so callers fall through to the
/// slice-shaped `send_on_qp_dqo` path (one extra memcpy per
/// frame). A DQO direct-fill landed once but always stalled on
/// real c3 hardware under load, so it was removed; everything
/// goes through `send_on_qp_dqo` until that's diagnosed.
fn acquire_tx_buf() -> Option<uni_net_driver::TxBufHandle> {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return None;
    }
    gqi::acquire_tx_buf_for_qp(current_qp()?)
}

/// Public submit — paired with [`acquire_tx_buf`]. Consumes the
/// handle (slot returns to pool on device completion). GQI_QPL
/// only: callers never get a real handle in DQO mode (acquire
/// returns None), so there's no DQO branch.
fn submit_tx(
    handle: uni_net_driver::TxBufHandle,
    frame_len: usize,
    csum: uni_net_driver::CsumOffload,
) {
    gqi::submit_tx_inner(handle, frame_len, csum);
}

/// Public TSO acquire — picks the calling worker's qp and returns
/// a 16 KiB big-pool handle (or `None` on DQO / pool saturation).
fn acquire_tx_tso_buf() -> Option<uni_net_driver::TxTsoBufHandle> {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        return None;
    }
    gqi::acquire_tx_tso_buf_for_qp(current_qp()?)
}

/// Public TSO submit — paired with [`acquire_tx_tso_buf`]. Emits
/// 1 TSO + 1 SEG descriptor; the device segments the payload into
/// `gso_size`-byte chunks with TCP/IP headers fixed up per segment.
fn submit_tx_tso(
    handle: uni_net_driver::TxTsoBufHandle,
    frame_len: usize,
    hdr_len: u16,
    csum_start: u16,
    gso_size: u16,
) {
    // GQI_QPL only — `acquire_tx_tso_buf` returns None on DQO so
    // we never get a real big-pool handle in DQO mode. Just in
    // case (e.g. a saved handle), drop it cleanly.
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        // Dropping `handle` releases the slot via release_fn.
        return;
    }
    gqi::submit_tx_tso_inner(handle, frame_len, hdr_len, csum_start, gso_size);
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
        // DQO doorbell wants the masked tail position; raw cumulative
        // fill_cnt wraps differently than what the device expects
        // and wedges the queue after the first ring cycle.
        let mask = (tx.ring_entries - 1) as u32;
        dqo::doorbell_write_le(bar2_va, tx.db_offset, fill & mask);
    } else {
        gqi::doorbell_write(bar2_va, tx.db_offset, fill);
    }
    tx.last_kicked.store(fill, Ordering::Relaxed);
    true
}

/// Flush the current core's TX queue if dirty. Mirrors
/// `uni_drivers::virtio_net::flush_tx_kick_if_dirty` so the shim in
/// `uni_drivers::net` can dispatch through the same signature.
fn flush_tx_kick_if_dirty() -> bool {
    match current_qp() {
        Some(qp) => flush_tx_kick_if_dirty_qp(qp),
        None => false,
    }
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


/// Turn on batched TX doorbells. Called once by the kernel after
/// it has wired `flush_tx_kick_if_dirty` into the event loop —
/// without that guarantee the device would never see the doorbell
/// writes and TX would stall once the ring fills.
fn enable_deferred_tx_kick() {
    DEFERRED_KICK.store(true, Ordering::Release);
}

/// Submit a single-segment packet on queue pair `qp`. Returns
/// `true` on success, `false` when the ring has no free slots
/// (device hasn't caught up) or the frame exceeds the format's
/// per-packet limit. Dispatches to GQI_QPL or DQO_RDA based on
/// the queue format committed at init time.
fn send_on_qp(qp: usize, data: &[u8]) -> bool {
    if QUEUE_FORMAT_DQO.load(Ordering::Acquire) {
        dqo::send_on_qp(qp, data)
    } else {
        gqi::send_on_qp(qp, data)
    }
}

/// Per-core TX. Picks the queue pair matching `cpu_id()` when that
/// fits within `num_qp`, else falls back to qp 0. Matches the
/// virtio-net "send on your own core's queue" semantics so Tier 1
/// scaling keeps working.
fn send(data: &[u8]) {
    if let Some(qp) = current_qp() {
        let _ = send_on_qp(qp, data);
    }
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

// Diagnostic counters + descriptor capture + NicDiagOps adapters
// live in `crate::diag`.

// ---- RX (NicOps::poll_rx / poll_qp) --------------------------------------
//
// The callback receives an owned `IOBufChain` per frame (item B):
//   * DQO wraps the device's buf_id RX buffer as an `ExternalOwned`
//     IOBuf — zero copy. The `dqo_repost` drop callback returns
//     buf_id to the data ring when the chain drops, so a consumer
//     may retain the chain past the callback safely; the buffer is
//     never re-armed while a live IOBuf still views it.
//   * GQI cannot lend device QPL pages (strict in-order repost), so
//     it copies each frame into a recycle-pool slab and delivers
//     that; the device page is reposted at the batch boundary.
//
// This replaced an earlier borrowed-`&[u8]` shape that forced a
// synchronous copy at the driver boundary. The earlier *first*
// owned-IOBuf attempt was unsound because it had no auto-repost — a
// stalled consumer could pin a device buffer past the ~23 ms
// ring-wrap window, after which reads observed bytes the device had
// overwritten. `ExternalOwned`'s drop callback (item A) closes that
// hole: the buffer always reposts when the chain drops, and never
// before — so re-arm provably cannot race a live consumer.

fn poll_qp(qp: usize, callback: fn(Chain<OwnedIOBuf>)) -> usize {
    poll_qp_inner(qp, callback) as usize
}

/// Non-per-core poll. Callers (DHCP bring-up, Tier 2 distribute)
/// don't know which RX queue a given packet landed on, so walk
/// every live queue. RSS is active by the time `init()` returns,
/// and DHCP's reply may hash onto any queue — not just qp 0.
fn poll(callback: fn(Chain<OwnedIOBuf>)) -> usize {
    let n = NUM_QP.load(Ordering::Acquire) as usize;
    let mut total: usize = 0;
    for qp in 0..n.min(MAX_QUEUE_PAIRS) {
        total = total.saturating_add(poll_qp_inner(qp, callback) as usize);
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

pub(crate) fn log_hex32(v: u32) {
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

// `DEVICE_STATUS_RESET` is defined for completeness vs the BAR0
// register spec but the driver doesn't issue a reset path. Reference
// it here so `#[deny(dead_code)]` builds don't trip.
#[allow(dead_code)]
const _: u32 = DEVICE_STATUS_RESET;

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

static GVE_DIAG_OPS: NicDiagOps = NicDiagOps {
    rx_counts: diag::rx_counts,
    rx_used_cursors: diag::rx_used_cursors,
    tx_diag: Some(diag::tx_diag),
    tx_desc_log_snapshot: Some(diag::tx_desc_log_snapshot_export),
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
    // TSO v4 / v6 via GQI's `GVE_TXD_TSO` + `GVE_TXD_SEG` desc
    // pair (per Linux's `gve_tx_fill_pkt_desc` / `_seg_desc`).
    // The device segments super-segments host-side using the
    // `mss` field on the SEG desc; CSUM is wired alongside via
    // `GVE_TXF_L4CSUM`. Big-pool slots are 16 KiB so a typical
    // 10× MSS super-segment lands in one slot.
    tso_available: || true,
    // CSUM offload via GQI's `GVE_TXF_L4CSUM` + `l4_csum_offset` /
    // `l4_hdr_offset` (per Linux's `gve_tx_fill_pkt_desc`). Stamp
    // convention is `PseudoHeaderPartial` to match Linux's
    // `CHECKSUM_PARTIAL` skb path (caller pre-stamps the
    // pseudo-header sum at the L4 checksum field; device adds
    // data and folds).
    csum_tx_offload: || true,
    csum_stamp_convention:
        || uni_net_driver::CsumStampConvention::PseudoHeaderPartial,
    acquire_tx_tso_buf: Some(acquire_tx_tso_buf),
    submit_tx_tso: Some(submit_tx_tso),
    // UDP-GSO via the same TSO descriptor shape with
    // l4_csum_offset = 3 (UDP cksum at byte 6 of UDP header). The
    // device picks TCP vs UDP segmentation from the IP-header
    // protocol field. Upstream Linux gve doesn't currently
    // advertise `NETIF_F_GSO_UDP_L4`, so live device support on
    // GCE is unverified — the descriptor path is wired and
    // bench-validatable by flipping `udp_gso_available` to
    // `|| true`. Default off keeps callers on the per-datagram
    // small-pool path until we confirm.
    udp_gso_available: || false,
    acquire_tx_udp_gso_buf: Some(acquire_tx_udp_gso_buf),
    submit_tx_udp_gso: Some(submit_tx_udp_gso),
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
