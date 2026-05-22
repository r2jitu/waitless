// crates/drivers/gve/src/lib.rs — Google Virtual Ethernet (gve) driver.
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
//
// File layout:
//   * `lib.rs`  — types, statics, BE/MMIO helpers, NicOps registration,
//                 and the small bits of public surface the kernel needs.
//   * `init.rs` — probe + DESCRIBE_DEVICE + CONFIGURE_DEVICE_RESOURCES
//                 + REGISTER_PAGE_LIST + CREATE_*_QUEUE + finalize.
//                 Decides DQO vs GQI and stamps `QUEUE_FORMAT_DQO`.
//   * `tx.rs`   — TX dispatch: per-core qp pick, the DQO/GQI mode
//                 switch on send/submit, deferred-kick flush helpers.
//   * `rx.rs`   — RX dispatch: poll / poll_qp, the DQO/GQI mode switch
//                 on the drain path.
//   * `adminq.rs` / `dqo.rs` / `gqi.rs` / `diag.rs` — unchanged.

#![no_std]

mod adminq;
mod diag;
pub mod dqo;
mod gqi;
mod init;
mod rx;
mod tx;

// Re-export diagnostic counters + descriptor-log helpers so the
// DQO/GQI submodules can `use crate::TX_PACKETS_PER_QP` etc.
// without knowing the diag module exists, and so the public
// `tx_desc_log_snapshot` keeps its `gve::tx_desc_log_snapshot`
// path. `RX_BUF_REPOST_COUNT` / `GQI_RECYCLE_POOL_EXHAUSTED` are
// `pub` (not `pub(crate)`) so the `/obs` `nic` block can read
// them as `gve::…`.
pub use diag::{GQI_RECYCLE_POOL_EXHAUSTED, RX_BUF_REPOST_COUNT, TxDescLogEntry, tx_desc_log_snapshot};
pub(crate) use diag::{
    RX_BYTES_PER_QP, TX_BIG_ACQUIRES, TX_BIG_FULL_RETURNS, TX_BYTES_PER_QP, TX_PACKETS_PER_QP,
    TX_SMALL_ACQUIRES, TX_SMALL_FULL_SPINS, TX_SMALL_SCAN_ITERS, record_tx_desc, tx_desc_kind,
};

use bus::{log, mmio_read32, mmio_write32};
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering,
};
use sync::Spinlock;

// ---- PCI identity ----------------------------------------------------------

pub(crate) const PCI_VENDOR_GVE: u16 = 0x1ae0;
pub(crate) const PCI_DEVICE_GVE: u16 = 0x0042;

// ---- BAR0 register offsets (all fields big-endian on the wire) -------------
//
// Layout from `gve_register.h` in both the Linux and FreeBSD
// reference drivers. The first 12 bytes are read-only device
// advertising (status + max_tx / max_rx); the middle chunk is the
// legacy admin-queue interface; the trailing chunk is the modern
// 64-bit base-address form (unused on current GCE firmware).

pub(crate) const REG_DEVICE_STATUS: u64 = 0x00;
// 0x04: REG_DRIVER_STATUS — defined by the device but unused here.
pub(crate) const REG_MAX_TX_QUEUES: u64 = 0x08;
pub(crate) const REG_MAX_RX_QUEUES: u64 = 0x0C;
// REG_ADMINQ_* registers are owned by `crate::adminq`.
// 0x1C..=0x1F: reserved (3) + driver_version (1)
// 0x20..=0x2B: modern adminq base_address_hi/lo + length (we don't use these)

// Admin queue constants, opcodes, command builder, and submission
// helpers live in `crate::adminq` (q.v.).

/// RSS hash algorithm value (Toeplitz). Matches Linux's
/// `ETH_RSS_HASH_TOP = 1`. The device only implements Toeplitz.
pub(crate) const RSS_HASH_ALG_TOEPLITZ: u8 = 1;

/// `enum gve_rss_hash_type` bit positions (from the Linux header).
/// Our mask enables 4-tuple hashing for TCP + UDP on v4 and v6 —
/// that's what real traffic hits. Anything else falls back to
/// whatever LUT slot 0 maps to.
pub(crate) const RSS_HASH_TCPV4: u16 = 1 << 1;
pub(crate) const RSS_HASH_TCPV6: u16 = 1 << 4;
pub(crate) const RSS_HASH_UDPV4: u16 = 1 << 6;
pub(crate) const RSS_HASH_UDPV6: u16 = 1 << 7;

pub(crate) const RSS_KEY_SIZE: usize = 40;
pub(crate) const RSS_LUT_SIZE: usize = 128;

/// Marker for GQI_RDA mode (raw DMA addressing). In QPL mode the
/// `queue_page_list_id` field of CREATE_*_QUEUE is the real QPL id
/// we got from REGISTER_PAGE_LIST.
pub(crate) const GVE_RAW_ADDRESSING_QPL_ID: u32 = 0xFFFFFFFF;

/// Values for `CONFIGURE_DEVICE_RESOURCES.queue_format`. Only the
/// two we actually negotiate are listed; see the comment on
/// `QueueFormat` for why `QF_GQI_RDA` (0x1) and `QF_DQO_QPL` (0x4)
/// were removed.
pub(crate) const QF_GQI_QPL: u8 = 0x2;
pub(crate) const QF_DQO_RDA: u8 = 0x3;

// Version field the device expects in DESCRIBE_DEVICE.
pub(crate) const DEVICE_DESCRIPTOR_VERSION: u32 = 1;

// Device-option ids — only the queue formats this driver knows
// how to bring up. `OPT_ID_GQI_RDA` (0x2) and `OPT_ID_DQO_QPL`
// (0x7) are also defined in the spec but are never advertised
// by GCE in any generation we've tested + we have no driver
// support for them, so they're not parsed here. Unknown ids in
// the device descriptor are skipped silently.
pub(crate) const OPT_ID_GQI_QPL: u16 = 0x3;
pub(crate) const OPT_ID_DQO_RDA: u16 = 0x4;
// MODIFY_RING (advertised by every GCE generation we test) tells
// the driver the [min, max] envelope for TX/RX ring sizes. The
// option payload is a u32 supported_features_mask followed by
// four big-endian u16s: max_rx, max_tx, min_rx, min_tx.
pub(crate) const OPT_ID_MODIFY_RING: u16 = 0x6;

// ---- Driver state ----------------------------------------------------------

/// Publication guard. Set at the end of a successful `init()`. Lets
/// the rest of the system probe whether gVNIC came up without
/// racing against the init path on another core.
pub(crate) static GVNIC_OK: AtomicBool = AtomicBool::new(false);

pub(crate) struct State {
    /// Negotiated queue format — filled in by DESCRIBE_DEVICE.
    /// `None` until init runs. Read by queue bring-up to pick a datapath.
    pub(crate) queue_format: Option<QueueFormat>,
    /// MAC from the device descriptor. Populated by DESCRIBE_DEVICE.
    pub(crate) mac: [u8; 6],
    /// Device-advertised caps from the device descriptor. Logged
    /// from init; consumed by queue bring-up when sizing rings.
    pub(crate) max_tx_queues: u32,
    pub(crate) max_rx_queues: u32,
    pub(crate) default_num_queues: u16,
    pub(crate) mtu: u16,
    /// Number of event counters the device advertises. Sized by
    /// DESCRIBE_DEVICE's `counters` field. CONFIGURE_DEVICE_RESOURCES
    /// allocates a DMA array of this size that the device writes
    /// TX-completion counters into.
    pub(crate) num_event_counters: u16,
    /// Ring-size bounds advertised via the MODIFY_RING device option
    /// (id=6). All zero if the option wasn't present in DESCRIBE_DEVICE
    /// (no known GCE SKU omits it, but the field defaults are inert).
    /// Our compile-time `TX_RING_ENTRIES` / `RX_RING_ENTRIES` are
    /// asserted to fall within these bounds in `build_create_*_queue_cmd`
    /// before the admin command goes out.
    pub(crate) max_tx_ring: u16,
    pub(crate) min_tx_ring: u16,
    pub(crate) max_rx_ring: u16,
    pub(crate) min_rx_ring: u16,
    /// Number of active queue pairs. <= MAX_QUEUE_PAIRS. Set by
    /// `init()` after all queues come up. Tier 1 polling in
    /// `net::poll_tier1` walks `0..num_qp`.
    pub(crate) num_qp: u16,
    /// TX / RX queues. Indexed by queue-pair number 0..num_qp.
    /// One pair per vCPU; multi-queue RX distribution happens
    /// inside the NIC via CONFIGURE_RSS.
    pub(crate) tx: [Option<TxQueue>; MAX_QUEUE_PAIRS],
    pub(crate) rx: [Option<RxQueue>; MAX_QUEUE_PAIRS],
}

/// Matches `bus::virtio_net::MAX_QUEUE_PAIRS`. Upper bound for
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
    /// a deferred-kick check or an `/obs` `nic`-block snapshot).
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
    /// core that polls this queue in Tier 1 mode; atomic so `/obs`
    /// can snapshot from any other core without a lock.
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
    pub(crate) rx_pool: Option<iobuf::IOBufPool>,
}

/// The two queue formats we actually support. GCE today advertises
/// `GqiQpl` on n2/n2d/e2 and both `GqiQpl` + `DqoRda` on c3/c4. The
/// driver historically also enumerated `GqiRda` and `DqoQpl` for
/// completeness, but neither is ever advertised by GCE in any
/// generation we've tested, and neither has driver-side support
/// (CREATE_*_QUEUE shape, descriptor format, completion handling),
/// so the variants were pure dead code — removed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueFormat {
    GqiQpl,
    DqoRda,
}

impl QueueFormat {
    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            QueueFormat::GqiQpl => b"GQI_QPL",
            QueueFormat::DqoRda => b"DQO_RDA",
        }
    }
}

pub(crate) static STATE: Spinlock<Option<State>> = Spinlock::new(None);

// Lock-free hot-path state — published at init time, then read
// without the big `STATE` spinlock so `poll_qp` / `send_on_qp` can
// run on multiple cores concurrently without serialising through
// a shared lock. Each of these atomics is written exactly once at
// init and only read afterward (except the queue-cursor fields
// inside TxQueue/RxQueue, which are their own atomics).

// BAR0 virtual address (admin-queue register window).
pub(crate) static BAR0: AtomicU64 = AtomicU64::new(0);
// BAR2 virtual address (per-queue doorbell register window).
pub(crate) static BAR2_VA: AtomicU64 = AtomicU64::new(0);
// DMA counter array VA (device writes TX completion counts here).
pub(crate) static COUNTER_ARRAY_VA: AtomicU64 = AtomicU64::new(0);
// Active queue pair count. Published once init is done so
// `num_queue_pairs()` can read it without taking STATE.
pub(crate) static NUM_QP: AtomicU16 = AtomicU16::new(0);
// Hot-path dispatch flag: true once init() has committed to DQO_RDA
// (modern descriptor format on c3 / c4 / future GCE generations).
// Read by `send_on_qp` / `poll_qp_inner` / `tx_drain` / etc. — one
// Acquire load + branch, no STATE.lock(). False in GQI_QPL mode.
pub(crate) static QUEUE_FORMAT_DQO: AtomicBool = AtomicBool::new(false);
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
    unsafe {
        core::arch::asm!("sfence", options(nostack, preserves_flags));
    }
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
        src[offset],
        src[offset + 1],
        src[offset + 2],
        src[offset + 3],
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

/// Read a field the device wrote into a DMA-coherent buffer the
/// driver allocated. Equivalent to `ptr::read_volatile` on the byte
/// range. Having this as a named helper makes the descriptor-
/// parsing sites easier to audit — each one is "device wrote here".
#[inline]
pub(crate) unsafe fn slice_at<'a>(va: u64, len: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(va as *const u8, len) }
}

// ---- TX ring sizing + QPL pool constants ----------------------------------

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

pub(crate) const PAGE_SIZE: u32 = 4096;

// ---- virtio-net-compatible public surface --------------------------------

/// Copy the device MAC into `mac_out` (6 bytes). Matches the
/// signature of `bus::virtio_net::get_mac` so the dispatch
/// shim can call either driver the same way. The caller is
/// responsible for `mac_out` pointing at 6 writable bytes — same
/// unwritten contract virtio-net's version has.
fn get_mac(mac_out: *mut u8) {
    let st = STATE.lock();
    let src = st.as_ref().map(|s| s.mac).unwrap_or([0u8; 6]);
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), mac_out, 6);
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

// ---- Serial logging helpers ------------------------------------------------

pub(crate) fn log_u32(mut v: u32) {
    if v == 0 {
        log(b"0");
        return;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    let mut out = [0u8; 10];
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
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

pub(crate) fn log_mac(mac: &[u8; 6]) {
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
        if i < 5 {
            buf[i * 3 + 2] = b':';
        }
    }
    log(&buf);
}

// ============================================================================
// NicOps registration
// ============================================================================
//
// Registered into the `.waitless_drivers_ethernet` section as a static
// `NicOps`. Every dispatcher call does one Acquire load + one direct
// call through the pointer. gve is polling-only — no NAPI, no MSI-X,
// so `idle` is `None` and the dispatcher's idle path skips it.

use nic_api::{NicDiagOps, NicOps};

/// `init()` internally short-circuits on `GVNIC_OK`, but we also
/// check `probe_ok` here so multi-probe driver walks don't re-enter
/// bring-up. Matches virtio-net's shape.
fn probe() -> bool {
    init::probe_ok() || init::init()
}

static GVE_DIAG_OPS: NicDiagOps = NicDiagOps {
    rx_counts: diag::rx_counts,
    rx_used_cursors: diag::rx_used_cursors,
    tx_diag: Some(diag::tx_diag),
    tx_desc_log_snapshot: Some(diag::tx_desc_log_snapshot_export),
    obs_json: diag::write_obs_json,
};

static GVE_OPS: NicOps = NicOps {
    name: "gve",
    probe,
    send: tx::send,
    // Direct-fill TX: GQI_QPL implemented; DQO_RDA returns None
    // and callers fall back to the slice-shaped `send` (one extra
    // memcpy per frame). Wiring DQO direct-fill is a follow-up.
    acquire_tx_buf: Some(tx::acquire_tx_buf),
    submit_tx: Some(tx::submit_tx),
    // TSO v4 / v6 via GQI's `GVE_TXD_TSO` + `GVE_TXD_SEG` desc
    // pair (per Linux's `gve_tx_fill_pkt_desc` / `_seg_desc`).
    // The device segments super-segments host-side using the
    // `mss` field on the SEG desc; CSUM is wired alongside via
    // `GVE_TXF_L4CSUM`. Big-pool slots are 16 KiB so a typical
    // 10× MSS super-segment lands in one slot.
    tso_available: || true,
    acquire_tx_tso_buf: Some(tx::acquire_tx_tso_buf),
    submit_tx_tso: Some(tx::submit_tx_tso),
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
    acquire_tx_udp_gso_buf: Some(tx::acquire_tx_udp_gso_buf),
    submit_tx_udp_gso: Some(tx::submit_tx_udp_gso),
    poll_rx: rx::poll,
    poll_qp: rx::poll_qp,
    get_mac,
    num_queue_pairs,
    enable_irq: noop,
    enable_deferred_tx_kick: tx::enable_deferred_tx_kick,
    flush_tx_staging: tx::flush_all_tx_kicks,
    flush_tx_kick_if_dirty: tx::flush_tx_kick_if_dirty,
    poke_interrupt_status: noop,
    idle: None,
    diag: Some(&GVE_DIAG_OPS),
};

fn noop() {}

nic_api::register_ethernet_driver!(GVE_OPS);
