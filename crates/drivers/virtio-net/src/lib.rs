// virtio-net/src/lib.rs — VirtIO network device driver.
//
// Crate root: declares the submodules that hold the cohesive
// per-path code (init / tx / rx / irq / diag), defines the shared
// driver-state types they all touch, and registers the public
// `NicOps` vtable into the `nic_api::ACTIVE_OPS` slot via
// `register_ethernet_driver!`.

#![no_std]

extern crate alloc;

use core::ptr;

use bus::virtio::Virtqueue;

mod diag;
mod init;
mod irq;
mod rx;
mod tx;

// Re-export the one item callers may read by name. Today the only
// `pub` symbol from this crate is the per-qp RX-repost counter —
// kept for symmetry with `gve::RX_BUF_REPOST_COUNT` even though
// no external caller imports it as `virtio_net::…` yet.
pub use diag::RX_BUF_REPOST_COUNT;

// ============================================================================
// VirtIO-net constants and types
// ============================================================================

pub(crate) const RX_BUFFERS: usize = 256;
pub(crate) const BUFFER_SIZE: u32 = 2048;
pub(crate) const VIRTIO_NET_HDR_SIZE: usize = 12; // VirtioNetHeader (with num_buffers)

// ── TX pool sizing (two-tier post-G) ────────────────────────────
//
// Small pool: 64 × 1514-byte slots. Used by every TX path that
// fits in one MTU — UDP, ARP, TCP per-MSS segments, TCP control
// (ACK/FIN/RST), QUIC packets. ~97 KiB per worker. Always
// allocated.
//
// Big pool: 16 × 16512-byte slots. Used ONLY by the TCP TSO
// super-segment path when `VIRTIO_NET_F_HOST_TSO4` is negotiated;
// each slot fits one full TLS 1.3 record (16384 plaintext + 22
// envelope) plus L2/L3/L4 headers. ~264 KiB per worker.
// Heap-allocated lazily inside `init_qp_storage` only when TSO
// is on; null pointer when off so a TSO-disabled device pays
// zero memory for unused slots.
//
// Total per-worker TX memory: 97 KiB (TSO off) or 361 KiB (TSO on).
// Compares to ~1 MiB if we'd kept a single 64-slot pool sized for
// the TSO worst case.
pub(crate) const TX_POOL_SMALL_SIZE: usize = 64;
pub(crate) const TX_POOL_BIG_SIZE: usize = 16;
pub(crate) const MAX_ETH_FRAME_SMALL: usize = 1514;
/// Big-slot capacity. 14 (Eth) + 40 (max IPv6) + 20 (TCP) + 16384
/// (TLS plaintext) + 22 (TLS envelope = 5 hdr + 1 type + 16 tag)
/// = 16480 bytes. Round to the next 64-B cache-line boundary.
pub(crate) const MAX_ETH_FRAME_BIG: usize = 16512;

/// Virtio gso_type values (RFC: virtio spec §5.1.6).
pub(crate) const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub(crate) const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

/// Virtio flags values.
pub(crate) const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

// virtio-net *device* feature bits (virtio spec §5.1.3). These are
// device-class knowledge, so they live here (with the header constants
// above) rather than in the transport `bus` crate, which negotiates
// features generically and never interprets them.
/// Driver handles packets with partial checksum (host computes for us).
/// Prerequisite for `VIRTIO_NET_F_HOST_TSO4`.
pub(crate) const VIRTIO_NET_F_CSUM: u32 = 1 << 0;
// MAC / MRG_RXBUF / STATUS are consumed only by the aarch64 MMIO
// bring-up path (`init.rs`, where the import is the matching
// `#[cfg(target_arch = "aarch64")]`); gate the declarations the same
// way so x86_64 — which negotiates these generically and never names
// the consts — doesn't see them as dead code under `-D warnings`.
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_NET_F_MAC: u32 = 1 << 5;
/// Device segments a driver-supplied TCPv4 GSO super-segment host-side
/// (`gso_type=TCPV4` + `gso_size=MSS`) — saves the per-MSS TX loop.
pub(crate) const VIRTIO_NET_F_HOST_TSO4: u32 = 1 << 11;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_NET_F_MRG_RXBUF: u32 = 1 << 15;
#[cfg(target_arch = "aarch64")]
pub(crate) const VIRTIO_NET_F_STATUS: u32 = 1 << 16;
pub(crate) const VIRTIO_NET_F_CTRL_VQ: u32 = 1 << 17;
pub(crate) const VIRTIO_NET_F_MQ: u32 = 1 << 22;
/// Guest-side RX-offload feature bits the RX path does **not**
/// implement and must clear from the negotiated set: `poll_qp` delivers
/// each frame as a single ≤`BUFFER_SIZE` descriptor and never reads the
/// header's `num_buffers`/`gso_type`, so `GUEST_TSO4`(7)/`MRG_RXBUF`(15)
/// — which coalesce/span inbound TCP across buffers — plus
/// `GUEST_CSUM`(1)/`TSO6`(8)/`ECN`(9)/`UFO`(10) would shred large
/// inbound TCP. Masked off.
pub(crate) const VIRTIO_NET_RX_OFFLOAD_MASK: u32 =
    (1 << 1) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 15);

/// Public diagnostic API (`net_rx_counts` / `net_rx_used_cursors`)
/// returns fixed-size arrays of this length. The actual queue-pair
/// storage is heap-allocated and uncapped — this only bounds what
/// the `/obs` `nic` block can show in a single response. Must match
/// `nic_api::DIAG_QP_CAP` and `gve::MAX_QUEUE_PAIRS`.
pub(crate) const DIAG_QP_CAP: usize = 22;

/// NAPI-style IP-header alignment shift. Layout of each RX buffer:
///
///   [virtio_net_hdr (12)][eth hdr (14)][IP hdr ...]
///
/// kmalloc returns 4-byte-aligned pointers, so the IP header lands at
/// `buf + 26` — not 4-aligned, which on aarch64 makes the network
/// stack's u32 reads (src/dst IP, checksum) fall back to the slow
/// misaligned path. Shifting the DMA target by 2 moves the IP header
/// to `buf + 28`, back on a 4-byte boundary. The x86 legacy-mmio
/// init path (`init_legacy_mmio`) intentionally skips this shift —
/// x86 handles misaligned loads at full speed.
pub(crate) const RX_IP_ALIGN: usize = 2;

#[repr(C, packed)]
pub(crate) struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

#[repr(C)]
pub(crate) struct TxBufSmall {
    pub hdr: VirtioNetHeader,
    pub data: [u8; MAX_ETH_FRAME_SMALL],
}

#[repr(C)]
pub(crate) struct TxBufBig {
    pub hdr: VirtioNetHeader,
    pub data: [u8; MAX_ETH_FRAME_BIG],
}

impl TxBufSmall {
    pub(crate) const ZERO: Self = TxBufSmall {
        hdr: VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        },
        data: [0; MAX_ETH_FRAME_SMALL],
    };
}

impl TxBufBig {
    pub(crate) const ZERO: Self = TxBufBig {
        hdr: VirtioNetHeader {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        },
        data: [0; MAX_ETH_FRAME_BIG],
    };
}

// Transport state
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Transport {
    None,
    #[cfg(target_arch = "aarch64")]
    Mmio {
        base: u64,
        is_v2: bool,
    },
    ModernPci {
        vpci_idx: usize,
    },
}

// ============================================================================
// Per-queue-pair state (one per NIC virtqueue pair)
// ============================================================================

pub(crate) struct QueuePairState {
    pub rx_buffers: [*mut u8; RX_BUFFERS],
    /// Serialises `(*rx_q(qp)).add_buf(...)` calls. With the
    /// `&[u8]` RX path, re-arm runs inline in `poll_qp` right
    /// after the callback returns — same core as the device-ring
    /// drain. The lock is kept for forward-compat (e.g. an IRQ
    /// handler that also re-arms) and as a single-writer
    /// invariant inside `add_buf`.
    pub rx_lock: sync::Spinlock<()>,
    /// Set by inline re-arm after a successful `add_buf`.
    /// Read + cleared by the end-of-batch kick in `poll_qp`,
    /// which kicks the device if set so it sees the freshly-
    /// posted buffers. Lets us batch kicks across many re-arms
    /// within one poll cycle without losing device-side visibility.
    pub rx_dirty: core::sync::atomic::AtomicBool,
}

impl QueuePairState {
    // Zero-initialised queue-pair-state template. Intentionally a
    // `const` (not a `const fn`): it is `ptr::write`-copied into each
    // freshly-allocated slot in `init_qp_storage`, and as a `const` it
    // lives in rodata so the copy is a plain rodata->slot memcpy with
    // no stack temporary. clippy's `declare_interior_mutable_const`
    // flags it because the type holds a `Spinlock`/`AtomicBool`; the
    // per-use copy the lint warns about is exactly what every call
    // site wants here — one fresh, independent instance per slot — so
    // the lint is suppressed deliberately.
    #[allow(clippy::declare_interior_mutable_const)]
    pub(crate) const ZEROED: Self = QueuePairState {
        rx_buffers: [ptr::null_mut(); RX_BUFFERS],
        rx_lock: sync::Spinlock::new(()),
        rx_dirty: core::sync::atomic::AtomicBool::new(false),
    };
}

// ============================================================================
// Per-worker TX pools (one per worker, regardless of nqp)
// ============================================================================
//
// The TX pool — the storage slots a frame builder fills before
// `submit_tx` — is per-worker, NOT per-qp. On Tier 1 (per-core
// queue pair) num_workers == num_qps and the indexing coincides;
// on Tier 2 (shared qp 0) we still want pool slot allocation to
// be lock-free per worker, with only the virtq submission going
// through TX_LOCK.
//
// `*_used` flags are AtomicBool so the qp-drain path (which on
// Tier 2 may run on any worker, freeing slots that belong to
// other workers' pools) can mark slots free without racing the
// owning worker's allocation scan. Allocation is still single-
// writer per worker (only the owning worker calls
// `acquire_tx_buf`), so it's a load + a store (no CAS needed —
// the only cross-worker write is the drain's `store(false)` of
// a slot the owning worker already saw as `true`).

pub(crate) struct WorkerTxPool {
    /// Small TX-pool slots — always allocated. 64 × 1514 B.
    pub small: [TxBufSmall; TX_POOL_SMALL_SIZE],
    pub small_used: [core::sync::atomic::AtomicBool; TX_POOL_SMALL_SIZE],
    /// Big TX-pool slots — heap-alloc'd in `init_qp_storage` only
    /// when `VIRTIO_NET_F_HOST_TSO4` is negotiated. Pointer is
    /// null when TSO is off so a TSO-disabled device pays no
    /// memory for the unused slots.
    pub big: *mut TxBufBig,
    pub big_used: [core::sync::atomic::AtomicBool; TX_POOL_BIG_SIZE],
}

impl WorkerTxPool {
    // Zero-initialised worker-TX-pool template. MUST stay a `const`
    // (not a `const fn`): `WorkerTxPool` is ~97 KiB, and as a `const`
    // it lives in rodata so `init_qp_storage` copies it rodata->slot.
    // A `const fn` returning it by value materialises a ~97 KiB stack
    // temporary that overflows the kernel boot stack on aarch64 and
    // wedges boot (verified: it breaks webserver_hvf / _qemu_aarch64).
    // clippy's `declare_interior_mutable_const` flags the interior-
    // mutable `AtomicBool` arrays; the per-use copy it warns about is
    // the intended behaviour — one fresh pool per worker.
    #[allow(clippy::declare_interior_mutable_const)]
    pub(crate) const ZEROED: Self = WorkerTxPool {
        small: [const { TxBufSmall::ZERO }; TX_POOL_SMALL_SIZE],
        small_used: [const { core::sync::atomic::AtomicBool::new(false) }; TX_POOL_SMALL_SIZE],
        big: ptr::null_mut(),
        big_used: [const { core::sync::atomic::AtomicBool::new(false) }; TX_POOL_BIG_SIZE],
    };
}

// ============================================================================
// VirtIO-net driver state
// ============================================================================

pub(crate) struct NetDevice {
    pub transport: Transport,
    // Queue-pair storage. Heap-allocated once at init from the
    // negotiated `num_pairs`, then read-shared from every core's
    // hot path. Per-slot ownership: `rx_queues[qp]`, `tx_queues[qp]`,
    // `qp_state[qp]` are owned by the core whose id == qp under
    // Tier 1 multi-queue (Tier 2 / single-queue: serialised via
    // TX_LOCK + the SPSC inbox layer). Null until `init_qp_storage`.
    pub rx_queues: *mut Virtqueue,
    pub tx_queues: *mut Virtqueue,
    pub qp_state: *mut QueuePairState,
    /// Per-worker TX pools — one per worker, regardless of
    /// `num_queue_pairs`. `acquire_tx_buf` indexes by
    /// `CurrentWorker::id()` so slot allocation is lock-free per
    /// worker on both Tier 1 (per-core qp) and Tier 2 (shared qp
    /// 0); only the virtq-submit step takes TX_LOCK on Tier 2.
    pub worker_pools: *mut WorkerTxPool,
    /// Number of workers — the size of the `worker_pools` array.
    /// Captured at `init_qp_storage` time from
    /// `kernel_bare::percpu::num_cores()`.
    pub num_workers: usize,
    pub ctrl_queue: Virtqueue, // Control VQ for multi-queue commands
    pub mac: [u8; 6],
    pub num_queue_pairs: u16, // 1 = single-queue, >1 = multi-queue
    /// Number of queue pairs the device has negotiated capacity for.
    /// Usually equals `num_queue_pairs` once init completes; the
    /// split exists because `activate_multi_queue` sends
    /// `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` with this value and the
    /// `poll` fallback iterates all of them to drain queues host-
    /// side RSS may have sprayed into before activation landed.
    pub negotiated_queue_pairs: u16,
    pub irq_idle_available: bool,
    pub guest_features: u32,
    pub has_mq: bool, // VIRTIO_NET_F_MQ negotiated
    /// VIRTIO_NET_F_HOST_TSO4 + VIRTIO_NET_F_CSUM negotiated. When
    /// true, the TCP layer can hand us a single super-segment up
    /// to MAX_ETH_FRAME bytes with `gso_type=TCPV4` + `gso_size=MSS`
    /// in the per-slot virtio_net_hdr; the device segments it
    /// host-side. Saves the per-MSS frame-build loop in
    /// `async_try_send_chain`.
    pub has_tso4: bool,
    /// `VIRTIO_NET_F_CSUM` negotiated — the device finishes an L4
    /// checksum from a guest-stamped pseudo-header partial sum
    /// (`VIRTIO_NET_HDR_F_NEEDS_CSUM`). Tracked apart from
    /// `has_tso4`: a device can offer CSUM without TSO4. When this
    /// is false, `submit_tx` finishes the L4 checksum in software.
    pub has_csum: bool,
}

impl NetDevice {
    pub(crate) const ZEROED: Self = NetDevice {
        transport: Transport::None,
        rx_queues: ptr::null_mut(),
        tx_queues: ptr::null_mut(),
        qp_state: ptr::null_mut(),
        worker_pools: ptr::null_mut(),
        num_workers: 1,
        ctrl_queue: Virtqueue::ZERO,
        mac: [0; 6],
        num_queue_pairs: 1,
        negotiated_queue_pairs: 1,
        irq_idle_available: false,
        guest_features: 0,
        has_mq: false,
        has_tso4: false,
        has_csum: false,
    };
}

/// Shorthand pointer accessors for per-queue-pair state. Caller
/// must ensure `qp < negotiated_queue_pairs` (or the in-flight
/// `num_pairs` during init).
#[inline]
pub(crate) unsafe fn rx_q(qp: usize) -> *mut Virtqueue {
    unsafe { (*ndev()).rx_queues.add(qp) }
}
#[inline]
pub(crate) unsafe fn tx_q(qp: usize) -> *mut Virtqueue {
    unsafe { (*ndev()).tx_queues.add(qp) }
}
#[inline]
pub(crate) unsafe fn qps(qp: usize) -> *mut QueuePairState {
    unsafe { (*ndev()).qp_state.add(qp) }
}
#[inline]
pub(crate) unsafe fn wpool(worker: usize) -> *mut WorkerTxPool {
    unsafe { (*ndev()).worker_pools.add(worker) }
}

/// Pick the qp this worker submits its TX through. On Tier 1
/// (per-core qp) `qp == worker`. On Tier 2 / single-queue,
/// every worker submits via qp 0.
#[inline]
pub(crate) fn worker_qp(worker: usize) -> usize {
    let nqp = unsafe { (*ndev()).num_queue_pairs as usize };
    if nqp > 1 && worker < nqp { worker } else { 0 }
}

/// Driver state singleton.
///
/// Wrapped in `UnsafeCell` so cross-core access is via raw-pointer place
/// expressions (`(*ndev()).foo`) rather than via `&mut NetDevice`. Forming
/// `&mut NetDevice` from multiple cores would alias even when the
/// underlying memory accesses target disjoint per-qp slots — undefined
/// behaviour by the Rust aliasing model regardless of whether they
/// actually overlap.
///
/// Per-field SPSC/ownership rules (e.g. "rx_queues[qp] is owned by the
/// core whose id == qp under Tier 1 multi-queue") are documented at the
/// access sites; the wrapper just makes "no &mut NetDevice" enforceable
/// at the syntactic level.
struct NetCell(core::cell::UnsafeCell<NetDevice>);
unsafe impl Sync for NetCell {}

static NET: NetCell = NetCell(core::cell::UnsafeCell::new(NetDevice::ZEROED));

/// Raw pointer to the driver state. Use as `(*ndev()).field` so the
/// place expression yields a `&mut Field` directly without going via
/// `&mut NetDevice`.
#[inline(always)]
pub(crate) fn ndev() -> *mut NetDevice {
    NET.0.get()
}

/// Get the number of active queue pairs.
fn num_queue_pairs() -> u16 {
    unsafe { (*ndev()).num_queue_pairs }
}

// ============================================================================
// Public API — VirtIO-net
// ============================================================================

/// Set when `init()` has returned `true`. Read via `probe_ok()` below;
/// do not read directly.
static PROBE_OK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn init() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        if init::init_mmio() {
            PROBE_OK.store(true, core::sync::atomic::Ordering::Release);
            return true;
        }
    }
    if init::init_pci_modern() {
        PROBE_OK.store(true, core::sync::atomic::Ordering::Release);
        return true;
    }
    false
}

/// Whether `init()` successfully bound a VirtIO-net NIC. Used by
/// the `NicOps::probe` adapter to short-circuit repeat probes
/// during multi-driver discovery.
fn probe_ok() -> bool {
    PROBE_OK.load(core::sync::atomic::Ordering::Acquire)
}

fn get_mac(mac_out: *mut u8) {
    unsafe {
        ptr::copy_nonoverlapping((*ndev()).mac.as_ptr(), mac_out, 6);
    }
}

// ============================================================================
// NicOps registration
// ============================================================================
//
// ── Registration ────────────────────────────────────────────────────────────
//
// A static `NicOps` struct of fn pointers, registered into the
// `.waitless_drivers_ethernet` section via `register_ethernet_driver!`.
// The active-driver slot stores `&'static NicOps`; every dispatcher
// call does one Acquire load + one direct call.

use nic_api::{NicDiagOps, NicIdleOps, NicOps};

/// `init()` is NOT idempotent — it re-runs PCI/MMIO probe + queue
/// realloc + MSI-X rebind, corrupting in-flight state if called after
/// the TCP stack is up. Short-circuit through the cached `probe_ok`
/// flag; only run the real bring-up on the first call.
fn probe() -> bool {
    probe_ok() || init()
}

static VIRTIO_NET_IDLE_OPS: NicIdleOps = NicIdleOps {
    arm_rx_interrupts: rx::arm_rx_interrupts,
    has_pending_rx: rx::has_pending_rx,
    has_pending_tx: tx::has_pending_tx,
    rearm_rx_napi: rx::rearm_rx_napi,
};

static VIRTIO_NET_DIAG_OPS: NicDiagOps = NicDiagOps {
    rx_counts: diag::rx_counts,
    rx_used_cursors: diag::rx_used_cursors,
    tx_diag: Some(diag::tx_diag),
    // virtio-net doesn't keep a per-descriptor capture log — TSO on
    // virtio-net works as designed, so the gve-style /diag-gve
    // endpoint isn't needed here. Keep `None` so the trait surface
    // stays uniform across drivers without forcing every backend
    // to add the ring.
    tx_desc_log_snapshot: None,
    obs_json: diag::write_obs_json,
};

static VIRTIO_NET_OPS: NicOps = NicOps {
    name: "virtio-net",
    probe,
    send: tx::send,
    acquire_tx_buf: Some(tx::acquire_tx_buf),
    submit_tx: Some(tx::submit_tx),
    tso_available: tx::tso_available,
    acquire_tx_tso_buf: Some(tx::acquire_tx_tso_buf),
    submit_tx_tso: Some(tx::submit_tx_tso),
    // UDP-GSO would require negotiating `VIRTIO_NET_F_HOST_USO` and
    // wiring `VIRTIO_NET_HDR_GSO_UDP_L4`. The HVF runner's
    // userspace UDP proxy would also need to parse super-packets
    // and emit N datagrams per super-packet — currently it reads
    // the descriptor as a single frame and forwards verbatim.
    // Until both pieces are in place, advertise unavailable.
    udp_gso_available: || false,
    acquire_tx_udp_gso_buf: None,
    submit_tx_udp_gso: None,
    poll_rx: rx::poll,
    poll_qp: rx::poll_qp,
    get_mac,
    num_queue_pairs,
    enable_irq: irq::enable_irq,
    enable_deferred_tx_kick: tx::enable_deferred_tx_kick,
    flush_tx_staging: tx::flush_tx_staging,
    flush_tx_kick_if_dirty: tx::flush_tx_kick_if_dirty,
    poke_interrupt_status: irq::poke_interrupt_status,
    idle: Some(&VIRTIO_NET_IDLE_OPS),
    arm_rx_idle: None,
    diag: Some(&VIRTIO_NET_DIAG_OPS),
};

nic_api::register_ethernet_driver!(VIRTIO_NET_OPS);
