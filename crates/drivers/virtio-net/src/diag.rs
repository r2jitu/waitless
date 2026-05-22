// Driver diagnostics — per-qp byte/packet counters, TX-pool
// saturation counters, and the `tx_diag` / `rx_counts` /
// `rx_used_cursors` accessors the `NicDiagOps` vtable in `lib.rs`
// dispatches to. Read-mostly: every per-packet site touches just a
// single relaxed atomic increment.

use core::sync::atomic::{AtomicU64, Ordering};

use obs::{Counter, LastEvent, ObsRecord};

use crate::{DIAG_QP_CAP, TX_POOL_BIG_SIZE, TX_POOL_SMALL_SIZE, ndev, tx_q};

// ---- Per-qp byte / packet counters -----------------------------------------

/// Per-queue RX counters. Incremented once per consumed frame.
/// Read via `rx_counts()` from app code (e.g. the `/obs` `nic`
/// block) to see which queues are actually getting traffic — useful for
/// diagnosing RSS / flow-hash distribution under Tier 1 MQ. Cap at
/// `DIAG_QP_CAP` because the public `net_rx_counts` API returns a
/// fixed-size array; queues beyond that are not tracked here.
pub(crate) static RX_COUNTS: [AtomicU64; DIAG_QP_CAP] =
    [const { AtomicU64::new(0) }; DIAG_QP_CAP];

/// Per-qp count of RX descriptor buffers reposted to the avail
/// ring (item B). Bumped from `virtio_rx_repost` — the drop
/// callback of a delivered RX `IOBuf` — once per buffer, possibly
/// on a core other than the one that received the frame. Pairs
/// with `RX_COUNTS` as a cross-core drop-callback sanity check: a
/// persistent shortfall means a chain's IOBuf isn't being dropped
/// (a leaked descriptor buffer).
pub static RX_BUF_REPOST_COUNT: [AtomicU64; DIAG_QP_CAP] =
    [const { AtomicU64::new(0) }; DIAG_QP_CAP];

/// TX-side hot-path counters surfaced via [`crate::NicDiagOps::tx_diag`].
/// Each is a single relaxed atomic — bumped once per acquire /
/// once per scan-iteration / once per submit. `packets_per_qp[i]`
/// is bumped from `submit_tx*` for the qp the worker maps to.
///
/// The pair `(SCAN_ITERS_SMALL, ACQUIRES_SMALL)` lets the reader
/// compute average linear-scan depth: high values flag that a
/// real freelist would help. `FULL_SPINS_SMALL` counts the times
/// we wrapped the scan and had to flush+drain — direct saturation
/// indicator.
pub(crate) static TX_PACKETS_PER_QP: [AtomicU64; DIAG_QP_CAP] =
    [const { AtomicU64::new(0) }; DIAG_QP_CAP];
/// Per-qp cumulative TX wire bytes — sum of `frame_len` over every
/// submit. For TSO the value is the pre-segmentation super-segment
/// length, not post-segmentation wire bytes.
pub(crate) static TX_BYTES_PER_QP: [AtomicU64; DIAG_QP_CAP] =
    [const { AtomicU64::new(0) }; DIAG_QP_CAP];
/// Per-qp cumulative RX wire bytes — driver-side count of frame
/// lengths the callback receives.
pub(crate) static RX_BYTES_PER_QP: [AtomicU64; DIAG_QP_CAP] =
    [const { AtomicU64::new(0) }; DIAG_QP_CAP];
pub(crate) static TX_SMALL_FULL_SPINS: Counter = Counter::new();
pub(crate) static TX_SMALL_SCAN_ITERS: Counter = Counter::new();
pub(crate) static TX_SMALL_ACQUIRES: Counter = Counter::new();
pub(crate) static TX_BIG_FULL_RETURNS: Counter = Counter::new();
pub(crate) static TX_BIG_ACQUIRES: Counter = Counter::new();

pub(crate) fn tx_diag() -> nic_api::TxDiag {
    use Ordering::Relaxed;
    let mut packets = [0u64; DIAG_QP_CAP];
    let mut inflight = [0u32; DIAG_QP_CAP];
    let mut tx_bytes = [0u64; DIAG_QP_CAP];
    let mut rx_bytes = [0u64; DIAG_QP_CAP];
    for i in 0..DIAG_QP_CAP {
        packets[i] = TX_PACKETS_PER_QP[i].load(Relaxed);
        tx_bytes[i] = TX_BYTES_PER_QP[i].load(Relaxed);
        rx_bytes[i] = RX_BYTES_PER_QP[i].load(Relaxed);
    }
    // Per-qp in-flight count: virtio's avail-used delta on each TX
    // queue. Pool slot count instead would conflate small and big
    // pools — the descriptor-side count is the device's view.
    let nqp = unsafe { (*ndev()).negotiated_queue_pairs as usize };
    for (i, slot) in inflight.iter_mut().enumerate().take(nqp.min(DIAG_QP_CAP)) {
        unsafe {
            let q = &*tx_q(i);
            // Outstanding descriptors = avail.idx - used.idx.
            *slot = (q.avail_idx().wrapping_sub(q.used_idx())) as u32;
        }
    }
    nic_api::TxDiag {
        packets_per_qp: packets,
        inflight_per_qp: inflight,
        tx_bytes_per_qp: tx_bytes,
        rx_bytes_per_qp: rx_bytes,
        small_pool_full_spins: TX_SMALL_FULL_SPINS.get(),
        small_pool_scan_iters: TX_SMALL_SCAN_ITERS.get(),
        small_pool_acquires: TX_SMALL_ACQUIRES.get(),
        big_pool_full_returns: TX_BIG_FULL_RETURNS.get(),
        big_pool_acquires: TX_BIG_ACQUIRES.get(),
        small_pool_size: TX_POOL_SMALL_SIZE as u32,
        big_pool_size: TX_POOL_BIG_SIZE as u32,
    }
}

/// Snapshot of per-queue RX frame counts.
pub(crate) fn rx_counts() -> [u64; DIAG_QP_CAP] {
    let mut out = [0u64; DIAG_QP_CAP];
    for i in 0..DIAG_QP_CAP {
        out[i] = RX_COUNTS[i].load(Ordering::Relaxed);
    }
    out
}

/// Raw used-ring cursors per RX queue:
///   [ (device_idx, driver_cursor), ... ]
///
/// `device_idx` is the volatile `used->idx` the device advances as
/// it writes RX buffers. `driver_cursor` is the driver's local
/// `last_used_idx`, incremented each time `poll_qp` consumes one.
///
/// Use the two together to tell where traffic is getting stuck:
///   device_idx == driver_cursor == 0   → device never delivered here
///   device_idx >  driver_cursor        → device delivered but we're
///                                        not polling fast enough / at all
///   device_idx == driver_cursor, both large → healthy: fully drained
pub(crate) fn rx_used_cursors() -> [(u16, u16); DIAG_QP_CAP] {
    let mut out = [(0u16, 0u16); DIAG_QP_CAP];
    // Only negotiated queues are actually initialised — the rest have
    // null `used` pointers and reading `used_idx()` on them would
    // page-fault in the kernel. `negotiated_queue_pairs` caps the
    // loop at what the `init_pci_modern` / `init_mmio` paths wired
    // up; the diag-array bound is what fits in the public API tuple.
    let n = unsafe { (*ndev()).negotiated_queue_pairs as usize }.min(DIAG_QP_CAP);
    unsafe {
        for (i, slot) in out.iter_mut().enumerate().take(n) {
            *slot = (
                (*crate::rx_q(i)).used_idx(),
                (*crate::rx_q(i)).last_used_cursor(),
            );
        }
    }
    out
}

// ---- Observability doctrine: anomaly counters + /obs block -----------------
//
// The observability doctrine (`docs/observability.md`) applied to the
// virtio-net driver. The per-qp byte / packet counters above feed the
// driver-agnostic distribution view; the gap the doctrine closes is
// the *failure* pillar — an RX runt frame, a corrupted drop-callback
// `ctx`, a rejected TX descriptor previously vanished without a trace.
// `Counters` + `LAST_TX_DROP` close that. `write_obs_json` is the
// virtio-net half of the `/obs` `nic` block's `counters`; `gve::diag`
// is the gve half — `nic::obs_json` dispatches to whichever driver is
// active.

/// One counter per virtio-net failure / anomaly. Field names are the
/// stable tokens used in `LAST_TX_DROP` reasons and the `/obs` block.
pub struct Counters {
    /// RX completion whose `used_len` was no larger than the 12-byte
    /// virtio-net header — a frame with no payload. The descriptor
    /// is re-armed and nothing is delivered to the net stack.
    pub rx_runt_frames: Counter,
    /// `virtio_rx_repost` (a delivered RX `IOBuf`'s drop callback)
    /// was handed an out-of-range queue-pair index — its `ctx` is
    /// corrupt. The device buffer is leaked rather than reposted.
    /// Impossible under correct use; any nonzero value is a bug.
    pub rx_repost_bad_qp: Counter,
    /// A TX submit's virtq `add_buf` returned `< 0` — the TX
    /// descriptor ring was full. The frame is dropped and its
    /// pool slot released. Read `LAST_TX_DROP` for the qp.
    pub tx_submit_failed: Counter,
    /// A TX submit was handed a zero-length or oversized frame and
    /// dropped it (slot released). A caller bug — `submit_tx` /
    /// `submit_tx_tso` expect `0 < frame_len <= MAX_ETH_FRAME_*`.
    pub tx_bad_frame_len: Counter,
    /// A TX submit decoded an out-of-range worker / slot from the
    /// handle token, or the TSO big pool was null mid-flight — the
    /// submit was abandoned. Impossible under correct use (the
    /// type-distinct handles guarantee a valid pool); any nonzero
    /// value means a corrupted `TxBufHandle`.
    pub tx_bad_token: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            rx_runt_frames: Counter::new(),
            rx_repost_bad_qp: Counter::new(),
            tx_submit_failed: Counter::new(),
            tx_bad_frame_len: Counter::new(),
            tx_bad_token: Counter::new(),
        }
    }
}

/// Process-wide virtio-net failure counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent dropped TX frame — which submit failure fired, on
/// which qp, and the frame length involved.
pub static LAST_TX_DROP: LastEvent<TxDropRecord> = LastEvent::new();

/// Snapshot payload for `LAST_TX_DROP`.
#[derive(Clone, Copy)]
pub struct TxDropRecord {
    /// Failure token — a `Counters` field name.
    pub reason: &'static str,
    /// Queue pair the drop occurred on. For `tx_bad_token` this is
    /// the (corrupt) decoded worker index, retained as-is.
    pub qp: u32,
    /// Frame length the submit was called with.
    pub frame_len: u32,
    /// `kernel_bare::clock::now_ms()` at the drop.
    pub at_ms: u64,
}

impl ObsRecord for TxDropRecord {
    fn write_fields(&self, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(
            w,
            "\"reason\":\"{}\",\"qp\":{},\"frame_len\":{},\"at_ms\":{}",
            self.reason, self.qp, self.frame_len, self.at_ms,
        )
    }
}

/// Record a dropped TX frame: bump `counter` and snapshot the
/// reason / qp / frame length into `LAST_TX_DROP`. Called from the
/// `submit_tx` / `submit_tx_tso` failure arms.
pub fn record_tx_drop(counter: &Counter, reason: &'static str, qp: u32, frame_len: u32) {
    counter.bump();
    LAST_TX_DROP.record(TxDropRecord {
        reason,
        qp,
        frame_len,
        at_ms: kernel_bare::clock::now_ms(),
    });
}

/// Render the virtio-net observability block as a JSON object — the
/// failure counters, the RX-repost / per-qp throughput totals, then
/// the `LAST_TX_DROP` snapshot. The leading `"driver"` field lets a
/// reader tell which NIC produced the block. This is virtio-net's
/// contribution to the `/obs` `nic` block; `nic::obs_json` forwards
/// it when virtio-net is the active driver.
pub fn write_obs_json(w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    let sum = |a: &[AtomicU64]| -> u64 { a.iter().map(|c| c.load(Ordering::Relaxed)).sum() };
    let c = &COUNTERS;
    write!(
        w,
        "{{\"driver\":\"virtio-net\",\"rx_runt_frames\":{},\"rx_repost_bad_qp\":{},\
         \"tx_submit_failed\":{},\"tx_bad_frame_len\":{},\"tx_bad_token\":{},\
         \"rx_buf_reposts\":{},\"tx_packets\":{},\"tx_bytes\":{},\"rx_bytes\":{},\
         \"tx_small_full_spins\":{},\"tx_big_full_returns\":{},",
        c.rx_runt_frames.get(),
        c.rx_repost_bad_qp.get(),
        c.tx_submit_failed.get(),
        c.tx_bad_frame_len.get(),
        c.tx_bad_token.get(),
        sum(&RX_BUF_REPOST_COUNT),
        sum(&TX_PACKETS_PER_QP),
        sum(&TX_BYTES_PER_QP),
        sum(&RX_BYTES_PER_QP),
        TX_SMALL_FULL_SPINS.get(),
        TX_BIG_FULL_RETURNS.get(),
    )?;
    LAST_TX_DROP.write_json(w, "last_tx_drop")?;
    w.write_str("}")
}
