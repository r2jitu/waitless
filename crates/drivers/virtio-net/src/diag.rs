// Driver diagnostics — per-qp byte/packet counters, TX-pool
// saturation counters, and the `tx_diag` / `rx_counts` /
// `rx_used_cursors` accessors the `NicDiagOps` vtable in `lib.rs`
// dispatches to. Read-mostly: every per-packet site touches just a
// single relaxed atomic increment.

use core::sync::atomic::{AtomicU64, Ordering};

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
pub(crate) static TX_SMALL_FULL_SPINS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TX_SMALL_SCAN_ITERS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TX_SMALL_ACQUIRES: AtomicU64 = AtomicU64::new(0);
pub(crate) static TX_BIG_FULL_RETURNS: AtomicU64 = AtomicU64::new(0);
pub(crate) static TX_BIG_ACQUIRES: AtomicU64 = AtomicU64::new(0);

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
        small_pool_full_spins: TX_SMALL_FULL_SPINS.load(Relaxed),
        small_pool_scan_iters: TX_SMALL_SCAN_ITERS.load(Relaxed),
        small_pool_acquires: TX_SMALL_ACQUIRES.load(Relaxed),
        big_pool_full_returns: TX_BIG_FULL_RETURNS.load(Relaxed),
        big_pool_acquires: TX_BIG_ACQUIRES.load(Relaxed),
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
