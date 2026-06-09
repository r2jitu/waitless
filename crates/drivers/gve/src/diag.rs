// Driver diagnostics — counters, descriptor capture ring, and the
// `NicDiagOps`-style accessors the runtime registers under the
// `/obs` `nic` block / `/diag-gve`. None of this is on the critical
// send/recv path's correctness chain; everything here is read-mostly
// and the per-packet hot path touches only relaxed atomic increments.

use core::sync::atomic::{AtomicU64, Ordering};

use obs::{Counter, LastEvent, ObsRecord};
use sync::Spinlock;

use crate::{MAX_QUEUE_PAIRS, RX_QUEUES, TX_BIG_POOL_SLOTS, TX_QUEUES, TX_SMALL_POOL_SLOTS};

// ---- Per-qp byte / packet counters -----------------------------------------

/// Per-qp count of packets successfully handed to the device by
/// `submit_tx*`. Diagnostic only — the device's own completion
/// counter is the source of truth for "done", this counts "issued".
pub(crate) static TX_PACKETS_PER_QP: [AtomicU64; MAX_QUEUE_PAIRS] = [const { AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

/// Per-qp cumulative TX wire bytes — sum of all `frame_len` values
/// passed to `submit_tx` / `submit_tx_tso`. For TSO the count is the
/// super-segment frame length (NOT the post-segmentation wire bytes
/// the device actually emits), so a TSO/STD comparison is not
/// byte-for-byte equal on the wire — interpret carefully.
pub(crate) static TX_BYTES_PER_QP: [AtomicU64; MAX_QUEUE_PAIRS] = [const { AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

/// Per-qp cumulative RX wire bytes — driver-side count of the
/// frame length the callback receives. Includes Eth + IP + L4
/// headers + payload.
pub(crate) static RX_BYTES_PER_QP: [AtomicU64; MAX_QUEUE_PAIRS] = [const { AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

/// Per-qp count of RX device buffers reposted to the receive ring
/// (item B). DQO bumps it from the `dqo_repost` drop callback —
/// once per buffer, possibly on a different core; GQI bumps it per
/// drained completion at the batch-end repost. The cross-core
/// drop-callback sanity check: this should track the per-qp RX
/// frame count — a persistent shortfall means a drop callback
/// isn't firing (a leaked device buffer). Surfaced via the `/obs`
/// `nic` block.
pub static RX_BUF_REPOST_COUNT: [AtomicU64; MAX_QUEUE_PAIRS] = [const { AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

/// Per-qp count of GQI frames dropped because the recycle pool was
/// exhausted — no slab free to copy the frame into (item B).
/// Always 0 on a healthy GQI queue; a non-zero value means the
/// consumer isn't draining pooled slabs fast enough (see
/// `gqi::GQI_RX_POOL_SLABS`). Surfaced via the `/obs` `nic` block.
pub static GQI_RECYCLE_POOL_EXHAUSTED: [AtomicU64; MAX_QUEUE_PAIRS] = [const { AtomicU64::new(0) }; MAX_QUEUE_PAIRS];

// ---- TX direct-fill pool saturation counters -------------------------------

pub(crate) static TX_SMALL_FULL_SPINS: Counter = Counter::new();
pub(crate) static TX_SMALL_SCAN_ITERS: Counter = Counter::new();
pub(crate) static TX_SMALL_ACQUIRES: Counter = Counter::new();
pub(crate) static TX_BIG_FULL_RETURNS: Counter = Counter::new();
pub(crate) static TX_BIG_ACQUIRES: Counter = Counter::new();
/// GQI small-pool acquires abandoned by the TX-stall circuit breaker
/// (spin budget elapsed, or fast-fail cooldown active — see
/// `gqi::acquire_tx_buf_for_qp`). Always 0 on a healthy ring; nonzero
/// flags a TX ring the device stopped draining, where the old
/// unbounded spin would have hard-hung the whole core.
pub(crate) static GQI_TX_STALL_DROPS: Counter = Counter::new();

// ---- TX descriptor capture ring -------------------------------------------
//
// Records every 16-byte descriptor handed to the device; latest
// `TX_DESC_LOG_DEPTH` retained. Surfaced via `tx_desc_log_snapshot`
// → /diag-gve so a remote operator can inspect what the driver
// actually wrote when the device misbehaves. Particularly load-
// bearing for TSO debug on GCE where serial-port output is gated
// by sandbox IAM.
//
// 32 entries × 24 bytes + spinlock ≈ 800 B fixed. Each `submit_tx_*`
// call takes the lock once on the hot path; the contended window
// (a few stores) is dwarfed by the surrounding allocator +
// descriptor work.

const TX_DESC_LOG_DEPTH: usize = 32;

#[derive(Clone, Copy)]
pub struct TxDescLogEntry {
    /// Monotonic sequence number — lets readers reconstruct the
    /// chronological order even after the ring wraps.
    pub seq: u32,
    /// Queue pair index (0..MAX_QUEUE_PAIRS). u8 is plenty: we never
    /// expose more than 8 qps to the kernel.
    pub qp: u8,
    /// Descriptor kind: see [`tx_desc_kind`].
    pub kind: u8,
    /// Raw 16-byte gve descriptor bytes as written into the ring.
    pub bytes: [u8; 16],
}

struct TxDescLog {
    entries: [TxDescLogEntry; TX_DESC_LOG_DEPTH],
    /// Next slot to overwrite (0..TX_DESC_LOG_DEPTH).
    head: usize,
    /// Monotonic counter; matches the most recently written
    /// entry's `seq`. Wraps on overflow but the relative order
    /// across ≤ TX_DESC_LOG_DEPTH live entries stays unambiguous.
    seq: u32,
    /// Total entries written since boot. `valid_count =
    /// min(written, TX_DESC_LOG_DEPTH)` tells the snapshot reader
    /// how many slots to walk.
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

/// Descriptor-kind tags used by `/diag-gve` to annotate each row.
/// Use these (not raw integers) at call sites so the rendering stays
/// in sync with what the driver actually wrote.
pub(crate) mod tx_desc_kind {
    pub const STD: u8 = 0;
    pub const TSO: u8 = 1;
    pub const SEG: u8 = 2;
}

pub(crate) fn record_tx_desc(qp: u8, kind: u8, bytes: &[u8; 16]) {
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
    for (i, dst) in out.iter_mut().take(n).enumerate() {
        *dst = log.entries[(start + i) % TX_DESC_LOG_DEPTH];
    }
    n
}

/// Trampoline that bridges this module's local `TxDescLogEntry`
/// to the cross-crate `nic_api::TxDescLogEntry` the consumer
/// reads. Same fields, same layout — we copy field-by-field rather
/// than transmute to keep the boundary explicit. Registered as the
/// `NicDiagOps::tx_desc_log_snapshot` function pointer.
pub(crate) fn tx_desc_log_snapshot_export(out: &mut [nic_api::TxDescLogEntry]) -> usize {
    let mut local = [TxDescLogEntry {
        seq: 0,
        qp: 0,
        kind: 0,
        bytes: [0; 16],
    }; TX_DESC_LOG_DEPTH];
    let limit = out.len().min(TX_DESC_LOG_DEPTH);
    let n = tx_desc_log_snapshot(&mut local[..limit]);
    for i in 0..n {
        out[i] = nic_api::TxDescLogEntry {
            seq: local[i].seq,
            qp: local[i].qp,
            kind: local[i].kind,
            bytes: local[i].bytes,
        };
    }
    n
}

// ---- NicDiagOps adapters ---------------------------------------------------

pub(crate) fn tx_diag() -> nic_api::TxDiag {
    let mut packets = [0u64; nic_api::DIAG_QP_CAP];
    let mut inflight = [0u32; nic_api::DIAG_QP_CAP];
    let mut tx_bytes = [0u64; nic_api::DIAG_QP_CAP];
    let mut rx_bytes = [0u64; nic_api::DIAG_QP_CAP];
    for i in 0..nic_api::DIAG_QP_CAP {
        packets[i] = TX_PACKETS_PER_QP[i].load(Ordering::Relaxed);
        if i < TX_BYTES_PER_QP.len() {
            tx_bytes[i] = TX_BYTES_PER_QP[i].load(Ordering::Relaxed);
            rx_bytes[i] = RX_BYTES_PER_QP[i].load(Ordering::Relaxed);
        }
        // In-flight = fill_cnt - done_cnt for each live qp. Pinned
        // at `ring_entries` across multiple snapshots flags a stall
        // — the driver's queueing more, but the device hasn't
        // issued completions.
        let tx_ptr = TX_QUEUES[i].load(Ordering::Acquire);
        if !tx_ptr.is_null() {
            let tx = unsafe { &*tx_ptr };
            let fill = tx.fill_cnt.load(Ordering::Relaxed);
            let done = tx.done_cnt.load(Ordering::Relaxed);
            inflight[i] = fill.wrapping_sub(done);
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
        small_pool_size: TX_SMALL_POOL_SLOTS,
        big_pool_size: TX_BIG_POOL_SLOTS,
    }
}

/// Per-queue RX frame count. Lock-free snapshot — uses the atomic
/// `cons_cnt` on each live queue.
pub(crate) fn rx_counts() -> [u64; MAX_QUEUE_PAIRS] {
    let mut out = [0u64; MAX_QUEUE_PAIRS];
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
/// naturally onto virtio's `(device_idx, driver_cursor)` in the
/// `/obs` `nic` block.
pub(crate) fn rx_used_cursors() -> [(u16, u16); MAX_QUEUE_PAIRS] {
    let mut out = [(0u16, 0u16); MAX_QUEUE_PAIRS];
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

// ---- Observability doctrine: RX-skip snapshot + /obs block -----------------
//
// The observability doctrine (`docs/observability.md`) applied to the
// NIC. The driver's counters already exist (above + `dqo`); the gap
// the doctrine closes is *context*: the DQO RX path kept only a bare
// `DQO_RX_LAST_SKIP_STATUS` byte for skipped completions. `LAST_RX_SKIP`
// retains the qp and a timestamp alongside it. `write_obs_json` is the
// NIC's `/obs` block.

/// Most recent RX completion the DQO drain skipped (`buf_id` out of
/// range, EOP clear, or `pkt_len == 0` — see `dqo::DQO_RX_COMPL_SKIPPED`).
pub static LAST_RX_SKIP: LastEvent<RxSkipRecord> = LastEvent::new();

/// Snapshot payload for `LAST_RX_SKIP`.
#[derive(Clone, Copy)]
pub struct RxSkipRecord {
    /// Status byte (offset 8) of the skipped completion descriptor.
    pub status: u8,
    /// Queue pair the skip occurred on.
    pub qp: u8,
    /// `kernel_core::clock::now_ms()` at the skip.
    pub at_ms: u64,
}

impl ObsRecord for RxSkipRecord {
    fn write_fields(&self, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(
            w,
            "\"status\":{},\"qp\":{},\"at_ms\":{}",
            self.status, self.qp, self.at_ms,
        )
    }
}

/// Record a skipped RX completion into `LAST_RX_SKIP`. Called from
/// the DQO RX drain; `DQO_RX_COMPL_SKIPPED` is bumped at the site.
pub fn record_rx_skip(qp: u8, status: u8) {
    LAST_RX_SKIP.record(RxSkipRecord {
        status,
        qp,
        at_ms: kernel_bare::clock::now_ms(),
    });
}

/// Render the gve driver's observability block as JSON — the
/// anomaly counters (TX miss/reinject, RX skip, recycle-pool
/// exhaustion, repost shortfall) and throughput totals, then the
/// `LAST_RX_SKIP` snapshot. The leading `"driver"` field self-
/// identifies the block. This is gve's `counters` contribution to
/// the `/obs` `nic` block; `nic::obs_json` dispatches here when gve
/// is the active driver (virtio-net renders its own block).
pub fn write_obs_json(w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    let sum = |a: &[AtomicU64]| -> u64 { a.iter().map(|c| c.load(Ordering::Relaxed)).sum() };
    // TX descriptor totals (Σ across qps): submitted vs device-completed.
    // Lets /obs triangulate egress drops vs our `datagrams_sent` and the wire.
    let (tx_desc_fill, tx_desc_done) = crate::tx::tx_desc_totals();
    write!(
        w,
        "{{\"driver\":\"gve\",\"tx_miss_compl\":{},\"tx_reinject_compl\":{},\
         \"tx_ring_full_drops\":{},\"tx_tso_sent\":{},\
         \"rx_compl_skipped\":{},\"rx_pending_chain_timeouts\":{},\
         \"rx_buf_reposts\":{},\"gqi_recycle_exhausted\":{},\
         \"tx_packets\":{},\"tx_bytes\":{},\"rx_bytes\":{},\"tx_small_full_spins\":{},\
         \"gqi_tx_stall_drops\":{},\
         \"tx_big_full_returns\":{},\"rx_irq\":{},\
         \"tx_desc_fill\":{},\"tx_desc_done\":{},",
        crate::dqo::DQO_TX_MISS_COMPL.load(Ordering::Relaxed),
        crate::dqo::DQO_TX_REINJECT_COMPL.load(Ordering::Relaxed),
        crate::dqo::DQO_TX_RING_FULL_DROPS.load(Ordering::Relaxed),
        crate::dqo::DQO_TX_TSO_SENT.load(Ordering::Relaxed),
        crate::dqo::DQO_RX_COMPL_SKIPPED.load(Ordering::Relaxed),
        crate::dqo::DQO_RX_PENDING_CHAIN_TIMEOUTS.load(Ordering::Relaxed),
        sum(&RX_BUF_REPOST_COUNT),
        sum(&GQI_RECYCLE_POOL_EXHAUSTED),
        sum(&TX_PACKETS_PER_QP),
        sum(&TX_BYTES_PER_QP),
        sum(&RX_BYTES_PER_QP),
        TX_SMALL_FULL_SPINS.get(),
        GQI_TX_STALL_DROPS.get(),
        TX_BIG_FULL_RETURNS.get(),
        // RX MSI-X interrupts handled (T7 wake-on-packet idle). Nonzero
        // confirms the IRQ path fires; 0 on a busy server (never arms)
        // or an MSI-X-less boot (timer-only idle).
        crate::irq::rx_irq_count(),
        tx_desc_fill,
        tx_desc_done,
    )?;
    LAST_RX_SKIP.write_json(w, "last_rx_skip")?;
    w.write_str("}")
}
