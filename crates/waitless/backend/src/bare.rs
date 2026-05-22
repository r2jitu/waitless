// crates/waitless/backend/src/bare.rs — Bare-metal dispatch.

use kernel_bare::serial;

// ---- Lifecycle / config ---------------------------------------------------

pub fn log(msg: &[u8]) {
    serial::puts(msg)
}

pub fn check_shutdown() -> bool {
    serial::check_shutdown()
}

// ---- Net stack re-exports (TCP/UDP + driver diagnostics) ------------------

pub use nic::{
    DIAG_QP_CAP as NET_DIAG_QP_CAP, TxDescLogEntry as NetTxDescLogEntry, TxDiag as NetTxDiag,
    num_queue_pairs as net_num_queue_pairs, rx_counts as net_rx_counts,
    rx_used_cursors as net_rx_used_cursors, tx_desc_log_snapshot as net_tx_desc_log_snapshot,
    tx_diag as net_tx_diag,
};

/// gve NIC driver diagnostic counters (RX-path items B/H — see
/// `/stats`). Reads the bare-metal gve driver's atomics directly;
/// every field stays 0 unless the gve NIC is the active driver
/// (so all-zero under virtio-net). The native backend has no gve
/// driver and stubs this all-zero (`native::gve_diag`), so an
/// application can surface these counters through
/// `waitless::diagnostics` *without* itself depending on the
/// `os:none`-only gve driver crate — the dependency that, placed
/// in app code, breaks the native build.
pub fn gve_diag() -> crate::GveDiag {
    use core::sync::atomic::Ordering::Relaxed;
    let sum =
        |a: &[core::sync::atomic::AtomicU64]| -> u64 { a.iter().map(|c| c.load(Relaxed)).sum() };
    crate::GveDiag {
        dqo_tx_miss_compl: gve::dqo::DQO_TX_MISS_COMPL.load(Relaxed),
        dqo_tx_reinject_compl: gve::dqo::DQO_TX_REINJECT_COMPL.load(Relaxed),
        dqo_rx_compl_skipped: gve::dqo::DQO_RX_COMPL_SKIPPED.load(Relaxed),
        dqo_rx_last_skip_status: gve::dqo::DQO_RX_LAST_SKIP_STATUS.load(Relaxed),
        rx_buf_repost_count: sum(&gve::RX_BUF_REPOST_COUNT),
        gqi_recycle_pool_exhausted: sum(&gve::GQI_RECYCLE_POOL_EXHAUSTED),
    }
}

/// TCP/IP-stack diagnostic counters (`/stats`). Reads the
/// bare-metal `net` stack's atomics; the native backend has no
/// `net` stack and stubs this all-zero (`native::tcp_diag`), so an
/// application reads them through `waitless::diagnostics` without a
/// direct dependency on the `os:none` `net` crate.
pub fn tcp_diag() -> crate::TcpDiag {
    let c = &tcp::diag::COUNTERS;
    crate::TcpDiag {
        syn_rx: c.syn_rx.get(),
        synack_tx: c.synack_tx.get(),
        rx_chunk_stash_hits: c.rx_chunk_stash_hits.get(),
        rx_chunk_ring_drain: c.rx_chunk_ring_drain.get(),
    }
}

/// Render the TCP stack's full observability block (`tcp::diag`) as
/// JSON into `w` — the `os:none` half of the `/obs` `"tcp"` block.
/// The native backend stubs this `{}` (`native::tcp_obs_json`), so
/// the app surfaces it through `waitless::diagnostics` without a
/// direct dependency on the `os:none` `net` crate.
pub fn tcp_obs_json(w: &mut dyn core::fmt::Write) {
    let _ = tcp::diag::write_obs_json(w);
}

// ---- Event loop re-exports ------------------------------------------------

pub use kernel_bare::eventloop::{request_shutdown, set_ready};
pub use kernel_bare::percpu::num_cores as num_workers;

/// Per-core event-loop stats snapshot. Tuple form so the cross-
/// boundary type is opaque (the bare struct lives in the kernel
/// crate, not exported across `backend`). Fields, in order:
///   * `loops`         — total event-loop iterations on this core
///   * `poll_work`     — iterations where the net-poll callback returned true
///   * `drain_work`    — iterations where the net-drain callback returned true
///   * `service_work`  — iterations where the app-service callback returned true
///   * `runtime_work`  — iterations where `executor::tick` polled a ready task
///     (the webserver's TCP/TLS/QUIC accept loops live here)
///   * `idle_enters`   — number of times the core actually slept (HLT/WFI)
///   * `busy_cycles`   — cumulative cycles spent in the loop body (non-idle)
///   * `idle_cycles`   — cumulative cycles spent inside HLT/WFI
///
/// Idle-percent on core `c` is then
/// `idle_cycles / (busy_cycles + idle_cycles)`. Caller computes
/// rates from two snapshots a known interval apart.
pub fn core_stats(core_id: u32) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    kernel_bare::eventloop::core_stats_snapshot(core_id)
}

/// TSC / virtual-counter rate. Companion to `core_stats` —
/// callers translate cycle deltas to wall-clock time via this
/// multiplier. Cheap on aarch64 (CNTFRQ_EL0 read) and cached on
/// x86_64 (PIT-calibrated TSC).
pub fn cycles_per_us() -> u64 {
    kernel_bare::time::cycles_per_us()
}


// ---- Heap stats -----------------------------------------------------------

pub fn heap_stats() -> super::HeapStats {
    let s = kernel_bare::mm::heap_stats();
    super::HeapStats {
        allocated_bytes: s.allocated_bytes,
        available_bytes: s.available_bytes,
        claimed_bytes: s.claimed_bytes,
        allocation_count: s.allocation_count,
        fragment_count: s.fragment_count,
        total_allocation_count: s.total_allocation_count,
    }
}

// ---- Diag-capture re-exports --------------------------------------------

/// Append a byte slice to the in-band diag-capture buffer. Used by
/// boot-time KATs / one-shot probes to log results that should
/// survive in `/diag-panic` even if the rest of the kernel later
/// halts.
pub fn diag_append(bytes: &[u8]) {
    kernel_bare::diag::append(bytes)
}

/// Append a hex-encoded u64 (no `0x` prefix) — pairs with
/// `diag_append` for boot-time format-free logging.
pub fn diag_append_hex(value: u64) {
    kernel_bare::diag::append_hex(value)
}

/// Append a 2-char hex-encoded u8 — for byte-window dumps where
/// `diag_append_hex` would render 14 leading zeros.
pub fn diag_append_hex_u8(value: u8) {
    kernel_bare::diag::append_hex_u8(value)
}

/// Snapshot the in-band diag-capture buffer (panics + unhandled
/// exceptions, cf. `kernel::diag`). Returns the byte count written.
pub fn diag_snapshot(out: &mut [u8]) -> usize {
    kernel_bare::diag::snapshot(out)
}

/// Bytes captured so far in the diag buffer. Cheap test for "is there
/// anything to read?".
pub fn diag_captured_len() -> usize {
    kernel_bare::diag::captured_len()
}

/// Reset the diag buffer to empty. Useful for repro loops that want
/// to capture a fresh trace per iteration.
pub fn diag_reset() {
    kernel_bare::diag::reset()
}

// ---- Wait for events ------------------------------------------------------

/// RAII guard that masks IRQs on construction and unmasks on drop.
/// Used to bracket the "check pending → idle" race window. Zero cost
/// on x86 where the idle uses `sti;hlt;cli` atomically.
#[must_use = "the guard unmasks IRQs when dropped; binding to _ unmasks immediately"]
struct IrqGuard {
    _no_send: core::marker::PhantomData<*mut ()>,
}

impl IrqGuard {
    #[inline]
    fn new() -> Self {
        kernel_bare::cpu::mask_irq();
        IrqGuard {
            _no_send: core::marker::PhantomData,
        }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        kernel_bare::cpu::unmask_irq();
    }
}

pub fn wait_for_events() {
    nic::flush_tx_staging();

    if nic::irq_idle_supported() {
        let _irq = IrqGuard::new();
        nic::arm_rx_interrupts();
        if !nic::has_pending_rx() && !nic::has_pending_tx() {
            kernel_bare::cpu::idle_bounded();
        }
        nic::flush_tx_staging();
    } else {
        kernel_bare::cpu::relax();
    }
}
