// drivers/net.rs — NIC dispatch through `uni_net_driver::active_ops()`.
//
// `init()` walks `linked_ethernet_drivers()`, calls the `probe` fn
// pointer on each registration, and installs the first success into
// the active-ops slot. Before that — and on native, where no section
// exists — `active_ops()` resolves to `NULL_OPS` (all no-ops), so
// every dispatcher below is a single load + direct call with no
// null branch.

use uni_net_driver::{active_ops, is_installed, linked_ethernet_drivers, set_active_ops};

// ---- Init / lifecycle -----------------------------------------------------

/// Installs the first driver whose `probe` succeeds.
pub fn init() -> bool {
    for reg in linked_ethernet_drivers() {
        if (reg.ops.probe)() {
            set_active_ops(reg.ops);
            return true;
        }
    }
    false
}

pub fn get_mac(mac_out: *mut u8) { (active_ops().get_mac)(mac_out) }
pub fn num_queue_pairs() -> u16 { (active_ops().num_queue_pairs)() }
pub fn driver_name() -> &'static str { active_ops().name }
pub fn enable_irq() { (active_ops().enable_irq)() }

// ---- RX / TX datapath -----------------------------------------------------

/// Drain every queue pair into `callback`, one owned [`IOBuf`] per
/// frame. Used by Tier 2 (single-queue distribute) and the pre-
/// `set_ready` boot window where APs aren't polling yet.
pub fn poll(callback: fn(uni_net_driver::IOBuf)) -> usize {
    (active_ops().poll_rx)(callback)
}

/// Per-queue variant for Tier 1 multi-queue, where each core only
/// polls its own RX queue pair.
pub fn poll_qp(qp: usize, callback: fn(uni_net_driver::IOBuf)) -> usize {
    (active_ops().poll_qp)(qp, callback)
}

pub fn send(data: &[u8]) { (active_ops().send)(data) }

/// Acquire a writable TX buffer from the driver's pool. Caller fills
/// the returned region in place, then [`submit_tx`]s it for
/// transmission. Returns `None` when the driver doesn't support
/// the direct-fill path (Tier 2 shared queue, GVE, native), or
/// when the pool is full — caller falls back to [`send`] (which
/// memcpys through the legacy slice path).
///
/// On `Some(handle)`:
///   * Caller writes the L2 frame into `handle.data_mut()[..len]`.
///   * Caller hands the handle to [`submit_tx`].
///   * Dropping the handle without submission returns the slot
///     to the pool (the caller's error path doesn't need to do
///     bookkeeping).
pub fn acquire_tx_buf() -> Option<uni_net_driver::TxBufHandle> {
    let f = active_ops().acquire_tx_buf?;
    f()
}

/// Submit a previously-acquired TX buffer with `frame_len` bytes of
/// frame data at the head of `handle.data_mut()`. Consumes the
/// handle.
pub fn submit_tx(handle: uni_net_driver::TxBufHandle, frame_len: usize) {
    if let Some(f) = active_ops().submit_tx {
        f(handle, frame_len);
    } else {
        // Only reachable via API misuse — `acquire_tx_buf` returns
        // `None` when the driver lacks the surface, so a caller that
        // does proper acquire+submit can never end up here. Drop the
        // handle (its `Drop` returns the slot to the pool).
        drop(handle);
    }
}

// ---- Idle / TX-flush knobs -----------------------------------------------

pub fn flush_tx_staging() { (active_ops().flush_tx_staging)() }
pub fn flush_tx_kick_if_dirty() -> bool { (active_ops().flush_tx_kick_if_dirty)() }
pub fn enable_deferred_tx_kick() { (active_ops().enable_deferred_tx_kick)() }
pub fn poke_interrupt_status() { (active_ops().poke_interrupt_status)() }

/// Presence of `idle` ops is the signal — NAPI-capable drivers
/// populate it, polling-only drivers leave it `None`.
pub fn irq_idle_supported() -> bool { active_ops().idle.is_some() }

pub fn arm_rx_interrupts() {
    if let Some(i) = active_ops().idle { (i.arm_rx_interrupts)(); }
}
pub fn has_pending_rx() -> bool {
    active_ops().idle.map(|i| (i.has_pending_rx)()).unwrap_or(false)
}
pub fn has_pending_tx() -> bool {
    active_ops().idle.map(|i| (i.has_pending_tx)()).unwrap_or(false)
}
pub fn rearm_rx_napi(core_id: u32) -> bool {
    active_ops().idle.map(|i| (i.rearm_rx_napi)(core_id)).unwrap_or(false)
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    active_ops().diag.map(|d| (d.rx_counts)()).unwrap_or([0; 8])
}
pub fn rx_used_cursors() -> [(u16, u16); 8] {
    active_ops().diag.map(|d| (d.rx_used_cursors)()).unwrap_or([(0, 0); 8])
}

/// Cold-path: used by `uni::Net::enable` to tell "no driver linked"
/// from "drivers linked but none bound hardware".
pub fn installed() -> bool { is_installed() }
