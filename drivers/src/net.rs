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

pub fn poll(callback: fn(&[u8])) -> usize { (active_ops().poll_rx)(callback) }
pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> usize {
    (active_ops().poll_qp)(qp, callback)
}
pub fn send(data: &[u8]) { (active_ops().send)(data) }

// ---- Zero-copy RX (opt-in via NicOps::iobuf_rx) ---------------------------

/// `true` iff the active driver implements the IOBuf-RX path.
/// Callers branch on this to pick `poll_iobuf` over `poll`
/// (and the IOBuf-shaped Tier 2 inbox over the memcpy one).
pub fn iobuf_rx_supported() -> bool { active_ops().iobuf_rx.is_some() }

/// Zero-copy variant of `poll`. Each frame arrives at `callback`
/// as an owned [`uni_iobuf::IOBuf`] (typically `IOBuf::External`
/// pointing at the descriptor's storage). Returns 0 when the
/// active driver doesn't implement the path — callers should
/// gate on `iobuf_rx_supported()` first to avoid spinning.
pub fn poll_iobuf(callback: fn(uni_net_driver::IOBuf)) -> usize {
    match active_ops().iobuf_rx {
        Some(ops) => (ops.poll_rx)(callback),
        None => 0,
    }
}

/// Zero-copy per-queue variant of `poll_qp`.
pub fn poll_qp_iobuf(qp: usize, callback: fn(uni_net_driver::IOBuf)) -> usize {
    match active_ops().iobuf_rx {
        Some(ops) => (ops.poll_qp)(qp, callback),
        None => 0,
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
