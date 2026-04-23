// drivers/net.rs — NIC dispatch through `uni_net_driver::active_ops()`.
//
// `init()` walks `linked_ethernet_drivers()`, calls the `probe` fn
// pointer on each registration, and installs the first success into
// the active-ops slot. Every other entry point reads the slot and
// dispatches through the `NicOps` fn pointers. No driver linked →
// `linked_ethernet_drivers()` is empty, `init()` returns `false`,
// every other dispatcher entry is a no-op.
//
// Cost per dispatcher call: one Acquire load + one direct fn-pointer
// call.

use uni_net_driver::{active_ops, linked_ethernet_drivers, set_active_ops};

// ---- Init / lifecycle -----------------------------------------------------

/// Installs the first driver whose `probe` succeeds. Returns `false`
/// if no linked driver binds hardware.
pub fn init() -> bool {
    for reg in linked_ethernet_drivers() {
        if (reg.ops.probe)() {
            set_active_ops(reg.ops);
            return true;
        }
    }
    false
}

pub fn get_mac(mac_out: *mut u8) {
    if let Some(o) = active_ops() {
        (o.get_mac)(mac_out);
    }
}

pub fn num_queue_pairs() -> u16 {
    active_ops().map(|o| (o.num_queue_pairs)()).unwrap_or(1)
}

/// Short identifier of the active driver. Used by `uni::boot_info()`
/// and diagnostic endpoints.
pub fn driver_name() -> &'static str {
    active_ops().map(|o| o.name).unwrap_or("none")
}

pub fn activate_multi_queue() {
    if let Some(o) = active_ops() {
        (o.activate_multi_queue)();
    }
}

pub fn enable_irq() {
    if let Some(o) = active_ops() {
        (o.enable_irq)();
    }
}

// ---- RX / TX datapath -----------------------------------------------------

pub fn poll(callback: fn(&[u8])) -> i32 {
    active_ops().map(|o| (o.poll_rx)(callback)).unwrap_or(0)
}

pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    active_ops().map(|o| (o.poll_qp)(qp, callback)).unwrap_or(0)
}

pub fn send(data: &[u8]) {
    if let Some(o) = active_ops() {
        (o.send)(data);
    }
}

// ---- Idle / TX-flush knobs -----------------------------------------------

pub fn flush_tx_staging() {
    if let Some(o) = active_ops() {
        (o.flush_tx_staging)();
    }
}

pub fn flush_tx_kick_if_dirty() -> bool {
    active_ops().map(|o| (o.flush_tx_kick_if_dirty)()).unwrap_or(false)
}

/// Presence of `idle` ops is the signal — NAPI-capable drivers
/// populate it, polling-only drivers leave it `None`.
pub fn irq_idle_supported() -> bool {
    active_ops().and_then(|o| o.idle).is_some()
}

pub fn arm_rx_interrupts() {
    if let Some(i) = active_ops().and_then(|o| o.idle) {
        (i.arm_rx_interrupts)();
    }
}

pub fn has_pending_rx() -> bool {
    active_ops()
        .and_then(|o| o.idle)
        .map(|i| (i.has_pending_rx)())
        .unwrap_or(false)
}

pub fn has_pending_tx() -> bool {
    active_ops()
        .and_then(|o| o.idle)
        .map(|i| (i.has_pending_tx)())
        .unwrap_or(false)
}

pub fn rearm_rx_napi(core_id: u32) -> bool {
    active_ops()
        .and_then(|o| o.idle)
        .map(|i| (i.rearm_rx_napi)(core_id))
        .unwrap_or(false)
}

pub fn enable_deferred_tx_kick() {
    if let Some(o) = active_ops() {
        (o.enable_deferred_tx_kick)();
    }
}

pub fn poke_interrupt_status() {
    if let Some(o) = active_ops() {
        (o.poke_interrupt_status)();
    }
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    active_ops()
        .and_then(|o| o.diag)
        .map(|d| (d.rx_counts)())
        .unwrap_or([0; 8])
}

pub fn rx_used_cursors() -> [(u16, u16); 8] {
    active_ops()
        .and_then(|o| o.diag)
        .map(|d| (d.rx_used_cursors)())
        .unwrap_or([(0, 0); 8])
}
