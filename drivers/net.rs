// drivers/net.rs — NIC dispatch through `uni_net_driver::active_driver()`.
//
// `init()` walks `linked_ethernet_drivers()`, calls `probe()` on each,
// and installs the first success into the active-driver slot. Every
// other entry point reads the slot and trait-dispatches. No driver
// linked → `linked_ethernet_drivers()` is empty, `init()` returns
// `false`, every other dispatcher entry is a no-op.
//
// Cost per dispatcher call: one atomic load + one vtable call.

use uni_net_driver::{active_driver, linked_ethernet_drivers, set_active_driver, NicHandle};

/// Canonical NicHandle passed to every trait call. Each driver today
/// has a single device, so the handle's payload (empty) is unused.
/// Using a `static` so we can pass `&'static NicHandle` to every
/// trait method that takes `&NicHandle` without constructing a fresh
/// temporary each call.
static HANDLE: NicHandle = NicHandle::new();

// ---- Init / lifecycle -----------------------------------------------------

/// Walk the linker-section-registered driver table, try each driver's
/// `probe()`, install the first success as active. Returns `true` if
/// any driver came up. Called from `boot/entry.rs` before `uni_main`.
pub fn init() -> bool {
    for reg in linked_ethernet_drivers() {
        if reg.driver.probe().is_some() {
            set_active_driver(reg);
            return true;
        }
    }
    false
}

pub fn get_mac(mac_out: *mut u8) {
    if let Some(d) = active_driver() {
        d.get_mac(&HANDLE, mac_out);
    }
}

pub fn num_queue_pairs() -> u16 {
    active_driver().map(|d| d.num_queue_pairs(&HANDLE)).unwrap_or(1)
}

/// Short identifier of the active driver. Used by `uni::boot_info()`
/// to label the NIC entry and by diagnostic endpoints.
pub fn driver_name() -> &'static str {
    active_driver().map(|d| d.name()).unwrap_or("none")
}

pub fn activate_multi_queue() {
    if let Some(d) = active_driver() {
        d.activate_multi_queue(&HANDLE);
    }
}

pub fn enable_irq() {
    if let Some(d) = active_driver() {
        d.enable_irq(&HANDLE);
    }
}

// ---- RX / TX datapath -----------------------------------------------------

pub fn poll(callback: fn(&[u8])) -> i32 {
    active_driver().map(|d| d.poll_rx(&HANDLE, callback) as i32).unwrap_or(0)
}

pub fn poll_qp(qp: usize, callback: fn(&[u8])) -> i32 {
    active_driver().map(|d| d.poll_qp(&HANDLE, qp, callback)).unwrap_or(0)
}

pub fn send(data: &[u8]) {
    if let Some(d) = active_driver() {
        let _ = d.send(&HANDLE, data);
    }
}

// ---- Idle / TX-flush knobs -----------------------------------------------

pub fn flush_tx_staging() {
    if let Some(d) = active_driver() {
        d.flush_tx_staging(&HANDLE);
    }
}

pub fn flush_tx_kick_if_dirty() -> bool {
    active_driver().map(|d| d.flush_tx_kick_if_dirty(&HANDLE)).unwrap_or(false)
}

pub fn irq_idle_supported() -> bool {
    active_driver().map(|d| d.irq_idle_supported(&HANDLE)).unwrap_or(false)
}

pub fn arm_rx_interrupts() {
    if let Some(d) = active_driver() {
        d.arm_rx_interrupts(&HANDLE);
    }
}

pub fn has_pending_rx() -> bool {
    active_driver().map(|d| d.has_pending_rx(&HANDLE)).unwrap_or(false)
}

pub fn has_pending_tx() -> bool {
    active_driver().map(|d| d.has_pending_tx(&HANDLE)).unwrap_or(false)
}

pub fn rearm_rx_napi(core_id: u32) -> bool {
    active_driver().map(|d| d.rearm_rx_napi(&HANDLE, core_id)).unwrap_or(false)
}

pub fn enable_deferred_tx_kick() {
    if let Some(d) = active_driver() {
        d.enable_deferred_tx_kick(&HANDLE);
    }
}

pub fn poke_interrupt_status() {
    if let Some(d) = active_driver() {
        d.poke_interrupt_status(&HANDLE);
    }
}

// ---- Diagnostics (/stats) ------------------------------------------------

pub fn rx_counts() -> [u64; 8] {
    active_driver().map(|d| d.rx_counts(&HANDLE)).unwrap_or([0; 8])
}

pub fn rx_used_cursors() -> [(u16, u16); 8] {
    active_driver().map(|d| d.rx_used_cursors(&HANDLE)).unwrap_or([(0, 0); 8])
}
