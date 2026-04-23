// uni-kernel/src/lib.rs — Bare-metal backend for the `uni` runtime.
//
// Sibling of `uni-native`: both fit behind `uni`'s `mod backend`
// dispatch. This crate owns the glue that maps `uni`'s
// cross-platform API (log, config_port, check_shutdown,
// wait_for_events) onto `kernel` + `drivers::net`.
//
// CPU primitives (idle, relax, mask/unmask IRQ) live in
// `kernel::cpu` — we just consume them here.

#![no_std]

use kernel::serial;

// ---- Lifecycle / config -----------------------------------------------------

pub fn log(msg: &[u8]) {
    serial::puts(msg)
}

pub fn config_port(default_port: u16) -> u16 {
    default_port
}

/// TLS port override stub. On the unikernel there are no env
/// variables, so the caller-supplied default is the only source
/// of truth; the real override lives in the native backend.
pub fn config_tls_port(default_port: u16) -> u16 {
    default_port
}

pub fn check_shutdown() -> bool {
    serial::check_shutdown()
}

// ---- Async runtime re-exports ----------------------------------------------
//
// Lets `uni::executor` dispatch to `kernel::executor` on the unikernel
// side without every app having to name `//kernel` directly.

pub mod executor {
    pub use kernel::executor::{sleep_us, spawn, Sleep};
}

// ---- Wait for events --------------------------------------------------------

/// RAII guard that masks IRQs on construction and unmasks on drop.
/// Used to bracket the "check pending → idle" race window in
/// `wait_for_events`. Can't forget to unmask. Zero cost: Drop inlines
/// to one `daifclr #0x2` (no-op on x86 where the idle uses
/// `sti;hlt;cli` atomically).
#[must_use = "the guard unmasks IRQs when dropped; binding to _ unmasks immediately"]
struct IrqGuard {
    _no_send: core::marker::PhantomData<*mut ()>,
}

impl IrqGuard {
    #[inline]
    fn new() -> Self {
        kernel::cpu::mask_irq();
        IrqGuard { _no_send: core::marker::PhantomData }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        kernel::cpu::unmask_irq();
    }
}

pub fn wait_for_events() {
    drivers::net::flush_tx_staging();

    if drivers::net::irq_idle_supported() {
        // RAII: mask on construction, unmask on Drop. Even if
        // `idle_bounded` panics, IRQs are guaranteed to be unmasked
        // by the guard's drop.
        let _irq = IrqGuard::new();
        drivers::net::arm_rx_interrupts();
        if !drivers::net::has_pending_rx() && !drivers::net::has_pending_tx() {
            kernel::cpu::idle_bounded();
        }
        drivers::net::flush_tx_staging();
        // _irq dropped here → unmask.
    } else {
        kernel::cpu::relax();
    }
}
