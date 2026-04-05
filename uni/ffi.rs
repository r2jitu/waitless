// uni/ffi.rs — Unikernel backend: lifecycle/config functions for Rust HTTP server
//
// Provides the same uni_* extern "C" symbols that http.rs calls.
// Replaces the C++ uni/ffi.cc — calls kernel/driver Rust functions directly.

#![no_std]
#![allow(static_mut_refs)]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

unsafe extern "C" {
    // kernel/serial.rs
    fn serial_puts(s: *const u8);
    fn serial_check_shutdown() -> bool;

    // drivers/drivers.rs
    fn driver_virtio_net_irq_idle_supported() -> bool;
    fn driver_virtio_net_arm_rx_interrupts();
    fn driver_virtio_net_has_pending_rx() -> bool;
}

// ---- Lifecycle / config -------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_log(msg: *const u8) {
    unsafe { serial_puts(msg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_config_port(default_port: u16) -> u16 {
    default_port
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_check_shutdown() -> bool {
    unsafe { serial_check_shutdown() }
}

// ---- Wait for events (arch-specific idle) -------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_wait_for_events() {
    unsafe {
        if driver_virtio_net_irq_idle_supported() {
            arch_mask_irq();
            driver_virtio_net_arm_rx_interrupts();
            if !driver_virtio_net_has_pending_rx() {
                arch_idle();
            }
            arch_unmask_irq();
        } else {
            arch_cpu_relax();
        }
    }
}

// ---- Architecture primitives (inline assembly) --------------------------------

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn arch_mask_irq() {
    // no-op on x86 — idle() uses sti;hlt;cli internally
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn arch_unmask_irq() {
    // no-op on x86
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn arch_idle() {
    // STI;HLT;CLI — atomic idle pattern on x86
    core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn arch_cpu_relax() {
    core::arch::asm!("pause", options(nomem, nostack));
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_mask_irq() {
    // Mask IRQ only (DAIF.I) — never touch FIQ, VZ uses it
    core::arch::asm!("msr daifset, #0x2", options(nomem, nostack));
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_unmask_irq() {
    core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_idle() {
    // Arm a one-shot ~100ms virtual timer so WFI wakes periodically
    // for serial input checking (Ctrl-C).
    let freq: u64;
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
    let tval = if freq / 10 == 0 { 1u64 } else { freq / 10 };
    core::arch::asm!("msr cntv_tval_el0, {}", in(reg) tval);
    core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 1u64); // ENABLE
    core::arch::asm!("isb", options(nomem, nostack));
    core::arch::asm!("wfi", options(nomem, nostack));
    core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 0u64); // DISABLE
    core::arch::asm!("isb", options(nomem, nostack));
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_cpu_relax() {
    core::arch::asm!("yield", options(nomem, nostack));
}
