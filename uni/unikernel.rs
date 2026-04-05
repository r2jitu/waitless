// uni/unikernel.rs — Unikernel backend: lifecycle/config functions
//
// Called directly from uni/api.rs via Rust crate deps.

#![no_std]
#![allow(static_mut_refs)]
#![allow(unsafe_op_in_unsafe_fn)]

extern crate kernel_serial;
extern crate drivers;

// ---- Lifecycle / config -------------------------------------------------------

pub fn log(msg: &[u8]) {
    unsafe { kernel_serial::serial_puts(msg.as_ptr()) }
}

pub fn config_port(default_port: u16) -> u16 {
    default_port
}

pub fn check_shutdown() -> bool {
    unsafe { kernel_serial::serial_check_shutdown() }
}

// ---- Wait for events (arch-specific idle) -------------------------------------

pub fn wait_for_events() {
    if drivers::driver_virtio_net_irq_idle_supported() {
        unsafe { arch_mask_irq() };
        drivers::driver_virtio_net_arm_rx_interrupts();
        if !drivers::driver_virtio_net_has_pending_rx() {
            unsafe { arch_idle() };
        }
        unsafe { arch_unmask_irq() };
    } else {
        unsafe { arch_cpu_relax() };
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
