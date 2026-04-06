// uni/unikernel.rs — Unikernel backend: lifecycle/config functions

use kernel::serial;

// ---- Lifecycle / config -------------------------------------------------------

pub fn log(msg: &[u8]) {
    serial::puts(msg)
}

pub fn config_port(default_port: u16) -> u16 {
    default_port
}

pub fn check_shutdown() -> bool {
    serial::check_shutdown()
}

// ---- Wait for events (arch-specific idle) -------------------------------------

pub fn wait_for_events() {
    if drivers::virtio_net::irq_idle_supported() {
        unsafe { arch_mask_irq() };
        drivers::virtio_net::arm_rx_interrupts();
        if !drivers::virtio_net::has_pending_rx() {
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
    unsafe {
        // STI;HLT;CLI — atomic idle pattern on x86
        core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn arch_cpu_relax() {
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_mask_irq() {
    unsafe {
        // Mask IRQ only (DAIF.I) — never touch FIQ, VZ uses it
        core::arch::asm!("msr daifset, #0x2", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_unmask_irq() {
    unsafe {
        core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_idle() {
    unsafe {
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
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn arch_cpu_relax() {
    unsafe {
        core::arch::asm!("yield", options(nomem, nostack));
    }
}
