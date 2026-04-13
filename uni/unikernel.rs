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

/// RAII guard that masks IRQs on construction and unmasks on drop.
/// Used to bracket the "check pending → idle" race window in
/// `wait_for_events`. Can't forget to unmask. Zero cost: Drop inlines
/// to one `daifclr #0x2` (or nothing on x86 where mask/unmask are
/// no-ops because the idle path uses `sti;hlt;cli` atomically).
#[must_use = "the guard unmasks IRQs when dropped; binding to _ unmasks immediately"]
struct IrqGuard {
    _no_send: core::marker::PhantomData<*mut ()>,
}

impl IrqGuard {
    #[inline]
    fn new() -> Self {
        arch_mask_irq();
        IrqGuard { _no_send: core::marker::PhantomData }
    }
}

impl Drop for IrqGuard {
    #[inline]
    fn drop(&mut self) {
        arch_unmask_irq();
    }
}

pub fn wait_for_events() {
    drivers::virtio_net::flush_tx_staging();

    if drivers::virtio_net::irq_idle_supported() {
        // RAII: mask on construction, unmask on Drop. Even if `arch_idle`
        // is added later that may early-return or panic, IRQs are
        // guaranteed to be unmasked by the guard's drop.
        let _irq = IrqGuard::new();
        drivers::virtio_net::arm_rx_interrupts();
        if !drivers::virtio_net::has_pending_rx() && !drivers::virtio_net::has_pending_tx() {
            arch_idle();
        }
        drivers::virtio_net::flush_tx_staging();
        // _irq dropped here → unmask.
    } else {
        arch_cpu_relax();
    }
}

// ---- Architecture primitives ------------------------------------------------
//
// These are all safe to call from any context — they only affect the current
// core and have no caller-supplied invariants. The asm! invocations are
// genuinely unsafe (since the macro is `unsafe`) but the safety scope is
// confined to "execute this instruction on the current CPU", which is always
// sound. The functions therefore expose a safe API.

#[cfg(target_arch = "x86_64")]
#[inline]
fn arch_mask_irq() {
    // no-op on x86 — idle() uses sti;hlt;cli atomically.
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn arch_unmask_irq() {
    // no-op on x86 — see arch_mask_irq.
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn arch_idle() {
    // STI;HLT;CLI — atomic idle pattern on x86. SAFETY: privileged but
    // sound on the current CPU.
    unsafe {
        core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn arch_cpu_relax() {
    // SAFETY: PAUSE is a hint, always sound.
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn arch_mask_irq() {
    // Mask IRQ only (DAIF.I) — leave FIQ alone, Apple hypervisors reserve it.
    // SAFETY: affects the current CPU's PSTATE only.
    unsafe {
        core::arch::asm!("msr daifset, #0x2", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn arch_unmask_irq() {
    // SAFETY: affects the current CPU's PSTATE only.
    unsafe {
        core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn arch_idle() {
    // If the HVF runner advertised a yield register, write to it instead
    // of WFI. The write causes a stage-2 fault; the runner parks this
    // vCPU thread at zero CPU cost until the IO thread has data.
    let yield_addr = kernel::aarch64::fdt::info().yield_mmio_base;
    if yield_addr != 0 {
        unsafe { core::ptr::write_volatile(yield_addr as *mut u32, 0); }
        return;
    }

    // Fallback: vtimer + WFI (QEMU and other hypervisors without the
    // hvf-yield register).
    unsafe {
        let freq: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
        // 1ms timer (freq/1000). Wakes WFI promptly for networking.
        let tval = if freq / 1000 == 0 { 1u64 } else { freq / 1000 };
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
fn arch_cpu_relax() {
    // SAFETY: YIELD is a hint, always sound.
    unsafe {
        core::arch::asm!("yield", options(nomem, nostack));
    }
}
