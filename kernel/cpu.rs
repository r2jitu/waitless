// kernel/cpu.rs — Cross-arch CPU primitives.
//
// Thin wrappers around single-instruction CPU ops that every caller
// in the bare-metal tree used to write inline. Centralising them
// here gives one audited source of truth for the handful of sites
// that idle a core, relax in a busy-wait, or bracket a pending-check
// with IRQ masking.
//
// Every function here is safe to call from any context — each one
// executes a single arch instruction on the current CPU and leaves
// no half-applied state behind. The inline asm is itself `unsafe`,
// but the safety scope is confined to "do this thing on this core",
// which is always sound.

// ---- CPU pause / yield ------------------------------------------------------

/// Scheduling hint — spin-wait relax. Cheap on both arches (PAUSE
/// on x86, YIELD on aarch64).
#[inline]
pub fn relax() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("yield", options(nomem, nostack));
    }
}

// ---- IRQ masking ------------------------------------------------------------

/// Mask interrupts on the current core.
///
/// On x86 the callers that would normally set `CLI` here use the
/// atomic `sti; hlt; cli` idle sequence instead (see `idle_bounded`),
/// so mask/unmask are no-ops. On aarch64 this sets `DAIF.I` — IRQ
/// only, FIQ left alone because Apple hypervisors reserve FIQ.
#[inline]
pub fn mask_irq() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifset, #0x2", options(nomem, nostack));
    }
    // x86: no-op — idle path uses sti;hlt;cli atomically.
}

/// Unmask interrupts on the current core. Paired with [`mask_irq`].
#[inline]
pub fn unmask_irq() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));
    }
    // x86: no-op — see `mask_irq`.
}

// ---- Idle ------------------------------------------------------------------

/// Put the core to sleep until an interrupt arrives, bounded so
/// callers without a guaranteed wake-up source don't block forever.
///
/// aarch64 paths:
///   * If the HVF runner advertised a cooperative-yield register via
///     the `hvf,yield` FDT node, a store there triggers a stage-2
///     fault and parks the vCPU thread at zero CPU cost until the
///     host IO thread has data. Lowest latency on Apple Silicon.
///   * Otherwise, program `cntv_tval_el0` for ~1 ms, `WFI`, then
///     disable the timer. Timer-bounded WFI wakes promptly for
///     networking even without a GIC, which matches QEMU-without-
///     GIC guests.
///
/// x86_64: `sti; hlt; cli` — the atomic idle pattern. HLT is
/// interruptible, no explicit timer needed.
#[inline]
pub fn idle_bounded() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // SAFETY: privileged but sound on the current CPU.
        core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let yield_addr = crate::aarch64::fdt::info().yield_mmio_base;
        if yield_addr != 0 {
            core::ptr::write_volatile(yield_addr as *mut u32, 0);
            return;
        }
        let freq: u64;
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq);
        // 1 ms timer (freq/1000). Wakes WFI promptly for networking.
        let tval = if freq / 1000 == 0 { 1u64 } else { freq / 1000 };
        core::arch::asm!("msr cntv_tval_el0, {}", in(reg) tval);
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 1u64); // ENABLE
        core::arch::asm!("isb", options(nomem, nostack));
        core::arch::asm!("wfi", options(nomem, nostack));
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 0u64); // DISABLE
        core::arch::asm!("isb", options(nomem, nostack));
    }
}

/// Unbounded idle — sleep until an interrupt wakes us. Callers that
/// don't care about a timed wake (e.g. waiting for `READY` before
/// the app starts) can use this directly; every real event-loop
/// idle should prefer [`idle_bounded`] so a lost IRQ can't hang the
/// core forever.
#[inline]
pub fn idle_unbounded() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack));
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
    }
}

/// Idle until the virtual timer fires `cycles` from now, or an IRQ
/// arrives — whichever comes first. Unlike [`idle_bounded`], this
/// *always* uses the CNTV timer even when an HVF yield register is
/// advertised, because the yield path only wakes on host-driven IO
/// and an async task waiting on a `Sleep` future has no such signal.
///
/// x86_64: no per-idle timer is wired up yet (no LAPIC oneshot
/// configured), so this busy-spins until `cycles` TSC ticks elapse.
/// Correct but not power-efficient — the proper fix is a one-shot
/// LAPIC timer + handler, tracked in the roadmap.
#[inline]
pub fn idle_until_cycles(cycles: u64) {
    #[cfg(target_arch = "x86_64")]
    {
        let deadline = crate::time::now_cycles().saturating_add(cycles);
        while crate::time::now_cycles() < deadline {
            unsafe {
                core::arch::asm!("pause", options(nomem, nostack));
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let tval = cycles.max(1);
        core::arch::asm!("msr cntv_tval_el0, {}", in(reg) tval);
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 1u64); // ENABLE
        core::arch::asm!("isb", options(nomem, nostack));
        core::arch::asm!("wfi", options(nomem, nostack));
        core::arch::asm!("msr cntv_ctl_el0, {}", in(reg) 0u64); // DISABLE
        core::arch::asm!("isb", options(nomem, nostack));
    }
}
