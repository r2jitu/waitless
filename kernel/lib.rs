// kernel/lib.rs — Unified kernel library crate.
//
// Platform-independent modules at the top level, arch-specific
// modules in x86_64/ and aarch64/ subdirectories.

#![no_std]
#![allow(static_mut_refs)]

pub mod types;
pub mod sync;
pub mod serial;
pub mod mm;
pub mod kbox;
pub mod mmio;
pub mod time;
pub mod bump;
pub mod deque;
pub mod once;
pub mod spsc;
pub mod timer;
pub mod percpu;
pub mod eventloop;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

/// Get current CPU ID (arch-independent).
pub fn cpu_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    { x86_64::smp::cpu_id() }
    #[cfg(target_arch = "aarch64")]
    { aarch64::smp::cpu_id() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Send IPI to a specific core (arch-independent).
/// Used for cold-path operations like shutdown. Hot-path signaling
/// uses wake_cores() / wake_core0() which are lighter weight.
pub fn send_ipi(target_core: u32) {
    #[cfg(target_arch = "aarch64")]
    { aarch64::smp::send_sgi_to(target_core); }
    #[cfg(target_arch = "x86_64")]
    {
        let topo = x86_64::acpi::topology();
        let apic_id = topo.apic_ids[target_core as usize] as u32;
        unsafe { x86_64::apic::send_ipi(apic_id, 0x40); }
    }
}

/// Lightweight wakeup: signal all sleeping cores that work is available.
/// Uses SEV (aarch64 QEMU) or IPI broadcast. On VZ, SEV may not
/// propagate between vCPUs, so we also send SGI as fallback.
#[inline]
pub fn wake_cores() {
    let n = percpu::num_cores();
    if n <= 1 { return; }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
        // Also send SGI — VZ may not propagate SEV between vCPU threads.
        for i in 1..n {
            aarch64::smp::send_sgi_to(i);
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        for i in 1..n {
            send_ipi(i);
        }
    }
}

/// Lightweight wakeup: signal core 0 that TX staging is ready.
#[inline]
pub fn wake_core0() {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
        aarch64::smp::send_sgi_to(0);
    }
    #[cfg(target_arch = "x86_64")]
    send_ipi(0);
}
