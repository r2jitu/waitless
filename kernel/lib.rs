// kernel/lib.rs — Unified kernel library crate.
//
// Platform-independent modules at the top level, arch-specific
// modules in x86_64/ and aarch64/ subdirectories.

#![no_std]
#![allow(static_mut_refs)]

pub mod types;
pub mod serial;
pub mod mm;
pub mod time;
pub mod bump;
pub mod deque;
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
/// aarch64: SEV (Send Event) — ~1 cycle, broadcasts to all cores.
/// x86_64: broadcast IPI (HLT requires an interrupt to wake).
#[inline]
pub fn wake_cores() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
    #[cfg(target_arch = "x86_64")]
    {
        // Send IPI to all APs. Still cheaper than per-core IPIs since
        // we only call this once per batch of distributed packets.
        let n = percpu::num_cores();
        for i in 1..n {
            send_ipi(i);
        }
    }
}

/// Lightweight wakeup: signal core 0 that TX staging is ready.
/// aarch64: SEV broadcasts to all cores (core 0 wakes from WFE/WFI).
/// x86_64: IPI to core 0 (HLT requires interrupt).
#[inline]
pub fn wake_core0() {
    #[cfg(target_arch = "aarch64")]
    unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
    #[cfg(target_arch = "x86_64")]
    send_ipi(0);
}
