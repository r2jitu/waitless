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
pub fn send_ipi(target_core: u32) {
    #[cfg(target_arch = "aarch64")]
    { aarch64::smp::send_sgi_to(target_core); }
    #[cfg(target_arch = "x86_64")]
    {
        // x86: send fixed IPI vector 0x40 to target APIC ID
        let topo = x86_64::acpi::topology();
        let apic_id = topo.apic_ids[target_core as usize] as u32;
        unsafe { x86_64::apic::send_ipi(apic_id, 0x40); }
    }
}
