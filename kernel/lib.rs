// Kernel library. Arch-specific modules in `x86_64/` and `aarch64/`.
// The `#[global_allocator]` for the whole bare-metal build lives at
// `mm::GLOBAL_ALLOCATOR`.

#![no_std]

extern crate alloc;

pub mod types;
pub mod sync;
pub mod serial;
pub mod mm;
pub mod mmio;
pub mod time;
pub mod bump;
pub mod cpu;
pub mod deque;
pub mod once;
pub mod spsc;
pub mod timer;
pub mod percpu;
pub mod eventloop;
pub mod rng;

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
        // SAFETY: send_ipi writes to the Local APIC ICR via MMIO at a
        // page that BSP init has mapped RW. The vector 0x40 is the
        // wake IPI bound to an idle handler (see x86_64::apic::init),
        // and the destination APIC ID came from the ACPI-parsed
        // topology, so it names a CPU that was present at boot.
        unsafe { x86_64::apic::send_ipi(apic_id, 0x40); }
    }
}

/// Lightweight wakeup: signal all sleeping cores that work is available.
/// On aarch64 SEV is cheap but some hypervisors (Apple's in particular)
/// don't reliably propagate it between vCPUs, so we always follow up with
/// an SGI to each AP. On x86_64 we broadcast IPIs directly.
#[inline]
pub fn wake_cores() {
    let n = percpu::num_cores();
    if n <= 1 { return; }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `sev` (Send Event) is a hint instruction with no
        // memory or register side effects; nomem + nostack is accurate.
        unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
        // SGI fallback — needed when SEV doesn't propagate across vCPU threads.
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
        // SAFETY: see wake_cores — `sev` is a hint with no side effects.
        unsafe { core::arch::asm!("sev", options(nomem, nostack)); }
        aarch64::smp::send_sgi_to(0);
    }
    #[cfg(target_arch = "x86_64")]
    send_ipi(0);
}

