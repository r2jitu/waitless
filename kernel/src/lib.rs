// Kernel library. Arch-specific modules in `x86_64/` and `aarch64/`.
// The `#[global_allocator]` for the whole bare-metal build lives at
// `mm::GLOBAL_ALLOCATOR`.

#![no_std]

extern crate alloc;

pub mod cpu;
pub mod cpu_info;
pub mod deque;
pub mod diag;
pub mod eventloop;
pub mod mm;
pub mod mmio;
pub mod once;
pub mod percpu;
pub mod rng;
pub mod runtime;
pub mod rx_inbox;
pub mod serial;
pub mod spsc;
pub mod sync;
pub mod time;
pub mod timer;
pub mod types;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

/// Get current CPU ID (arch-independent).
pub fn cpu_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::smp::cpu_id()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::smp::cpu_id()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Number of secondary cores that have reported online so far.
/// Arch-independent. Increments monotonically as APs finish their
/// entry path; the counter starts at 1 (BSP) and tops out at
/// `percpu::num_cores()` once every AP has come up.
pub fn num_cores_online() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        x86_64::smp::num_cores_online()
    }
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::smp::num_cores_online()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        1
    }
}

/// Spin until every configured core has come up, with a wall-clock
/// deadline. Returns `true` if all cores are online before the
/// deadline, `false` on timeout. Useful for tests / apps that want
/// to do something explicitly multi-core (send IPIs to APs, observe
/// per-core counters) before they declare themselves ready —
/// normal-app boot doesn't need this because `eventloop::run`'s
/// per-AP `READY` spin already handles join.
pub fn wait_for_cores_online(timeout_us: u64) -> bool {
    let count = percpu::num_cores();
    if num_cores_online() >= count {
        return true;
    }
    let deadline = time::now_cycles().wrapping_add(timeout_us * time::cycles_per_us());
    while num_cores_online() < count {
        if time::now_cycles() >= deadline {
            return false;
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("yield", options(nomem, nostack));
        }
        #[cfg(target_arch = "x86_64")]
        core::hint::spin_loop();
    }
    true
}

/// Send IPI to a specific core (arch-independent).
/// Used for cold-path operations like shutdown. Hot-path signaling
/// uses wake_cores() / wake_core0() which are lighter weight.
pub fn send_ipi(target_core: u32) {
    #[cfg(target_arch = "aarch64")]
    {
        aarch64::smp::send_sgi_to(target_core);
    }
    #[cfg(target_arch = "x86_64")]
    {
        let topo = x86_64::acpi::topology();
        let apic_id = topo.apic_ids[target_core as usize] as u32;
        // SAFETY: send_ipi writes to the Local APIC ICR via MMIO at a
        // page that BSP init has mapped RW. The vector 0x40 is the
        // wake IPI bound to an idle handler (see x86_64::apic::init),
        // and the destination APIC ID came from the ACPI-parsed
        // topology, so it names a CPU that was present at boot.
        unsafe {
            x86_64::apic::send_ipi(apic_id, 0x40);
        }
    }
}

/// Lightweight wakeup: signal all sleeping cores that work is available.
/// On aarch64 SEV is cheap but some hypervisors (Apple's in particular)
/// don't reliably propagate it between vCPUs, so we always follow up with
/// an SGI to each AP. On x86_64 we broadcast IPIs directly.
#[inline]
pub fn wake_cores() {
    let n = percpu::num_cores();
    if n <= 1 {
        return;
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `sev` (Send Event) is a hint instruction with no
        // memory or register side effects; nomem + nostack is accurate.
        unsafe {
            core::arch::asm!("sev", options(nomem, nostack));
        }
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
        unsafe {
            core::arch::asm!("sev", options(nomem, nostack));
        }
        aarch64::smp::send_sgi_to(0);
    }
    #[cfg(target_arch = "x86_64")]
    send_ipi(0);
}
