// uni-platform/src/lib.rs — Leaf crate for platform-primitive reads.
//
// Owns the two platform-dependent reads that every upper crate needs:
//
//   * `current_worker() -> u32` — the calling worker's id.
//   * `now_ticks() -> u64`      — monotonic µs since boot.
//
// Both are cfg-gated between bare-metal (inline asm, populated by the
// kernel's boot code) and native (std thread-local + Instant). The
// implementation lives here rather than going through a
// `register(&Runtime)` hook at a higher crate so `uni-worker` and
// `uni-runtime` can just call and inline, without the cross-crate
// plug-in dance.
//
// Boot-time contract: bare-metal callers must not invoke these
// before the kernel sets `TPIDR_EL1` / `GS_BASE` (for
// `current_worker`) and calls `set_x86_tsc_per_us` (for `now_ticks`
// on x86). Native callers must not invoke `current_worker` before
// their thread has called `set_current_worker`. Failing those
// ordering constraints returns garbage / zero respectively, not UB.

#![cfg_attr(target_os = "none", no_std)]

// ============================================================================
// current_worker
// ============================================================================

#[cfg(target_os = "none")]
#[inline(always)]
pub fn current_worker() -> u32 {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // TPIDR_EL1 points at this core's PerCore struct; the u32 at
        // offset 0 is the worker id. Kernel boot sets TPIDR_EL1 per
        // core before dispatching to user code.
        let id: u32;
        core::arch::asm!(
            "mrs {tmp}, tpidr_el1",
            "ldr {id:w}, [{tmp}]",
            tmp = out(reg) _,
            id = out(reg) id,
            options(nomem, nostack),
        );
        id
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // GS_BASE points at this core's PerCore struct; the u32 at
        // offset 0 is the worker id. Kernel boot sets GS_BASE per
        // core.
        let id: u32;
        core::arch::asm!(
            "mov {:e}, gs:[0]",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
        id
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    0
}

#[cfg(not(target_os = "none"))]
std::thread_local! {
    static WORKER_ID: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// Stash the calling thread's worker id. Native backends call this
/// from each worker thread at startup; subsequent `current_worker`
/// calls on that thread read the stashed value.
#[cfg(not(target_os = "none"))]
pub fn set_current_worker(id: u32) {
    WORKER_ID.with(|c| c.set(id));
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
pub fn current_worker() -> u32 {
    WORKER_ID.with(|c| c.get())
}

// ============================================================================
// now_ticks
// ============================================================================

#[cfg(target_os = "none")]
#[inline(always)]
fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    0
}

/// x86_64 TSC rate — published by kernel boot after PIT calibration.
/// aarch64 reads CNTFRQ_EL0 directly so this static is unused there.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static X86_TSC_PER_US: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Publish the calibrated TSC rate. Called once from the kernel's
/// PIT calibration path during boot.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn set_x86_tsc_per_us(v: u64) {
    X86_TSC_PER_US.store(v, core::sync::atomic::Ordering::Release);
}

#[cfg(target_os = "none")]
#[inline(always)]
fn cycles_per_us() -> u64 {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let freq: u64;
        core::arch::asm!(
            "mrs {0}, cntfrq_el0",
            out(reg) freq,
            options(nomem, nostack, preserves_flags),
        );
        (freq / 1_000_000).max(1)
    }
    #[cfg(target_arch = "x86_64")]
    {
        X86_TSC_PER_US
            .load(core::sync::atomic::Ordering::Relaxed)
            .max(1)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    1
}

#[cfg(target_os = "none")]
#[inline]
pub fn now_ticks() -> u64 {
    now_cycles() / cycles_per_us()
}

#[cfg(not(target_os = "none"))]
pub fn now_ticks() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    Instant::now().duration_since(*start).as_micros() as u64
}
