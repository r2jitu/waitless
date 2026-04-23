// kernel/executor.rs — Bare-metal backend for the shared runtime.
//
// `init()` used to register a `current_worker` / `now_ticks` hook
// pair with uni-percpu / uni-runtime. Those are now direct inline-asm
// reads in `uni-platform`, so the only remaining bring-up is
// publishing the calibrated x86 TSC rate — aarch64 reads CNTFRQ_EL0
// directly and needs nothing.

/// Publish any backend-side state `uni-platform` depends on. Safe
/// (and required) to call even before any async work is spawned.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        // `cycles_per_us` internally triggers PIT calibration on
        // first call, then caches; mirror the result into
        // uni-platform's own static so `uni_platform::now_ticks()`
        // doesn't have to reach back into `//kernel`.
        uni_platform::set_x86_tsc_per_us(crate::time::cycles_per_us());
    }
}

// ---- Re-exports for app + event-loop code ---------------------------------

pub use uni_runtime::{has_pending, sleep_us, spawn, tick, Sleep};
