// kernel/executor.rs — Bare-metal boot wiring for the shared runtime.
//
// `uni_platform::{current_worker, now_ticks}` are direct cfg-gated
// calls, not register-style hooks, so this module has almost nothing
// to do. The one piece of state that needs publishing is the
// PIT-calibrated TSC rate (x86_64 only) — uni-platform caches it
// separately so `now_ticks()` doesn't have to reach back into
// `//kernel`.

/// Publish any backend-side state `uni-platform` depends on. Called
/// once from `boot/src/entry.rs` before any `spawn` / `sleep_us`.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        uni_platform::set_x86_tsc_per_us(crate::time::cycles_per_us());
    }
}
