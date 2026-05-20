// kernel/executor.rs — Bare-metal boot wiring for the shared runtime.
//
// `platform::{current_worker, now_ticks}` are direct cfg-gated
// calls, not register-style hooks, so this module has almost nothing
// to do. The one piece of state that needs publishing is the
// PIT-calibrated TSC rate (x86_64 only) — platform caches it
// separately so `now_ticks()` doesn't have to reach back into
// `//crates/kernel/bare`.

/// Publish any backend-side state `platform` depends on. Called
/// once from `boot/src/entry.rs` before any `spawn` / `sleep_us`.
pub fn init() {
    #[cfg(target_arch = "x86_64")]
    {
        platform::set_x86_tsc_per_us(crate::time::cycles_per_us());
    }
    // Cross-worker arena wakes need an IPI to bring the target out
    // of HLT/WFI when it's idle. Without this, Tier 2 (single NIC
    // RX queue, multi-core) deadlocks on workloads where one core
    // delivers a UDP/TCP packet that wakes a task on a different
    // core — the bit gets set on the target's arena but the target
    // sleeps until its next NIC IRQ.
    platform::set_wake_fn(crate::send_ipi);
}
