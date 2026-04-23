// kernel/executor.rs — Bare-metal backend for the shared runtime.

fn current_worker() -> u32 {
    crate::cpu_id()
}

fn now_ticks() -> u64 {
    crate::time::now_cycles() / crate::time::cycles_per_us()
}

static RUNTIME: uni_runtime::Runtime = uni_runtime::Runtime { now_ticks };

/// Register the bare-metal runtime hooks. Call once, before `uni_main`.
pub fn init() {
    uni_percpu::register_current_worker(current_worker);
    uni_runtime::register(&RUNTIME);
}

// ---- Re-exports for app + event-loop code ---------------------------------

pub use uni_runtime::{has_pending, sleep_us, spawn, tick, Sleep};
