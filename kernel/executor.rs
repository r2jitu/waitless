// kernel/executor.rs — Bare-metal backend for the shared runtime.

fn current_worker() -> u32 {
    crate::cpu_id()
}

fn now_ticks() -> u64 {
    crate::time::now_cycles() / crate::time::cycles_per_us()
}

static RUNTIME: uni_percpu::Runtime = uni_percpu::Runtime {
    current_worker,
    now_ticks,
};

/// Register the bare-metal runtime. Call once, before `uni_main`.
pub fn init() {
    uni_percpu::register(&RUNTIME);
}

// ---- Re-exports for app + event-loop code ---------------------------------

pub use uni_executor::{has_pending, sleep_us, spawn, tick, Sleep};
