// kernel/executor.rs — Bare-metal backend for `uni-executor`.

#[inline]
fn rt_now_ticks() -> u64 {
    crate::time::now_cycles() / crate::time::cycles_per_us()
}

static RUNTIME: uni_executor::Runtime = uni_executor::Runtime {
    now_ticks: rt_now_ticks,
};

/// Register the bare-metal runtime. Call once, before `uni_main`.
pub fn init() {
    uni_executor::register(&RUNTIME);
}

// ---- Re-exports for app + event-loop code ---------------------------------

pub use uni_executor::{has_pending, sleep_us, spawn, tick, Sleep};
