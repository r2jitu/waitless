// backend-native/src/executor.rs — Native (POSIX) backend for the shared runtime.

use std::time::Instant;

fn start() -> Instant {
    static S: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *S.get_or_init(Instant::now)
}

fn current_worker() -> u32 {
    super::current_thread_id()
}

fn now_ticks() -> u64 {
    Instant::now().duration_since(start()).as_micros() as u64
}

static RUNTIME: uni_percpu::Runtime = uni_percpu::Runtime {
    current_worker,
    now_ticks,
};

/// Register the native runtime. Call once, before `uni_main`.
pub fn init() {
    uni_percpu::register(&RUNTIME);
}

// ---- Re-exports for app + worker-loop code --------------------------------

pub use uni_executor::{has_pending, sleep_us, spawn, tick, Sleep};
