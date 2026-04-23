// uni-native/src/executor.rs — Native (POSIX) backend for `uni-executor`.

use std::time::Instant;

fn start() -> Instant {
    static S: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *S.get_or_init(Instant::now)
}

fn rt_now_ticks() -> u64 {
    Instant::now().duration_since(start()).as_micros() as u64
}

static RUNTIME: uni_executor::Runtime = uni_executor::Runtime {
    now_ticks: rt_now_ticks,
};

/// Register the native runtime. Call once, before `uni_main`.
pub fn init() {
    uni_executor::register(&RUNTIME);
}

// ---- uni-percpu hook -------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_percpu_current_worker() -> u32 {
    super::current_thread_id()
}

// ---- Re-exports for app + worker-loop code --------------------------------

pub use uni_executor::{has_pending, sleep_us, spawn, tick, Sleep};
