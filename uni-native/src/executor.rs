// uni-native/src/executor.rs — Native (POSIX) backend for `uni-executor`.

use std::cell::UnsafeCell;
use std::time::Instant;

use uni_percpu::timer::{Timer, TimerWheel};
use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

// ---- Monotonic tick source -------------------------------------------------

fn start() -> Instant {
    static S: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *S.get_or_init(Instant::now)
}

fn now_us() -> u64 {
    Instant::now().duration_since(start()).as_micros() as u64
}

// ---- Per-worker wheel storage ----------------------------------------------

struct WheelCell(UnsafeCell<TimerWheel>);

// SAFETY: touched only by its owning worker via
// `PerCpu::current(&CurrentCore)`.
unsafe impl Sync for WheelCell {}
unsafe impl Send for WheelCell {}

static WHEELS: PerCpu<WheelCell, MAX_WORKERS> = PerCpu::new(
    [const { WheelCell(UnsafeCell::new(TimerWheel::new())) }; MAX_WORKERS],
);

fn wheel(cc: &CurrentCore) -> &mut TimerWheel {
    let cell = WHEELS.current(cc);
    // SAFETY: owning-worker-only; `CurrentCore` proves we're on it.
    unsafe { &mut *cell.0.get() }
}

// ---- uni_executor::Runtime plug-in -----------------------------------------

fn rt_now_ticks() -> u64 {
    now_us()
}

fn rt_schedule_timer(deadline: u64, func: fn(usize), arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).insert(Timer { deadline, func, arg })
}

fn rt_cancel_timer(arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).cancel(arg)
}

static RUNTIME: uni_executor::Runtime = uni_executor::Runtime {
    now_ticks: rt_now_ticks,
    schedule_timer: rt_schedule_timer,
    cancel_timer: rt_cancel_timer,
};

/// Register the native runtime. Call once, before `uni_main`.
pub fn init() {
    uni_executor::register(&RUNTIME);
}

// ---- Event-loop integration ------------------------------------------------

pub fn tick(worker_id: u32) -> bool {
    // SAFETY: `run_worker` only calls this on the running worker.
    let cc = unsafe { CurrentCore::from_id_unchecked(worker_id) };
    let _ = wheel(&cc).advance(now_us());
    uni_executor::tick(worker_id)
}

// ---- uni-percpu hook -------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_percpu_current_worker() -> u32 {
    super::current_thread_id()
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
