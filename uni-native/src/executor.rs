// uni-native/src/executor.rs — Native (POSIX) backend for `uni-executor`.
//
// Same per-worker shape as bare-metal: each worker owns its own
// timer wheel, accessed through `uni_percpu::PerCpu` + `CurrentCore`.
// The `!Send + !Sync` token is all the synchronisation needed — no
// `Mutex` — because the wheel is touched only by its owning worker
// (insert from a running task's `Sleep::poll`, cancel from
// `Sleep::drop` on the same task, advance from `run_worker`).

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

// ---- Per-worker timer storage ----------------------------------------------

/// Owning-worker-only `TimerWheel`. The `CurrentCore` token gates
/// access; the `unsafe impl Sync` is the paperwork that tells the
/// compiler we've enforced the contract.
struct WheelCell(UnsafeCell<TimerWheel>);

// SAFETY: touched only by the worker whose id this slot holds,
// via `PerCpu::current(&CurrentCore)`.
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

// ---- Event-loop integration ------------------------------------------------

/// Advance this worker's wheel, then poll its arena. Called from
/// `run_worker` once per iteration.
pub fn tick(worker_id: u32) -> bool {
    // SAFETY: `run_worker` only calls this on the running worker.
    let cc = unsafe { CurrentCore::from_id_unchecked(worker_id) };
    let _ = wheel(&cc).advance(now_us());
    uni_executor::tick(worker_id)
}

// ---- Backend hooks ---------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn uni_percpu_current_worker() -> u32 {
    super::current_thread_id()
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_now_ticks() -> u64 {
    now_us()
}

// `func: fn(usize)` is Rust ABI; on every target we support it
// lowers to the same register as a C-ABI fn pointer. The lint is
// about portability we don't need.
#[allow(improper_ctypes_definitions)]
#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_schedule_timer(
    deadline: u64,
    func: fn(usize),
    arg: usize,
) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).insert(Timer {
        deadline,
        func,
        arg,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_cancel_timer(arg: usize) -> bool {
    let cc = CurrentCore::enter();
    wheel(&cc).cancel(arg)
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
