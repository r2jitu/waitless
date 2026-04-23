// uni-native/src/executor.rs — Native (POSIX) backend for `uni-executor`.
//
// Same per-worker shape as bare-metal: each worker owns its own
// timer list, accessed through `uni_percpu::PerCpu` + `CurrentCore`.
// The `!Send + !Sync` token is all the synchronisation needed — no
// `Mutex` — because the list is touched only by its owning worker
// (insert from a running task's `Sleep::poll`, cancel from
// `Sleep::drop` on the same task, advance from `run_worker`).

use std::cell::UnsafeCell;
use std::time::Instant;

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

struct NativeTimer {
    deadline: u64,
    func: fn(usize),
    arg: usize,
}

/// Owning-worker-only `Vec<NativeTimer>`. The `CurrentCore` token
/// gates access; the `unsafe impl Sync` is the paperwork that tells
/// the compiler we've enforced the contract.
struct TimerList(UnsafeCell<Vec<NativeTimer>>);

// SAFETY: touched only by the worker whose id this slot holds,
// via `PerCpu::current(&CurrentCore)`.
unsafe impl Sync for TimerList {}
unsafe impl Send for TimerList {}

impl TimerList {
    const fn new() -> Self {
        TimerList(UnsafeCell::new(Vec::new()))
    }
}

static TIMERS: PerCpu<TimerList, MAX_WORKERS> =
    PerCpu::new([const { TimerList::new() }; MAX_WORKERS]);

fn timers_for(cc: &CurrentCore) -> &mut Vec<NativeTimer> {
    let cell = TIMERS.current(cc);
    // SAFETY: owning-worker-only; `CurrentCore` proves we're on it.
    unsafe { &mut *cell.0.get() }
}

fn advance(cc: &CurrentCore, now: u64) {
    let list = timers_for(cc);
    // Partition in-place: keep pending ahead, collect fired at the
    // tail. `split_off` at `keep` returns the fired portion.
    let mut keep = 0;
    let mut i = 0;
    while i < list.len() {
        if list[i].deadline <= now {
            i += 1;
        } else {
            list.swap(keep, i);
            keep += 1;
            i += 1;
        }
    }
    let fired = list.split_off(keep);
    for t in fired {
        (t.func)(t.arg);
    }
}

// ---- Event-loop integration ------------------------------------------------

/// Advance this worker's timer list, then poll its arena. Called
/// from `run_worker` once per iteration.
pub fn tick(worker_id: u32) -> bool {
    // SAFETY: `run_worker` only calls this on the running worker.
    let cc = unsafe { CurrentCore::from_id_unchecked(worker_id) };
    advance(&cc, now_us());
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
    timers_for(&cc).push(NativeTimer {
        deadline,
        func,
        arg,
    });
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_cancel_timer(arg: usize) -> bool {
    let cc = CurrentCore::enter();
    let list = timers_for(&cc);
    let before = list.len();
    list.retain(|t| t.arg != arg);
    list.len() != before
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
