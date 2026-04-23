// uni-native/src/executor.rs — Native (POSIX) backend for `uni-executor`.
//
// Per-worker timer storage + the four `extern "C"` hooks the shared
// runtime expects. Each worker thread calls `tick(worker_id)` from
// `run_worker`; that advances this worker's timer list, fires any
// expired callbacks (which wake their tasks via `Sleep` → waker),
// then hands off to `uni_executor::tick` for the poll scan.
//
// Timer storage: one `Mutex<Vec<NativeTimer>>` per worker. The mutex
// is uncontended in the common path (owning worker only) — it's there
// to give the static the `Send + Sync` it needs to live at global
// scope.

use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use uni_executor::MAX_WORKERS;

// ---- Monotonic tick source -------------------------------------------------

fn start() -> Instant {
    static S: OnceLock<Instant> = OnceLock::new();
    *S.get_or_init(Instant::now)
}

fn now_us() -> u64 {
    Instant::now().duration_since(start()).as_micros() as u64
}

// ---- Per-worker timer storage ----------------------------------------------

struct NativeTimer {
    deadline: u64,
    func: extern "C" fn(usize),
    arg: usize,
}

struct TimerList(Mutex<Vec<NativeTimer>>);

impl TimerList {
    const fn new() -> Self {
        TimerList(Mutex::new(Vec::new()))
    }
}

static TIMERS: [TimerList; MAX_WORKERS] = [const { TimerList::new() }; MAX_WORKERS];

fn advance(worker_id: u32, now: u64) {
    let list = &TIMERS[worker_id as usize];
    // Collect expired timers under the lock, fire them after releasing
    // so a timer callback that re-schedules doesn't deadlock.
    let fired: Vec<NativeTimer> = {
        let mut guard = list.0.lock().unwrap();
        let mut i = 0;
        let mut out = Vec::new();
        while i < guard.len() {
            if guard[i].deadline <= now {
                out.push(guard.remove(i));
            } else {
                i += 1;
            }
        }
        out
    };
    for t in fired {
        (t.func)(t.arg);
    }
}

// ---- Event-loop integration ------------------------------------------------

/// Advance this worker's timer list, then poll its arena. Called from
/// `run_worker` once per iteration.
pub fn tick(worker_id: u32) -> bool {
    advance(worker_id, now_us());
    uni_executor::tick(worker_id)
}

// ---- Backend hooks ---------------------------------------------------------
//
// Linked against the `extern "C"` declarations in
// `//uni-executor/src/lib.rs`.

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_current_worker() -> u32 {
    super::current_thread_id()
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_now_ticks() -> u64 {
    now_us()
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_schedule_timer(
    deadline: u64,
    func: extern "C" fn(usize),
    arg: usize,
) -> bool {
    let wid = super::current_thread_id() as usize;
    if wid >= MAX_WORKERS {
        return false;
    }
    TIMERS[wid].0.lock().unwrap().push(NativeTimer {
        deadline,
        func,
        arg,
    });
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn uni_exec_cancel_timer(arg: usize) -> bool {
    let wid = super::current_thread_id() as usize;
    if wid >= MAX_WORKERS {
        return false;
    }
    let mut guard = TIMERS[wid].0.lock().unwrap();
    let before = guard.len();
    guard.retain(|t| t.arg != arg);
    guard.len() != before
}

// ---- Re-exports for app code ----------------------------------------------

pub use uni_executor::{sleep_us, spawn, Sleep};
