// crates/runtime/executor/src/sleep.rs — Per-worker timer wheel + `Sleep` future.
//
// Owns the `WHEELS` static (one `TimerWheel` per worker) and the
// `Sleep` future that schedules into it. Task-arena code in
// `task.rs` calls the `pub(crate)` helpers here from `tick` / `has_pending`
// so it doesn't have to know about `WHEELS` directly.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use platform::now_ticks;
use worker::timer::{Timer, TimerWheel};
use worker::{CurrentWorker, WorkerLocal};

// ---- Per-worker timer storage ----------------------------------------------

static WHEELS: WorkerLocal<TimerWheel> = WorkerLocal::new();

/// Size `WHEELS` for `n` workers. Called once at boot from `crate::init`.
pub(crate) fn init(n: u32) {
    WHEELS.init(n, |_| TimerWheel::new());
}

/// Fire every timer whose deadline has passed for this worker.
/// Called from `task::tick` once per event-loop iteration.
pub(crate) fn advance_timers(cc: &CurrentWorker) {
    let _ = WHEELS.with_mut(cc, |w| w.advance(now_ticks()));
}

/// True if this worker has any timers still scheduled.
pub(crate) fn has_timers(cc: &CurrentWorker) -> bool {
    WHEELS.with(cc, |w| w.count()) > 0
}

// ---- Sleep future ----------------------------------------------------------

pub struct Sleep {
    deadline: u64,
    timer_scheduled: bool,
    /// Integer-packed `(worker, slot)` id of the polling task's waker
    /// (see `task::make_waker_for`). Stored — instead of a raw
    /// `*const Sleep` — so the timer wakes the task WITHOUT
    /// dereferencing this future; a timer that outlives the future
    /// (cancel-on-drop missed under churn) then only sets a harmless
    /// ready bit. Also the cancel key (with `deadline`). 0 until polled.
    waker_packed: usize,
}

impl Sleep {
    #[inline]
    pub const fn until(deadline: u64) -> Self {
        Sleep {
            deadline,
            timer_scheduled: false,
            waker_packed: 0,
        }
    }
}

/// Sleep for `us` microseconds from now.
#[inline]
pub fn sleep_us(us: u64) -> Sleep {
    Sleep::until(now_ticks().saturating_add(us))
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if now_ticks() >= this.deadline {
            return Poll::Ready(());
        }
        if !this.timer_scheduled {
            // The packed task-waker id — an integer bit-pattern, never a
            // real pointer (see `task::make_waker_for`). The timer wakes
            // the task by this id, so it never dereferences this future.
            let packed = cx.waker().data() as usize;
            this.waker_packed = packed;
            let cc = CurrentWorker::enter();
            if WHEELS.with_mut(&cc, |w| {
                w.insert(Timer {
                    deadline: this.deadline,
                    func: sleep_fire,
                    arg: packed,
                })
            }) {
                this.timer_scheduled = true;
            }
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if self.timer_scheduled {
            let cc = CurrentWorker::enter();
            // Cancel by (deadline, packed-id). O(MAX_PER_SLOT) deadline-
            // keyed lookup. If churn ever leaves a stale timer behind,
            // `sleep_fire` only sets a harmless ready bit — it never
            // dereferences this (freed) future, so a missed cancel is
            // no longer a use-after-free.
            let _ = WHEELS.with_mut(&cc, |w| w.cancel_at(self.deadline, self.waker_packed));
        }
    }
}

fn sleep_fire(arg: usize) {
    // `arg` is the packed task-waker id. Wake the task by id — NO
    // dereference of the (possibly-already-freed) `Sleep` future. A
    // stale id is rejected by `waker_wake_by_ref`'s bounds + the
    // arena's generation check.
    crate::task::wake_by_packed(arg);
}
