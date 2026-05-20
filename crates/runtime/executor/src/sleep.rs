// uni-runtime/src/sleep.rs — Per-worker timer wheel + `Sleep` future.
//
// Owns the `WHEELS` static (one `TimerWheel` per worker) and the
// `Sleep` future that schedules into it. Task-arena code in
// `task.rs` calls the `pub(crate)` helpers here from `tick` / `has_pending`
// so it doesn't have to know about `WHEELS` directly.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

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
    waker: Option<Waker>,
}

impl Sleep {
    #[inline]
    pub const fn until(deadline: u64) -> Self {
        Sleep {
            deadline,
            timer_scheduled: false,
            waker: None,
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
            this.waker = None;
            return Poll::Ready(());
        }
        if !this.timer_scheduled {
            this.waker = Some(cx.waker().clone());
            let self_ptr: *const Sleep = this;
            let cc = CurrentWorker::enter();
            if WHEELS.with_mut(&cc, |w| {
                w.insert(Timer {
                    deadline: this.deadline,
                    func: sleep_fire,
                    arg: self_ptr as usize,
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
            let self_ptr: *const Sleep = self;
            let cc = CurrentWorker::enter();
            // O(MAX_PER_SLOT) via the deadline-keyed lookup —
            // significantly faster than the full-wheel scan when
            // many `timeout_us`-wrapped futures cancel-and-recreate
            // their inner Sleep on every iteration of a keep-alive
            // loop.
            let _ = WHEELS.with_mut(&cc, |w| w.cancel_at(self.deadline, self_ptr as usize));
        }
    }
}

fn sleep_fire(arg: usize) {
    let sleep = arg as *const Sleep;
    // SAFETY: `Sleep::drop` cancels the timer before the future is
    // freed.
    unsafe {
        if let Some(w) = (*sleep).waker.as_ref() {
            w.wake_by_ref();
        }
    }
}
