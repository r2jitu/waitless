// uni-native/src/executor.rs — Native backend for `uni::executor`.
//
// Minimal single-threaded async runtime mirroring `kernel::executor`'s
// shape for the host POSIX build. Polled from worker 0's run loop;
// other workers skip the tick. Sleep futures resolve by wall-clock
// deadline and are re-polled at each loop iteration — `run_worker`'s
// 10 ms `wait_for_events` timeout bounds the wake latency, same role
// that the CNTV / TSC-spin idle plays on the unikernel.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

type BoxedFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct TaskSlot {
    /// Set by wakers, consulted (but not required) by `tick`. The
    /// native tick polls every live task regardless, because without
    /// a central timer wheel we have no better way to drive `Sleep`
    /// re-polls. See module doc for the trade-off.
    ready: AtomicBool,
    future: Mutex<Option<BoxedFuture>>,
}

impl Wake for TaskSlot {
    fn wake(self: Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
    }
}

static TASKS: Mutex<Vec<Arc<TaskSlot>>> = Mutex::new(Vec::new());

/// Spawn a future onto the native executor's task list.
pub fn spawn<F>(f: F) -> Result<(), ()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let slot = Arc::new(TaskSlot {
        ready: AtomicBool::new(true),
        future: Mutex::new(Some(Box::pin(f))),
    });
    TASKS.lock().unwrap().push(slot);
    Ok(())
}

/// Poll every live task, drop any that reported `Ready`. Runs from
/// worker 0; other workers no-op (native tasks aren't thread-pinned
/// but there's no reason to have every worker contending on the
/// task list for the handful of futures a smoke test spawns).
pub fn tick(worker_id: u32) -> bool {
    if worker_id != 0 {
        return false;
    }
    let snapshot: Vec<Arc<TaskSlot>> = {
        let guard = TASKS.lock().unwrap();
        guard.iter().cloned().collect()
    };
    let mut completed = false;
    for slot in snapshot.iter() {
        slot.ready.store(false, Ordering::Release);
        let waker = Waker::from(Arc::clone(slot));
        let mut cx = Context::from_waker(&waker);
        let mut guard = slot.future.lock().unwrap();
        if let Some(fut) = guard.as_mut() {
            match fut.as_mut().poll(&mut cx) {
                Poll::Pending => {}
                Poll::Ready(()) => {
                    *guard = None;
                    completed = true;
                }
            }
        }
    }
    if completed {
        TASKS
            .lock()
            .unwrap()
            .retain(|s| s.future.lock().unwrap().is_some());
    }
    completed
}

/// Future that resolves at a wall-clock deadline. Polled eagerly by
/// `tick`; resolves lazily when `Instant::now() >= deadline`.
pub struct Sleep {
    deadline: Instant,
}

pub fn sleep_us(us: u64) -> Sleep {
    Sleep {
        deadline: Instant::now() + Duration::from_micros(us),
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if Instant::now() >= self.deadline {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
