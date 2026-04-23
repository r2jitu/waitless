// uni-runtime/src/lib.rs — Shared async runtime.

#![no_std]

extern crate alloc;

pub mod net;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use uni_percpu::timer::{Timer, TimerWheel};
use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};
use uni_platform::now_ticks;

// ---- Per-worker timer storage ---------------------------------------------

struct WheelCell(UnsafeCell<TimerWheel>);

// SAFETY: touched only by its owning worker via
// `PerCpu::current(&CurrentCore)`.
unsafe impl Sync for WheelCell {}
unsafe impl Send for WheelCell {}

static WHEELS: PerCpu<WheelCell, MAX_WORKERS> =
    PerCpu::new([const { WheelCell(UnsafeCell::new(TimerWheel::new())) }; MAX_WORKERS]);

fn wheel(cc: &CurrentCore) -> &mut TimerWheel {
    let cell = WHEELS.current(cc);
    // SAFETY: owning-worker-only; `CurrentCore` proves we're on it.
    unsafe { &mut *cell.0.get() }
}

// ---- Task arena ------------------------------------------------------------

pub const TASKS_PER_WORKER: usize = 64;

type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

pub struct TaskSlot {
    ready: AtomicBool,
    used: AtomicBool,
    future: UnsafeCell<Option<BoxedFuture>>,
}

impl TaskSlot {
    const fn new() -> Self {
        TaskSlot {
            ready: AtomicBool::new(false),
            used: AtomicBool::new(false),
            future: UnsafeCell::new(None),
        }
    }
}

// SAFETY: `ready` / `used` are atomic; `future` is mutated only by
// the owning worker (CAS on `used` serialises producers; polling
// runs on the same worker that spawned).
unsafe impl Sync for TaskSlot {}
unsafe impl Send for TaskSlot {}

#[repr(transparent)]
pub struct TaskArena {
    slots: [TaskSlot; TASKS_PER_WORKER],
}

impl TaskArena {
    const fn new() -> Self {
        TaskArena {
            slots: [const { TaskSlot::new() }; TASKS_PER_WORKER],
        }
    }
}

static ARENAS: PerCpu<TaskArena, MAX_WORKERS> =
    PerCpu::new([const { TaskArena::new() }; MAX_WORKERS]);

// ---- Spawning --------------------------------------------------------------

/// Spawn a future onto the current worker's arena. `Err(())` when
/// the arena is full.
pub fn spawn<F>(f: F) -> Result<(), ()>
where
    F: Future<Output = ()> + 'static,
{
    let cc = CurrentCore::enter();
    let arena = ARENAS.current(&cc);
    let fut: BoxedFuture = Box::pin(f);
    let mut fut_opt = Some(fut);
    for slot in arena.slots.iter() {
        if slot
            .used
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: the CAS gives us exclusive access until we
            // publish via `ready`.
            unsafe {
                *slot.future.get() = fut_opt.take();
            }
            slot.ready.store(true, Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

// ---- Waker vtable ----------------------------------------------------------

static WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    waker_clone,
    waker_wake,
    waker_wake_by_ref,
    waker_drop,
);

fn waker_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &WAKER_VTABLE)
}

fn waker_wake(data: *const ()) {
    waker_wake_by_ref(data);
}

fn waker_wake_by_ref(data: *const ()) {
    let slot = data as *const TaskSlot;
    // SAFETY: `data` points into static ARENAS.
    unsafe {
        (*slot).ready.store(true, Ordering::Release);
    }
}

fn waker_drop(_data: *const ()) {}

fn make_waker_for(slot: *const TaskSlot) -> Waker {
    let raw = RawWaker::new(slot as *const (), &WAKER_VTABLE);
    // SAFETY: vtable meets the RawWaker contract; data is a valid,
    // 'static pointer.
    unsafe { Waker::from_raw(raw) }
}

// ---- Event-loop entry points ----------------------------------------------

/// Advance this worker's timer wheel (firing expired timers, which
/// wake their tasks via the `Sleep` → waker chain), then poll every
/// ready slot in its arena. Backends call this once per event-loop
/// iteration.
pub fn tick(worker_id: u32) -> bool {
    if (worker_id as usize) >= MAX_WORKERS {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentCore::from_id_unchecked(worker_id) };
    let _ = wheel(&cc).advance(now_ticks());

    let arena = ARENAS.at(worker_id);
    let mut did_work = false;
    for slot in arena.slots.iter() {
        if !slot.used.load(Ordering::Acquire) {
            continue;
        }
        if !slot.ready.swap(false, Ordering::AcqRel) {
            continue;
        }
        did_work = true;
        poll_slot(slot);
    }
    did_work
}

/// True if the worker has outstanding async work — either a
/// scheduled timer in its wheel or a task slot flagged ready.
pub fn has_pending(worker_id: u32) -> bool {
    if (worker_id as usize) >= MAX_WORKERS {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentCore::from_id_unchecked(worker_id) };
    if wheel(&cc).count() > 0 {
        return true;
    }
    ARENAS
        .at(worker_id)
        .slots
        .iter()
        .any(|s| s.ready.load(Ordering::Acquire))
}

fn poll_slot(slot: &TaskSlot) {
    let waker = make_waker_for(slot as *const TaskSlot);
    let mut cx = Context::from_waker(&waker);

    // SAFETY: only the owning worker polls its slots.
    let fut_slot: &mut Option<BoxedFuture> = unsafe { &mut *slot.future.get() };
    let Some(fut) = fut_slot.as_mut() else {
        return;
    };
    match fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(()) => {
            *fut_slot = None;
            slot.used.store(false, Ordering::Release);
        }
    }
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
            let cc = CurrentCore::enter();
            if wheel(&cc).insert(Timer {
                deadline: this.deadline,
                func: sleep_fire,
                arg: self_ptr as usize,
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
            let cc = CurrentCore::enter();
            let _ = wheel(&cc).cancel(self_ptr as usize);
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
