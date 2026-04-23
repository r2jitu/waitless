// uni-executor/src/lib.rs — Shared async runtime.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

// ---- Backend plug-in -------------------------------------------------------
//
// Each backend (`//kernel`, `//uni-native`) defines a `static
// Runtime` filled with its own fn pointers and calls `register` at
// boot. No `dyn Trait`, no `extern "C"` hooks — just a POD struct of
// Rust-ABI fn pointers, thin-pointer `AtomicPtr` for publication.

pub struct Runtime {
    pub now_ticks: fn() -> u64,
    pub schedule_timer: fn(deadline: u64, func: fn(usize), arg: usize) -> bool,
    pub cancel_timer: fn(arg: usize) -> bool,
}

static RUNTIME: AtomicPtr<Runtime> = AtomicPtr::new(ptr::null_mut());

/// Publish the backend runtime. Call once at boot, before any
/// `spawn` / `sleep_us` / `Sleep::poll`.
pub fn register(rt: &'static Runtime) {
    RUNTIME.store(rt as *const Runtime as *mut Runtime, Ordering::Release);
}

#[inline]
fn runtime() -> &'static Runtime {
    let p = RUNTIME.load(Ordering::Acquire);
    // SAFETY: backend is expected to call `register` before any
    // `runtime()` access.
    unsafe { &*p }
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

// ---- Poll entry points -----------------------------------------------------

/// Poll every ready slot in `worker_id`'s arena. Backends call this
/// once per event-loop iteration.
pub fn tick(worker_id: u32) -> bool {
    if (worker_id as usize) >= MAX_WORKERS {
        return false;
    }
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

/// True iff `worker_id`'s arena has at least one slot flagged ready.
pub fn has_ready(worker_id: u32) -> bool {
    if (worker_id as usize) >= MAX_WORKERS {
        return false;
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
    Sleep::until((runtime().now_ticks)().saturating_add(us))
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let rt = runtime();
        if (rt.now_ticks)() >= this.deadline {
            this.waker = None;
            return Poll::Ready(());
        }
        if !this.timer_scheduled {
            this.waker = Some(cx.waker().clone());
            let self_ptr: *const Sleep = this;
            if (rt.schedule_timer)(this.deadline, sleep_fire, self_ptr as usize) {
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
            let _ = (runtime().cancel_timer)(self_ptr as usize);
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
