// uni-executor/src/lib.rs — Shared async runtime.
//
// Per-worker task arena + slot-pointer `Waker` + `Sleep` future.
// Uses `uni_percpu::{CurrentCore, PerCpu}` for the arena storage
// and worker-id lookup; calls out to three `extern "C"` hooks for
// the things that vary across backends (time source + timer
// registration).
//
// Each worker polls only its own arena. A waker is a raw
// `*const TaskSlot` into the static `ARENAS` PerCpu array (always-
// valid pointer), so clone is a bit-copy and drop is free. Cross-
// worker wake sets `ready` on the target slot; the target worker
// sees it on its next tick (bounded by the backend's idle timeout).

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

// ---- Backend hooks ---------------------------------------------------------
//
// Provided by the backend crate via `#[unsafe(no_mangle)]
// pub extern "C" fn uni_exec_*(…)`. Function-pointer args use plain
// Rust ABI (`fn(usize)`) — declaring the outer block `extern "C"`
// only sets the calling convention of the hook itself, not of
// pointers passed through it. Backends can store the `func` pointer
// directly without a transmute. (The worker-id lookup goes through
// `uni_percpu::CurrentCore::enter` rather than a separate hook.)

// `fn(usize)` inside an `extern "C"` block trips the
// `improper_ctypes` lint — rustc warns that Rust-ABI fn pointers
// aren't C-calling-convention. In practice a Rust `fn(usize)` and a
// C `void(*)(size_t)` have the same register lowering on every
// target we support; the alternative (`extern "C" fn(usize)`) forced
// a transmute inside the bare-metal backend, which is what this
// refactor exists to remove. We own both the declaration and the
// definition, so the lint is a theoretical warning, not a real
// concern.
#[allow(improper_ctypes)]
unsafe extern "C" {
    fn uni_exec_now_ticks() -> u64;
    fn uni_exec_schedule_timer(deadline: u64, func: fn(usize), arg: usize) -> bool;
    fn uni_exec_cancel_timer(arg: usize) -> bool;
}

// ---- Task arena ------------------------------------------------------------

pub const TASKS_PER_WORKER: usize = 64;

type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

pub struct TaskSlot {
    /// Set by wakers (any worker), cleared by the owning worker
    /// before each poll.
    ready: AtomicBool,
    /// Claimed via CAS by `spawn`; cleared when the future completes.
    used: AtomicBool,
    /// Mutated only by the owning worker. CAS on `used` serialises
    /// producers; polling runs on the same worker that spawned.
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
// the owning worker (enforced by the CAS-on-`used` contract + the
// backend's `current_worker()` invariant).
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

/// Spawn a future onto the current worker's arena.
///
/// Returns `Err(())` when the arena is full (raise `TASKS_PER_WORKER`
/// or rethink your task fan-out).
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
            // SAFETY: the CAS above gives us exclusive access to this
            // slot's `future` cell until we publish via `ready`.
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
//
// `data` pointer = `*const TaskSlot` into static ARENAS storage.
// No refcount, no allocation. Clone is bit-copy; drop is a no-op.

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
    // SAFETY: `data` points into static ARENAS; valid for the program
    // lifetime. Release on store so the owning worker observes
    // everything the waker did.
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
/// once per event-loop iteration. Returns true if any slot was polled.
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
/// Backends use this to decide whether to enter a hypervisor-friendly
/// idle or a timer-bounded one.
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

    // SAFETY: only the owning worker polls its slots (enforced by the
    // backend's `current_worker()` → `tick(current_worker)` call).
    let fut_slot: &mut Option<BoxedFuture> = unsafe { &mut *slot.future.get() };
    let Some(fut) = fut_slot.as_mut() else {
        return;
    };
    match fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(()) => {
            // Drop future while `used == true` so a racing `spawn`
            // can't observe a half-cleared slot.
            *fut_slot = None;
            slot.used.store(false, Ordering::Release);
        }
    }
}

// ---- Sleep future ----------------------------------------------------------

/// Future that resolves at `deadline` ticks (matching the backend's
/// `now_ticks()` scale, i.e. µs on both backends today). Parks the
/// task's waker via `uni_exec_schedule_timer`; `Drop` cancels so a
/// stale fire can't hit a reused slot.
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

/// Sleep for `us` microseconds from the moment of the call.
#[inline]
pub fn sleep_us(us: u64) -> Sleep {
    let now = unsafe { uni_exec_now_ticks() };
    Sleep::until(now.saturating_add(us))
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // `Sleep`'s fields are all `Unpin`; safe to reach through.
        let this = self.get_mut();
        let now = unsafe { uni_exec_now_ticks() };
        if now >= this.deadline {
            this.waker = None;
            return Poll::Ready(());
        }
        if !this.timer_scheduled {
            this.waker = Some(cx.waker().clone());
            let self_ptr: *const Sleep = this;
            let ok = unsafe {
                uni_exec_schedule_timer(
                    this.deadline,
                    sleep_fire,
                    self_ptr as usize,
                )
            };
            if ok {
                this.timer_scheduled = true;
            }
            // If scheduling fails (backend storage full), the event
            // loop's periodic re-tick will re-poll us and we converge
            // once the deadline is reached.
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if self.timer_scheduled {
            let self_ptr: *const Sleep = self;
            let _ = unsafe { uni_exec_cancel_timer(self_ptr as usize) };
        }
    }
}

fn sleep_fire(arg: usize) {
    let sleep = arg as *const Sleep;
    // SAFETY: `Sleep::drop` cancels the timer before the future is
    // freed, so reaching here implies `sleep` still points at a live
    // `Sleep` in the task's boxed future storage.
    unsafe {
        if let Some(w) = (*sleep).waker.as_ref() {
            w.wake_by_ref();
        }
    }
}
