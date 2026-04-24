// uni-runtime/src/lib.rs — Shared async runtime.

#![no_std]

extern crate alloc;

pub mod net;
pub mod select;

use atomic_fn::AtomicFn;

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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
const _: () = assert!(TASKS_PER_WORKER <= 64, "ready_bits is u64");

type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

pub struct TaskSlot {
    used: AtomicBool,
    /// Cancel flag — set by `TaskHandle::abort` (possibly from a
    /// different worker). Checked by `tick` before polling; if set,
    /// the future is dropped in place and the slot freed.
    abort: AtomicBool,
    /// Bumped every time this slot transitions used → free (on
    /// completion OR abort). `TaskHandle` captures the epoch at
    /// spawn time and verifies on every cross-worker op, so a stale
    /// handle to a reused slot becomes a no-op rather than aborting
    /// the unrelated task.
    epoch: AtomicU32,
    future: UnsafeCell<Option<BoxedFuture>>,
}

impl TaskSlot {
    const fn new() -> Self {
        TaskSlot {
            used: AtomicBool::new(false),
            abort: AtomicBool::new(false),
            epoch: AtomicU32::new(0),
            future: UnsafeCell::new(None),
        }
    }
}

// SAFETY: `used` / `abort` / `epoch` are atomic; `future` is
// mutated only by the owning worker (CAS on `used` serialises
// producers; polling runs on the same worker that spawned).
unsafe impl Sync for TaskSlot {}
unsafe impl Send for TaskSlot {}

pub struct TaskArena {
    slots: [TaskSlot; TASKS_PER_WORKER],
    /// Per-arena ready bitmap — bit `i` set iff slot `i` is scheduled
    /// to poll. Waker fires the bit; `tick` reads-and-clears the whole
    /// word then iterates set bits via `trailing_zeros`. O(ready) work
    /// per tick instead of O(TASKS_PER_WORKER).
    ready_bits: AtomicU64,
}

impl TaskArena {
    const fn new() -> Self {
        TaskArena {
            slots: [const { TaskSlot::new() }; TASKS_PER_WORKER],
            ready_bits: AtomicU64::new(0),
        }
    }
}

static ARENAS: PerCpu<TaskArena, MAX_WORKERS> =
    PerCpu::new([const { TaskArena::new() }; MAX_WORKERS]);

// ---- Spawning --------------------------------------------------------------

/// Handle to a spawned task. Lets the caller query whether the task
/// is still running and request cancellation. Safe to call from any
/// worker (cross-worker `abort` defers the drop to the target
/// worker's next `tick`).
///
/// Captured fields: the owning worker, the slot index, and the
/// epoch stamp at spawn time. A mismatch means the slot has since
/// been reused; cross-worker ops become no-ops so we never abort an
/// unrelated task.
#[derive(Clone, Copy)]
pub struct TaskHandle {
    worker_id: u32,
    slot_idx: u32,
    epoch: u32,
}

impl TaskHandle {
    /// Request that the task stop. The drop runs on the target
    /// worker's next `tick` — this call itself is just an atomic
    /// flag write + ready-bit set to force a tick. A no-op if the
    /// task already finished or the slot was reused.
    pub fn abort(&self) {
        let arena = ARENAS.at(self.worker_id);
        let slot = &arena.slots[self.slot_idx as usize];
        // Epoch check prevents aborting a stranger that reused the
        // slot after our task completed.
        if slot.epoch.load(Ordering::Acquire) != self.epoch {
            return;
        }
        slot.abort.store(true, Ordering::Release);
        // Force a tick so the abort is honoured promptly, even if
        // the task isn't otherwise ready.
        arena
            .ready_bits
            .fetch_or(1u64 << self.slot_idx, Ordering::Release);
    }

    /// True iff the task has completed or been aborted. False
    /// while still running.
    pub fn is_finished(&self) -> bool {
        let arena = ARENAS.at(self.worker_id);
        let slot = &arena.slots[self.slot_idx as usize];
        slot.epoch.load(Ordering::Acquire) != self.epoch
            || !slot.used.load(Ordering::Acquire)
    }
}

/// Spawn a future onto the current worker's arena. `Err(())` when
/// the arena is full — the future is dropped in that case.
pub fn spawn<F>(f: F) -> Result<TaskHandle, ()>
where
    F: Future<Output = ()> + 'static,
{
    let cc = CurrentCore::enter();
    let worker_id = cc.id();
    let arena = ARENAS.current(&cc);
    let fut: BoxedFuture = Box::pin(f);
    let mut fut_opt = Some(fut);
    for (idx, slot) in arena.slots.iter().enumerate() {
        if slot
            .used
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: the CAS gives us exclusive access until we
            // publish via the ready bit below.
            unsafe {
                *slot.future.get() = fut_opt.take();
            }
            // Clear any stale abort flag from the prior task that
            // lived in this slot (swap-not-store to be defensive).
            slot.abort.store(false, Ordering::Release);
            let epoch = slot.epoch.load(Ordering::Acquire);
            arena.ready_bits.fetch_or(1u64 << idx, Ordering::Release);
            return Ok(TaskHandle {
                worker_id,
                slot_idx: idx as u32,
                epoch,
            });
        }
    }
    Err(())
}

// ---- Waker vtable ----------------------------------------------------------
//
// `data: *const ()` is repurposed as a packed `(worker_id, slot_idx)`
// integer (not a real pointer). Bits [0..6]: slot_idx (0..=63). Bits
// [8..]: worker_id. The vtable is compile-time fixed, so knowing the
// two indices is enough to locate the arena's ready_bits via
// `ARENAS.at(worker_id)` and OR-in the bit.
//
// Packing as an integer avoids pointer-stability concerns (TaskSlot
// is in a `static`, fine today, but this is simpler) and keeps
// wake-site work to a single `fetch_or` — no indirection, no
// per-slot AtomicBool scan.

const WAKER_SLOT_MASK: usize = 0xFF;
const WAKER_WORKER_SHIFT: u32 = 8;

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
    let packed = data as usize;
    let slot_idx = packed & WAKER_SLOT_MASK;
    let worker_id = (packed >> WAKER_WORKER_SHIFT) as u32;
    if (worker_id as usize) >= MAX_WORKERS || slot_idx >= TASKS_PER_WORKER {
        return;
    }
    ARENAS
        .at(worker_id)
        .ready_bits
        .fetch_or(1u64 << slot_idx, Ordering::Release);
}

fn waker_drop(_data: *const ()) {}

fn make_waker_for(worker_id: u32, slot_idx: usize) -> Waker {
    let packed = ((worker_id as usize) << WAKER_WORKER_SHIFT) | (slot_idx & WAKER_SLOT_MASK);
    let raw = RawWaker::new(packed as *const (), &WAKER_VTABLE);
    // SAFETY: vtable meets the RawWaker contract; `data` is an
    // integer bit-pattern, never dereferenced as a pointer.
    unsafe { Waker::from_raw(raw) }
}

// ---- Per-worker startup hook ----------------------------------------------
//
// `spawn_on_each_worker(f)` registers `f` to fire exactly once on
// each worker, on that worker, on its first `tick`. Inside `f`,
// `spawn()` lands the task in the running worker's arena. Common
// pattern for long-lived per-core reactors (UDP, TCP, QUIC).
//
// Multiple registrations accumulate — each call claims the next
// slot in a fixed-size table. Used internally by `net::UdpSocket::
// run` and `net::TcpListener::run`; also exposed for apps.
//
// Registration after a worker's first `tick` is a no-op for that
// worker (the `STARTUP_FIRED` flag is already set). Intent is
// "register all hooks before `set_ready()`"; later registrations
// still fire on workers that haven't ticked yet.

const MAX_STARTUP_HOOKS: usize = 8;

static PER_WORKER_STARTUP: [AtomicFn<fn()>; MAX_STARTUP_HOOKS] =
    [const { AtomicFn::null() }; MAX_STARTUP_HOOKS];
static STARTUP_HOOK_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// Per-worker cursor into `PER_WORKER_STARTUP` — incremented each
/// tick by the number of hooks fired. Replaces the single-shot
/// `STARTUP_FIRED` flag so hooks registered *after* a worker's
/// first tick (e.g. from inside the boot task itself) still run
/// on that worker on its next tick.
static STARTUP_FIRED_COUNT: [core::sync::atomic::AtomicUsize; MAX_WORKERS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_WORKERS];

/// Register `f` to run on every worker on its next tick after
/// registration. Up to `MAX_STARTUP_HOOKS` hooks accumulate; excess
/// registrations are silently dropped.
pub fn spawn_on_each_worker(f: fn()) {
    let i = STARTUP_HOOK_COUNT
        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    if i < MAX_STARTUP_HOOKS {
        PER_WORKER_STARTUP[i].store(f);
    }
    // else: table full, hook discarded. Acceptable under the doc
    // contract; callers that hit this limit are doing something
    // unusual.
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

    // Fire every per-worker startup hook registered since this
    // worker last ticked. Hooks registered from *within* a worker's
    // own boot task (e.g. `TcpListener::run` inside `uni::run(app)`)
    // land before the count advances here, so they still fire on
    // the current worker on its next tick.
    {
        let total = STARTUP_HOOK_COUNT
            .load(Ordering::Acquire)
            .min(MAX_STARTUP_HOOKS);
        let fired = STARTUP_FIRED_COUNT[worker_id as usize].load(Ordering::Relaxed);
        if fired < total {
            for slot in PER_WORKER_STARTUP.iter().take(total).skip(fired) {
                if let Some(f) = slot.load() {
                    f();
                }
            }
            STARTUP_FIRED_COUNT[worker_id as usize]
                .store(total, Ordering::Relaxed);
        }
    }

    let _ = wheel(&cc).advance(now_ticks());

    let arena = ARENAS.at(worker_id);
    // Atomically take the current ready bitmap. Wakes that fire
    // *during* this tick flip fresh bits for the next iteration.
    let mut ready = arena.ready_bits.swap(0, Ordering::AcqRel);
    let mut did_work = false;
    while ready != 0 {
        let slot_idx = ready.trailing_zeros() as usize;
        ready &= ready - 1;
        let slot = &arena.slots[slot_idx];
        // Spurious wakes on freed slots are possible if an external
        // reference fires a stale waker after the task completed.
        // `used` guards the slot's future storage.
        if !slot.used.load(Ordering::Acquire) {
            continue;
        }
        // Cancellation beats polling: `TaskHandle::abort` set the
        // flag + flipped the ready bit to force us here. Drop the
        // future in place (on the owning worker, where it's safe),
        // bump the epoch so lingering handles observe completion,
        // then free the slot.
        if slot.abort.swap(false, Ordering::AcqRel) {
            // SAFETY: owning-worker-only access.
            unsafe {
                *slot.future.get() = None;
            }
            slot.epoch.fetch_add(1, Ordering::AcqRel);
            slot.used.store(false, Ordering::Release);
            did_work = true;
            continue;
        }
        did_work = true;
        poll_slot(slot, worker_id, slot_idx);
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
    ARENAS.at(worker_id).ready_bits.load(Ordering::Acquire) != 0
}

fn poll_slot(slot: &TaskSlot, worker_id: u32, slot_idx: usize) {
    let waker = make_waker_for(worker_id, slot_idx);
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
            // Bump epoch so `TaskHandle::is_finished` sees completion
            // and any in-flight `abort` call on this handle becomes
            // a no-op rather than aborting the next task in this slot.
            slot.epoch.fetch_add(1, Ordering::AcqRel);
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
