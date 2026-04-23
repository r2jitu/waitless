// kernel/executor.rs — Minimum async runtime.
//
// Per-core task arena + slot-pointer `Waker` + timer-driven wake source.
// Futures are pinned to the core they spawned on; the event loop polls
// ready slots inline between IO phases. See ROADMAP §2f / §2g.
//
// Explicit non-goals (for now):
//   - `select!` / `join!` combinators.
//   - `Send + Sync` bounds on futures — per-core affinity is the point.
//   - Cross-core `spawn`. Tasks run on the core that spawned them.
//   - Cross-core IPI on wake. A sleeping target core notices the wake on
//     its next `idle_bounded` tick (bounded-latency, not zero-latency).

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::percpu::{CurrentCore, PerCpu, MAX_CORES};
use crate::timer::{Timer, TimerWheel};

// ---- Task arena ------------------------------------------------------------

/// Maximum concurrent spawned tasks per core. Raise when QUIC needs more
/// streams; keep small while we're proving the shape.
const TASKS_PER_CORE: usize = 64;

type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

/// A slot in a per-core task arena.
pub struct TaskSlot {
    /// true = wake was called since last poll. Set by wakers (any core),
    /// cleared by the event loop before re-polling. Release on store so
    /// cross-core wake publishes to the owning core.
    ready: AtomicBool,
    /// true = slot holds a live future. Claimed via CAS by `spawn`,
    /// cleared when the future returns `Poll::Ready`.
    used: AtomicBool,
    /// The future. Mutated only by the owning core — the CAS on `used`
    /// serialises producers (spawn), and poll is owning-core-only.
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

// SAFETY: `ready`/`used` use atomic ops; `future` is mutated only by the
// owning core. The CAS on `used` serialises spawn; poll runs on the same
// core that spawned. The slot never migrates.
unsafe impl Sync for TaskSlot {}
unsafe impl Send for TaskSlot {}

/// Per-core task arena: fixed-size array of slots.
pub struct TaskArena {
    slots: [TaskSlot; TASKS_PER_CORE],
}

impl TaskArena {
    const fn new() -> Self {
        TaskArena {
            slots: [const { TaskSlot::new() }; TASKS_PER_CORE],
        }
    }
}

static ARENAS: PerCpu<TaskArena, MAX_CORES> =
    PerCpu::new([const { TaskArena::new() }; MAX_CORES]);

// ---- Per-core timer wheel --------------------------------------------------
//
// `TimerWheel` uses `&mut self`, so the `&'static PerCpu` slot needs interior
// mutability. Owning-core-only access proven by `CurrentCore` makes the
// single-writer / single-reader contract sound.

struct WheelCell(UnsafeCell<TimerWheel>);

// SAFETY: owning-core-only access via the `CurrentCore` accessor below.
unsafe impl Sync for WheelCell {}
unsafe impl Send for WheelCell {}

static WHEELS: PerCpu<WheelCell, MAX_CORES> = PerCpu::new(
    [const { WheelCell(UnsafeCell::new(TimerWheel::new())) }; MAX_CORES],
);

fn wheel(cc: &CurrentCore) -> &mut TimerWheel {
    let cell = WHEELS.current(cc);
    // SAFETY: CurrentCore proves we're on the owning core; no other core
    // touches this wheel.
    unsafe { &mut *cell.0.get() }
}

// ---- Spawning --------------------------------------------------------------

/// Spawn a future onto the current core's arena.
///
/// `Err(())` if the arena is full (raise `TASKS_PER_CORE` or rethink your
/// task fan-out).
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
            // SAFETY: the CAS above gives us exclusive ownership of the
            // slot's `future` field until we publish via `ready.store`.
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
// `data` pointer = `*const TaskSlot` into static storage (ARENAS).
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
    // SAFETY: `data` points into static ARENAS storage; valid for the
    // program's lifetime. Store is `Release` so the owning core's next
    // `ready.swap(false, AcqRel)` observes everything the waker did.
    unsafe {
        (*slot).ready.store(true, Ordering::Release);
    }
}

fn waker_drop(_data: *const ()) {}

fn make_waker_for(slot: *const TaskSlot) -> Waker {
    let raw = RawWaker::new(slot as *const (), &WAKER_VTABLE);
    // SAFETY: vtable meets the RawWaker contract (thread-safe wake, static
    // data pointer, no cleanup needed).
    unsafe { Waker::from_raw(raw) }
}

// ---- Event-loop tick -------------------------------------------------------

/// Drain pending-timer MPSC into the local wheel, fire expired timers, and
/// poll every ready slot in the arena. Called once per event-loop iteration
/// on every core. Returns true if any slot was polled.
pub fn tick(core_id: u32) -> bool {
    // SAFETY: the event loop only calls `tick` on the running core.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };

    let pc = cc.percore();
    let w = wheel(&cc);
    let _ = pc.pending_timers.drain_into(w);
    let _ = w.advance(now_ticks());

    let arena = ARENAS.current(&cc);
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

/// Does this core have async work that might wake on its own — either
/// a timer pending in the wheel, or a task slot already flagged ready?
/// The event loop uses this to pick the right idle flavour: when true,
/// it must bound the sleep on the local timer rather than relying on
/// the HVF yield register (which only wakes on host IO).
pub fn has_pending(core_id: u32) -> bool {
    // SAFETY: caller guarantees `core_id` is the running core.
    let cc = unsafe { CurrentCore::from_id_unchecked(core_id) };
    if wheel(&cc).count() > 0 {
        return true;
    }
    let arena = ARENAS.current(&cc);
    arena
        .slots
        .iter()
        .any(|s| s.ready.load(Ordering::Acquire))
}

fn poll_slot(slot: &TaskSlot) {
    let waker = make_waker_for(slot as *const TaskSlot);
    let mut cx = Context::from_waker(&waker);

    // SAFETY: only the owning core polls its slots (enforced by `tick`'s
    // CurrentCore token); `used == true` means the future is live.
    let fut_slot: &mut Option<BoxedFuture> = unsafe { &mut *slot.future.get() };
    let Some(fut) = fut_slot.as_mut() else {
        return;
    };
    match fut.as_mut().poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(()) => {
            // Drop the future while `used` is still true so a racing
            // `spawn` can't observe a half-cleared slot. Then release.
            *fut_slot = None;
            slot.used.store(false, Ordering::Release);
        }
    }
}

// ---- Time source -----------------------------------------------------------

/// Monotonic tick count in microseconds since boot. Timer-wheel deadlines
/// are in these units.
#[inline]
pub fn now_ticks() -> u64 {
    crate::time::now_cycles() / crate::time::cycles_per_us()
}

// ---- Sleep future ----------------------------------------------------------

/// Future that resolves at a given tick (see `now_ticks`). Parks the task's
/// waker on the per-core timer wheel; `Drop` cancels the scheduled timer
/// so a wake can't hit a reused slot.
pub struct Sleep {
    deadline: u64,
    timer_scheduled: bool,
    /// Owned clone of the latest waker the task was polled with. `sleep_fire`
    /// reads this via a raw pointer into `Self`, so `Sleep` must not move
    /// after the timer is scheduled — it lives inside a `Pin<Box<_>>` in the
    /// arena for exactly that reason.
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

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // `Sleep` is auto-`Unpin` (all fields are `Unpin`), so it's fine to
        // reach through the pin.
        let this = self.get_mut();
        if now_ticks() >= this.deadline {
            this.waker = None;
            return Poll::Ready(());
        }
        if !this.timer_scheduled {
            this.waker = Some(cx.waker().clone());
            let self_ptr: *const Sleep = this;
            let t = Timer {
                deadline: this.deadline,
                func: sleep_fire,
                arg: self_ptr as usize,
            };
            let cc = CurrentCore::enter();
            if !wheel(&cc).insert(t) {
                crate::serial::puts(b"[executor] timer slot full; sleep stalled\n");
            }
            this.timer_scheduled = true;
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if self.timer_scheduled {
            let cc = CurrentCore::enter();
            let self_ptr: *const Sleep = self;
            let _ = wheel(&cc).cancel(self_ptr as usize);
        }
    }
}

fn sleep_fire(arg: usize) {
    let sleep = arg as *const Sleep;
    // SAFETY: `Sleep::drop` cancels the timer before the future is freed,
    // so reaching here implies `sleep` still points at a live `Sleep`.
    unsafe {
        if let Some(w) = (*sleep).waker.as_ref() {
            w.wake_by_ref();
        }
    }
}

/// Sleep for `us` microseconds from the moment of the call.
#[inline]
pub fn sleep_us(us: u64) -> Sleep {
    Sleep::until(now_ticks().saturating_add(us))
}
