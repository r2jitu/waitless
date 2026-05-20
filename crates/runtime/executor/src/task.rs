// uni-runtime/src/task.rs — Per-worker task arena + spawn/tick/abort.
//
// Each worker owns one `TaskArena` (in the `ARENAS` PerWorker), which
// holds `TASKS_PER_WORKER` `TaskSlot`s plus a `ready_bits: AtomicU64`.
// Spawn claims a free slot, tick swap-takes the ready bitmap and polls
// every set bit. Wakers identify their (worker, slot) by bit-packing
// the two indices into the `*const ()` data field — no heap, no
// indirection, single `fetch_or` per wake.
//
// Cross-worker abort defers the actual drop to the target worker's next
// tick (the future is dropped on the worker that polled it). Epoch
// counters protect against handle-reuse races.

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use uni_worker::{CurrentWorker, PerWorker};

// ---- Task arena ------------------------------------------------------------

pub const TASKS_PER_WORKER: usize = 64;
const _: () = assert!(TASKS_PER_WORKER <= 64, "ready_bits is u64");

/// Pre-boxed future shape accepted by [`spawn_boxed`]. Listeners
/// that already type-erase per-conn futures into `Pin<Box<dyn …>>`
/// hand the box straight to the spawner without a second allocation.
pub type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

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

static ARENAS: PerWorker<TaskArena> = PerWorker::new();

/// Size `ARENAS` for `n` workers. Called once at boot from `crate::init`.
pub(crate) fn init(n: u32) {
    ARENAS.init(n, |_| TaskArena::new());
}

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
        slot.epoch.load(Ordering::Acquire) != self.epoch || !slot.used.load(Ordering::Acquire)
    }
}

/// Spawn a future onto the current worker's arena. `Err(())` when
/// the arena is full — the future is dropped in that case.
///
/// One heap alloc per spawn (the `Box::pin`). Callers that
/// already have a `Pin<Box<dyn Future>>` should use
/// [`spawn_boxed`] instead to skip the redundant re-box.
pub fn spawn<F>(f: F) -> Result<TaskHandle, ()>
where
    F: Future<Output = ()> + 'static,
{
    spawn_boxed(Box::pin(f))
}

/// Spawn a pre-boxed future onto the current worker's arena.
/// Saves one heap allocation vs `spawn(f)` when the caller has
/// already produced a `Pin<Box<dyn Future>>` (typical pattern:
/// listener accept-loops that route through a type-erased
/// factory closure returning `BoxFuture`).
///
/// `Err(())` when the arena is full — the future is dropped
/// in that case.
pub fn spawn_boxed(fut: BoxedFuture) -> Result<TaskHandle, ()> {
    let cc = CurrentWorker::enter();
    let worker_id = cc.id();
    let arena = ARENAS.current(&cc);
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

static WAKER_VTABLE: RawWakerVTable =
    RawWakerVTable::new(waker_clone, waker_wake, waker_wake_by_ref, waker_drop);

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
    if worker_id >= uni_worker::num_workers() || slot_idx >= TASKS_PER_WORKER {
        return;
    }
    let prev = ARENAS
        .at(worker_id)
        .ready_bits
        .fetch_or(1u64 << slot_idx, Ordering::Release);
    // Cross-worker wake: the target may be in HLT/WFI / blocking
    // kqueue waiting for its next idle tick; bumping `ready_bits`
    // alone won't bring it back. Skip when:
    //   - the target IS the current worker (we'll observe the bit
    //     on our own next tick, no kernel round-trip needed), or
    //   - `ready_bits` was already non-zero (the target is either
    //     mid-tick or about to tick — another bit doesn't change
    //     the wake semantics, and an extra IPI per packet under
    //     heavy load just adds overhead).
    if prev == 0 && worker_id != uni_platform::current_worker() {
        uni_platform::wake_worker(worker_id);
    }
}

fn waker_drop(_data: *const ()) {}

fn make_waker_for(worker_id: u32, slot_idx: usize) -> Waker {
    let packed = ((worker_id as usize) << WAKER_WORKER_SHIFT) | (slot_idx & WAKER_SLOT_MASK);
    let raw = RawWaker::new(packed as *const (), &WAKER_VTABLE);
    // SAFETY: vtable meets the RawWaker contract; `data` is an
    // integer bit-pattern, never dereferenced as a pointer.
    unsafe { Waker::from_raw(raw) }
}

// ---- Event-loop entry points ----------------------------------------------

/// Advance this worker's timer wheel (firing expired timers, which
/// wake their tasks via the `Sleep` → waker chain), then poll every
/// ready slot in its arena. Backends call this once per event-loop
/// iteration.
pub fn tick(worker_id: u32) -> bool {
    if worker_id >= uni_worker::num_workers() {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentWorker::from_id_unchecked(worker_id) };

    // Spawn per-worker launchers registered by `UdpSocket::run` /
    // `TcpListener::run` since this worker last ticked.
    crate::net::fire_pending_net_launchers(worker_id);

    crate::sleep::advance_timers(&cc);

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

/// Force-drop every live task in every worker's arena.
///
/// Called once from `uni::shutdown_and_drop` after listener handles
/// have been dropped (which sets the abort flag on per-worker
/// recv/accept tasks, but doesn't actually free their `Box<dyn
/// Future>` storage — that drop normally happens on the next `tick`,
/// which never runs again post-eventloop-break). This walks every
/// arena and drops any `used` slot in place, releasing the heap.
///
/// Safety: APs have already broken out of `eventloop::run`'s main
/// loop and are spin-looping past it before issuing PSCI CPU_OFF
/// (see `kernel/src/eventloop.rs` — they don't tick after break).
/// They are not concurrently writing to their arenas during this
/// window, so cross-worker mutable access is race-free.
pub fn drain_all_arenas() {
    let n = uni_worker::num_workers();
    for worker_id in 0..n {
        let arena = ARENAS.at(worker_id);
        for slot in arena.slots.iter() {
            if !slot.used.load(Ordering::Acquire) {
                continue;
            }
            // SAFETY: see fn-level comment — APs are post-eventloop-
            // break and not polling.
            unsafe {
                *slot.future.get() = None;
            }
            slot.epoch.fetch_add(1, Ordering::AcqRel);
            slot.used.store(false, Ordering::Release);
            slot.abort.store(false, Ordering::Release);
        }
        // Clear ready bits so a later spurious wake observes nothing
        // to do.
        arena.ready_bits.store(0, Ordering::Release);
    }
}

/// True if the worker has outstanding async work — either a
/// scheduled timer in its wheel or a task slot flagged ready.
pub fn has_pending(worker_id: u32) -> bool {
    if worker_id >= uni_worker::num_workers() {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentWorker::from_id_unchecked(worker_id) };
    if crate::sleep::has_timers(&cc) {
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
