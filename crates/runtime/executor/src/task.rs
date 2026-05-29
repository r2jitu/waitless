// crates/runtime/executor/src/task.rs — Per-worker task arena + spawn/tick/abort.
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

use worker::{CurrentWorker, PerWorker};

// ---- Task arena ------------------------------------------------------------

/// Per-worker task slot count. With `WORKERS × TASKS_PER_WORKER`
/// total in-flight tasks across the machine, this is the ceiling on
/// concurrent connections / spawned futures the runtime can handle.
/// Sized to fit the largest planned bench point (32K conns / 8
/// workers = 4096 per worker) with headroom for non-conn tasks
/// (listeners, timers, internal jobs).
pub const TASKS_PER_WORKER: usize = 4096;
/// Words in the slot bitmap; one bit per slot. Spawn linear-scans
/// `used_bits` for a zero bit before CAS-claiming; `ready_bits`
/// mirrors per-slot wake state for the tick poll loop.
pub const TASKS_BITMAP_WORDS: usize = TASKS_PER_WORKER / 64;
const _: () = assert!(
    TASKS_PER_WORKER.is_power_of_two() && TASKS_PER_WORKER >= 64,
    "TASKS_PER_WORKER must be a power-of-two ≥ 64 so the bitmap maths is clean",
);

/// Bits dedicated to the slot index in the waker's packed
/// `(worker, slot)` data field. 16 covers TASKS_PER_WORKER up to
/// 65536 with plenty of headroom; the high bits hold the worker
/// id. Must be `≥ log2(TASKS_PER_WORKER)`.
const WAKER_SLOT_BITS: u32 = 16;
const WAKER_SLOT_MASK: usize = (1 << WAKER_SLOT_BITS) - 1;
const WAKER_WORKER_SHIFT: u32 = WAKER_SLOT_BITS;
const _: () = assert!(
    TASKS_PER_WORKER <= (1 << WAKER_SLOT_BITS),
    "slot index must fit in WAKER_SLOT_BITS",
);

/// Pre-boxed future shape accepted by [`spawn_boxed`]. Listeners
/// that already type-erase per-conn futures into `Pin<Box<dyn …>>`
/// hand the box straight to the spawner without a second allocation.
pub type BoxedFuture = Pin<Box<dyn Future<Output = ()>>>;

pub struct TaskSlot {
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
            abort: AtomicBool::new(false),
            epoch: AtomicU32::new(0),
            future: UnsafeCell::new(None),
        }
    }
}

// SAFETY: `abort` / `epoch` are atomic; `future` is mutated only by
// the owning worker (the used-bitmap CAS serialises producers; only
// the owning worker polls, so the UnsafeCell access is
// single-threaded at any given time).
unsafe impl Sync for TaskSlot {}
unsafe impl Send for TaskSlot {}

pub struct TaskArena {
    slots: [TaskSlot; TASKS_PER_WORKER],
    /// Per-arena used bitmap — bit `i` set iff slot `i` currently
    /// holds a live (or aborting) future. Spawn does a find-first-
    /// zero scan + CAS-claim. Replaces the per-slot `AtomicBool used`
    /// so that the scan is O(words) instead of O(slots).
    used_bits: [AtomicU64; TASKS_BITMAP_WORDS],
    /// Per-arena ready bitmap — bit `i` set iff slot `i` is scheduled
    /// to poll. Waker fires the bit; `tick` swaps each word to 0 and
    /// iterates set bits via `trailing_zeros`. O(ready) work per tick
    /// instead of O(TASKS_PER_WORKER).
    ready_bits: [AtomicU64; TASKS_BITMAP_WORDS],
}

impl TaskArena {
    const fn new() -> Self {
        TaskArena {
            slots: [const { TaskSlot::new() }; TASKS_PER_WORKER],
            used_bits: [const { AtomicU64::new(0) }; TASKS_BITMAP_WORDS],
            ready_bits: [const { AtomicU64::new(0) }; TASKS_BITMAP_WORDS],
        }
    }

    /// True iff slot `idx` is currently in use. Wraps the per-word
    /// bitmap lookup; callers should always check this on the poll /
    /// abort paths to filter out spurious wakes against freed slots.
    fn is_used(&self, idx: usize) -> bool {
        let (word, bit) = (idx / 64, idx % 64);
        (self.used_bits[word].load(Ordering::Acquire) & (1u64 << bit)) != 0
    }

    /// Clear the used bit for `idx`. Called from the tick loop when
    /// a task completes or aborts, and from `drain_all_arenas`.
    fn clear_used(&self, idx: usize) {
        let (word, bit) = (idx / 64, idx % 64);
        self.used_bits[word].fetch_and(!(1u64 << bit), Ordering::Release);
    }

    /// Set the ready bit for `idx` and return whether ANY ready bit
    /// in the entire arena was already set before this call (per-
    /// word check is a fast approximation that's good enough for the
    /// "is the target tick already pending?" wake-suppression check
    /// in `waker_wake_by_ref`).
    fn mark_ready(&self, idx: usize) -> bool {
        let (word, bit) = (idx / 64, idx % 64);
        let prev = self.ready_bits[word].fetch_or(1u64 << bit, Ordering::Release);
        prev != 0
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
        arena.mark_ready(self.slot_idx as usize);
    }

    /// True iff the task has completed or been aborted. False
    /// while still running.
    pub fn is_finished(&self) -> bool {
        let arena = ARENAS.at(self.worker_id);
        let slot = &arena.slots[self.slot_idx as usize];
        slot.epoch.load(Ordering::Acquire) != self.epoch
            || !arena.is_used(self.slot_idx as usize)
    }
}

/// Failure returned by [`spawn`] / [`spawn_boxed`] when the
/// current worker's arena is full. The submitted future has been
/// dropped — callers typically log and back off, or abort an
/// existing task to free a slot. A unit struct (vs an enum)
/// because "arena full" is the only failure mode the spawner has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpawnError;

/// Spawn a future onto the current worker's arena. Returns
/// `Err(SpawnError)` when the arena is full — the future is
/// dropped in that case.
///
/// One heap alloc per spawn (the `Box::pin`). Callers that
/// already have a `Pin<Box<dyn Future>>` should use
/// [`spawn_boxed`] instead to skip the redundant re-box.
pub fn spawn<F>(f: F) -> Result<TaskHandle, SpawnError>
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
/// `Err(SpawnError)` when the arena is full — the future is
/// dropped in that case.
pub fn spawn_boxed(fut: BoxedFuture) -> Result<TaskHandle, SpawnError> {
    let cc = CurrentWorker::enter();
    let worker_id = cc.id();
    let arena = ARENAS.current(&cc);
    let mut fut_opt = Some(fut);
    // Find-first-zero scan over `used_bits`, CAS-claim the slot,
    // publish via `ready_bits`. The bitmap collapses a linear
    // per-slot AtomicBool scan (O(TASKS_PER_WORKER) on the spawn-
    // when-full path) down to O(TASKS_BITMAP_WORDS) — at 4096
    // slots that's 64 words instead of 4096 AtomicBool loads,
    // and the typical case finds a free word on the first probe.
    for word_idx in 0..TASKS_BITMAP_WORDS {
        loop {
            let word = arena.used_bits[word_idx].load(Ordering::Acquire);
            if word == u64::MAX {
                // Word fully claimed; try the next one. Most-loaded
                // arenas have a sparse `!word`, so the find-first-
                // zero (bitwise-NOT trailing_zeros) is one CPU op.
                break;
            }
            let bit = (!word).trailing_zeros() as usize;
            let mask = 1u64 << bit;
            let prev = arena.used_bits[word_idx].fetch_or(mask, Ordering::AcqRel);
            if (prev & mask) != 0 {
                // Another spawn or wake raced us to this bit; retry
                // the same word (a different bit may still be free).
                continue;
            }
            // CAS succeeded — slot is ours. Compute the absolute
            // slot index, populate, publish ready.
            let idx = word_idx * 64 + bit;
            let slot = &arena.slots[idx];
            // SAFETY: the used-bit CAS gives us exclusive access to
            // the slot's future cell until completion clears it.
            unsafe {
                *slot.future.get() = fut_opt.take();
            }
            // Clear any stale abort flag from the prior task that
            // lived in this slot (defensive — abort sets-and-forgets,
            // tick swaps-and-checks, so a leftover `true` from a
            // previous incarnation would otherwise immediately drop
            // the new future on its first tick).
            slot.abort.store(false, Ordering::Release);
            let epoch = slot.epoch.load(Ordering::Acquire);
            arena.mark_ready(idx);
            crate::diag::COUNTERS.tasks_spawned.bump();
            return Ok(TaskHandle {
                worker_id,
                slot_idx: idx as u32,
                epoch,
            });
        }
    }
    // Arena full — the future is dropped. Trace the silent loss.
    crate::diag::record_spawn_failure(worker_id);
    Err(SpawnError)
}

// ---- Waker vtable ----------------------------------------------------------
//
// `data: *const ()` is repurposed as a packed `(worker_id, slot_idx)`
// integer (not a real pointer). Low `WAKER_SLOT_BITS` (16) hold the
// slot index — enough for any reasonable `TASKS_PER_WORKER`; the
// remaining high bits hold the worker id. The vtable is compile-
// time fixed, so knowing the two indices is enough to locate the
// arena's `used_bits` / `ready_bits` via `ARENAS.at(worker_id)` and
// flip the appropriate bit.
//
// Packing as an integer avoids pointer-stability concerns (TaskSlot
// is in a `static`, fine today, but this is simpler) and keeps
// wake-site work to a single `fetch_or` — no indirection, no
// per-slot scan.

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
    if worker_id >= worker::num_workers() || slot_idx >= TASKS_PER_WORKER {
        return;
    }
    let any_was_ready = ARENAS.at(worker_id).mark_ready(slot_idx);
    // Cross-worker wake: the target may be in HLT/WFI / blocking
    // kqueue waiting for its next idle tick; bumping `ready_bits`
    // alone won't bring it back. Skip when:
    //   - the target IS the current worker (we'll observe the bit
    //     on our own next tick, no kernel round-trip needed), or
    //   - any ready bit in that arena word was already set (the
    //     target is either mid-tick or about to tick — another bit
    //     doesn't change the wake semantics, and an extra IPI per
    //     packet under heavy load just adds overhead). This is a
    //     per-word check rather than per-arena; "any pending in
    //     this word" is a strict subset of "any pending anywhere",
    //     so we may issue a redundant wake in the multi-word case,
    //     which is harmless.
    if !any_was_ready && worker_id != platform::current_worker() {
        platform::wake_worker(worker_id);
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
/// Cycle counter for the `RUNTIME_CYCLES` serve-bucket bracket. The
/// executor sits below `kernel_core`, so we read the counter directly
/// (rdtsc / cntvct) rather than depend on it. Same instruction the
/// `tls`/`http` profilers use; zero on unsupported targets.
#[inline(always)]
fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

pub fn tick(worker_id: u32) -> bool {
    if worker_id >= worker::num_workers() {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentWorker::from_id_unchecked(worker_id) };

    // Spawn per-worker launchers registered by `UdpSocket::run` /
    // `TcpListener::run` since this worker last ticked.
    crate::reactor::fire_pending_net_launchers(worker_id);

    crate::sleep::advance_timers(&cc);

    let arena = ARENAS.at(worker_id);
    // Idle-worker fast path: a `swap(0, AcqRel)` on every word is
    // ~6 cy/word × 64 words ≈ 400 cy per empty tick. A worker
    // that spends most of its time idle (waiting for the NIC RX
    // queue to produce a frame, then doing one tick of work, then
    // idling again) pays this for nothing. A cheaper relaxed-load
    // scan first lets the idle path short-circuit before any
    // atomic-RMW work runs. Pure observation — relaxed loads
    // can't see writes our local core hasn't yet acquired, but
    // any wake that landed *here* must have come from this same
    // core (single-core arena ownership for the writer side
    // beyond cross-core wakes, which use `wake_worker` after the
    // bit flip — that IPI guarantees we'll re-enter `tick` after
    // they land).
    let mut did_work = false;
    if arena
        .ready_bits
        .iter()
        .all(|w| w.load(Ordering::Relaxed) == 0)
    {
        return did_work;
    }
    // Atomically take the current ready bitmap, one word at a time.
    // Wakes that fire *during* this tick flip fresh bits in the
    // words we've already swept and get picked up on the next tick.
    for word_idx in 0..TASKS_BITMAP_WORDS {
        let mut ready = arena.ready_bits[word_idx].swap(0, Ordering::AcqRel);
        while ready != 0 {
            let bit = ready.trailing_zeros() as usize;
            ready &= ready - 1;
            let slot_idx = word_idx * 64 + bit;
            let slot = &arena.slots[slot_idx];
            // Spurious wakes on freed slots are possible if an
            // external reference fires a stale waker after the task
            // completed. The used bitmap guards the slot's future
            // storage.
            if !arena.is_used(slot_idx) {
                continue;
            }
            did_work = true;
            // Cancellation beats polling: `TaskHandle::abort` set
            // the flag + flipped the ready bit to force us here.
            // Drop the future in place (on the owning worker, where
            // it's safe), bump the epoch so lingering handles
            // observe completion, then free the slot.
            if slot.abort.swap(false, Ordering::AcqRel) {
                // SAFETY: owning-worker-only access.
                unsafe {
                    *slot.future.get() = None;
                }
                slot.epoch.fetch_add(1, Ordering::AcqRel);
                arena.clear_used(slot_idx);
                crate::diag::COUNTERS.tasks_aborted.bump();
                continue;
            }
            crate::diag::bump_tasks_polled(worker_id);
            let __rt0 = now_cycles();
            poll_slot(arena, slot, worker_id, slot_idx);
            crate::diag::RUNTIME_CYCLES.add(worker_id, now_cycles().wrapping_sub(__rt0));
        }
    }
    did_work
}

/// Force-drop every live task in every worker's arena.
///
/// Called once from `waitless::shutdown_and_drop` after listener handles
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
    let n = worker::num_workers();
    for worker_id in 0..n {
        let arena = ARENAS.at(worker_id);
        for slot_idx in 0..TASKS_PER_WORKER {
            if !arena.is_used(slot_idx) {
                continue;
            }
            let slot = &arena.slots[slot_idx];
            // SAFETY: see fn-level comment — APs are post-eventloop-
            // break and not polling.
            unsafe {
                *slot.future.get() = None;
            }
            slot.epoch.fetch_add(1, Ordering::AcqRel);
            arena.clear_used(slot_idx);
            slot.abort.store(false, Ordering::Release);
        }
        // Clear ready bits across all words so a later spurious wake
        // observes nothing to do.
        for word in arena.ready_bits.iter() {
            word.store(0, Ordering::Release);
        }
    }
}

/// True if the worker has outstanding async work — either a
/// scheduled timer in its wheel or a task slot flagged ready.
pub fn has_pending(worker_id: u32) -> bool {
    if worker_id >= worker::num_workers() {
        return false;
    }
    // SAFETY: caller guarantees `worker_id` is the running worker.
    let cc = unsafe { CurrentWorker::from_id_unchecked(worker_id) };
    if crate::sleep::has_timers(&cc) {
        return true;
    }
    let arena = ARENAS.at(worker_id);
    arena
        .ready_bits
        .iter()
        .any(|w| w.load(Ordering::Acquire) != 0)
}

fn poll_slot(arena: &TaskArena, slot: &TaskSlot, worker_id: u32, slot_idx: usize) {
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
            arena.clear_used(slot_idx);
            crate::diag::COUNTERS.tasks_completed.bump();
        }
    }
}
