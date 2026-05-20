// crates/runtime/executor/src/launcher.rs — Per-worker "fire once per worker"
// launcher table.
//
// A `LaunchTable` holds type-erased closures. Each worker's
// event-loop tick calls `fire_pending` on the table; the first tick
// on each worker after a `register` observes the new launcher and
// invokes it on that worker. Typical launcher bodies call
// `crate::spawn(fut)` to spawn a per-worker task; the table is the
// coordination primitive that gets the same closure run on every
// worker exactly once without requiring the registrant to know how
// many workers exist or synchronize with their event loops.
//
// ## Storage
//
// Slots live in a two-level table: a fixed outer array of
// `NUM_CHUNKS` chunk pointers, each lazily pointing at a
// heap-allocated `Chunk` of `CHUNK_SIZE` slots. Total addressable
// capacity is `NUM_CHUNKS * CHUNK_SIZE` (1M today) — large enough
// that no realistic app hits it. Chunks are allocated on first
// registration into them, so a small app pays only the outer
// pointer array (8 KiB).
//
// Once a chunk is published it is permanent — the table never
// frees chunks, even if every slot in the chunk is later
// tombstoned. This keeps `fire_pending` lock-free and avoids ABA
// issues on the per-worker monotonic cursor.
//
// ## Ownership
//
//   * `register(l) -> usize` moves `l` into a heap cell and stores
//     the pointer into the next free slot. The returned slot index
//     is the handle for cleanup.
//   * `release(idx)` swaps in a tombstone sentinel and frees the
//     heap cell. Tombstones are skipped by `fire_pending` — the
//     slot is never reused (see below).
//
// Why slots are never reused: once `fire_pending` has advanced
// some worker's cursor past slot `i`, rewriting slot `i` with a
// new launcher would leak that launcher on that worker forever
// (the cursor never comes back). Keeping the counter monotonic
// makes the "each worker fires each slot at most once" invariant
// trivial. The total cap is therefore an upper bound on launchers
// ever allocated over the program's lifetime, not on live-at-once
// launchers — but at 1M slots that's effectively unbounded.
//
// Slot states (stored in `AtomicPtr<Launcher>`):
//   * `null`      — not yet stored. `register` is a two-step op
//                   (fetch_add then store); a reader that observes
//                   the bumped count but not the store stops here
//                   and retries on the next tick. Skipping-and-
//                   advancing would drop the registration.
//   * `TOMBSTONE` — previously live, released via `release`.
//                   Readers skip; cursor advances past permanently.
//   * anything else — `Box::into_raw(Box::new(Launcher{..}))`.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use worker::{PerWorker, num_workers};

/// Type-erased launcher closure. Captures any state needed for the
/// per-worker fan-out (typically `Arc`s shared with the owning
/// handle); the `Send + Sync` bounds cover cross-worker publication.
pub type Launcher = Box<dyn Fn() + Send + Sync + 'static>;

/// Number of chunk slots in the outer pointer array. Outer cost is
/// `NUM_CHUNKS * size_of::<*mut>()` paid upfront in BSS.
const NUM_CHUNKS: usize = 1024;

/// Slots per chunk. Chunks are heap-allocated on first registration
/// into them, so a small app pays only one chunk's worth.
const CHUNK_SIZE: usize = 1024;

/// Hard cap on launchers ever allocated. At 1M with single-listener-
/// per-second registration churn, the table would saturate in 11
/// days; realistic apps are nowhere near that.
const MAX_LAUNCHERS: usize = NUM_CHUNKS * CHUNK_SIZE;

struct Chunk {
    slots: [AtomicPtr<Launcher>; CHUNK_SIZE],
}

impl Chunk {
    fn new() -> Self {
        Chunk {
            slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; CHUNK_SIZE],
        }
    }
}

/// Per-worker fire-once launcher table. Const-constructible for use
/// in `static`s.
pub struct LaunchTable {
    /// Lazy chunk array. `chunks[c]` is null until the first
    /// registration into chunk `c` allocates and publishes it.
    /// Chunks are never freed.
    chunks: [AtomicPtr<Chunk>; NUM_CHUNKS],
    count: AtomicUsize,
    /// Per-worker fired cursor. Lazy-init on first `fire_pending`
    /// — the BSP path goes through here too, so we can't rely on
    /// boot to have called an explicit init.
    fired: PerWorker<AtomicUsize>,
}

// SAFETY: all mutable state is behind atomics. `Launcher` carries
// its own `Send + Sync` bounds.
unsafe impl Sync for LaunchTable {}

impl Default for LaunchTable {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn tombstone() -> *mut Launcher {
    // Any non-null pointer that can't collide with a real
    // `Box::into_raw` result. `ptr::dangling_mut` returns a pointer
    // whose address is `align_of::<Launcher>()`, which is bogus for
    // a heap allocation (no real heap object lives at the alignment
    // value alone) — and gives clippy a happy `manual_dangling_ptr`-
    // free idiom.
    core::ptr::dangling_mut::<Launcher>()
}

#[inline]
fn is_tombstone(p: *mut Launcher) -> bool {
    p == core::ptr::dangling_mut::<Launcher>()
}

impl LaunchTable {
    pub const fn new() -> Self {
        LaunchTable {
            chunks: [const { AtomicPtr::new(core::ptr::null_mut()) }; NUM_CHUNKS],
            count: AtomicUsize::new(0),
            fired: PerWorker::new(),
        }
    }

    /// Get-or-allocate the chunk at `chunk_idx`. First writer wins;
    /// concurrent losers free their unused chunk and adopt the
    /// winner. Returns a permanent pointer — chunks are never freed.
    fn get_or_alloc_chunk(&self, chunk_idx: usize) -> *mut Chunk {
        let slot = &self.chunks[chunk_idx];
        let p = slot.load(Ordering::Acquire);
        if !p.is_null() {
            return p;
        }
        let new_ptr = Box::into_raw(Box::new(Chunk::new()));
        match slot.compare_exchange(
            core::ptr::null_mut(),
            new_ptr,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new_ptr,
            Err(existing) => {
                // Lost the race. SAFETY: `new_ptr` was just produced
                // by `Box::into_raw` and never published anywhere.
                unsafe {
                    drop(Box::from_raw(new_ptr));
                }
                existing
            }
        }
    }

    /// Register `launcher`. Returns the slot index for later
    /// `release`, or `usize::MAX` if the table is full (the
    /// launcher is dropped — the caller's handle is still valid
    /// but the closure never fires on any worker).
    pub fn register(&self, launcher: Launcher) -> usize {
        // Eagerly size the per-worker cursor table on first
        // registration — every worker tick reads it via
        // `fire_pending`, and we want that path branch-free.
        // `ensure_init` is idempotent + race-safe.
        self.fired
            .ensure_init(num_workers(), |_| AtomicUsize::new(0));
        let i = self.count.fetch_add(1, Ordering::AcqRel);
        if i >= MAX_LAUNCHERS {
            return usize::MAX;
        }
        let chunk_idx = i / CHUNK_SIZE;
        let slot_idx = i % CHUNK_SIZE;
        let chunk_ptr = self.get_or_alloc_chunk(chunk_idx);
        // SAFETY: `get_or_alloc_chunk` returns a pointer that stays
        // valid for the program's lifetime.
        let chunk = unsafe { &*chunk_ptr };
        let outer: Box<Launcher> = Box::new(launcher);
        chunk.slots[slot_idx].store(Box::into_raw(outer), Ordering::Release);
        i
    }

    /// Release the slot for `idx` — swap a tombstone in and free
    /// the heap cell. `fire_pending` skips the slot; the cursor
    /// advances past it on the next visit.
    pub fn release(&self, idx: usize) {
        if idx >= MAX_LAUNCHERS {
            return;
        }
        let chunk_idx = idx / CHUNK_SIZE;
        let slot_idx = idx % CHUNK_SIZE;
        let chunk_ptr = self.chunks[chunk_idx].load(Ordering::Acquire);
        if chunk_ptr.is_null() {
            // The chunk for this index was never allocated, so the
            // slot was never written. Nothing to free.
            return;
        }
        // SAFETY: chunks are never freed once published.
        let chunk = unsafe { &*chunk_ptr };
        let prev = chunk.slots[slot_idx].swap(tombstone(), Ordering::AcqRel);
        if prev.is_null() || is_tombstone(prev) {
            return;
        }
        // SAFETY: every non-null non-tombstone pointer was produced
        // by `Box::into_raw(Box::new(Launcher{..}))` in `register`.
        // We own it exclusively now — the swap removed it from the
        // shared table.
        unsafe {
            let _ = Box::from_raw(prev);
        }
    }

    /// Invoke every launcher registered since `worker_id` last
    /// called here. A no-op when the per-worker cursor is already
    /// caught up (the common case). Safe to call from any worker
    /// concurrently with `register` / `release`.
    pub fn fire_pending(&self, worker_id: u32) {
        if worker_id >= num_workers() {
            return;
        }
        // No `register()` ever called → no slots to walk and the
        // cursor table is uninitialised. Hot-path tick exits here.
        let total = self.count.load(Ordering::Acquire).min(MAX_LAUNCHERS);
        if total == 0 {
            return;
        }
        let fired_slot = self.fired.at(worker_id);
        let fired = fired_slot.load(Ordering::Relaxed);
        if fired >= total {
            return;
        }
        let mut new_fired = fired;
        for i in fired..total {
            let chunk_idx = i / CHUNK_SIZE;
            let slot_idx = i % CHUNK_SIZE;
            let chunk_ptr = self.chunks[chunk_idx].load(Ordering::Acquire);
            if chunk_ptr.is_null() {
                // Chunk allocation mid-flight (count bumped but
                // chunk pointer not yet published). Stop; retry on
                // next tick.
                break;
            }
            // SAFETY: chunks are never freed once published.
            let chunk = unsafe { &*chunk_ptr };
            let p = chunk.slots[slot_idx].load(Ordering::Acquire);
            if p.is_null() {
                // Registration mid-flight (fetch_add done, store
                // not yet visible). Stop; retry on next tick.
                break;
            }
            if is_tombstone(p) {
                // Released. Skip + advance; never retouched.
                new_fired = i + 1;
                continue;
            }
            // SAFETY: `p` came from `Box::into_raw(Box::new(
            // Launcher{..}))` and stays valid until `release`
            // swaps in a tombstone (detected above). The swap is
            // AcqRel so we see a consistent snapshot.
            let launcher: &Launcher = unsafe { &*p };
            launcher();
            new_fired = i + 1;
        }
        if new_fired > fired {
            fired_slot.store(new_fired, Ordering::Relaxed);
        }
    }
}
