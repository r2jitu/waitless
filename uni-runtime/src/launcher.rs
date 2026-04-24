// uni-runtime/src/launcher.rs — Per-worker "fire once per worker"
// launcher table.
//
// A `LaunchTable<N>` holds up to `N` type-erased closures. Each
// worker's event-loop tick calls `fire_pending` on the table; the
// first tick on each worker after a `register` observes the new
// launcher and invokes it on that worker. Typical launcher bodies
// call `crate::spawn(fut)` to spawn a per-worker task; the table
// is the coordination primitive that gets the same closure run on
// every worker exactly once without requiring the registrant to
// know how many workers exist or synchronize with their event
// loops.
//
// Ownership model:
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
// trivial. `N` is therefore an upper bound on launchers ever
// allocated over the program's lifetime, not on live-at-once
// launchers — size accordingly.
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

use uni_worker::MAX_WORKERS;

/// Type-erased launcher closure. Captures any state needed for the
/// per-worker fan-out (typically `Arc`s shared with the owning
/// handle); the `Send + Sync` bounds cover cross-worker publication.
pub type Launcher = Box<dyn Fn() + Send + Sync + 'static>;

/// Per-worker fire-once launcher table with up to `N` ever-allocated
/// slots. Const-constructible for use in `static`s.
///
/// `N` caps the total number of registrations over the program's
/// lifetime — released slots tombstone, they do not recycle. Size
/// with enough headroom for the registration rate × uptime of your
/// longest-running reactor.
pub struct LaunchTable<const N: usize> {
    slots: [AtomicPtr<Launcher>; N],
    count: AtomicUsize,
    fired: [AtomicUsize; MAX_WORKERS],
}

// SAFETY: all mutable state is behind atomics. `Launcher` carries
// its own `Send + Sync` bounds.
unsafe impl<const N: usize> Sync for LaunchTable<N> {}

#[inline]
fn tombstone() -> *mut Launcher {
    // Any non-null pointer that can't collide with a real
    // `Box::into_raw` result. All heap pointers are aligned to at
    // least the pointer size, so `1` is safe as a sentinel.
    1 as *mut Launcher
}

#[inline]
fn is_tombstone(p: *mut Launcher) -> bool {
    p as usize == 1
}

impl<const N: usize> LaunchTable<N> {
    pub const fn new() -> Self {
        LaunchTable {
            slots: [const { AtomicPtr::new(core::ptr::null_mut()) }; N],
            count: AtomicUsize::new(0),
            fired: [const { AtomicUsize::new(0) }; MAX_WORKERS],
        }
    }

    /// Register `launcher`. Returns the slot index for later
    /// `release`, or `usize::MAX` if the table is full (the
    /// launcher is dropped — the caller's handle is still valid
    /// but the closure never fires on any worker).
    pub fn register(&self, launcher: Launcher) -> usize {
        let i = self.count.fetch_add(1, Ordering::AcqRel);
        if i >= N {
            return usize::MAX;
        }
        let outer: Box<Launcher> = Box::new(launcher);
        self.slots[i].store(Box::into_raw(outer), Ordering::Release);
        i
    }

    /// Release the slot for `idx` — swap a tombstone in and free
    /// the heap cell. `fire_pending` skips the slot; the cursor
    /// advances past it on the next visit.
    pub fn release(&self, idx: usize) {
        if idx >= N {
            return;
        }
        let prev = self.slots[idx].swap(tombstone(), Ordering::AcqRel);
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
        if (worker_id as usize) >= MAX_WORKERS {
            return;
        }
        let total = self.count.load(Ordering::Acquire).min(N);
        let fired = self.fired[worker_id as usize].load(Ordering::Relaxed);
        if fired >= total {
            return;
        }
        let mut new_fired = fired;
        for i in fired..total {
            let p = self.slots[i].load(Ordering::Acquire);
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
            self.fired[worker_id as usize].store(new_fired, Ordering::Relaxed);
        }
    }
}
