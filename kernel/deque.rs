// kernel/deque.rs — Chase-Lev work-stealing deque.
//
// Lock-free deque for cooperative work stealing:
// - Owner pushes/pops from the "bottom" (LIFO, cache-friendly)
// - Thieves steal from the "top" (FIFO, single CAS)
//
// Fixed-size (no allocation), suitable for bare-metal.
// Based on "Dynamic Circular Work-Stealing Deque" (Chase & Lev, 2005)
// and the formal proof in Lê et al., "Correct and Efficient Work-Stealing
// for Weak Memory Models" (PPoPP'13).
//
// The version replaced here had two soundness bugs:
//
//   1. `push`/`pop` took `&mut self`, which is incompatible with the
//      `Deque` living inside a shared `&PerCore` reachable from any
//      core. Owner and thieves both needed shared access.
//
//   2. `pop` did not run the t==b CAS race resolution path: after
//      `if t <= b { return take(); }`, the `if t == b` branch below
//      was unreachable. Under concurrent pop+steal on a single-element
//      deque, both could "succeed" and return the same value. Tests
//      didn't catch it because they exercised pop and steal sequentially.
//
//   3. Slot accesses raced: `pop` mutated the slot via `Option::take()`
//      while `steal` read it via `read_volatile`. Even though the CAS
//      determines the winner, both threads touched the slot bytes
//      concurrently — a data race in the Rust memory model regardless
//      of which one ends up using the value.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Fixed capacity of the deque. Must be a power of 2.
const CAPACITY: usize = 256;
const MASK: usize = CAPACITY - 1;

/// A task stored in the deque. Opaque function pointer + context.
#[derive(Clone, Copy)]
pub struct Task {
    pub func: fn(usize),
    pub arg: usize,
}

/// Chase-Lev work-stealing deque.
///
/// Owner (single thread): `push` and `pop` from the bottom.
/// Thieves (any thread): `steal` from the top.
///
/// All three methods take `&self`. The owner/thief discipline is a
/// caller obligation (not enforced by the type system). `Sync` is
/// implemented unsafely below.
pub struct Deque {
    buffer: [UnsafeCell<MaybeUninit<Task>>; CAPACITY],
    bottom: AtomicUsize,
    top: AtomicUsize,
}

// SAFETY: shared access is sound under the Chase-Lev discipline:
//   * Slot writes happen only in `push`, by the single owner, and are
//     released to other cores via the `bottom` release-store.
//   * Slot reads in `pop` and `steal` are *copies* (Task: Copy); no
//     in-place mutation, so two readers cannot conflict, and the only
//     writer is the owner.
//   * The CAS on `top` resolves single-element races so that exactly
//     one of {owner-pop, thief-steal} is told it owns the value.
unsafe impl Sync for Deque {}

impl Deque {
    pub const fn new() -> Self {
        Deque {
            buffer: [const { UnsafeCell::new(MaybeUninit::uninit()) }; CAPACITY],
            bottom: AtomicUsize::new(0),
            top: AtomicUsize::new(0),
        }
    }

    /// Push a task onto the bottom (owner only). Returns false if full.
    pub fn push(&self, task: Task) -> bool {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        if b - t >= CAPACITY {
            return false; // full
        }
        // SAFETY: only the owner writes to slots. The slot at (b & MASK)
        // was previously either uninitialised or read-stale by a thief
        // whose CAS could no longer claim it (top has advanced past it
        // — otherwise the deque would have been full and we returned).
        unsafe { (*self.buffer[b & MASK].get()).write(task); }
        // Release: make the write visible before advancing bottom.
        self.bottom.store(b + 1, Ordering::Release);
        true
    }

    /// Pop a task from the bottom (owner only). Returns None if empty.
    pub fn pop(&self) -> Option<Task> {
        let b = self.bottom.load(Ordering::Relaxed);
        if b == 0 {
            return None;
        }
        let b = b - 1;
        self.bottom.store(b, Ordering::SeqCst);
        let t = self.top.load(Ordering::SeqCst);

        if t > b {
            // Empty. Restore bottom and bail.
            self.bottom.store(t, Ordering::Relaxed);
            return None;
        }

        // SAFETY: t <= b means slot (b & MASK) was published by some
        // earlier `push` and has not yet been claimed by a thief
        // (top hasn't advanced past it). Task is Copy, so reading it
        // does not affect the slot bytes — multiple readers (this pop
        // and a racing steal) cannot conflict.
        let task = unsafe { (*self.buffer[b & MASK].get()).assume_init_read() };

        if t < b {
            // Multiple elements: pop wins outright, no race possible.
            return Some(task);
        }

        // t == b: single element, race with a possible concurrent steal.
        // Resolve via CAS on top. Whichever side advances top owns the value.
        let result = self.top.compare_exchange(
            t,
            t + 1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
        // The deque is now logically empty regardless of the CAS outcome;
        // restore bottom to t+1 so the next push starts fresh.
        self.bottom.store(t + 1, Ordering::Relaxed);
        if result.is_ok() {
            Some(task)
        } else {
            // Stealer got it. Our copy is discarded (Task: Copy, no drop).
            None
        }
    }

    /// Steal a task from the top (any thread). Returns None if empty.
    pub fn steal(&self) -> Option<Task> {
        let t = self.top.load(Ordering::Acquire);
        let b = self.bottom.load(Ordering::Acquire);
        if t >= b {
            return None; // empty
        }
        // SAFETY: see pop(). Slot (t & MASK) was published by some push
        // and is read by copy; concurrent owner-pop on the same slot is
        // also a copy, so the bytes are accessed read-only by both sides.
        let task = unsafe { (*self.buffer[t & MASK].get()).assume_init_read() };
        // CAS to claim ownership of this slot.
        let result = self.top.compare_exchange(
            t,
            t + 1,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
        if result.is_ok() {
            Some(task)
        } else {
            None // another thief or the owner got it
        }
    }

    /// Number of tasks currently in the deque (best-effort snapshot).
    pub fn len(&self) -> usize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);
        if b >= t { b - t } else { 0 }
    }

    /// True if the deque is empty (best-effort snapshot).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop(_: usize) {}

    fn make_task(arg: usize) -> Task {
        Task { func: noop, arg }
    }

    #[test]
    fn push_pop_single() {
        let d = Deque::new();
        assert!(d.is_empty());
        assert!(d.push(make_task(42)));
        assert_eq!(d.len(), 1);
        let t = d.pop().unwrap();
        assert_eq!(t.arg, 42);
        assert!(d.is_empty());
    }

    #[test]
    fn push_pop_lifo() {
        let d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        // Pop is LIFO
        assert_eq!(d.pop().unwrap().arg, 3);
        assert_eq!(d.pop().unwrap().arg, 2);
        assert_eq!(d.pop().unwrap().arg, 1);
        assert!(d.pop().is_none());
    }

    #[test]
    fn steal_fifo() {
        let d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        // Steal is FIFO
        assert_eq!(d.steal().unwrap().arg, 1);
        assert_eq!(d.steal().unwrap().arg, 2);
        assert_eq!(d.steal().unwrap().arg, 3);
        assert!(d.steal().is_none());
    }

    #[test]
    fn mixed_pop_and_steal() {
        let d = Deque::new();
        d.push(make_task(1));
        d.push(make_task(2));
        d.push(make_task(3));
        d.push(make_task(4));
        // Steal takes from top (FIFO), pop from bottom (LIFO)
        assert_eq!(d.steal().unwrap().arg, 1); // top
        assert_eq!(d.pop().unwrap().arg, 4);   // bottom
        assert_eq!(d.steal().unwrap().arg, 2); // next from top
        assert_eq!(d.pop().unwrap().arg, 3);   // next from bottom
        assert!(d.is_empty());
    }

    #[test]
    fn pop_empty() {
        let d = Deque::new();
        assert!(d.pop().is_none());
    }

    #[test]
    fn steal_empty() {
        let d = Deque::new();
        assert!(d.steal().is_none());
    }

    #[test]
    fn capacity_full() {
        let d = Deque::new();
        for i in 0..CAPACITY {
            assert!(d.push(make_task(i)));
        }
        assert!(!d.push(make_task(999))); // full
        assert_eq!(d.len(), CAPACITY);
    }

    #[test]
    fn wrap_around() {
        let d = Deque::new();
        // Fill and drain a few times to exercise wrap-around
        for round in 0..3 {
            for i in 0..100 {
                assert!(d.push(make_task(round * 100 + i)));
            }
            for i in (0..100).rev() {
                assert_eq!(d.pop().unwrap().arg, round * 100 + i);
            }
            assert!(d.is_empty());
        }
    }

    /// Concurrent owner pop vs many thieves stealing. The deque is
    /// continuously refilled by the owner. Each task value is unique;
    /// at the end, every task must have been delivered exactly once
    /// (no duplicates, no losses) — this catches the t==b race bug
    /// where pop and steal could both claim the same single element.
    #[test]
    fn concurrent_pop_steal_no_dup() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        const N_THIEVES: usize = 4;
        const N_TASKS: usize = 50_000;

        let d = Arc::new(Deque::new());
        let collected: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::with_capacity(N_TASKS)));

        // Spawn thieves first so they're racing immediately.
        let thieves: Vec<_> = (0..N_THIEVES)
            .map(|_| {
                let d = Arc::clone(&d);
                let collected = Arc::clone(&collected);
                thread::spawn(move || {
                    let mut local = Vec::new();
                    loop {
                        if let Some(task) = d.steal() {
                            local.push(task.arg);
                        } else {
                            // Bail when the owner has finished AND the deque is empty.
                            // The owner stores usize::MAX as a sentinel after the last push.
                            if d.is_empty() && OWNER_DONE.load(Ordering::Acquire) {
                                break;
                            }
                            std::thread::yield_now();
                        }
                    }
                    collected.lock().unwrap().extend(local);
                })
            })
            .collect();

        // Owner pushes N_TASKS tasks, popping some itself along the way.
        let mut owner_collected = Vec::new();
        let mut pushed = 0;
        while pushed < N_TASKS {
            // Push a small burst, then pop a few from the bottom.
            for _ in 0..16 {
                if pushed >= N_TASKS { break; }
                while !d.push(make_task(pushed)) {
                    // Full — drain a few via owner pop.
                    if let Some(t) = d.pop() {
                        owner_collected.push(t.arg);
                    } else {
                        std::thread::yield_now();
                    }
                }
                pushed += 1;
            }
            // Owner LIFO pops to simulate cooperative scheduling.
            if let Some(t) = d.pop() {
                owner_collected.push(t.arg);
            }
        }
        // Drain anything the owner can still pop locally.
        while let Some(t) = d.pop() {
            owner_collected.push(t.arg);
        }
        OWNER_DONE.store(true, Ordering::Release);

        for th in thieves { th.join().unwrap(); }

        // Combine results.
        let mut all: Vec<usize> = collected.lock().unwrap().clone();
        all.extend(owner_collected);
        let unique: HashSet<usize> = all.iter().copied().collect();

        // Every task delivered exactly once.
        assert_eq!(all.len(), N_TASKS, "lost or duplicated tasks");
        assert_eq!(unique.len(), N_TASKS, "duplicate task arg observed");
        for v in 0..N_TASKS {
            assert!(unique.contains(&v), "task {} missing", v);
        }
        // Reset for any subsequent test invocations.
        OWNER_DONE.store(false, Ordering::Release);
    }

    static OWNER_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
}
