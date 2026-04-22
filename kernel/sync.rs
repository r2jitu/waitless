// kernel/sync.rs — `Spinlock<T>`: typed RAII spinlock for shared mutable state.
//
// `Spinlock<T>` owns the protected data and hands out access only through a
// guard:
//
//   * `Spinlock::new(value)` consumes `value`. The only way to reach the
//     interior is `lock() -> SpinlockGuard<T>`, which derefs to `&mut T`.
//   * The guard is RAII — `Drop::drop` releases the lock. There is no
//     `unlock()` API, so paired lock/unlock bugs are impossible.
//   * The guard is `!Send` (`PhantomData<*mut ()>`), so it cannot leak
//     across cores.
//
// Layout is `repr(C)` over an `AtomicBool` flag and an `UnsafeCell<T>`.
// `lock()` inlines to a CAS loop, `Drop` inlines to one
// `store(false, Release)`, and field access through the guard compiles
// to the same code as a raw `*mut T` dereference.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A typed RAII spinlock guarding interior `T`.
pub struct Spinlock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: Spinlock<T> provides exclusive access via the lock; the
// guard's lifetime ensures only one `&mut T` exists at a time. T must
// be Send because it's logically transferred between cores when the
// lock is acquired on different cores.
unsafe impl<T: Send> Sync for Spinlock<T> {}
unsafe impl<T: Send> Send for Spinlock<T> {}

impl<T> Spinlock<T> {
    /// Construct a new spinlock around `value`. Const-callable so the
    /// lock can live in a `static`.
    #[inline]
    pub const fn new(value: T) -> Self {
        Spinlock {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, spinning until it's free. Returns a guard that
    /// releases the lock automatically on drop.
    #[inline]
    pub fn lock(&self) -> SpinlockGuard<'_, T> {
        // CAS-based spin: standard pattern. compare_exchange_weak is
        // cheaper than the strong variant on architectures where the
        // cache line ping-pongs (it can fail spuriously, which is fine
        // here since we're already in a loop).
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            // Backoff: hint to the CPU that we're spin-waiting.
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinlockGuard {
            lock: self,
            _not_send: core::marker::PhantomData,
        }
    }

    /// Try to acquire the lock without spinning. Returns `None` if
    /// another holder has it. Useful for paths that prefer to bail out
    /// rather than wait (e.g., the TX flush path that returns and lets
    /// the next poll cycle retry).
    #[inline]
    pub fn try_lock(&self) -> Option<SpinlockGuard<'_, T>> {
        let acquired = self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok();
        if acquired {
            Some(SpinlockGuard {
                lock: self,
                _not_send: core::marker::PhantomData,
            })
        } else {
            None
        }
    }

    /// Get a raw pointer to the inner value. SAFETY: caller must ensure
    /// no concurrent access. Used by code that wants to bypass the lock
    /// for known-single-threaded init paths (rare; almost always wrong
    /// to use).
    #[inline]
    pub fn as_mut_ptr(&self) -> *mut T {
        self.value.get()
    }
}

/// RAII guard returned by `Spinlock::lock` / `try_lock`. Releases the
/// lock on `Drop`. `!Send` so the lock can't escape the acquiring core.
///
/// **Do not hold a `SpinlockGuard` across an `.await` point** when we
/// add async (ROADMAP §2g). A guard dropped across a suspension would
/// release the spinlock during the suspend, another task could acquire
/// it and progress, and the first task — which assumed the lock was
/// still held — would wake into a broken invariant. If you need to
/// hold shared state across an await, use an async-aware primitive
/// (a future-oriented mutex or channel) rather than this spinlock.
#[must_use = "if you want the lock to release immediately, drop the guard explicitly"]
pub struct SpinlockGuard<'a, T> {
    lock: &'a Spinlock<T>,
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl<'a, T> Deref for SpinlockGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: we hold the lock; no other accessor exists.
        unsafe { &*self.lock.value.get() }
    }
}

impl<'a, T> DerefMut for SpinlockGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: we hold the lock; no other accessor exists.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<'a, T> Drop for SpinlockGuard<'a, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// AtomicFn<F> — typed atomic function pointer
// ============================================================================
//
// The implementation lives in `//util:atomic_fn` (crate
// `atomic_fn`): `net_protocol`'s registry and `uni/lib.rs`'s native
// IO-poll slots share the same pattern but can't depend on `//kernel`
// without inheriting the RustCrypto / talc deps that break
// `rust_test`'s panic=unwind. A no-dep leaf crate gives every
// consumer the same type.
//
// Re-exported here so existing `kernel::sync::AtomicFn` imports
// keep resolving unchanged. Gated on `not(test)` so the
// `//kernel:sync_test` rust_test target (which compiles this file
// as a standalone `panic=unwind` binary and only exercises
// `Spinlock`) doesn't pull in the `atomic_fn` crate and hit the
// `panic=abort` vs `=unwind` mismatch.
#[cfg(not(test))]
pub use atomic_fn::AtomicFn;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_grants_exclusive_access() {
        let s: Spinlock<u32> = Spinlock::new(42);
        {
            let mut g = s.lock();
            *g += 1;
        }
        {
            let g = s.lock();
            assert_eq!(*g, 43);
        }
    }

    #[test]
    fn try_lock_succeeds_then_fails() {
        let s: Spinlock<u32> = Spinlock::new(0);
        let g = s.try_lock().expect("first try_lock should succeed");
        assert!(s.try_lock().is_none(), "second try_lock should fail");
        drop(g);
        assert!(s.try_lock().is_some(), "after drop, try_lock should succeed");
    }

    /// Cross-thread stress test: many threads each increment a shared
    /// counter under the lock. Final value must equal sum of increments.
    #[test]
    fn cross_thread_increments_are_serialised() {
        use std::sync::Arc;
        use std::thread;

        const THREADS: usize = 16;
        const ITERS: usize = 10_000;

        let s: Arc<Spinlock<u64>> = Arc::new(Spinlock::new(0));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        let mut g = s.lock();
                        *g += 1;
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let g = s.lock();
        assert_eq!(*g, (THREADS * ITERS) as u64);
    }

    /// Cross-thread invariant test: a `Spinlock<(u64, u64)>` where the
    /// invariant is `a == b`. Threads atomically increment both fields
    /// under the lock; observers always see the invariant hold. If the
    /// lock were broken, an observer could see `a > b` for one cycle.
    #[test]
    fn cross_thread_invariant_holds() {
        use std::sync::Arc;
        use std::thread;

        const THREADS: usize = 8;
        const ITERS: usize = 10_000;

        let s: Arc<Spinlock<(u64, u64)>> = Arc::new(Spinlock::new((0, 0)));

        // Half writers, half observers.
        let writers: Vec<_> = (0..THREADS / 2)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        let mut g = s.lock();
                        g.0 += 1;
                        g.1 += 1;
                    }
                })
            })
            .collect();
        let observers: Vec<_> = (0..THREADS / 2)
            .map(|_| {
                let s = Arc::clone(&s);
                thread::spawn(move || {
                    for _ in 0..ITERS {
                        let g = s.lock();
                        assert_eq!(g.0, g.1, "invariant violated under lock");
                    }
                })
            })
            .collect();
        for h in writers { h.join().unwrap(); }
        for h in observers { h.join().unwrap(); }
        let g = s.lock();
        assert_eq!(g.0, ((THREADS / 2) * ITERS) as u64);
        assert_eq!(g.0, g.1);
    }
}
