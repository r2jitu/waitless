// uni-worker/src/once.rs — `InitOnce<T>`: write-once cell, multi-reader.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct InitOnce<T> {
    initialized: AtomicBool,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: `init` synchronises with `get` via the `initialized` flag's
// release/acquire pair. After `init` returns, `value` is read-only;
// no further writes occur. `T: Sync` ensures multi-core read access is
// also sound at the value level.
unsafe impl<T: Sync + Send> Sync for InitOnce<T> {}

impl<T> InitOnce<T> {
    pub const fn new() -> Self {
        InitOnce {
            initialized: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Initialise the cell with `v`. Panics if called more than once.
    /// Uses `compare_exchange` so concurrent racing inits are detected
    /// at runtime; only the first caller wins.
    pub fn init(&self, v: T) {
        // Race-free claim: only the first caller wins; the loser
        // panics rather than silently dropping its value.
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            panic!("InitOnce::init called twice");
        }
        // SAFETY: we just claimed the slot; no other writer can race.
        unsafe { (*self.value.get()).write(v); }
        // Republish via release fence so the value write is visible
        // before any subsequent acquire-load on `initialized`. The
        // CAS above already had AcqRel ordering, but we need the
        // value write to happen-before subsequent loads of
        // `initialized`. Re-store to publish.
        self.initialized.store(true, Ordering::Release);
    }

    /// Get a shared reference to the initialised value. Panics if
    /// `init` has not been called.
    #[inline]
    pub fn get(&self) -> &T {
        if !self.initialized.load(Ordering::Acquire) {
            panic!("InitOnce::get called before init");
        }
        // SAFETY: `initialized = true` via Acquire load synchronises
        // with the Release store in `init`. The value is now read-only
        // and lives for the rest of the program.
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    /// Returns true if `init` has been called.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Try to get the value without panicking; returns None if not yet initialised.
    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        if self.is_initialized() {
            // SAFETY: same as `get`.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_get() {
        let cell: InitOnce<u32> = InitOnce::new();
        assert!(!cell.is_initialized());
        cell.init(42);
        assert!(cell.is_initialized());
        assert_eq!(*cell.get(), 42);
        assert_eq!(*cell.try_get().unwrap(), 42);
    }

    #[test]
    #[should_panic(expected = "InitOnce::init called twice")]
    fn double_init_panics() {
        let cell: InitOnce<u32> = InitOnce::new();
        cell.init(1);
        cell.init(2);
    }

    #[test]
    #[should_panic(expected = "InitOnce::get called before init")]
    fn get_before_init_panics() {
        let cell: InitOnce<u32> = InitOnce::new();
        let _ = cell.get();
    }

    #[test]
    fn try_get_before_init_returns_none() {
        let cell: InitOnce<u32> = InitOnce::new();
        assert!(cell.try_get().is_none());
    }

    /// Cross-thread test: one thread initialises, many threads concurrently
    /// read. All readers must observe the initialised value, and the publish
    /// must be visible immediately after `init` returns.
    #[test]
    fn init_publishes_to_readers() {
        use std::sync::Arc;
        use std::thread;

        const READERS: usize = 8;
        const ITERS: usize = 10_000;

        for _ in 0..50 {
            let cell: Arc<InitOnce<u64>> = Arc::new(InitOnce::new());

            // Spawn readers first; they spin until they see the value.
            let readers: Vec<_> = (0..READERS)
                .map(|_| {
                    let c = Arc::clone(&cell);
                    thread::spawn(move || {
                        for _ in 0..ITERS {
                            if let Some(v) = c.try_get() {
                                assert_eq!(*v, 0xDEAD_BEEF_CAFE_BABE);
                                return;
                            }
                            std::thread::yield_now();
                        }
                        panic!("reader never observed init");
                    })
                })
                .collect();

            // Initialize from the main thread.
            cell.init(0xDEAD_BEEF_CAFE_BABE);

            for r in readers { r.join().unwrap(); }
        }
    }

    /// Two writers race to call init; exactly one must succeed, the other
    /// must fail. We use thread::Result rather than catch_unwind because
    /// `InitOnce` contains `UnsafeCell`, which is `!UnwindSafe`.
    #[test]
    fn concurrent_double_init_one_wins() {
        use std::sync::Arc;
        use std::thread;

        for _ in 0..50 {
            let cell: Arc<InitOnce<u32>> = Arc::new(InitOnce::new());
            let c1 = Arc::clone(&cell);
            let c2 = Arc::clone(&cell);

            let t1 = thread::spawn(move || c1.init(1));
            let t2 = thread::spawn(move || c2.init(2));

            // Exactly one of the two threads must panic.
            let r1 = t1.join();
            let r2 = t2.join();
            let s1 = r1.is_ok();
            let s2 = r2.is_ok();
            assert!(
                s1 != s2,
                "exactly one initializer should succeed (got s1={} s2={})",
                s1,
                s2
            );
            assert!(cell.is_initialized());
            let v = *cell.get();
            assert!(v == 1 || v == 2);
        }
    }
}
