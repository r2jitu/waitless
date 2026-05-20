// uni-worker/src/lib.rs — Cross-platform per-worker primitives.
//
// Three types, picked deliberately so the names tell the whole story:
//
// `CurrentWorker` — zero-sized token whose existence proves the holder
// is running on a specific worker (core on bare-metal, POSIX thread
// on native). `!Send + !Sync` so it cannot migrate. Obtained via
// `CurrentWorker::enter()`, which calls `platform::current_worker()`
// directly — cfg-gated asm on bare-metal, thread-local on native.
//
// `PerWorker<T>` — typed array of slots indexed by worker id, sized at
// runtime via `init(n, |i| …)`. Heap-allocated once at boot after the
// actual worker count is known, then read-shared from every worker.
// Use when `T` provides its own interior mutability (`Atomic*`,
// `Mutex`, SPSC ring, …) — `current(&cc)` returns `&T` and `T`'s
// own primitives serialise concurrent access.
//
// `WorkerLocal<T>` — combines `PerWorker` indexing with owner-only
// mutable access. Use when `T` is a plain (non-`Sync`) type and only
// the owning worker ever mutates it. The `with_mut(&cc, |t| …)` API
// is safe by construction: the cell lives in this worker's slot
// (PerWorker indexing), and `&CurrentWorker` proves the caller is on
// that worker. Replaces the `PerWorker<UnsafeCell<T>>` +
// hand-rolled `unsafe { &mut *cell.get() }` pattern.
//
// `kernel::percpu::PerCore` is *not* a fourth abstraction — it's the
// kernel's domain struct (RxInbox, TxStaging, …) that happens to live
// inside `PerWorker<PerCore>`. Read it as "the bare-metal name for
// 'per-worker state'."

#![no_std]

extern crate alloc;

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

pub mod once;
pub mod timer;

pub use once::InitOnce;

/// Number of workers configured for this run. Set once during boot
/// (BSP, after detecting CPU count) and read shared by every worker
/// thereafter. Used as the canonical N for any `PerWorker<T>::init(N, …)`
/// call so all per-worker structures agree on size.
static NUM_WORKERS: AtomicU32 = AtomicU32::new(0);

/// Set the worker count. Must be called exactly once during boot
/// before any `PerWorker<T>::init` runs. Subsequent calls are
/// no-ops to keep the boot sequence robust against double-calls
/// from quirky bootloaders.
pub fn set_num_workers(n: u32) {
    let _ = NUM_WORKERS.compare_exchange(0, n, Ordering::Release, Ordering::Relaxed);
}

/// Return the configured worker count, or 0 if `set_num_workers`
/// hasn't run yet (callers gate on this; we don't panic so very-
/// early boot diagnostics can still log).
#[inline]
pub fn num_workers() -> u32 {
    NUM_WORKERS.load(Ordering::Acquire)
}

// ============================================================================
// CurrentWorker — ZST proof-of-current-worker token.
// ============================================================================

/// Token proving that the holder is currently running on the worker
/// named by `id()`. Cannot be sent to or shared with another
/// thread / core (`!Send + !Sync` via `PhantomData<*mut ()>`), so
/// its existence carries a strict happens-on-this-worker invariant.
#[derive(Clone, Copy)]
pub struct CurrentWorker {
    id: u32,
    _not_send: PhantomData<*mut ()>,
}

impl CurrentWorker {
    /// Read the current worker id from `platform` and bind it
    /// into a token.
    #[inline(always)]
    pub fn enter() -> Self {
        CurrentWorker {
            id: platform::current_worker(),
            _not_send: PhantomData,
        }
    }

    /// Construct a token from a worker id the caller already knows
    /// matches the current worker (e.g. threaded through from an
    /// event-loop callback dispatch). Saves the `platform` read.
    ///
    /// SAFETY: caller must guarantee that `id == platform::
    /// current_worker()` at the time of the call AND that the token
    /// does not outlive the iteration (which can never cross threads
    /// because `CurrentWorker` is `!Send`).
    #[inline(always)]
    pub unsafe fn from_id_unchecked(id: u32) -> Self {
        CurrentWorker {
            id,
            _not_send: PhantomData,
        }
    }

    /// The worker id this token represents.
    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.id
    }
}

// ============================================================================
// PerWorker<T> — typed per-worker array, runtime-sized.
// ============================================================================
//
// Slot array is heap-allocated once via `init(n, |i| T)` then read-shared
// from every worker. `T` provides its own interior mutability. The hot
// path is one Relaxed load of `slots` (an L1-cached AtomicPtr) — the
// pointer is `Release`-published and never changes after init, so the
// per-access cost matches a const-sized static within noise.

pub struct PerWorker<T> {
    /// Heap-allocated `[UnsafeCell<T>; len]`. Null until `init`.
    slots: AtomicPtr<UnsafeCell<T>>,
    /// Number of slots. Read-shared after `init`.
    len: AtomicU32,
}

// SAFETY: PerWorker provides shared (`&T`) access only. T is responsible
// for its own interior mutability (Atomic*, UnsafeCell, Mutex, …).
// We require T: Sync because cross-worker read access is shared, and
// T: Send because the slot is logically transferable between workers
// (though in practice each slot is owned by one worker).
unsafe impl<T: Sync + Send> Sync for PerWorker<T> {}

impl<T> PerWorker<T> {
    /// Construct an empty cell. Allocation happens later in `init()`.
    /// Const-callable so the cell can live in a `static`.
    #[inline]
    pub const fn new() -> Self {
        PerWorker {
            slots: AtomicPtr::new(core::ptr::null_mut()),
            len: AtomicU32::new(0),
        }
    }

    /// Allocate `n` slots and populate each via `f(i)`. Idempotent and
    /// safe to call concurrently — the first thread to win a CAS on
    /// the slot pointer publishes; losers free their allocation. The
    /// race-free flavour is what `LaunchTable::register` and the
    /// per-port `bind` paths in the UDP/TCP reactors rely on, so the
    /// CAS is load-bearing, not just defensive.
    pub fn init<F: FnMut(u32) -> T>(&self, n: u32, mut f: F) {
        if !self.slots.load(Ordering::Acquire).is_null() {
            return;
        }
        let count = n as usize;
        let layout = alloc::alloc::Layout::array::<UnsafeCell<T>>(count)
            .expect("PerWorker::init: layout overflow");
        // SAFETY: layout is non-zero (count >= 1 by contract), and
        // we treat the alloc as a raw `[UnsafeCell<T>]` we own
        // exclusively until the CAS below publishes it.
        let raw = unsafe { alloc::alloc::alloc(layout) as *mut UnsafeCell<T> };
        if raw.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        for i in 0..count {
            // SAFETY: writing into freshly-allocated, owned memory.
            unsafe {
                core::ptr::write(raw.add(i), UnsafeCell::new(f(i as u32)));
            }
        }
        // Publish via CAS so concurrent initialisers don't both
        // succeed and leak one allocation each. Set len BEFORE the
        // CAS — losers free without touching it, the winner's len
        // store happens-before any reader's Acquire on slots.
        self.len.store(n, Ordering::Release);
        if self
            .slots
            .compare_exchange(
                core::ptr::null_mut(),
                raw,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // Lost the race: drop our T's, free the alloc, observe
            // the winner via the next `at()` Acquire.
            for i in 0..count {
                // SAFETY: we wrote each slot above; nobody else has
                // observed `raw` because the CAS failed.
                unsafe {
                    core::ptr::drop_in_place(raw.add(i));
                }
            }
            // SAFETY: `raw` came from `alloc(layout)` and was never
            // published; we're the unique owner.
            unsafe {
                alloc::alloc::dealloc(raw as *mut u8, layout);
            }
        }
    }

    /// `init` if not already initialised — the call-site idiom for
    /// lazy per-listener `PerWorker`s (UDP/TCP reactors) and for
    /// the launcher table's per-worker fired cursor. The wrapper
    /// elides the `is_initialized` check at boot-time call sites
    /// that already know they're calling exactly once, but for
    /// lazy paths it makes the intent obvious.
    #[inline]
    pub fn ensure_init<F: FnMut(u32) -> T>(&self, n: u32, f: F) {
        if !self.is_initialized() {
            self.init(n, f);
        }
    }

    /// Get a shared reference to the slot for the current worker.
    /// Safe by construction: the `&CurrentWorker` token proves the
    /// caller's identity, and `T`'s interior mutability provides the
    /// actual mutation synchronisation.
    #[inline(always)]
    pub fn current(&self, cc: &CurrentWorker) -> &T {
        self.at(cc.id())
    }

    /// Get a shared reference to slot `id`. Safe at the reference
    /// level (T uses interior mutability); the caller is responsible
    /// for the per-worker ownership convention if they intend to
    /// mutate. Useful for cross-worker read access (e.g. worker 0
    /// walking every per-worker inbox).
    #[inline(always)]
    pub fn at(&self, id: u32) -> &T {
        let base = self.slots.load(Ordering::Relaxed);
        debug_assert!(!base.is_null(), "PerWorker::at before init");
        debug_assert!(
            id < self.len.load(Ordering::Relaxed),
            "PerWorker::at out-of-bounds"
        );
        // SAFETY: after `init` completes, `base` points at a valid
        // `[UnsafeCell<T>; len]` for the lifetime of the program.
        // `id < len` is the caller's invariant (typically guaranteed
        // by `cc.id() < num_workers()` at the boot site that set up
        // both this cell and the worker dispatcher).
        unsafe { &*(*base.add(id as usize)).get() }
    }

    /// Number of slots. Returns 0 before `init`.
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.len.load(Ordering::Relaxed)
    }

    /// True if `init` has been called.
    #[inline(always)]
    pub fn is_initialized(&self) -> bool {
        !self.slots.load(Ordering::Relaxed).is_null()
    }
}

impl<T> Drop for PerWorker<T> {
    fn drop(&mut self) {
        // Statics never drop, so this only runs for `PerWorker`s
        // owned by short-lived state — e.g. the per-listener
        // `handles` field inside `Arc<UdpFanoutCtx>` /
        // `Arc<TcpFanoutCtx>`. Without it, every reactor handle
        // drop leaked `num_workers * size_of::<T>` bytes.
        let raw = *self.slots.get_mut();
        if raw.is_null() {
            return;
        }
        let count = *self.len.get_mut() as usize;
        // SAFETY: we have `&mut self`, so no other thread can be
        // touching the cell. `raw` was produced by
        // `alloc::alloc::alloc` with `Layout::array::<UnsafeCell<T>>(count)`
        // in `init`, and every slot was populated.
        unsafe {
            for i in 0..count {
                core::ptr::drop_in_place(raw.add(i));
            }
            let layout = alloc::alloc::Layout::array::<UnsafeCell<T>>(count)
                .expect("PerWorker::drop: layout overflow");
            alloc::alloc::dealloc(raw as *mut u8, layout);
        }
    }
}

// ============================================================================
// WorkerLocal<T> — per-worker cell with safe owner-only mutable access.
// ============================================================================
//
// Wraps `PerWorker<UnsafeCell<T>>` with a closure-based API
// (`with_mut(&CurrentWorker, |t| …)`) that's safe by construction:
// the cell lives in this worker's slot (PerWorker indexing), and
// the `CurrentWorker` token proves the caller is on that worker.
// `CurrentWorker` is `!Send`, so no other worker can hold a borrow
// concurrently, and the closure scope guarantees no two calls
// produce overlapping `&mut T` even with multiple tokens in scope.
//
// Replaces the `PerWorker<UnsafeCell<T>>` + ad-hoc
// `unsafe { &mut *cell.get() }` pattern: one safe call site instead
// of one unsafe block per access. Use when `T` is a plain type and
// only the owning worker mutates it. For cross-worker-shared state
// where `T` provides its own interior mutability (atomics, SPSC
// rings, …), use `PerWorker<T>` directly.

pub struct WorkerLocal<T> {
    inner: PerWorker<UnsafeCell<T>>,
}

// SAFETY: cross-worker access is gated by the `with_mut` /
// `with` API, both of which take `&CurrentWorker` and bound the
// borrow to a closure. `T: Send` because the slot's logical owner
// is the worker the value was constructed for, even though in
// practice each value never moves.
unsafe impl<T: Send> Sync for WorkerLocal<T> {}

impl<T> WorkerLocal<T> {
    /// Empty cell. Allocation happens in `init()`.
    #[inline]
    pub const fn new() -> Self {
        WorkerLocal {
            inner: PerWorker::new(),
        }
    }

    /// Allocate `n` slots and populate each via `f(i)`. Same
    /// idempotent + race-free contract as `PerWorker::init`.
    pub fn init<F: FnMut(u32) -> T>(&self, n: u32, mut f: F) {
        self.inner.init(n, |i| UnsafeCell::new(f(i)));
    }

    /// `init` if not already initialised. Mirrors
    /// `PerWorker::ensure_init` for lazy-init call sites.
    #[inline]
    pub fn ensure_init<F: FnMut(u32) -> T>(&self, n: u32, mut f: F) {
        self.inner.ensure_init(n, |i| UnsafeCell::new(f(i)));
    }

    /// Mutate this worker's local value. The closure scope bounds
    /// the borrow so no two calls can produce overlapping `&mut T`,
    /// even if multiple `CurrentWorker` tokens are in scope.
    #[inline(always)]
    pub fn with_mut<R>(&self, cc: &CurrentWorker, f: impl FnOnce(&mut T) -> R) -> R {
        let cell: &UnsafeCell<T> = self.inner.current(cc);
        // SAFETY: PerWorker indexing → cell belongs to `cc`'s
        // worker; `CurrentWorker` is `!Send` so no other worker is
        // accessing it; the closure scope prevents overlap with
        // any concurrent same-worker call.
        unsafe { f(&mut *cell.get()) }
    }

    /// Shared borrow over this worker's local value. Same scoping
    /// guarantees as `with_mut`.
    #[inline(always)]
    pub fn with<R>(&self, cc: &CurrentWorker, f: impl FnOnce(&T) -> R) -> R {
        let cell: &UnsafeCell<T> = self.inner.current(cc);
        // SAFETY: see `with_mut`. Returning `&T` is also fine
        // because no other worker can be holding `&mut T`
        // concurrently (the type system rules it out via the same
        // !Send token argument).
        unsafe { f(&*cell.get()) }
    }

    /// True if `init` has been called.
    #[inline(always)]
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }
}
