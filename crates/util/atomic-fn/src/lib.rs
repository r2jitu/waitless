// util/atomic_fn/lib.rs — typed atomic function-pointer cell.
//
// `AtomicFn<F>` wraps an `AtomicUsize` holding the bit pattern of a
// function-pointer type `F`. Provides a type-safe `store(f)` /
// `load() -> Option<F>` API so call sites don't do raw pointer
// transmutes for every callback slot they want to publish.
//
// Used for the "publish a fn pointer once at boot, read it from any
// core later" pattern that recurs across the kernel / net / runtime.
// Extracted from `kernel_bare::sync` into its own crate so downstream
// consumers (`//net:protocol`, `//uni-net:driver`, `//uni:uni`
// native backend, future `//util:*` hosts) can depend on it
// without inheriting kernel's transitive deps (RustCrypto, talc,
// …) — those pull in `panic=abort` crates that collide with
// `panic=unwind` rust_tests.
//
// Semantics:
//   * `null()` — const-constructible, `None` on load.
//   * `store(f)` — Release. Publishes `f`; any later Acquire load
//     sees either the new `f` or a value stored even later.
//   * `load()` — Acquire. Returns `Some(f)` iff some `store(f)` has
//     happened-before this load (in the Rust-memory-model sense).
//
// Compile-time invariants: `F` must be pointer-sized and pointer-
// aligned. Both checked in `store` / `load` via `const { assert!(…) }`
// so mis-parameterisation fails at compile time instead of
// silently truncating under `transmute_copy`.

// `cfg_attr(not(test), no_std)` is the workspace-standard test
// pattern: the crate is `no_std` for every production build and
// flips to `std` only under `--test`, so the libtest harness has
// the `std` it needs. A `no_std` crate links fine as a
// `panic=unwind` dependency of another crate's `rust_test`, so no
// `feature`-gated std-flip is needed here.
#![cfg_attr(not(test), no_std)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Atomic, nullable, typed function-pointer cell.
///
/// `F` must be a function-pointer type (`fn(...) -> ...`). The
/// type system can't enforce that in stable Rust — there's no
/// `FnPtr` trait — so we instead assert pointer-sized + pointer-
/// aligned at the two methods that actually transmute. Passing a
/// non-fn-pointer `F` causes a compile-time error at the call
/// site.
pub struct AtomicFn<F: Copy> {
    bits: AtomicUsize,
    _phantom: PhantomData<fn() -> F>,
}

// SAFETY: `AtomicFn` only stores a fn-pointer bit pattern, which is
// `Copy` and pointer-sized; `AtomicUsize` provides cross-thread
// synchronisation. `F: Sync` / `Send` are implied by "F is a fn
// pointer" but the language doesn't let us express that without an
// unstable trait, so we assert at the crate level.
unsafe impl<F: Copy> Send for AtomicFn<F> {}
unsafe impl<F: Copy> Sync for AtomicFn<F> {}

impl<F: Copy> AtomicFn<F> {
    /// Create an empty cell. `load()` returns `None` until a
    /// `store(f)` publishes a value.
    #[inline]
    pub const fn null() -> Self {
        AtomicFn {
            bits: AtomicUsize::new(0),
            _phantom: PhantomData,
        }
    }

    /// Publish `f`. Any later `load()` on any thread observes
    /// either `Some(f)` or the value of a subsequent `store`.
    /// Release-ordered: writes the registrant made before `store(f)`
    /// are visible to any thread that subsequently observes
    /// `Some(f)` via `load()`.
    #[inline]
    pub fn store(&self, f: F) {
        const {
            assert!(
                core::mem::size_of::<F>() == core::mem::size_of::<usize>(),
                "AtomicFn<F>: F must be pointer-sized (a fn pointer)"
            );
            assert!(
                core::mem::align_of::<F>() == core::mem::align_of::<usize>(),
                "AtomicFn<F>: F must be pointer-aligned (a fn pointer)"
            );
        }
        // SAFETY: `F` is pointer-sized/aligned (asserted above) and,
        // by crate-doc contract, a fn-pointer type. fn pointers and
        // `usize` share representation on every target we support.
        let bits: usize = unsafe { core::mem::transmute_copy(&f) };
        self.bits.store(bits, Ordering::Release);
    }

    /// Load the published `F`, or `None` if no `store` has happened
    /// yet. Acquire-ordered against `store` for cross-thread
    /// happens-before.
    #[inline]
    pub fn load(&self) -> Option<F> {
        const {
            assert!(
                core::mem::size_of::<F>() == core::mem::size_of::<usize>(),
                "AtomicFn<F>: F must be pointer-sized (a fn pointer)"
            );
            assert!(
                core::mem::align_of::<F>() == core::mem::align_of::<usize>(),
                "AtomicFn<F>: F must be pointer-aligned (a fn pointer)"
            );
        }
        let bits = self.bits.load(Ordering::Acquire);
        if bits == 0 {
            None
        } else {
            // SAFETY: only `store(f)` writes to `bits`, and `f`'s
            // type is statically `F`. A non-zero bit pattern is
            // therefore a valid `F`.
            Some(unsafe { core::mem::transmute_copy(&bits) })
        }
    }

    /// Reset to the empty state. Release-ordered so a later
    /// `load()` observing `None` does so with a happens-before
    /// edge onto the write, not stale bit-pattern residue.
    ///
    /// Tests use this to reset between runs; production code
    /// typically stores once and never clears.
    #[inline]
    pub fn clear(&self) {
        self.bits.store(0, Ordering::Release);
    }

    /// Whether a handler is currently published.
    #[inline]
    pub fn is_some(&self) -> bool {
        self.bits.load(Ordering::Acquire) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Handler = fn(u32) -> u32;

    fn double(x: u32) -> u32 {
        x.wrapping_mul(2)
    }
    fn triple(x: u32) -> u32 {
        x.wrapping_mul(3)
    }

    #[test]
    fn null_loads_none() {
        let cell: AtomicFn<Handler> = AtomicFn::null();
        assert!(cell.load().is_none());
        assert!(!cell.is_some());
    }

    #[test]
    fn store_then_load_round_trip() {
        let cell: AtomicFn<Handler> = AtomicFn::null();
        cell.store(double);
        assert!(cell.is_some());
        let f = cell.load().expect("set above");
        assert_eq!(f(21), 42);
    }

    #[test]
    fn store_replaces_previous() {
        let cell: AtomicFn<Handler> = AtomicFn::null();
        cell.store(double);
        cell.store(triple);
        let f = cell.load().expect("set above");
        assert_eq!(f(10), 30);
    }

    #[test]
    fn clear_returns_to_none() {
        let cell: AtomicFn<Handler> = AtomicFn::null();
        cell.store(double);
        cell.clear();
        assert!(cell.load().is_none());
        assert!(!cell.is_some());
    }

    #[test]
    fn is_const_constructible() {
        // Sanity: `null()` is `const`, so `AtomicFn` can live in a
        // `static` without any late initialiser.
        static CELL: AtomicFn<Handler> = AtomicFn::null();
        assert!(CELL.load().is_none());
    }
}
