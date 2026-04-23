// uni-percpu/src/lib.rs — Cross-platform per-worker primitives.
//
// `CurrentCore` — zero-sized token whose existence proves the holder
// is running on a specific worker (core on bare-metal, POSIX thread
// on native). Obtained via `CurrentCore::enter()`, which reads the
// backend's `uni_percpu_current_worker` hook (TPIDR_EL1 / GS_BASE /
// pthread TLS depending on target).
//
// `PerCpu<T, N>` — typed array of `N` slots indexed by worker id.
// Returns a shared `&T`; `T` is responsible for its own interior
// mutability (`Atomic*`, `UnsafeCell` behind owning-worker discipline,
// `Mutex`, …). The `&CurrentCore` accessor is safe by construction
// because the token's existence proves we're on a specific worker.

#![no_std]

use core::cell::UnsafeCell;
use core::marker::PhantomData;

/// Maximum workers supported by the shared runtime. Bare-metal sets
/// `MAX_CORES` to the same value; native treats this as a ceiling on
/// thread-pool size.
pub const MAX_WORKERS: usize = 8;

// ---- Backend hook ---------------------------------------------------------
//
// Provided by the backend crate via `#[unsafe(no_mangle)] pub extern
// "C" fn uni_percpu_current_worker(...)`. Only one backend links into
// any binary, so there's no symbol collision.

unsafe extern "C" {
    fn uni_percpu_current_worker() -> u32;
}

// ============================================================================
// CurrentCore — ZST proof-of-current-worker token.
// ============================================================================

/// Token proving that the holder is currently running on the worker
/// named by `id()`. Cannot be sent to or shared with another
/// thread / core (`!Send + !Sync` via `PhantomData<*mut ()>`), so
/// its existence carries a strict happens-on-this-worker invariant.
#[derive(Clone, Copy)]
pub struct CurrentCore {
    id: u32,
    _not_send: PhantomData<*mut ()>,
}

impl CurrentCore {
    /// Read the current worker id from the backend and bind it into
    /// a token. Cheap — on bare-metal this inlines to one MRS /
    /// `mov gs:[…]`; on native it's a `pthread_getspecific` call.
    #[inline(always)]
    pub fn enter() -> Self {
        CurrentCore {
            // SAFETY: the hook is unconditionally available after the
            // backend has initialised (which happens before any user
            // code runs).
            id: unsafe { uni_percpu_current_worker() },
            _not_send: PhantomData,
        }
    }

    /// Construct a token from a worker id the caller already knows
    /// matches the current worker (e.g. threaded through from an
    /// event-loop callback dispatch). Saves the hook call.
    ///
    /// SAFETY: caller must guarantee that `id == uni_percpu_current_worker()`
    /// at the time of the call AND that the token does not outlive
    /// the iteration (which can never cross threads because
    /// `CurrentCore` is `!Send`).
    #[inline(always)]
    pub unsafe fn from_id_unchecked(id: u32) -> Self {
        CurrentCore {
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
// PerCpu<T, N> — typed per-worker array.
// ============================================================================
//
// N slots of T, each wrapped in `UnsafeCell<T>` so the same `&PerCpu`
// can hand out references to different slots. `T` is responsible for
// its own interior mutability.

/// Typed per-worker array of `N` slots of `T`.
#[repr(transparent)]
pub struct PerCpu<T, const N: usize> {
    slots: [UnsafeCell<T>; N],
}

// SAFETY: PerCpu provides shared (`&T`) access only. T is responsible
// for its own interior mutability (Atomic*, UnsafeCell, Mutex, …).
// We require T: Sync because cross-worker read access is shared, and
// T: Send because the slot is logically transferable between workers
// (though in practice each slot is owned by one worker).
unsafe impl<T: Sync + Send, const N: usize> Sync for PerCpu<T, N> {}

impl<T, const N: usize> PerCpu<T, N> {
    /// Construct from an array of N initial values. Const-callable so
    /// the array can live in a `static`.
    #[inline]
    pub const fn new(values: [T; N]) -> Self {
        // Convert [T; N] → [UnsafeCell<T>; N] field-by-field via ptr
        // copy. This is the only way to do the conversion in const
        // context as of stable Rust. SAFETY: UnsafeCell<T> is
        // #[repr(transparent)] over T, so the layouts match exactly.
        let cells: [UnsafeCell<T>; N] = unsafe {
            let cells = core::mem::ManuallyDrop::new(values);
            core::ptr::read(&cells as *const _ as *const [UnsafeCell<T>; N])
        };
        PerCpu { slots: cells }
    }

    /// Get a shared reference to the slot for the current worker.
    /// Safe by construction: the `&CurrentCore` token proves the
    /// caller's identity, and `T`'s interior mutability provides the
    /// actual mutation synchronisation.
    #[inline(always)]
    pub fn current(&self, cc: &CurrentCore) -> &T {
        // SAFETY: cc.id() is the calling worker's id; reading from
        // the slot returns a `&T` whose mutation discipline is T's
        // job. PerCpu just guarantees that two different workers get
        // different slots.
        unsafe { &*self.slots[cc.id() as usize].get() }
    }

    /// Get a shared reference to slot `id`. Safe at the reference
    /// level (T uses interior mutability); the caller is responsible
    /// for the per-worker ownership convention if they intend to
    /// mutate. Useful for cross-worker read access (e.g. worker 0
    /// walking every per-worker inbox).
    #[inline(always)]
    pub fn at(&self, id: u32) -> &T {
        // SAFETY: same as current(); cross-worker access is sound at
        // the reference level because T provides its own
        // synchronisation.
        unsafe { &*self.slots[id as usize].get() }
    }

    /// Number of slots.
    #[inline(always)]
    pub const fn len(&self) -> usize {
        N
    }
}
