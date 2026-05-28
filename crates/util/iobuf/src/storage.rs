// crates/util/iobuf/src/storage.rs — the per-variant storage structs.
//
// Storage carries **bytes only** — the visible `(offset, len)` view
// lives on the outer `IOBuf` / `OwnedIOBuf`. Splitting storage from
// view sets up PR 3's `Shared` variant, where one `Arc<SharedRegion>`
// feeds many views via `Arc::clone` — the storage refcount stays put
// while each clone carries its own `(offset, len)` slider.
//
//   * `HeapStorage`   — heap-owned `Box<[u8]>`. `Send` (auto).
//   * `ExternalOwned` — a foreign region this storage owns via a drop
//                       callback (NIC zero-copy RX, pool slabs).
//                       `Send + Sync` via two localized `unsafe impl`s
//                       in this file — the genuine leaf assertions.
//   * `SharedRegion`  — refcounted backing wrapping either of the
//                       above; produced by `OwnedIOBuf::share()`.
//   * `BorrowedView`  — a non-owning view of foreign storage. The
//                       `PhantomData<*const ()>` makes it `!Send`,
//                       which is what taints the whole `IOBuf` enum
//                       `!Send` and keeps per-worker borrows from
//                       crossing workers.
//
// `HeapStorage`, `ExternalOwned`, and `SharedRegion` are the owning,
// `Send` set `OwnedIOBuf` is built from; `&'static [u8]` rides
// directly in an `OwnedStorage::Static` variant (`Send` via the
// `'static` lifetime). `BorrowedView` is the lone non-owning view —
// it only appears under `IOBuf`'s `Borrowed` variant.

use alloc::boxed::Box;
use core::marker::PhantomData;
use core::ptr::NonNull;

// The borrow tracker (`cfg(test)`-only aliasing detection for
// `BorrowedView`) and its `BorrowGuard` live at the *end* of this
// file: clippy's `items_after_test_module` treats any `#[cfg(test)]`
// module as a test module and wants production items before it.

/// Drop callback signature for [`ExternalOwned`]. Receives the
/// original `(base, capacity, ctx)` from `wrap_owned`, regardless
/// of how the IOBuf's offset/len shifted during its lifetime — the
/// consumer that gave us the buffer wants the whole region back
/// (e.g. a NIC descriptor index), not the shifted view. `unsafe`
/// because the impl reconstructs concrete types (`Box<[u8]>`,
/// descriptor index) from the raw pointers and must respect the
/// contract the caller of `wrap_owned` established.
pub type IOBufDropFn = unsafe fn(base: NonNull<u8>, capacity: u32, ctx: *mut ());

// ============================================================================
// HeapStorage — heap-owned `Box<[u8]>`.
// ============================================================================

/// Heap-owned byte storage. Bytes only; the visible `(offset, len)`
/// window is tracked on the outer `IOBuf` / `OwnedIOBuf`. `Send` by
/// auto-derivation — a `Box<[u8]>` is exclusively owned.
pub struct HeapStorage {
    storage: Box<[u8]>,
}

impl HeapStorage {
    /// Wrap an owned `Box<[u8]>`. The visible window is set by the
    /// outer `IOBuf` / `OwnedIOBuf`.
    pub(crate) fn new(storage: Box<[u8]>) -> Self {
        HeapStorage { storage }
    }

    /// Total bytes of the storage.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Full backing region.
    #[inline]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.storage
    }

    /// Mutable view of the full backing region. `Box<[u8]>` is
    /// exclusively owned, so `&mut self` is enough.
    #[inline]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.storage
    }
}

// ============================================================================
// ExternalOwned — a foreign region owned via a drop callback.
// ============================================================================

/// Externally-owned buffer with a drop callback. Canonical use
/// cases: NIC zero-copy RX (callback returns the descriptor to the
/// receive ring) and pool-backed buffers (callback pushes a slab
/// back to a free list). Bytes only — the visible `(offset, len)`
/// window lives on the outer `IOBuf` / `OwnedIOBuf`. The storage
/// isn't dropped — the callback fires instead, exactly once, with
/// the original `(base, capacity)`.
///
/// This is the genuine leaf where a raw region + drop_fn's
/// thread-safety is asserted (see the `unsafe impl Send` below) —
/// the *only* `unsafe impl Send` left in the crate.
pub struct ExternalOwned {
    /// Start of the underlying region.
    base: NonNull<u8>,
    /// Total bytes of the region (`base + capacity` is one past the
    /// end). The visible window is set by the outer IOBuf.
    capacity: u32,
    /// Release callback — always present for `ExternalOwned`
    /// (borrowed views with no callback are [`BorrowedView`]).
    drop_fn: IOBufDropFn,
    /// Opaque context passed to `drop_fn`. Typically a raw `*mut`
    /// pointer the caller cast from an `Rc`/`Arc` or integer (e.g.
    /// a NIC ring index). Untyped so we don't bake any one shape in.
    drop_ctx: *mut (),
}

// SAFETY: `ExternalOwned` is Send because the underlying memory is
// exclusively owned (the `wrap_owned` constructor takes that as a
// precondition) and the function-pointer drop callback together
// with the raw context pointer is Send-by-construction (function
// pointers are Send; the caller is responsible for ensuring the
// context's pointee is safe to drop on the worker that owns the
// IOBuf at drop time). This single, localized, documented `unsafe
// impl` is what lets `OwnedIOBuf` — and `Chain<OwnedIOBuf>` — be
// `Send` by *auto-derivation*, with no container-level `unsafe`.
unsafe impl Send for ExternalOwned {}

// SAFETY: `ExternalOwned` is Sync once wrapped in an `Arc` (the
// `Shared` variant): multiple `&ExternalOwned` references can
// concurrently read the bytes (via `data()` paths), and mutating
// access (`bytes_mut` reachable only via `Arc::get_mut`) requires
// the Arc to be uniquely held — so the borrow checker rules out
// concurrent read + write. `Drop` fires exactly once, on whichever
// thread held the last Arc.
unsafe impl Sync for ExternalOwned {}

impl ExternalOwned {
    /// Construct from the raw `(base, capacity)` plus the release
    /// callback. The caller's safety contract is the
    /// `IOBuf::wrap_owned` / `OwnedIOBuf::wrap_owned` doc.
    pub(crate) fn new(
        base: NonNull<u8>,
        capacity: u32,
        drop_fn: IOBufDropFn,
        drop_ctx: *mut (),
    ) -> Self {
        ExternalOwned {
            base,
            capacity,
            drop_fn,
            drop_ctx,
        }
    }

    /// Total bytes of the foreign region.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// Start of the foreign region. Outer-type methods compute
    /// `base.add(offset)` for the visible window.
    #[inline]
    pub(crate) fn base(&self) -> NonNull<u8> {
        self.base
    }
}

impl Drop for ExternalOwned {
    fn drop(&mut self) {
        // SAFETY: the function-pointer's contract was set by the
        // `wrap_owned` caller — they're responsible for ensuring the
        // pair (drop_fn, drop_ctx) is sound to invoke now. Drop runs
        // exactly once per `ExternalOwned`.
        unsafe {
            (self.drop_fn)(self.base, self.capacity, self.drop_ctx);
        }
    }
}

// ============================================================================
// BorrowedView — a non-owning view of foreign storage.
// ============================================================================

/// Non-owning view into foreign storage. The caller manages the
/// region's lifetime out-of-band; no drop callback fires. Typical
/// sites: per-worker scratch buffers (TLS record / body scratch),
/// driver TX-pool slots borrowed inside a synchronous callback,
/// per-conn stack-resident header arrays, a `&[u8]` borrowed for one
/// async send.
///
/// Bytes only — the visible `(offset, len)` window lives on the
/// outer `IOBuf`. `!Send` via the `PhantomData<*const ()>` — the
/// borrow contract is per-worker / per-stack-frame, and this
/// `!Send`-ness propagates through `IOBuf`'s enum so a borrowed view
/// *cannot* reach a cross-core path. The cross-core path is typed
/// `OwnedIOBuf`, which has no `BorrowedView` variant — a compile-
/// time guarantee, not a human-maintained invariant.
pub struct BorrowedView {
    base: NonNull<u8>,
    capacity: u32,
    /// Makes `BorrowedView` (and therefore `IOBuf`) `!Send + !Sync`.
    _not_send: PhantomData<*const ()>,
    /// Test-mode aliasing-tracker registration guard. The field is
    /// absent entirely outside `cfg(test)` (the tracker needs std).
    #[cfg(test)]
    _guard: BorrowGuard,
}

impl BorrowedView {
    /// Construct a view over `[base..base+capacity)`. The caller's
    /// safety contract is the `IOBuf::borrow` doc.
    pub(crate) fn new(base: NonNull<u8>, capacity: u32) -> Self {
        BorrowedView {
            base,
            capacity,
            _not_send: PhantomData,
            #[cfg(test)]
            _guard: BorrowGuard::new(base, capacity),
        }
    }

    /// Total bytes of the borrowed region.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// Start of the borrowed region. Outer-type methods compute
    /// `base.add(offset)` for the visible window.
    #[inline]
    pub(crate) fn base(&self) -> NonNull<u8> {
        self.base
    }
}

// ============================================================================
// SharedRegion — refcounted backing for the `Shared` variant.
// ============================================================================

/// Backing storage for the `Shared` variant — `HeapStorage` or
/// `ExternalOwned`, lifted behind an `Arc` so multiple IOBufs can
/// reference the same bytes without copying. The TCP rtx queue's
/// canonical use case (PR 5): keep a shadow of a sent segment with
/// no memcpy, paying only the Arc clone on the reference.
///
/// `Send + Sync` by auto-derivation: both `HeapStorage` (a
/// `Box<[u8]>`) and `ExternalOwned` (post-PR-3 `unsafe impl Sync`)
/// are. The `Arc<SharedRegion>` is therefore `Send`, so an
/// `OwnedIOBuf::Shared` is still `Send` by auto-derivation.
///
/// Mutating access is only safe when the Arc is uniquely held —
/// callers reach it via `Arc::get_mut`, which returns `Some` only
/// when `strong_count == 1 && weak_count == 0`. The IOBuf
/// mutators (`prepend` / `append_slice` / `extend_uninit` /
/// `data_mut`) try `get_mut` first and CoW into a fresh
/// `HeapStorage` if it returns `None`.
pub struct SharedRegion {
    inner: SharedInner,
}

/// The two backing shapes a `SharedRegion` can wrap: the same two
/// owning storage structs `OwnedIOBuf` already exposes — heap-owned
/// `Box<[u8]>` and a foreign region with a drop callback. Both
/// `Send + Sync`, so `Arc<SharedRegion>` is `Send`.
enum SharedInner {
    Heap(HeapStorage),
    External(ExternalOwned),
}

impl SharedRegion {
    /// Wrap an owned heap region for sharing.
    pub(crate) fn new_heap(h: HeapStorage) -> Self {
        SharedRegion {
            inner: SharedInner::Heap(h),
        }
    }

    /// Wrap a foreign owned region for sharing. The drop callback
    /// fires once when the last `Arc<SharedRegion>` drops.
    pub(crate) fn new_external(e: ExternalOwned) -> Self {
        SharedRegion {
            inner: SharedInner::External(e),
        }
    }

    /// Total bytes of the backing region.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        match &self.inner {
            SharedInner::Heap(h) => h.capacity(),
            SharedInner::External(e) => e.capacity(),
        }
    }

    /// Read-only view of the entire backing region. Concurrent
    /// readers across `Arc` clones go through here.
    #[inline]
    pub(crate) fn bytes(&self) -> &[u8] {
        match &self.inner {
            SharedInner::Heap(h) => h.bytes(),
            SharedInner::External(e) => {
                // SAFETY: `base..base+capacity` is the foreign
                // region the `wrap_owned` caller guaranteed valid
                // for the IOBuf's lifetime; the `Arc<SharedRegion>`
                // refcount keeps that lifetime alive across clones.
                unsafe { core::slice::from_raw_parts(e.base().as_ptr(), e.capacity()) }
            }
        }
    }

    /// Mutable view of the entire backing region. Reachable only
    /// when the caller has `&mut SharedRegion` — which the IOBuf
    /// mutators obtain via `Arc::get_mut`, i.e. only when the Arc
    /// is uniquely held. Concurrent mutation is therefore
    /// structurally ruled out.
    #[inline]
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        match &mut self.inner {
            SharedInner::Heap(h) => h.bytes_mut(),
            SharedInner::External(e) => {
                // SAFETY: as `bytes()`, plus `&mut self` ⇒ Arc is
                // uniquely held ⇒ no concurrent reader exists.
                unsafe { core::slice::from_raw_parts_mut(e.base().as_ptr(), e.capacity()) }
            }
        }
    }
}

// In non-test builds there is no `borrow_tracker` module at all:
// `BorrowGuard` (its only caller) is itself `cfg(test)`-only, so a
// no-op stub would just be dead code.

/// Per-`BorrowedView` Drop guard that owns the tracker's
/// register/unregister pairing. Carried as a field of the struct —
/// its Drop fires when the `BorrowedView` (and thus the `IOBuf`)
/// drops, so a live registration can't be orphaned. In every
/// non-test build the guard is absent entirely (the field is
/// `#[cfg]`-gated off), matching the `cfg(test)`-only tracker.
#[cfg(test)]
struct BorrowGuard {
    base: NonNull<u8>,
    capacity: u32,
}

#[cfg(test)]
impl BorrowGuard {
    fn new(base: NonNull<u8>, capacity: u32) -> Self {
        borrow_tracker::register(base, capacity);
        Self { base, capacity }
    }
}

#[cfg(test)]
impl Drop for BorrowGuard {
    fn drop(&mut self) {
        borrow_tracker::unregister(self.base, self.capacity);
    }
}

// ============================================================================
// Borrow tracker — debug-mode aliasing detection for `BorrowedView`.
//
// Every `IOBuf::borrow(base, capacity, ...)` registers its
// `[base..base+capacity)` region in a per-thread interval list. A
// second `borrow` overlapping any live entry panics on the spot,
// surfacing aliasing-arithmetic bugs (e.g. the body-scratch sub-range
// allocator's cursor going wrong) at the point of construction rather
// than as silent UAF later.
//
// Active only under `cfg(test)`. The tracker needs `std` — a
// `thread_local!` and a `Vec` — and the no_std `x86_64-waitless-none`
// unikernel target has no `std` crate to link, so it cannot compile
// there. It is therefore gated to `cfg(test)` (cargo test / the
// `iobuf_test` bazel target), which always builds against std; in
// every non-test build (including a default `fastbuild` bazel build,
// where `debug_assertions` is *on*) the tracker compiles to a no-op
// and production pays nothing.
//
// The tracker lives on a per-thread `Vec` (via `std::thread_local!`)
// because `BorrowedView`s are `!Send` — a borrowed view is bound to
// the worker / thread that constructed it, so cross-thread sharing of
// the tracker state is structurally impossible. The `Vec` is bounded
// in practice by the number of live `BorrowedView`s on this thread;
// typical depths are < 4 (one for body scratch, one for TLS scratch,
// occasional inner sub-views).
// ============================================================================
#[cfg(test)]
mod borrow_tracker {
    extern crate std;

    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::ptr::NonNull;

    /// One live `[base..base+capacity)` byte region.
    #[derive(Copy, Clone)]
    struct Region {
        base: usize,
        end: usize,
    }

    std::thread_local! {
        static ACTIVE: RefCell<Vec<Region>> = const { RefCell::new(Vec::new()) };
    }

    /// Register a new borrowed region. Panics on overlap with any
    /// already-live region — the typical failure mode is the body-
    /// scratch sub-range allocator's cursor arithmetic going wrong,
    /// or a re-entered scratch-acquire path minting a second view
    /// over the same per-worker buffer.
    pub(crate) fn register(base: NonNull<u8>, capacity: u32) {
        let base_addr = base.as_ptr() as usize;
        let end_addr = base_addr.wrapping_add(capacity as usize);
        ACTIVE.with(|r| {
            let mut reg = r.borrow_mut();
            for existing in reg.iter() {
                // Open-interval overlap test: [a, b) ∩ [c, d) ≠ ∅
                // iff a < d ∧ c < b.
                let overlap = base_addr < existing.end && existing.base < end_addr;
                if overlap {
                    panic!(
                        "overlapping IOBuf::borrow mint: new=[{:#x}..{:#x}) \
                         overlaps existing=[{:#x}..{:#x}); aliasing bug?",
                        base_addr, end_addr, existing.base, existing.end,
                    );
                }
            }
            reg.push(Region {
                base: base_addr,
                end: end_addr,
            });
        });
    }

    /// Drop a previously-registered region. Panics if no matching
    /// entry exists — that would indicate a balance error in the
    /// register/unregister pairing (e.g. a borrowed view
    /// constructed without going through `register`).
    pub(crate) fn unregister(base: NonNull<u8>, capacity: u32) {
        let base_addr = base.as_ptr() as usize;
        let end_addr = base_addr.wrapping_add(capacity as usize);
        ACTIVE.with(|r| {
            let mut reg = r.borrow_mut();
            // LIFO-friendly scan (borrowed views usually drop in
            // reverse construction order on a synchronous code path).
            for i in (0..reg.len()).rev() {
                if reg[i].base == base_addr && reg[i].end == end_addr {
                    reg.swap_remove(i);
                    return;
                }
            }
            panic!(
                "IOBuf::borrow unregister with no matching register: \
                 [{:#x}..{:#x}); register/unregister imbalance?",
                base_addr, end_addr,
            );
        });
    }
}
