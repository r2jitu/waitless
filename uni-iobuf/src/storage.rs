// uni-iobuf/src/storage.rs — the four per-variant storage structs.
//
// `IOBuf` is one type with two ownership models. Rather than inline
// every variant's offset/len arithmetic into a match arm of every
// `IOBuf` method (the logic for one variant scattered across ten
// methods), each ownership variant is **its own struct** here, with
// its data *and* its logic in one place. `IOBuf` (and `OwnedIOBuf`)
// become thin flat enums that forward to these — see `lib.rs`.
//
//   * `HeapStorage`   — heap-owned `Box<[u8]>`. `Send` (auto).
//   * `StaticView`    — a `&'static [u8]` borrow. Immutable. `Send`.
//   * `ExternalOwned` — a foreign region this IOBuf owns via a drop
//                       callback (NIC zero-copy RX, pool slabs).
//                       `Send` via the one `unsafe impl` in the
//                       crate — the genuine leaf assertion.
//   * `BorrowedView`  — a non-owning view of foreign storage. The
//                       `PhantomData<*const ()>` makes it `!Send`,
//                       which is what taints the whole `IOBuf` enum
//                       `!Send` and keeps per-worker borrows from
//                       crossing workers.
//
// `HeapStorage` + `ExternalOwned` are the owning, `Send` pair that
// `OwnedIOBuf` is built from; `StaticView` + `BorrowedView` are the
// non-owning views that only `IOBuf` carries.

use alloc::boxed::Box;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::{IOBufError, IOBufRead};

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
// Active only under `cfg(any(test, debug_assertions))`. In bazel
// release builds (the unikernel target ships with `-Copt-level=2`),
// `debug_assertions` is off and the tracker compiles to a no-op,
// so production pays nothing. In `cargo test`, the iobuf_test bazel
// target, and any debug build of a consumer, the tracker is on.
//
// The tracker lives on a per-thread `Vec` (via `std::thread_local!`)
// because `BorrowedView`s are `!Send` — a borrowed view is bound to
// the worker / thread that constructed it, so cross-thread sharing of
// the tracker state is structurally impossible. The `Vec` is bounded
// in practice by the number of live `BorrowedView`s on this thread;
// typical depths are < 4 (one for body scratch, one for TLS scratch,
// occasional inner sub-views).
// ============================================================================
#[cfg(any(test, debug_assertions))]
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
        static ACTIVE: RefCell<Vec<Region>> = RefCell::new(Vec::new());
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

#[cfg(not(any(test, debug_assertions)))]
mod borrow_tracker {
    use core::ptr::NonNull;
    #[inline(always)]
    pub(crate) fn register(_: NonNull<u8>, _: u32) {}
    #[inline(always)]
    pub(crate) fn unregister(_: NonNull<u8>, _: u32) {}
}

/// Per-`BorrowedView` Drop guard that owns the tracker's
/// register/unregister pairing. Carried as a field of the struct —
/// its Drop fires when the `BorrowedView` (and thus the `IOBuf`)
/// drops, so a live registration can't be orphaned. In release
/// builds (`!debug_assertions`) the guard is absent entirely (the
/// field is `#[cfg]`-gated off).
#[cfg(any(test, debug_assertions))]
struct BorrowGuard {
    base: NonNull<u8>,
    capacity: u32,
}

#[cfg(any(test, debug_assertions))]
impl BorrowGuard {
    fn new(base: NonNull<u8>, capacity: u32) -> Self {
        borrow_tracker::register(base, capacity);
        Self { base, capacity }
    }
}

#[cfg(any(test, debug_assertions))]
impl Drop for BorrowGuard {
    fn drop(&mut self) {
        borrow_tracker::unregister(self.base, self.capacity);
    }
}

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

/// Heap-owned byte storage. The buffer's full capacity is
/// `storage.len()`; the visible payload spans `[offset..offset+len]`.
/// Headroom is `offset` (bytes before the payload that lower layers
/// can prepend into); tailroom is `storage.len() - offset - len`
/// (bytes after the payload, e.g. for AEAD tags).
///
/// `offset` / `len` are `u32` (saves 8 B per node vs `usize`); 4 GiB
/// per chunk is plenty for any unikernel workload. `Send` by
/// auto-derivation — a `Box<[u8]>` is exclusively owned.
pub struct HeapStorage {
    storage: Box<[u8]>,
    offset: u32,
    len: u32,
}

impl HeapStorage {
    /// Wrap an owned `Box<[u8]>` with the visible payload at
    /// `[offset..offset+len]`.
    pub(crate) fn new(storage: Box<[u8]>, offset: u32, len: u32) -> Self {
        debug_assert!(offset as usize + len as usize <= storage.len());
        HeapStorage { storage, offset, len }
    }

    pub(crate) fn data_mut(&mut self) -> Option<&mut [u8]> {
        let o = self.offset as usize;
        let l = self.len as usize;
        Some(&mut self.storage[o..o + l])
    }

    pub(crate) fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        if n > self.offset as usize {
            return Err(IOBufError::NoHeadroom);
        }
        let new_offset = self.offset - n as u32;
        self.storage[new_offset as usize..self.offset as usize].copy_from_slice(data);
        self.offset = new_offset;
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let end = self.offset as usize + self.len as usize;
        let n = data.len();
        if end + n > self.storage.len() {
            return Err(IOBufError::NoTailroom);
        }
        self.storage[end..end + n].copy_from_slice(data);
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        let end = self.offset as usize + self.len as usize;
        if end + n > self.storage.len() {
            return Err(IOBufError::NoTailroom);
        }
        self.len += n as u32;
        Ok(&mut self.storage[end..end + n])
    }

    pub(crate) fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.offset += n as u32;
        self.len -= n as u32;
        Ok(())
    }

    pub(crate) fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.len -= n as u32;
        Ok(())
    }
}

impl IOBufRead for HeapStorage {
    #[inline]
    fn data(&self) -> &[u8] {
        let o = self.offset as usize;
        &self.storage[o..o + self.len as usize]
    }
    #[inline]
    fn len(&self) -> usize {
        self.len as usize
    }
    #[inline]
    fn headroom(&self) -> usize {
        self.offset as usize
    }
    #[inline]
    fn tailroom(&self) -> usize {
        self.storage
            .len()
            .saturating_sub(self.offset as usize + self.len as usize)
    }
}

// ============================================================================
// StaticView — a `&'static [u8]` borrow.
// ============================================================================

/// Borrowed reference to static-lifetime bytes. Immutable; no
/// headroom / tailroom semantics. Common for HTML literal chunks,
/// the QPACK static table, etc. `Send` (a `&'static [u8]` is an
/// immortal borrow) — but it is deliberately *not* part of
/// `OwnedIOBuf`: it is a view, not owned storage.
pub struct StaticView {
    data: &'static [u8],
}

impl StaticView {
    pub(crate) const fn new(data: &'static [u8]) -> Self {
        StaticView { data }
    }

    /// Always `None` — static borrows are immutable.
    pub(crate) fn data_mut(&mut self) -> Option<&mut [u8]> {
        None
    }
    pub(crate) fn prepend(&mut self, _data: &[u8]) -> Result<(), IOBufError> {
        Err(IOBufError::Immutable)
    }
    pub(crate) fn append_slice(&mut self, _data: &[u8]) -> Result<(), IOBufError> {
        Err(IOBufError::Immutable)
    }
    pub(crate) fn extend_uninit(&mut self, _n: usize) -> Result<&mut [u8], IOBufError> {
        Err(IOBufError::Immutable)
    }
    pub(crate) fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.data.len() {
            return Err(IOBufError::OutOfBounds);
        }
        self.data = &self.data[n..];
        Ok(())
    }
    pub(crate) fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.data.len() {
            return Err(IOBufError::OutOfBounds);
        }
        self.data = &self.data[..self.data.len() - n];
        Ok(())
    }
}

impl IOBufRead for StaticView {
    #[inline]
    fn data(&self) -> &[u8] {
        self.data
    }
    #[inline]
    fn len(&self) -> usize {
        self.data.len()
    }
    #[inline]
    fn headroom(&self) -> usize {
        0
    }
    #[inline]
    fn tailroom(&self) -> usize {
        0
    }
}

// ============================================================================
// ExternalOwned — a foreign region owned via a drop callback.
// ============================================================================

/// Externally-owned buffer with a drop callback. Canonical use
/// cases: NIC zero-copy RX (callback returns the descriptor to the
/// receive ring) and pool-backed buffers (callback pushes a slab
/// back to a free list). Same offset/len semantics as
/// [`HeapStorage`]; the storage isn't dropped — the callback fires
/// instead, exactly once, with the original `(base, capacity)`.
///
/// This is the genuine leaf where a raw region + drop_fn's
/// thread-safety is asserted (see the `unsafe impl Send` below) —
/// the *only* `unsafe impl Send` left in the crate.
pub struct ExternalOwned {
    /// Start of the underlying region.
    base: NonNull<u8>,
    /// Total bytes of the region (`base + capacity` is one past the
    /// end). The visible payload is at `[offset..offset+len]`.
    capacity: u32,
    /// Visible-payload start, relative to `base`. `prepend` shrinks
    /// it toward 0; `consume` grows it toward `offset + len`.
    offset: u32,
    /// Visible-payload byte length.
    len: u32,
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

impl ExternalOwned {
    /// Construct from the raw `(base, capacity, offset, len)` plus
    /// the release callback. The caller's safety contract is the
    /// `IOBuf::wrap_owned` / `OwnedIOBuf::wrap_owned` doc.
    pub(crate) fn new(
        base: NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
        drop_fn: IOBufDropFn,
        drop_ctx: *mut (),
    ) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        ExternalOwned {
            base,
            capacity,
            offset,
            len,
            drop_fn,
            drop_ctx,
        }
    }

    pub(crate) fn data_mut(&mut self) -> Option<&mut [u8]> {
        // SAFETY: base + offset is in-bounds (offset + len <=
        // capacity, the construction precondition); the region is
        // exclusively owned by this IOBuf, and `&mut self` gives
        // exclusive write access for this call.
        Some(unsafe {
            core::slice::from_raw_parts_mut(
                self.base.as_ptr().add(self.offset as usize),
                self.len as usize,
            )
        })
    }

    pub(crate) fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        if n > self.offset as usize {
            return Err(IOBufError::NoHeadroom);
        }
        let new_offset = self.offset - n as u32;
        // SAFETY: bounds checked above; exclusive access via `&mut self`.
        unsafe {
            core::slice::from_raw_parts_mut(self.base.as_ptr().add(new_offset as usize), n)
                .copy_from_slice(data);
        }
        self.offset = new_offset;
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let end = self.offset as usize + self.len as usize;
        let n = data.len();
        if end + n > self.capacity as usize {
            return Err(IOBufError::NoTailroom);
        }
        // SAFETY: bounds checked above; exclusive access via `&mut self`.
        unsafe {
            core::slice::from_raw_parts_mut(self.base.as_ptr().add(end), n)
                .copy_from_slice(data);
        }
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        let end = self.offset as usize + self.len as usize;
        if end + n > self.capacity as usize {
            return Err(IOBufError::NoTailroom);
        }
        self.len += n as u32;
        // SAFETY: bounds checked above; exclusive access via `&mut self`.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr().add(end), n) })
    }

    pub(crate) fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.offset += n as u32;
        self.len -= n as u32;
        Ok(())
    }

    pub(crate) fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.len -= n as u32;
        Ok(())
    }
}

impl IOBufRead for ExternalOwned {
    #[inline]
    fn data(&self) -> &[u8] {
        // SAFETY: base + offset is in-bounds by the construction
        // precondition (offset + len <= capacity); the memory is
        // exclusively owned by this IOBuf for its lifetime.
        unsafe {
            core::slice::from_raw_parts(
                self.base.as_ptr().add(self.offset as usize),
                self.len as usize,
            )
        }
    }
    #[inline]
    fn len(&self) -> usize {
        self.len as usize
    }
    #[inline]
    fn headroom(&self) -> usize {
        self.offset as usize
    }
    #[inline]
    fn tailroom(&self) -> usize {
        (self.capacity as usize).saturating_sub(self.offset as usize + self.len as usize)
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
/// `!Send` via the `PhantomData<*const ()>` — the borrow contract is
/// per-worker / per-stack-frame, and this `!Send`-ness propagates
/// through `IOBuf`'s enum so a borrowed view *cannot* reach a
/// cross-core path. The cross-core path is typed `OwnedIOBuf`, which
/// has no `BorrowedView` variant — a compile-time guarantee, not a
/// human-maintained invariant.
pub struct BorrowedView {
    base: NonNull<u8>,
    capacity: u32,
    offset: u32,
    len: u32,
    /// Makes `BorrowedView` (and therefore `IOBuf`) `!Send + !Sync`.
    _not_send: PhantomData<*const ()>,
    /// Debug-mode aliasing-tracker registration guard. ZST + no-op
    /// Drop in release; the field is absent entirely there.
    #[cfg(any(test, debug_assertions))]
    _guard: BorrowGuard,
}

impl BorrowedView {
    /// Construct a view over `[base..base+capacity)` with the
    /// visible payload at `[offset..offset+len]`. The caller's
    /// safety contract is the `IOBuf::borrow` doc.
    pub(crate) fn new(base: NonNull<u8>, capacity: u32, offset: u32, len: u32) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        BorrowedView {
            base,
            capacity,
            offset,
            len,
            _not_send: PhantomData,
            #[cfg(any(test, debug_assertions))]
            _guard: BorrowGuard::new(base, capacity),
        }
    }

    pub(crate) fn data_mut(&mut self) -> Option<&mut [u8]> {
        // SAFETY: the `borrow` caller guaranteed the region is not
        // concurrently mutated through any other route; `&mut self`
        // gives exclusive write access for this call.
        Some(unsafe {
            core::slice::from_raw_parts_mut(
                self.base.as_ptr().add(self.offset as usize),
                self.len as usize,
            )
        })
    }

    pub(crate) fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        if n > self.offset as usize {
            return Err(IOBufError::NoHeadroom);
        }
        let new_offset = self.offset - n as u32;
        // SAFETY: bounds checked above; exclusive access via `&mut
        // self`; `borrow` caller guaranteed no concurrent mutation.
        unsafe {
            core::slice::from_raw_parts_mut(self.base.as_ptr().add(new_offset as usize), n)
                .copy_from_slice(data);
        }
        self.offset = new_offset;
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let end = self.offset as usize + self.len as usize;
        let n = data.len();
        if end + n > self.capacity as usize {
            return Err(IOBufError::NoTailroom);
        }
        // SAFETY: bounds checked above; exclusive access; `borrow`
        // caller guaranteed no concurrent mutation.
        unsafe {
            core::slice::from_raw_parts_mut(self.base.as_ptr().add(end), n)
                .copy_from_slice(data);
        }
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        let end = self.offset as usize + self.len as usize;
        if end + n > self.capacity as usize {
            return Err(IOBufError::NoTailroom);
        }
        self.len += n as u32;
        // SAFETY: bounds checked above; exclusive access via `&mut self`.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr().add(end), n) })
    }

    pub(crate) fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.offset += n as u32;
        self.len -= n as u32;
        Ok(())
    }

    pub(crate) fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.len -= n as u32;
        Ok(())
    }
}

impl IOBufRead for BorrowedView {
    #[inline]
    fn data(&self) -> &[u8] {
        // SAFETY: the `borrow` caller guaranteed the region is valid
        // for this IOBuf's lifetime and not concurrently mutated.
        unsafe {
            core::slice::from_raw_parts(
                self.base.as_ptr().add(self.offset as usize),
                self.len as usize,
            )
        }
    }
    #[inline]
    fn len(&self) -> usize {
        self.len as usize
    }
    #[inline]
    fn headroom(&self) -> usize {
        self.offset as usize
    }
    #[inline]
    fn tailroom(&self) -> usize {
        (self.capacity as usize).saturating_sub(self.offset as usize + self.len as usize)
    }
}
