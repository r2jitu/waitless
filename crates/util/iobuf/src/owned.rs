// `OwnedIOBuf` — the `Send`-by-derivation owning IOBuf.
//
// See the crate root for the borrowed/owned type-split rationale.
// `OwnedIOBuf` covers every storage shape that is owned (or
// statically outlives the IOBuf): heap, foreign-with-drop-callback,
// refcounted, and static borrow. All of those are `Send`, so
// `OwnedIOBuf` is `Send` by auto-derivation — no `unsafe impl`, no
// human-maintained invariant.
//
// As of PR 4 `OwnedIOBuf` is the *only* tier of mutable IOBuf
// machinery: `IOBuf` is a thin two-variant wrapper around either an
// `OwnedIOBuf` or a `BorrowedView`-backed view, forwarding every
// method here. Per-variant `(offset, len)` view lives at the top of
// `OwnedIOBuf` (PR 2); refcounted backing arrived with `Shared` (PR
// 3); `Static` joined this tier with the two-tier refactor.

use alloc::sync::Arc;
use core::ptr::NonNull;

use crate::iobuf::{IOBuf, IOBufInner};
use crate::{Chain, ExternalOwned, HeapStorage, IOBufDropFn, IOBufError, IOBufRead, SharedRegion};

/// An IOBuf restricted to **owning** storage variants — `Heap`,
/// `External`, `Shared`, and `Static`. All are `Send`, so
/// `OwnedIOBuf` is `Send` **by auto-derivation**: no `unsafe impl`,
/// no container invariant. `Chain<OwnedIOBuf>` is likewise `Send`
/// for free.
///
/// This is the type the cross-core RX path is *born* in —
/// [`OwnedIOBuf::wrap_owned`] and [`crate::IOBufPool::alloc`] produce
/// it, and it stays `OwnedIOBuf` through the `Nic` poll callback, net
/// dispatch, and the per-core RX inbox. A `BorrowedView` *cannot*
/// reach that path: the path's type is `OwnedIOBuf` and no
/// constructor of `OwnedIOBuf` takes a borrow — compile-time
/// cross-core safety, not discipline.
///
/// Widening is one-way: `From<OwnedIOBuf> for IOBuf`. Nothing
/// narrows `IOBuf -> OwnedIOBuf`.
pub struct OwnedIOBuf {
    pub(crate) storage: OwnedStorage,
    /// Visible-payload start, relative to the storage base. `prepend`
    /// shrinks it toward 0; `consume` grows it.
    pub(crate) offset: u32,
    /// Visible-payload byte length.
    pub(crate) len: u32,
}

/// Storage backing an [`OwnedIOBuf`]. Bytes only; the visible window
/// lives on `OwnedIOBuf`.
pub(crate) enum OwnedStorage {
    /// Heap-owned `Box<[u8]>`.
    Heap(HeapStorage),
    /// A foreign region owned via a drop callback.
    External(ExternalOwned),
    /// Refcounted backing — produced by `share()`, cloned by
    /// `clone_shared()`. Multiple IOBufs share the same bytes; each
    /// carries its own `(offset, len)` view via the outer struct.
    Shared(Arc<SharedRegion>),
    /// A `&'static [u8]` borrow. Immutable; mutators return
    /// `IOBufError::Immutable`. Send via the `&'static` lifetime.
    Static(&'static [u8]),
}

impl OwnedStorage {
    /// The entire backing region (capacity bytes), independent of
    /// any `(offset, len)` view. Every read path indexes into this,
    /// so the four shapes share one accessor — no per-variant
    /// arithmetic at the call sites.
    #[inline]
    fn bytes(&self) -> &[u8] {
        match self {
            OwnedStorage::Heap(h) => h.bytes(),
            OwnedStorage::External(e) => e.bytes(),
            OwnedStorage::Shared(r) => r.bytes(),
            OwnedStorage::Static(s) => s,
        }
    }

    /// Mutable backing region, or `None` for the immutable `Static`
    /// shape. For `Shared` the caller MUST have run
    /// [`OwnedIOBuf::cow_if_shared_aliased`] first — `Arc::get_mut`
    /// then yields the unique reference (the `expect` documents that
    /// precondition).
    #[inline]
    fn bytes_mut(&mut self) -> Option<&mut [u8]> {
        match self {
            OwnedStorage::Heap(h) => Some(h.bytes_mut()),
            OwnedStorage::External(e) => Some(e.bytes_mut()),
            OwnedStorage::Shared(arc) => {
                Some(Arc::get_mut(arc).expect("unique after cow_if_shared_aliased").bytes_mut())
            }
            OwnedStorage::Static(_) => None,
        }
    }
}

/// Static assertion: `OwnedIOBuf` (and a chain of them) is `Send` by
/// auto-derivation. If a future change reintroduced a `!Send` field
/// — a raw pointer, a `PhantomData<*const ()>` — this stops
/// compiling, which is the point: the cross-core RX path's safety is
/// this fact, checked by the compiler on every build.
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}
    assert_send::<OwnedIOBuf>();
    assert_send::<Chain<OwnedIOBuf>>();
    // `SharedRegion: Send + Sync` is what makes `Arc<SharedRegion>`
    // — and therefore `OwnedStorage::Shared` — `Send`. A future
    // `!Sync` field on `HeapStorage` or `ExternalOwned` would taint
    // `SharedRegion` and break OwnedIOBuf's auto-derived `Send`;
    // assert it here so the regression is a compile error.
    assert_send::<SharedRegion>();
    assert_sync::<SharedRegion>();
    assert_send::<Arc<SharedRegion>>();
};

impl OwnedIOBuf {
    /// Wrap a foreign region this IOBuf takes ownership of via a drop
    /// callback — *the* owned, `Send` constructor for the cross-core
    /// RX path (NIC zero-copy RX, pool slabs). On drop, `drop_fn(base,
    /// capacity, drop_ctx)` runs exactly once with the original
    /// `(base, capacity)` regardless of how offset/len shifted. To
    /// land the result in a (borrow-mixing) `IOBuf` chain, widen it
    /// with `From<OwnedIOBuf>`.
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee:
    ///   * `base..base+capacity` is a valid, exclusively-owned byte
    ///     region for the IOBuf's lifetime.
    ///   * `offset + len <= capacity`.
    ///   * `drop_fn(base, capacity, drop_ctx)` is sound to invoke
    ///     once at drop time.
    ///   * The pair is Send-safe: the eventual drop runs on whichever
    ///     worker owns the IOBuf at drop time.
    pub unsafe fn wrap_owned(
        base: NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
        drop_fn: IOBufDropFn,
        drop_ctx: *mut (),
    ) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        OwnedIOBuf {
            storage: OwnedStorage::External(ExternalOwned::new(base, capacity, drop_fn, drop_ctx)),
            offset,
            len,
        }
    }

    /// Borrow a static-lifetime slice as an `OwnedIOBuf`. Zero
    /// allocation, infallible, `const`. Mutators on the resulting
    /// IOBuf return `IOBufError::Immutable`.
    pub const fn from_static(data: &'static [u8]) -> Self {
        OwnedIOBuf {
            storage: OwnedStorage::Static(data),
            offset: 0,
            len: data.len() as u32,
        }
    }

    /// Total bytes of the underlying storage (independent of the
    /// current visible window).
    #[inline]
    fn capacity(&self) -> usize {
        match &self.storage {
            OwnedStorage::Heap(h) => h.capacity(),
            OwnedStorage::External(e) => e.capacity(),
            OwnedStorage::Shared(r) => r.capacity(),
            OwnedStorage::Static(s) => s.len(),
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let o = self.offset as usize;
        let l = self.len as usize;
        &self.storage.bytes()[o..o + l]
    }

    /// Visible payload length.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes available before the payload.
    #[inline]
    pub fn headroom(&self) -> usize {
        self.offset as usize
    }

    /// Bytes available after the payload.
    #[inline]
    pub fn tailroom(&self) -> usize {
        self.capacity()
            .saturating_sub(self.offset as usize + self.len as usize)
    }

    /// Restrict the visible payload to `[offset..offset+len]` of the
    /// current visible region — `consume(offset)` then `trim_end` any
    /// surplus tail. `Err` if `offset` exceeds the visible length.
    ///
    /// The backing region and drop callback are untouched (only the
    /// internal offset/len shift), so a narrowed `OwnedIOBuf` still
    /// reposts its *full* device buffer on drop. The RX path uses this
    /// to narrow a frame buffer down to its L4 segment (RX item D):
    /// the eth/IP headers and any ethernet trailing padding fall
    /// outside the new window without moving a byte.
    #[inline]
    pub fn narrow(&mut self, offset: usize, len: usize) -> Result<(), IOBufError> {
        self.consume(offset)?;
        let visible = self.len as usize;
        if visible > len {
            self.trim_end(visible - len)?;
        }
        Ok(())
    }

    /// Trim `n` bytes from the FRONT of the visible payload (the
    /// region start advances; headroom grows).
    #[inline]
    pub fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.offset += n as u32;
        self.len -= n as u32;
        Ok(())
    }

    /// Trim `n` bytes from the BACK of the visible payload (the
    /// region end retreats; tailroom grows).
    #[inline]
    pub fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        if n > self.len as usize {
            return Err(IOBufError::OutOfBounds);
        }
        self.len -= n as u32;
        Ok(())
    }

    /// Promote to refcounted storage so the same bytes can back
    /// multiple `OwnedIOBuf` views via `clone_shared`. **Move-only**
    /// — bytes do NOT copy; the existing `HeapStorage` /
    /// `ExternalOwned` is lifted into a fresh `Arc<SharedRegion>`.
    /// Idempotent on a buffer that is already `Shared` or `Static`
    /// (`Static` is already an immortal borrow — multiple views
    /// just clone the `&'static [u8]`).
    ///
    /// One small Arc allocation. The canonical caller is the TCP
    /// rtx queue: keep a refcounted shadow of each sent segment so
    /// a retransmit can replay without memcpy.
    pub fn share(self) -> Self {
        let storage = match self.storage {
            OwnedStorage::Heap(h) => OwnedStorage::Shared(Arc::new(SharedRegion::new_heap(h))),
            OwnedStorage::External(e) => {
                OwnedStorage::Shared(Arc::new(SharedRegion::new_external(e)))
            }
            already @ OwnedStorage::Shared(_) => already,
            // Static is already an immortal borrow — any number of
            // clones is fine, no Arc needed.
            already @ OwnedStorage::Static(_) => already,
        };
        OwnedIOBuf {
            storage,
            offset: self.offset,
            len: self.len,
        }
    }

    /// Cheap clone of a shareable buffer — bumps the
    /// `Arc<SharedRegion>` strong count (or copies the `&'static`
    /// slice) and carries the same view. `Err(NotShared)` if
    /// `share()` was not called first on a non-static buffer.
    ///
    /// The plan's design keeps refcounting opt-in: a non-Shared
    /// buffer (`Heap` / `External`) is exclusively owned, with no
    /// atomics on the hot path. Callers explicitly promote with
    /// `share()` only when they need the shadow.
    pub fn clone_shared(&self) -> Result<Self, IOBufError> {
        match &self.storage {
            OwnedStorage::Shared(arc) => Ok(OwnedIOBuf {
                storage: OwnedStorage::Shared(Arc::clone(arc)),
                offset: self.offset,
                len: self.len,
            }),
            OwnedStorage::Static(s) => Ok(OwnedIOBuf {
                storage: OwnedStorage::Static(s),
                offset: self.offset,
                len: self.len,
            }),
            _ => Err(IOBufError::NotShared),
        }
    }

    // ---- Mutators (used by IOBuf via the two-tier wrapping) -----------
    //
    // These live on `OwnedIOBuf` so the per-variant dispatch is
    // colocated with the storage data — `IOBuf` just forwards. They
    // are `pub(crate)` because the public surface of `OwnedIOBuf` is
    // intentionally read-only: the cross-core RX path doesn't mutate
    // bytes through `OwnedIOBuf`, only the TX side does (through
    // `IOBuf`).

    /// CoW a `Shared` IOBuf into a fresh `Heap` IOBuf when the
    /// `Arc<SharedRegion>` is aliased (refcount > 1). Preserves the
    /// view's capacity layout — same `(offset, len)`, same total
    /// capacity — so subsequent prepends/appends see the same
    /// headroom/tailroom they would have on the original. No-op
    /// when the variant isn't `Shared`, or when it's `Shared` and
    /// the Arc is uniquely held (the mutator then writes in place
    /// via `Arc::get_mut`).
    ///
    /// Visible bytes are copied; the headroom/tailroom of the new
    /// heap is zero-init (those bytes are only ever overwritten by
    /// later prepends/appends, never read).
    fn cow_if_shared_aliased(&mut self) {
        let needs_cow = match &mut self.storage {
            OwnedStorage::Shared(arc) => Arc::get_mut(arc).is_none(),
            _ => false,
        };
        if !needs_cow {
            return;
        }
        // The previous `&mut` borrow ended at the `match` expression.
        // `needs_cow` is only true on the Shared arm, so this `if let`
        // always matches; the `else { unreachable }` is implicit by
        // not having an else (the variable bindings below depend on
        // the body running).
        let OwnedStorage::Shared(arc) = &self.storage else {
            unreachable!("needs_cow ⇒ variant was Shared");
        };
        let cap = arc.capacity();
        let o = self.offset as usize;
        let l = self.len as usize;
        // Zero-fill the full capacity: a subsequent prepend reads the
        // freshly-allocated headroom byte before overwriting it
        // (via `copy_from_slice`), so it has to be initialised. Same
        // reason `IOBuf::new_with_reserved` zero-fills its alloc.
        let mut buf: alloc::vec::Vec<u8> = alloc::vec![0u8; cap];
        buf[o..o + l].copy_from_slice(&arc.bytes()[o..o + l]);
        let new_box = buf.into_boxed_slice();
        let (new_offset, new_len) = (self.offset, self.len);
        self.storage = OwnedStorage::Heap(HeapStorage::new(new_box));
        self.offset = new_offset;
        self.len = new_len;
    }

    pub(crate) fn data_mut(&mut self) -> Option<&mut [u8]> {
        self.cow_if_shared_aliased();
        let o = self.offset as usize;
        let l = self.len as usize;
        // `bytes_mut()` is `None` only for `Static` (immutable);
        // `Shared` is unique post-CoW.
        Some(&mut self.storage.bytes_mut()?[o..o + l])
    }

    pub(crate) fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        self.cow_if_shared_aliased();
        // Static rejects up front; otherwise the headroom bound is
        // what can fail.
        if matches!(self.storage, OwnedStorage::Static(_)) {
            return Err(IOBufError::Immutable);
        }
        if n > self.offset as usize {
            return Err(IOBufError::NoHeadroom);
        }
        let new_offset = self.offset - n as u32;
        let old_offset = self.offset as usize;
        self.storage
            .bytes_mut()
            .expect("non-Static checked above")[new_offset as usize..old_offset]
            .copy_from_slice(data);
        self.offset = new_offset;
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        self.cow_if_shared_aliased();
        if matches!(self.storage, OwnedStorage::Static(_)) {
            return Err(IOBufError::Immutable);
        }
        let end = self.offset as usize + self.len as usize;
        if end + n > self.capacity() {
            return Err(IOBufError::NoTailroom);
        }
        self.storage
            .bytes_mut()
            .expect("non-Static checked above")[end..end + n]
            .copy_from_slice(data);
        self.len += n as u32;
        Ok(())
    }

    pub(crate) fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        self.cow_if_shared_aliased();
        if matches!(self.storage, OwnedStorage::Static(_)) {
            return Err(IOBufError::Immutable);
        }
        let end = self.offset as usize + self.len as usize;
        if end + n > self.capacity() {
            return Err(IOBufError::NoTailroom);
        }
        self.len += n as u32;
        Ok(&mut self.storage.bytes_mut().expect("non-Static checked above")[end..end + n])
    }
}

impl IOBufRead for OwnedIOBuf {
    #[inline]
    fn data(&self) -> &[u8] {
        OwnedIOBuf::data(self)
    }
    #[inline]
    fn len(&self) -> usize {
        OwnedIOBuf::len(self)
    }
    #[inline]
    fn headroom(&self) -> usize {
        OwnedIOBuf::headroom(self)
    }
    #[inline]
    fn tailroom(&self) -> usize {
        OwnedIOBuf::tailroom(self)
    }
}

/// Widen an `OwnedIOBuf` into an `IOBuf` — the one conversion the
/// borrowed/owned split adds. Infallible: `IOBuf` is a thin
/// `Owned`/`Borrowed` wrapper, and this just wraps the `OwnedIOBuf`
/// in the `Owned` variant. Zero copy, no allocation.
///
/// Exercised at the app RX API boundary — a `BodyReader` spanning
/// RX-buffer-backed chunks (`OwnedIOBuf`) and prebuf-backed chunks
/// (`Borrowed`) within one body holds `IOBuf`, so RX buffers widen
/// in per-chunk as they surface. There is deliberately **no**
/// *infallible* `From<IOBuf> for OwnedIOBuf`: narrowing a `Borrowed`
/// part would have to discard or silently materialise it. The
/// fallible `TryFrom<IOBuf>` below is the sanctioned narrowing — it
/// errors on `Borrowed` instead of guessing.
impl From<OwnedIOBuf> for IOBuf {
    fn from(o: OwnedIOBuf) -> IOBuf {
        IOBuf {
            inner: IOBufInner::Owned(o),
        }
    }
}

/// Narrow an `IOBuf` back down to its owning tier — the *fallible*
/// counterpart to the `From<OwnedIOBuf>` widening above. Succeeds for
/// every `Owned(_)` shape (heap, external, shared, static), returning
/// the inner `OwnedIOBuf` with **zero copy**; fails for the sole
/// non-owning `Borrowed` variant, handing the original `IOBuf` back
/// untouched in the `Err` so the caller can fall back (e.g.
/// `into_owned()` to materialise the bytes first).
///
/// This is the one narrowing the two-tier split admits, and only
/// because it can't silently drop a borrow: making a `Borrowed` view
/// `Send` would require copying its bytes, which this conversion
/// refuses to do behind the caller's back. The TLS RX share path is
/// the canonical caller — every chunk it shares was `into_owned()`'d
/// in `pump_rx` first, so the conversion is total there and the
/// `Err` arm is unreachable by construction.
impl TryFrom<IOBuf> for OwnedIOBuf {
    type Error = IOBuf;

    fn try_from(buf: IOBuf) -> Result<OwnedIOBuf, IOBuf> {
        match buf.inner {
            IOBufInner::Owned(o) => Ok(o),
            inner @ IOBufInner::Borrowed { .. } => Err(IOBuf { inner }),
        }
    }
}

/// Build a `Heap`-backed `OwnedIOBuf` from a `Vec<u8>`, reusing the
/// allocation (`Vec::into_boxed_slice` is no-copy when `len ==
/// capacity`). Headroom = tailroom = 0. Mirrors `From<Vec<u8>> for
/// IOBuf`; the TLS RX straddler path uses it to push a
/// freshly-decrypted plaintext copy as an owning queue entry without
/// round-tripping through `IOBuf`.
impl From<alloc::vec::Vec<u8>> for OwnedIOBuf {
    fn from(v: alloc::vec::Vec<u8>) -> OwnedIOBuf {
        let len = v.len() as u32;
        OwnedIOBuf {
            storage: OwnedStorage::Heap(HeapStorage::new(v.into_boxed_slice())),
            offset: 0,
            len,
        }
    }
}

// ============================================================================
// Tests — OwnedIOBuf-focused.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `share()` lifts an `OwnedIOBuf`'s storage into an
    /// `Arc<SharedRegion>` **without copying bytes** — observable
    /// via pointer-equality between the original buffer's data
    /// pointer and the shared buffer's data pointer.
    #[test]
    fn share_is_move_only_no_byte_copy() {
        use core::ptr::NonNull;
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, _ctx: *mut ()) {}

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[4..12].copy_from_slice(b"original");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the IOBuf in this block; cb is a no-op.
        let buf =
            unsafe { OwnedIOBuf::wrap_owned(ptr, 32, 4, 8, cb, core::ptr::null_mut()) };
        let ptr_before = buf.data().as_ptr();

        let shared = buf.share();
        assert!(matches!(shared.storage, OwnedStorage::Shared(_)));
        assert_eq!(shared.data(), b"original");
        assert_eq!(
            shared.data().as_ptr(),
            ptr_before,
            "share() must not copy bytes — same backing pointer",
        );
    }

    /// `clone_shared()` bumps the `Arc<SharedRegion>` refcount;
    /// both clones read the same bytes through the same backing
    /// pointer, and adjust offset/len independently.
    #[test]
    fn clone_shared_yields_two_views_of_same_bytes() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[4..12].copy_from_slice(b"abcdefgh");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        unsafe fn cb(_b: core::ptr::NonNull<u8>, _c: u32, _ctx: *mut ()) {}
        // SAFETY: storage outlives both views; cb is a no-op.
        let buf =
            unsafe { OwnedIOBuf::wrap_owned(ptr, 32, 4, 8, cb, core::ptr::null_mut()) };

        let a = buf.share();
        let b = a.clone_shared().unwrap();
        assert_eq!(a.data(), b"abcdefgh");
        assert_eq!(b.data(), b"abcdefgh");
        assert_eq!(
            a.data().as_ptr(),
            b.data().as_ptr(),
            "both views share the same backing pointer",
        );

        // Narrowing one view's window doesn't disturb the other.
        let mut b = b;
        b.narrow(2, 4).unwrap();
        assert_eq!(b.data(), b"cdef");
        assert_eq!(a.data(), b"abcdefgh", "the other view's window is independent");
    }

    /// `share()` on an already-Shared buffer is idempotent — same
    /// underlying Arc, no extra allocation. We detect this by
    /// pointer-equality of the SharedRegion bytes (a fresh Arc would
    /// move the storage to a new heap address).
    #[test]
    fn share_is_idempotent_on_already_shared() {
        let buf = OwnedIOBuf {
            storage: OwnedStorage::Heap(HeapStorage::new(
                alloc::vec![1u8, 2, 3, 4].into_boxed_slice(),
            )),
            offset: 0,
            len: 4,
        };
        let once = buf.share();
        let ptr_after_first_share = once.data().as_ptr();
        let twice = once.share();
        assert_eq!(twice.data(), &[1u8, 2, 3, 4]);
        assert_eq!(
            twice.data().as_ptr(),
            ptr_after_first_share,
            "share() on a Shared buffer must not re-allocate",
        );
    }

    /// `clone_shared()` on a non-Shared, non-Static buffer
    /// (`Heap` / `External`) returns `Err(NotShared)`. The caller
    /// must explicitly opt-in to refcounting via `share()` first.
    #[test]
    fn clone_shared_on_non_shared_errors() {
        let buf = OwnedIOBuf {
            storage: OwnedStorage::Heap(HeapStorage::new(alloc::vec![1u8].into_boxed_slice())),
            offset: 0,
            len: 1,
        };
        assert!(matches!(buf.clone_shared(), Err(IOBufError::NotShared)));
    }

    /// `clone_shared()` on a Static buffer succeeds and yields a
    /// fresh view of the same `&'static` slice — `Static` is
    /// already an immortal borrow, no Arc needed.
    #[test]
    fn clone_shared_on_static_succeeds() {
        let buf = OwnedIOBuf::from_static(b"hello world");
        let copy = buf.clone_shared().expect("Static is shareable");
        assert_eq!(buf.data(), b"hello world");
        assert_eq!(copy.data(), b"hello world");
    }

    /// A `Shared(External)`'s drop callback fires **exactly once**
    /// — when the last `Arc<SharedRegion>` strong reference drops,
    /// not before. Two clones; drop one, callback hasn't fired;
    /// drop the last, callback fires.
    #[test]
    fn shared_external_drop_callback_runs_exactly_once() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let drop_count = StdArc::new(AtomicUsize::new(0));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: StdArc<AtomicUsize> = unsafe { StdArc::from_raw(ctx as *const AtomicUsize) };
            arc.fetch_add(1, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![9u8; 16];
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = StdArc::into_raw(drop_count.clone()) as *mut ();
        let buf = unsafe { OwnedIOBuf::wrap_owned(ptr, 16, 0, 16, cb, ctx) };

        let a = buf.share();
        let b = a.clone_shared().unwrap();
        assert_eq!(drop_count.load(Ordering::SeqCst), 0);
        drop(a);
        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            0,
            "callback must not fire while one Arc clone is alive",
        );
        drop(b);
        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            1,
            "callback fires exactly once when the last Arc clone drops",
        );
    }

    /// RX item D's core primitive: `narrow` clamps the visible window
    /// to an inner sub-range (an L4 segment inside a frame), shifting
    /// only offset/len — the backing region is untouched, so the drop
    /// callback still reposts the *original* `(base, capacity)`. A
    /// frame buffer thus reposts whole even after being narrowed down
    /// to its TCP segment.
    #[test]
    fn owned_iobuf_narrow_clamps_window_keeps_backing() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        // cb records the capacity it was handed at drop time.
        let cap_at_drop = Arc::new(AtomicU32::new(0));
        unsafe fn cb(_base: NonNull<u8>, cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicU32> = unsafe { Arc::from_raw(ctx as *const AtomicU32) };
            arc.store(cap, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 20];
        // bytes 6..14 stand in for the "L4 segment"; 0..6 = the
        // eth/IP headers, 14..20 = ethernet trailing padding.
        storage[6..14].copy_from_slice(b"segment!");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(cap_at_drop.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf; cb reclaims the Arc once.
            let mut b = unsafe { OwnedIOBuf::wrap_owned(ptr, 20, 0, 20, cb, ctx) };
            assert_eq!(b.len(), 20);
            // Narrow to the inner 8-byte "segment": drop 6 header
            // bytes off the front, trim 6 padding bytes off the back.
            b.narrow(6, 8).unwrap();
            assert_eq!(b.data(), b"segment!");
            assert_eq!(b.headroom(), 6);
            assert_eq!(b.tailroom(), 6);
            // A narrow past the now-8-byte window is rejected and
            // leaves the window intact (the bound check precedes any
            // offset mutation).
            assert!(b.narrow(9, 1).is_err());
            assert_eq!(b.data(), b"segment!");
        }
        // The drop callback ran with the *original* capacity (20),
        // not the narrowed 8 — the whole device buffer reposts.
        assert_eq!(cap_at_drop.load(Ordering::SeqCst), 20);
    }

    /// `TryFrom<IOBuf>` on an `Owned(Heap)` IOBuf succeeds, yielding
    /// the inner `OwnedIOBuf` with bytes intact and **zero copy**
    /// (same backing pointer).
    #[test]
    fn try_from_iobuf_heap_ok() {
        let buf = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let ptr_before = buf.data().as_ptr();
        // `.ok().expect(..)` rather than `.expect(..)`: the `Err`
        // payload is `IOBuf`, which doesn't impl `Debug`.
        let owned = OwnedIOBuf::try_from(buf).ok().expect("Owned(Heap) narrows");
        assert!(matches!(owned.storage, OwnedStorage::Heap(_)));
        assert_eq!(owned.data(), &[1, 2, 3, 4]);
        assert_eq!(
            owned.data().as_ptr(),
            ptr_before,
            "narrowing must not reallocate",
        );
    }

    /// `TryFrom<IOBuf>` on a `Borrowed` IOBuf fails, returning the
    /// original `IOBuf` untouched in the `Err`.
    #[test]
    fn try_from_iobuf_borrowed_err_returns_original() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 16];
        storage[..8].copy_from_slice(b"borrowed");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the borrow.
        let buf = unsafe { IOBuf::borrow(ptr, 16, 0, 8) };
        // `.err().expect(..)` rather than `.expect_err(..)`: the `Ok`
        // payload is `OwnedIOBuf`, which doesn't impl `Debug`.
        let back = OwnedIOBuf::try_from(buf)
            .err()
            .expect("Borrowed cannot narrow");
        assert_eq!(back.data(), b"borrowed", "Err returns the IOBuf intact");
    }

    /// `TryFrom<IOBuf>` succeeds for the `Static`, `Shared`, and
    /// `External` owning shapes too — every `Owned(_)` variant
    /// narrows.
    #[test]
    fn try_from_iobuf_static_shared_external_ok() {
        // Static. (`.ok().expect(..)` throughout — `Err` is `IOBuf`,
        // which doesn't impl `Debug`.)
        let s = OwnedIOBuf::try_from(IOBuf::from_static(b"static"))
            .ok()
            .expect("Static narrows");
        assert!(matches!(s.storage, OwnedStorage::Static(_)));
        assert_eq!(s.data(), b"static");

        // Shared (Heap → share()).
        let shared_iobuf = IOBuf::from(alloc::vec![5u8, 6, 7]).share();
        let sh = OwnedIOBuf::try_from(shared_iobuf)
            .ok()
            .expect("Shared narrows");
        assert!(matches!(sh.storage, OwnedStorage::Shared(_)));
        assert_eq!(sh.data(), &[5, 6, 7]);

        // External (wrap_owned → widen → narrow back).
        unsafe fn cb(_b: NonNull<u8>, _c: u32, _ctx: *mut ()) {}
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 8];
        storage[..4].copy_from_slice(b"extn");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the IOBuf in this test; cb is a no-op.
        let ext_iobuf: IOBuf =
            unsafe { OwnedIOBuf::wrap_owned(ptr, 8, 0, 4, cb, core::ptr::null_mut()) }.into();
        let ext = OwnedIOBuf::try_from(ext_iobuf)
            .ok()
            .expect("External narrows");
        assert!(matches!(ext.storage, OwnedStorage::External(_)));
        assert_eq!(ext.data(), b"extn");
    }

    /// `From<Vec<u8>>` builds a `Heap` `OwnedIOBuf` reusing the Vec's
    /// allocation (no copy) with the full visible payload.
    #[test]
    fn from_vec_builds_heap_owned() {
        let v = alloc::vec![9u8, 8, 7, 6];
        let ptr_before = v.as_ptr();
        let owned = OwnedIOBuf::from(v);
        assert!(matches!(owned.storage, OwnedStorage::Heap(_)));
        assert_eq!(owned.data(), &[9, 8, 7, 6]);
        assert_eq!(owned.headroom(), 0);
        assert_eq!(owned.tailroom(), 0);
        assert_eq!(
            owned.data().as_ptr(),
            ptr_before,
            "Vec → OwnedIOBuf reuses the allocation",
        );
    }

    /// The TLS RX share fan-out, exercised at the primitive level:
    /// one `External` (device) buffer holding K back-to-back records
    /// is `share()`d once, then each record becomes a
    /// `clone_shared()` + `narrow()` view — exactly what
    /// `TlsServer::process_chunk` does with `app_data_ranges`. Asserts
    /// the two invariants the branch's zero-copy RX path depends on:
    ///
    ///   1. **Zero-copy fan-out** — every view's bytes are the right
    ///      record sub-range AND its `data()` pointer is co-located in
    ///      the *original* device allocation (no per-record copy).
    ///   2. **Pinning lifecycle** — the device buffer's drop callback
    ///      (which, on bare-metal, reposts the NIC RX buffer) fires
    ///      **exactly once**, and only after the *last* queued view
    ///      drops. This is the "device-buffer held until the app
    ///      consumes all plaintext records" property — the thing that
    ///      must be correct for the share-based RX path to be safe.
    #[test]
    fn share_fanout_k_records_zero_copy_and_drops_once() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let drop_count = StdArc::new(AtomicUsize::new(0));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: StdArc<AtomicUsize> = unsafe { StdArc::from_raw(ctx as *const AtomicUsize) };
            arc.fetch_add(1, Ordering::SeqCst);
        }

        // A device buffer holding three back-to-back "decrypted
        // records" at [0..100), [100..220), [220..300).
        const N: usize = 300;
        let ranges = [(0usize, 100usize), (100, 120), (220, 80)];
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; N];
        for (i, b) in storage.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let base = storage.as_ptr() as usize;
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = StdArc::into_raw(drop_count.clone()) as *mut ();
        // SAFETY: storage outlives every view in this test; cb reclaims
        // the Arc exactly once at drop.
        let chunk = unsafe { OwnedIOBuf::wrap_owned(ptr, N as u32, 0, N as u32, cb, ctx) };

        // share() once (1 Arc alloc, no copy), then clone_shared() +
        // narrow() per record — the process_chunk fan-out.
        let shared = chunk.share();
        let mut views: alloc::vec::Vec<OwnedIOBuf> = alloc::vec::Vec::new();
        for &(off, len) in &ranges {
            let mut v = shared.clone_shared().expect("shared is shareable");
            v.narrow(off, len).unwrap();
            views.push(v);
        }
        // Drop the fan-out handle; the K views keep the backing alive.
        drop(shared);

        // (1) Each view reads its record's bytes from the *original*
        // device allocation — pointer co-located, zero copy.
        for (i, &(off, len)) in ranges.iter().enumerate() {
            assert_eq!(views[i].len(), len, "view {i} length");
            assert_eq!(
                views[i].data().as_ptr() as usize,
                base + off,
                "view {i} shares the device backing at +{off} (no copy)",
            );
            assert_eq!(
                views[i].data()[0],
                (off & 0xFF) as u8,
                "view {i} reads the right record bytes",
            );
        }

        // (2) Pinning lifecycle: the device buffer is held while any
        // view is alive, then reposted exactly once.
        assert_eq!(drop_count.load(Ordering::SeqCst), 0, "buffer pinned while views live");
        views.pop();
        views.pop();
        assert_eq!(drop_count.load(Ordering::SeqCst), 0, "still pinned by the last view");
        views.pop();
        assert_eq!(
            drop_count.load(Ordering::SeqCst),
            1,
            "device buffer reposts exactly once after the last view drops",
        );
    }
}
