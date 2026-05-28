// `IOBuf` — the flat `!Send` enum over all four storage variants.
//
// See the crate root for the borrowed/owned type-split rationale.
// `IOBuf` is the TX-path buffer: it mixes owned and borrowed parts,
// and `BorrowedView`'s `PhantomData<*const ()>` propagates through
// the enum to make the whole type `!Send + !Sync`.
//
// As of PR 2 each variant of `Inner` carries its own `(offset, len)`
// view alongside the storage; the per-variant structs in `storage.rs`
// hold bytes only. Static keeps its self-contained slide semantics
// (no outer offset/len) — its slice is its view.

use alloc::boxed::Box;
use core::ptr::NonNull;

use crate::{
    BorrowedView, ExternalOwned, HeapStorage, IOBufError, IOBufRead, IOBufWriter, StaticView,
};

/// One byte segment. Holds heap-owned storage, a static-lifetime
/// borrow, foreign storage owned via a drop callback, or a non-owning
/// view of foreign storage. The `Borrowed` variant makes the whole
/// `IOBuf` `!Send + !Sync` so per-worker borrows can't accidentally
/// cross workers — see [`crate::OwnedIOBuf`] for the `Send` counterpart
/// that the cross-core path uses.
pub struct IOBuf {
    pub(crate) inner: Inner,
}

/// Storage backing an [`IOBuf`]. Private: `IOBuf`'s public surface is
/// its methods. Each variant carries its bytes-only storage plus the
/// visible `(offset, len)` view — except `Static`, whose slice IS its
/// view (consume/trim_end slide the slice; headroom/tailroom = 0).
pub(crate) enum Inner {
    /// Heap-owned `Box<[u8]>` + view.
    Heap {
        storage: HeapStorage,
        offset: u32,
        len: u32,
    },
    /// A `&'static [u8]` borrow. Immutable. Slides internally.
    Static(StaticView),
    /// A foreign region owned via a drop callback (NIC RX, pools) + view.
    External {
        storage: ExternalOwned,
        offset: u32,
        len: u32,
    },
    /// A non-owning view of foreign storage + view — the `!Send` variant.
    Borrowed {
        view: BorrowedView,
        offset: u32,
        len: u32,
    },
}

impl IOBuf {
    /// Allocate a heap-backed buffer with `headroom` bytes reserved
    /// at the front and `tailroom` at the end. Total allocation is
    /// `headroom + payload_capacity + tailroom`; the visible payload
    /// starts empty (`len = 0`) at offset `headroom`.
    pub fn new_with_reserved(headroom: usize, payload_capacity: usize, tailroom: usize) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // Zero-fill: nobody reads headroom / tailroom, but the
        // allocator's free-list returns this memory eventually so
        // initial-zeroing keeps info-leak-class bugs away.
        let storage = alloc::vec![0u8; cap].into_boxed_slice();
        IOBuf {
            inner: Inner::Heap {
                storage: HeapStorage::new(storage),
                offset: headroom as u32,
                len: 0,
            },
        }
    }

    /// Zero-init-free variant of [`Self::new_with_reserved`]. Saves
    /// the memset at the price of an unsafe contract: the caller must
    /// write to every byte before reading it.
    ///
    /// # Safety
    ///
    /// The caller must ensure no byte is read via `data()` before
    /// it's been written through one of `append_slice`, `writer`,
    /// `extend_uninit`, or a `prepend` that moves the visible
    /// window over it. The IOBuf API enforces this for callers
    /// that only use the public mutation entry points.
    pub unsafe fn new_with_reserved_uninit(
        headroom: usize,
        payload_capacity: usize,
        tailroom: usize,
    ) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // SAFETY: `new_uninit_slice(cap).assume_init()` returns a
        // `Box<[u8]>` whose bytes are uninitialised; the caller's
        // contract is that no byte is read before being written.
        let storage = unsafe { Box::<[u8]>::new_uninit_slice(cap).assume_init() };
        IOBuf {
            inner: Inner::Heap {
                storage: HeapStorage::new(storage),
                offset: headroom as u32,
                len: 0,
            },
        }
    }

    /// Heap-backed buffer pre-filled with `data`, with `headroom` /
    /// `tailroom` reserved around the payload.
    pub fn from_slice_with_headroom(headroom: usize, data: &[u8], tailroom: usize) -> Self {
        let mut buf = Self::new_with_reserved(headroom, data.len(), tailroom);
        buf.append_slice(data)
            .expect("freshly-sized buffer accepts payload");
        buf
    }

    /// Borrow a static-lifetime slice. Zero allocation. Subsequent
    /// `prepend` / `append_slice` / `data_mut` return errors / `None`
    /// — static borrows are immutable.
    pub const fn from_static(data: &'static [u8]) -> Self {
        IOBuf {
            inner: Inner::Static(StaticView::new(data)),
        }
    }

    /// Borrow a foreign region as an IOBuf view. No drop callback
    /// runs; the caller ensures the storage outlives every IOBuf
    /// that borrows it.
    ///
    /// The result is `!Send + !Sync` (the `Borrowed` variant
    /// propagates this through the enum). Crossing a worker boundary
    /// with a borrowed IOBuf is therefore a compile error — and the
    /// cross-core path is typed `OwnedIOBuf`, which has no borrowed
    /// variant, so a borrow can't reach it at all.
    ///
    /// # Safety
    ///
    /// The caller MUST guarantee:
    ///   * `base..base+capacity` is a valid byte region for the
    ///     entire lifetime of this IOBuf.
    ///   * `offset + len <= capacity`.
    ///   * No other route concurrently mutates the borrowed region
    ///     while this IOBuf exists.
    ///   * If multiple IOBufs view the same storage, their visible
    ///     regions do not overlap when any is mutated.
    pub unsafe fn borrow(base: NonNull<u8>, capacity: u32, offset: u32, len: u32) -> Self {
        debug_assert!(offset.saturating_add(len) <= capacity);
        IOBuf {
            inner: Inner::Borrowed {
                view: BorrowedView::new(base, capacity),
                offset,
                len,
            },
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        match &self.inner {
            Inner::Heap { storage, offset, len } => {
                let o = *offset as usize;
                &storage.bytes()[o..o + *len as usize]
            }
            Inner::Static(s) => s.data(),
            Inner::External { storage, offset, len } => {
                // SAFETY: offset + len <= capacity (construction
                // precondition, maintained by every mutator); the
                // region is exclusively owned for this IOBuf's
                // lifetime.
                unsafe {
                    core::slice::from_raw_parts(
                        storage.base().as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                }
            }
            Inner::Borrowed { view, offset, len } => {
                // SAFETY: the `borrow` caller guaranteed the region
                // is valid for this IOBuf's lifetime and not
                // concurrently mutated; offset + len <= capacity.
                unsafe {
                    core::slice::from_raw_parts(
                        view.base().as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                }
            }
        }
    }

    /// Visible payload length.
    #[inline]
    pub fn len(&self) -> usize {
        match &self.inner {
            Inner::Heap { len, .. }
            | Inner::External { len, .. }
            | Inner::Borrowed { len, .. } => *len as usize,
            Inner::Static(s) => s.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available before the payload. `0` for static borrows.
    #[inline]
    pub fn headroom(&self) -> usize {
        match &self.inner {
            Inner::Heap { offset, .. }
            | Inner::External { offset, .. }
            | Inner::Borrowed { offset, .. } => *offset as usize,
            Inner::Static(_) => 0,
        }
    }

    /// Bytes available after the payload. `0` for static borrows.
    #[inline]
    pub fn tailroom(&self) -> usize {
        match &self.inner {
            Inner::Heap { storage, offset, len } => storage
                .capacity()
                .saturating_sub(*offset as usize + *len as usize),
            Inner::Static(_) => 0,
            Inner::External { storage, offset, len } => storage
                .capacity()
                .saturating_sub(*offset as usize + *len as usize),
            Inner::Borrowed { view, offset, len } => view
                .capacity()
                .saturating_sub(*offset as usize + *len as usize),
        }
    }

    /// Mutable access to the visible payload. Returns `None` for
    /// static borrows. Used by in-place crypto (ChaCha20-Poly1305
    /// seals into the source bytes).
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        match &mut self.inner {
            Inner::Heap { storage, offset, len } => {
                let o = *offset as usize;
                let l = *len as usize;
                Some(&mut storage.bytes_mut()[o..o + l])
            }
            Inner::Static(_) => None,
            Inner::External { storage, offset, len } => {
                // SAFETY: as in `data`, plus `&mut self` gives
                // exclusive write access for this call.
                Some(unsafe {
                    core::slice::from_raw_parts_mut(
                        storage.base().as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                })
            }
            Inner::Borrowed { view, offset, len } => {
                // SAFETY: the `borrow` caller guaranteed no
                // concurrent mutation; `&mut self` gives exclusive
                // write access for this call.
                Some(unsafe {
                    core::slice::from_raw_parts_mut(
                        view.base().as_ptr().add(*offset as usize),
                        *len as usize,
                    )
                })
            }
        }
    }

    /// Prepend `data` into the headroom and grow the visible payload.
    /// `Err(NoHeadroom)` if headroom is too small; `Err(Immutable)`
    /// for static borrows.
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        match &mut self.inner {
            Inner::Static(_) => Err(IOBufError::Immutable),
            Inner::Heap { storage, offset, len } => {
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                storage.bytes_mut()[new_offset as usize..*offset as usize].copy_from_slice(data);
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
            Inner::External { storage, offset, len } => {
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                // SAFETY: `new_offset..*offset` is in-bounds
                // (new_offset >= 0 by the check); the region is
                // exclusively owned; `&mut self` gives exclusive
                // write access.
                unsafe {
                    core::slice::from_raw_parts_mut(
                        storage.base().as_ptr().add(new_offset as usize),
                        n,
                    )
                    .copy_from_slice(data);
                }
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
            Inner::Borrowed { view, offset, len } => {
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                // SAFETY: as `External` above; the `borrow` caller
                // guaranteed no concurrent mutation.
                unsafe {
                    core::slice::from_raw_parts_mut(
                        view.base().as_ptr().add(new_offset as usize),
                        n,
                    )
                    .copy_from_slice(data);
                }
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
        }
    }

    /// Append `data` into the tailroom and grow the visible payload.
    pub fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let n = data.len();
        match &mut self.inner {
            Inner::Static(_) => Err(IOBufError::Immutable),
            Inner::Heap { storage, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                storage.bytes_mut()[end..end + n].copy_from_slice(data);
                *len += n as u32;
                Ok(())
            }
            Inner::External { storage, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                // SAFETY: end..end+n is in-bounds (check above);
                // exclusive ownership; exclusive access via `&mut self`.
                unsafe {
                    core::slice::from_raw_parts_mut(storage.base().as_ptr().add(end), n)
                        .copy_from_slice(data);
                }
                *len += n as u32;
                Ok(())
            }
            Inner::Borrowed { view, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > view.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                // SAFETY: as `External` above.
                unsafe {
                    core::slice::from_raw_parts_mut(view.base().as_ptr().add(end), n)
                        .copy_from_slice(data);
                }
                *len += n as u32;
                Ok(())
            }
        }
    }

    /// Grow the visible payload by `n` bytes (contents
    /// uninitialised) and return a mutable slice over them. Used by
    /// AEAD seal: advance the visible len, write the tag in place.
    pub fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        match &mut self.inner {
            Inner::Static(_) => Err(IOBufError::Immutable),
            Inner::Heap { storage, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                Ok(&mut storage.bytes_mut()[end..end + n])
            }
            Inner::External { storage, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                // SAFETY: end..end+n in-bounds; exclusive access.
                Ok(unsafe { core::slice::from_raw_parts_mut(storage.base().as_ptr().add(end), n) })
            }
            Inner::Borrowed { view, offset, len } => {
                let end = *offset as usize + *len as usize;
                if end + n > view.capacity() {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                // SAFETY: as `External` above.
                Ok(unsafe { core::slice::from_raw_parts_mut(view.base().as_ptr().add(end), n) })
            }
        }
    }

    /// Narrow the visible payload to `[offset..offset+len]` relative
    /// to the current visible region. `Err` if `offset + len`
    /// exceeds the current visible length.
    #[inline]
    pub fn narrow(&mut self, offset: usize, len: usize) -> Result<(), IOBufError> {
        self.consume(offset)?;
        let visible = self.data().len();
        if visible > len {
            self.trim_end(visible - len)?;
        }
        Ok(())
    }

    /// Trim `n` bytes from the FRONT of the visible payload.
    #[inline]
    pub fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Static(s) => s.consume(n),
            Inner::Heap { offset, len, .. }
            | Inner::External { offset, len, .. }
            | Inner::Borrowed { offset, len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *offset += n as u32;
                *len -= n as u32;
                Ok(())
            }
        }
    }

    /// Trim `n` bytes from the BACK of the visible payload.
    #[inline]
    pub fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Static(s) => s.trim_end(n),
            Inner::Heap { len, .. }
            | Inner::External { len, .. }
            | Inner::Borrowed { len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *len -= n as u32;
                Ok(())
            }
        }
    }

    /// Consume `n` bytes from the front and return the IOBuf if
    /// the visible payload is non-empty after the advance, or
    /// `Ok(None)` if it's now empty. The "carry the leftover
    /// forward" primitive — used when a caller parsed the first
    /// `n` bytes of this buffer and wants to thread anything past
    /// `n` into the next iteration (e.g. body bytes that landed
    /// in the same chunk as a request HEAD).
    ///
    /// Borrow-preserving: a `Borrowed` IOBuf yields a `Borrowed`
    /// remainder. Callers that need an owned tail (i.e. need to
    /// hold it past the borrow's lifetime) follow with
    /// `into_owned()` on the `Some(_)` branch — see
    /// `RecvChunkGuard::into_remainder` for the bundled version.
    ///
    /// Returns the same `IOBufError` shape as `consume(n)` if `n`
    /// exceeds the visible payload; choice of panic vs propagate
    /// stays at the call site.
    #[inline]
    pub fn into_remainder(mut self, n: usize) -> Result<Option<IOBuf>, IOBufError> {
        self.consume(n)?;
        Ok((!self.data().is_empty()).then_some(self))
    }

    /// `core::fmt::Write` adapter that appends formatted bytes into
    /// the IOBuf's tailroom — `write!(buf.writer(), "{}", value)`
    /// renders straight into the IOBuf with no intermediate `String`.
    pub fn writer(&mut self) -> IOBufWriter<'_> {
        IOBufWriter::new(self)
    }

    /// Convert this IOBuf into one that fully owns (or statically
    /// outlives) its bytes — carrying no out-of-band lifetime
    /// contract.
    ///
    ///   * `Heap` / `Static` / `External` — each already owns its
    ///     storage (or `'static`-outlives it). Returned unchanged:
    ///     **zero copy**.
    ///   * `Borrowed` — the sole non-owning variant. Its visible
    ///     payload is copied into a freshly-allocated `Heap` buffer.
    ///     The **only** variant that costs a copy.
    ///
    /// The escape hatch for "I hold a `Borrowed` view of inbound
    /// bytes but need owned possession of them" — e.g. a proxy
    /// handler forwarding request bytes into an outbound async
    /// `send`, where the borrowed source could be overwritten before
    /// that send completes. Materialises owned storage on demand, a
    /// no-op when ownership already holds. It stays `IOBuf -> IOBuf`:
    /// a cross-*time* tool, orthogonal to the borrowed/owned split's
    /// cross-*core* `OwnedIOBuf` typing.
    pub fn into_owned(mut self) -> IOBuf {
        if matches!(self.inner, Inner::Borrowed { .. }) {
            // Copy the visible payload into owned heap storage.
            // `data()`'s borrow ends at `.to_vec()`; the subsequent
            // `self.inner` write drops the old `Borrowed`, whose
            // `BorrowGuard` unregisters from the debug-mode aliasing
            // tracker — symmetric with the `borrow` that minted it.
            let owned: Box<[u8]> = self.data().to_vec().into_boxed_slice();
            let len = owned.len() as u32;
            self.inner = Inner::Heap {
                storage: HeapStorage::new(owned),
                offset: 0,
                len,
            };
        }
        self
    }
}

impl IOBufRead for IOBuf {
    #[inline]
    fn data(&self) -> &[u8] {
        IOBuf::data(self)
    }
    #[inline]
    fn len(&self) -> usize {
        IOBuf::len(self)
    }
    #[inline]
    fn headroom(&self) -> usize {
        IOBuf::headroom(self)
    }
    #[inline]
    fn tailroom(&self) -> usize {
        IOBuf::tailroom(self)
    }
}

// ============================================================================
// From/Into for ergonomics — body shapes that flatten to one IOBuf.
// ============================================================================

impl From<&'static [u8]> for IOBuf {
    fn from(s: &'static [u8]) -> Self {
        IOBuf::from_static(s)
    }
}

impl<const N: usize> From<&'static [u8; N]> for IOBuf {
    fn from(s: &'static [u8; N]) -> Self {
        IOBuf::from_static(s)
    }
}

impl From<&'static str> for IOBuf {
    fn from(s: &'static str) -> Self {
        IOBuf::from_static(s.as_bytes())
    }
}

impl From<alloc::vec::Vec<u8>> for IOBuf {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        // `Vec::into_boxed_slice` reuses the allocation when len ==
        // capacity (no copy). Headroom = 0, tailroom = 0; callers who
        // want layer-prepend room construct via
        // `from_slice_with_headroom`.
        let len = v.len() as u32;
        IOBuf {
            inner: Inner::Heap {
                storage: HeapStorage::new(v.into_boxed_slice()),
                offset: 0,
                len,
            },
        }
    }
}

impl From<alloc::string::String> for IOBuf {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes())
    }
}

// ============================================================================
// Tests — IOBuf-focused, including ones that match on the private `Inner`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnedIOBuf;

    #[test]
    fn static_buf_basics() {
        let b = IOBuf::from_static(b"hello");
        assert_eq!(b.data(), b"hello");
        assert_eq!(b.len(), 5);
        assert_eq!(b.headroom(), 0);
        assert_eq!(b.tailroom(), 0);
    }

    #[test]
    fn static_buf_consume() {
        let mut b = IOBuf::from_static(b"hello world");
        b.consume(6).unwrap();
        assert_eq!(b.data(), b"world");
        b.trim_end(2).unwrap();
        assert_eq!(b.data(), b"wor");
    }

    #[test]
    fn static_buf_prepend_rejects() {
        let mut b = IOBuf::from_static(b"x");
        assert_eq!(b.prepend(b"y"), Err(IOBufError::Immutable));
        assert_eq!(b.append_slice(b"y"), Err(IOBufError::Immutable));
        assert!(b.data_mut().is_none());
    }

    #[test]
    fn heap_buf_headroom_prepend() {
        let mut b = IOBuf::from_slice_with_headroom(8, b"world", 0);
        assert_eq!(b.data(), b"world");
        assert_eq!(b.headroom(), 8);
        assert_eq!(b.tailroom(), 0);
        b.prepend(b"hello ").unwrap();
        assert_eq!(b.data(), b"hello world");
        assert_eq!(b.headroom(), 2);
    }

    #[test]
    fn heap_buf_prepend_overflow() {
        let mut b = IOBuf::from_slice_with_headroom(2, b"x", 0);
        assert_eq!(b.prepend(b"abc"), Err(IOBufError::NoHeadroom));
        assert_eq!(b.data(), b"x");
    }

    #[test]
    fn heap_buf_tailroom_append() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"hello", 8);
        b.append_slice(b" world").unwrap();
        assert_eq!(b.data(), b"hello world");
        assert_eq!(b.tailroom(), 2);
    }

    #[test]
    fn heap_buf_extend_uninit() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"hi", 8);
        let tail = b.extend_uninit(4).unwrap();
        tail.copy_from_slice(b"!!!!");
        assert_eq!(b.data(), b"hi!!!!");
    }

    #[test]
    fn heap_buf_data_mut_in_place_xor() {
        let mut b = IOBuf::from_slice_with_headroom(0, b"abc", 0);
        for byte in b.data_mut().unwrap() {
            *byte ^= 0x20;
        }
        assert_eq!(b.data(), b"ABC");
    }

    #[test]
    fn vec_into_iobuf_no_copy() {
        let v = alloc::vec![1u8, 2, 3, 4, 5];
        let ptr_before = v.as_ptr();
        let buf = IOBuf::from(v);
        assert_eq!(buf.data(), &[1u8, 2, 3, 4, 5]);
        let _ = ptr_before;
    }

    #[test]
    fn external_buf_drop_runs_callback() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));

        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> = unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[5..13].copy_from_slice(b"abcdefgh");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf in this block; the
            // callback reconstructs the Arc from ctx and lets it drop.
            // `wrap_owned` produces an `OwnedIOBuf`; widen it to the
            // mutable `IOBuf` this test exercises.
            let mut buf = IOBuf::from(unsafe { OwnedIOBuf::wrap_owned(ptr, 32, 5, 8, cb, ctx) });
            assert_eq!(buf.data(), b"abcdefgh");
            assert_eq!(buf.headroom(), 5);
            assert_eq!(buf.tailroom(), 19);
            buf.prepend(b"PRE").unwrap();
            assert_eq!(buf.data(), b"PREabcdefgh");
            buf.append_slice(b"END").unwrap();
            assert_eq!(buf.data(), b"PREabcdefghEND");
            for byte in buf.data_mut().unwrap() {
                if byte.is_ascii_lowercase() {
                    *byte ^= 0x20;
                }
            }
            assert_eq!(buf.data(), b"PREABCDEFGHEND");
            assert!(!released.load(Ordering::SeqCst));
        }
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn borrowed_buf_no_drop_callback() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[5..13].copy_from_slice(b"abcdefgh");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the IOBuf in this block.
        let mut buf = unsafe { IOBuf::borrow(ptr, 32, 5, 8) };
        assert_eq!(buf.data(), b"abcdefgh");
        assert_eq!(buf.headroom(), 5);
        assert_eq!(buf.tailroom(), 19);
        buf.prepend(b"PRE").unwrap();
        assert_eq!(buf.data(), b"PREabcdefgh");
        buf.append_slice(b"END").unwrap();
        assert_eq!(buf.data(), b"PREabcdefghEND");
        for byte in buf.data_mut().unwrap() {
            if byte.is_ascii_lowercase() {
                *byte ^= 0x20;
            }
        }
        assert_eq!(buf.data(), b"PREABCDEFGHEND");
        drop(buf);
        assert_eq!(&storage[5..13], b"ABCDEFGH");
    }

    /// `IOBuf` is `!Send` — the `Borrowed` variant's
    /// `PhantomData<*const ()>` propagates through the enum. Stable
    /// Rust can't express a `!Send` bound directly; this exercises
    /// the `Borrowed` variant and documents intent. The companion
    /// positive check — `OwnedIOBuf: Send` — is the module-level
    /// `const _` static assertion near `OwnedIOBuf`.
    #[test]
    fn iobuf_is_not_send() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 4];
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the borrow.
        let buf = unsafe { IOBuf::borrow(ptr, 4, 0, 0) };
        assert_eq!(buf.len(), 0);
        // Uncommenting the line below should fail to compile with
        // "`*const ()` cannot be sent between threads safely":
        //   std::thread::spawn(move || { let _ = buf; });
    }

    #[test]
    fn borrow_tracker_allows_disjoint_regions() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let p1 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr()) };
        let p2 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(16)) };
        // SAFETY: storage outlives both IOBufs; non-overlapping ranges.
        let b1 = unsafe { IOBuf::borrow(p1, 16, 0, 0) };
        let b2 = unsafe { IOBuf::borrow(p2, 16, 0, 0) };
        assert_eq!(b1.len(), 0);
        assert_eq!(b2.len(), 0);
    }

    #[test]
    #[should_panic(expected = "overlapping IOBuf::borrow mint")]
    fn borrow_tracker_detects_overlap() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let p1 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr()) };
        let p2 = unsafe { core::ptr::NonNull::new_unchecked(base.as_ptr().add(8)) };
        // SAFETY (for the demonstration): the second mint is the
        // intentional bug we're catching — overlap with the first.
        let _b1 = unsafe { IOBuf::borrow(p1, 16, 0, 0) };
        let _b2 = unsafe { IOBuf::borrow(p2, 16, 0, 0) };
    }

    #[test]
    fn borrow_tracker_reregister_after_drop() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        let base = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives both successive IOBufs; only one
        // is live at any given time.
        {
            let _b1 = unsafe { IOBuf::borrow(base, 32, 0, 0) };
        }
        let _b2 = unsafe { IOBuf::borrow(base, 32, 0, 0) };
    }

    #[test]
    fn into_owned_heap_is_zero_copy() {
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let ptr_before = b.data().as_ptr() as usize;
        let o = b.into_owned();
        assert!(matches!(o.inner, Inner::Heap { .. }));
        assert_eq!(o.data(), &[1, 2, 3, 4]);
        assert_eq!(
            o.data().as_ptr() as usize,
            ptr_before,
            "Heap into_owned must not reallocate"
        );
    }

    #[test]
    fn into_owned_static_is_noop() {
        let o = IOBuf::from_static(b"hello").into_owned();
        assert!(matches!(o.inner, Inner::Static(_)));
        assert_eq!(o.data(), b"hello");
    }

    #[test]
    fn into_owned_external_is_noop_and_drops_once() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> = unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 16];
        storage[0..4].copy_from_slice(b"data");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf; the callback
            // reconstructs the Arc from ctx and lets it drop.
            let b = IOBuf::from(unsafe { OwnedIOBuf::wrap_owned(ptr, 16, 0, 4, cb, ctx) });
            let o = b.into_owned();
            assert!(matches!(o.inner, Inner::External { .. }));
            assert_eq!(o.data(), b"data");
            assert!(!released.load(Ordering::SeqCst), "callback not yet run");
        }
        assert!(
            released.load(Ordering::SeqCst),
            "drop callback fires exactly once after into_owned"
        );
    }

    #[test]
    fn into_remainder_returns_none_on_full_consume() {
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        assert!(b.into_remainder(4).expect("in-range").is_none());
    }

    #[test]
    fn into_remainder_returns_tail_on_partial_consume() {
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let tail = b
            .into_remainder(2)
            .expect("in-range")
            .expect("non-empty after partial consume");
        assert_eq!(tail.data(), &[3, 4]);
    }

    #[test]
    fn into_remainder_zero_keeps_full_buffer() {
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        let tail = b
            .into_remainder(0)
            .expect("in-range")
            .expect("zero consume keeps everything");
        assert_eq!(tail.data(), &[1, 2, 3, 4]);
    }

    #[test]
    fn into_remainder_preserves_borrowed_variant() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[..16].copy_from_slice(b"AAAAAAAAtailtail");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        // SAFETY: storage outlives the IOBuf in this block.
        let b = unsafe { IOBuf::borrow(ptr, 32, 0, 16) };
        assert!(matches!(b.inner, Inner::Borrowed { .. }));
        let tail = b
            .into_remainder(8)
            .expect("in-range")
            .expect("tail is non-empty");
        assert!(
            matches!(tail.inner, Inner::Borrowed { .. }),
            "into_remainder is borrow-preserving — callers wanting an owned tail follow with into_owned()",
        );
        assert_eq!(tail.data(), b"tailtail");
    }

    #[test]
    fn into_remainder_returns_err_on_overconsume() {
        let b = IOBuf::from(alloc::vec![1u8, 2, 3, 4]);
        assert!(b.into_remainder(5).is_err());
    }

    #[test]
    fn into_owned_borrowed_copies_to_heap() {
        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[4..12].copy_from_slice(b"abcdefgh");
        let ptr = core::ptr::NonNull::new(storage.as_mut_ptr()).unwrap();
        let owned = {
            // SAFETY: storage outlives the borrow; the borrow ends
            // when into_owned consumes it.
            let b = unsafe { IOBuf::borrow(ptr, 32, 4, 8) };
            assert!(matches!(b.inner, Inner::Borrowed { .. }));
            b.into_owned()
        };
        assert!(matches!(owned.inner, Inner::Heap { .. }));
        assert_eq!(owned.data(), b"abcdefgh");
        storage[4..12].copy_from_slice(b"XXXXXXXX");
        assert_eq!(owned.data(), b"abcdefgh", "owned copy is independent");
    }

    /// `From<OwnedIOBuf> for IOBuf` — the one-way widening. Building
    /// an `OwnedIOBuf` via `wrap_owned` and widening it preserves the
    /// visible bytes *and* the drop callback: dropping the widened
    /// `IOBuf` fires the original `drop_fn` exactly once.
    #[test]
    fn from_owned_iobuf_widens_preserving_bytes_and_drop_fn() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> = unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 16];
        storage[2..10].copy_from_slice(b"owned-rx");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the buffers in this block; cb
            // reclaims the Arc from ctx exactly once at drop.
            let owned = unsafe { OwnedIOBuf::wrap_owned(ptr, 16, 2, 8, cb, ctx) };
            assert_eq!(owned.data(), b"owned-rx");
            assert_eq!(owned.headroom(), 2);
            assert_eq!(owned.tailroom(), 6);

            // Widen — infallible, zero copy. The storage struct is
            // re-tagged into `Inner::External`.
            let widened: IOBuf = owned.into();
            assert!(matches!(widened.inner, Inner::External { .. }));
            assert_eq!(widened.data(), b"owned-rx");
            assert!(
                !released.load(Ordering::SeqCst),
                "drop callback not yet run"
            );
        }
        // The widened IOBuf dropped at scope end → the original
        // drop_fn fires exactly once: widening kept it intact.
        assert!(
            released.load(Ordering::SeqCst),
            "widening preserved the drop callback"
        );
    }
}
