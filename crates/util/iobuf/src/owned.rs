// `OwnedIOBuf` — the flat `Send`-by-derivation enum for the RX path.
//
// See the crate root for the borrowed/owned type-split rationale.
// `OwnedIOBuf` is the cross-core RX path's type: it covers only the
// two owning storage variants (`HeapStorage`, `ExternalOwned`), both
// `Send`, so `OwnedIOBuf` is `Send` by auto-derivation — no
// `unsafe impl`, no human-maintained invariant.
//
// As of PR 2 the per-variant `(offset, len)` view lives at the top
// of `OwnedIOBuf` rather than inside each storage struct: bytes are
// in the storage, the visible window is on the outer type. The split
// is the prerequisite for PR 3's `Shared(Arc<…>)` variant, where one
// storage feeds many views via `Arc::clone`.

use core::ptr::NonNull;

use crate::iobuf::{IOBuf, Inner};
use crate::{Chain, ExternalOwned, HeapStorage, IOBufDropFn, IOBufError, IOBufRead};

/// An IOBuf restricted to the two **owning** storage variants —
/// `HeapStorage` and `ExternalOwned`. Both are `Send`, so `OwnedIOBuf`
/// is `Send` **by auto-derivation**: no `unsafe impl`, no container
/// invariant. `Chain<OwnedIOBuf>` is likewise `Send` for free.
///
/// This is the type the cross-core RX path is *born* in —
/// [`OwnedIOBuf::wrap_owned`] and [`crate::IOBufPool::alloc`] produce
/// it, and it stays `OwnedIOBuf` through the `NicOps` callback, net
/// dispatch, and the per-core RX inbox. A `BorrowedView` *cannot*
/// reach that path: the path's type is `OwnedIOBuf` and no
/// constructor of `OwnedIOBuf` takes a borrow — compile-time
/// cross-core safety, not discipline.
///
/// `StaticView` is deliberately excluded — not for a `Send` reason
/// (`&'static [u8]` is `Send`) but a modelling one: a static slice
/// is an *immortal borrow*, not owned storage, so it stays in
/// `IOBuf` with the other non-owning view.
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

/// Storage backing an [`OwnedIOBuf`] — the owning subset of
/// `iobuf::Inner`. Bytes only; the visible window lives on
/// `OwnedIOBuf`.
pub(crate) enum OwnedStorage {
    /// Heap-owned `Box<[u8]>`. Modelled for completeness (it is one
    /// of the two owning storage structs and keeps `From<OwnedIOBuf>`
    /// total), but no current `OwnedIOBuf` constructor mints it — the
    /// RX path only produces `External`. Not constructed in any build.
    #[allow(dead_code)]
    Heap(HeapStorage),
    /// A foreign region owned via a drop callback.
    External(ExternalOwned),
}

/// Static assertion: `OwnedIOBuf` (and a chain of them) is `Send` by
/// auto-derivation. If a future change reintroduced a `!Send` field
/// — a raw pointer, a `PhantomData<*const ()>` — this stops
/// compiling, which is the point: the cross-core RX path's safety is
/// this fact, checked by the compiler on every build.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<OwnedIOBuf>();
    assert_send::<Chain<OwnedIOBuf>>();
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

    /// Total bytes of the underlying storage (independent of the
    /// current visible window).
    #[inline]
    fn capacity(&self) -> usize {
        match &self.storage {
            OwnedStorage::Heap(h) => h.capacity(),
            OwnedStorage::External(e) => e.capacity(),
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let o = self.offset as usize;
        let l = self.len as usize;
        match &self.storage {
            OwnedStorage::Heap(h) => &h.bytes()[o..o + l],
            OwnedStorage::External(e) => {
                // SAFETY: `base + offset .. base + offset + len` is
                // in-bounds (offset + len <= capacity, construction
                // precondition); the region is exclusively owned by
                // this IOBuf for its lifetime.
                unsafe { core::slice::from_raw_parts(e.base().as_ptr().add(o), l) }
            }
        }
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
/// borrowed/owned split adds. Infallible: every `OwnedIOBuf` variant
/// is also an `IOBuf` variant, so this just re-tags the storage
/// struct into the wider enum. Zero copy, no allocation.
///
/// Exercised at the app RX API boundary — a `BodyReader` spanning
/// RX-buffer-backed chunks (`OwnedIOBuf`) and prebuf-backed chunks
/// (`Borrowed`) within one body holds `IOBuf`, so RX buffers widen
/// in per-chunk as they surface. There is deliberately **no**
/// `From<IOBuf> for OwnedIOBuf`: narrowing would have to discard or
/// materialise a `Borrowed`/`Static` part.
impl From<OwnedIOBuf> for IOBuf {
    fn from(o: OwnedIOBuf) -> IOBuf {
        let inner = match o.storage {
            OwnedStorage::Heap(h) => Inner::Heap {
                storage: h,
                offset: o.offset,
                len: o.len,
            },
            OwnedStorage::External(e) => Inner::External {
                storage: e,
                offset: o.offset,
                len: o.len,
            },
        };
        IOBuf { inner }
    }
}

// ============================================================================
// Tests — OwnedIOBuf-focused.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
}
