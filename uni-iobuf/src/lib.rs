// uni-iobuf — IOBuf primitive for the network stack.
//
// Inspired by folly::IOBuf: a chain of byte segments with reserved
// space at each end ("headroom" / "tailroom") so layers below can
// prepend / append their headers without re-allocating or copying
// the existing payload. Callers walk a chain via a `Cursor` that
// hops node boundaries transparently.
//
// What this buys us in the unikernel stack:
//
//   * App-side: a body is a chain of static literals (zero-copy)
//     and dynamically-rendered owned chunks.
//   * HTTP/1.1: the response status line + headers prepend onto the
//     body chain via `prepend_in_place`, reusing reserved headroom.
//   * TLS: prepends the 5-byte record header and appends the 16-byte
//     AEAD tag in-place.
//   * QUIC: prepends short-header byte + packet number, encrypts in
//     place; the rest of the chain follows the same prepend pattern.
//   * NIC RX: the driver wraps its DMA buffer as an IOBuf with a
//     drop callback that reposts the buffer — zero-copy receive.
//   * NIC TX: a final cursor pass copies bytes straight into the
//     hardware TX descriptor — one memcpy total, no intermediate Vec.
//
// ── The borrowed / owned type split ─────────────────────────────
//
// An IOBuf has two ownership models, and they have different
// thread-safety. Rather than one `!Send` type guarded by discipline,
// the crate splits them — see docs/uni-iobuf-type-model.md:
//
//   * Each ownership variant is its own struct in `storage.rs`
//     (`HeapStorage`, `StaticView`, `ExternalOwned`, `BorrowedView`),
//     with its data *and* offset/len logic in one place.
//   * `IOBuf` is a flat `!Send` enum over all four structs — the
//     TX-path buffer, which legitimately mixes owned and borrowed
//     parts. `BorrowedView`'s `PhantomData<*const ()>` is what makes
//     `IOBuf` `!Send`, so a per-worker borrow can't cross workers.
//   * `OwnedIOBuf` is a flat enum over `{HeapStorage, ExternalOwned}`
//     only — the owning pair. It is `Send` *by auto-derivation* (no
//     `unsafe impl`): both variants are `Send`. The cross-core RX
//     path is *typed* `OwnedIOBuf` / `Chain<OwnedIOBuf>`, so a
//     borrowed buffer physically cannot reach it — a compile error,
//     not a human-maintained invariant.
//   * `IOBufRead` is the read surface (`data` / `len` / `headroom` /
//     `tailroom`) shared by both and by `Chain<B>`.
//   * Widening is one-way: `From<OwnedIOBuf> for IOBuf` (infallible).
//     Nothing narrows `IOBuf -> OwnedIOBuf`.
//
// `no_std` and dep-less so it can be pulled into the kernel proper
// (driver layers) without dragging the runtime in.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use core::ptr::NonNull;

// Fixed-size slab pool for IOBuf RX recycling. Self-contained
// lock-free machinery, kept in its own module.
mod pool;
pub use pool::IOBufPool;

// The four per-variant storage structs + the debug-mode borrow
// tracker. `IOBuf` / `OwnedIOBuf` are flat enums over these.
mod storage;
pub use storage::{BorrowedView, ExternalOwned, HeapStorage, IOBufDropFn, StaticView};

// `Chain<B>` — a chain of `B: IOBufRead` segments — plus `Cursor`.
mod chain;
pub use chain::{Chain, Cursor, IOBufChain};

// ============================================================================
// IOBufRead — the shared read surface.
// ============================================================================

/// The **read** surface every IOBuf-shaped buffer exposes: the
/// visible payload, its length, and the reserved head/tail room.
///
/// Implemented by `IOBuf` (`!Send`), `OwnedIOBuf` (`Send`), and the
/// four per-variant storage structs. It is the bound a `Chain<B>` is
/// generic over — `fn consume<B: IOBufRead>(Chain<B>)` accepts both
/// `Chain<IOBuf>` (TX) and `Chain<OwnedIOBuf>` (cross-core RX).
///
/// Deliberately **read-only**: mutating operations (`prepend`,
/// `append`, partial-send `consume`) are *not* here. Cross-core RX
/// consumers happen to be read-only, so `IOBufRead` suffices for the
/// generic chain; TX-side mutation stays concrete-typed on `IOBuf`.
pub trait IOBufRead {
    /// Visible payload bytes.
    fn data(&self) -> &[u8];
    /// Visible payload length in bytes (`== data().len()`).
    fn len(&self) -> usize;
    /// Bytes reserved before the payload — lower layers (TLS, TCP,
    /// IP, Eth) prepend their headers into this space.
    fn headroom(&self) -> usize;
    /// Bytes reserved after the payload — for AEAD tags, trailers.
    fn tailroom(&self) -> usize;
    /// True when the visible payload is empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// IOBufError
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IOBufError {
    NoHeadroom,
    NoTailroom,
    OutOfBounds,
    Immutable,
}

// ============================================================================
// IOBuf — the flat `!Send` enum over all four storage structs.
// ============================================================================

/// One byte segment. Holds heap-owned storage, a static-lifetime
/// borrow, foreign storage owned via a drop callback, or a non-owning
/// view of foreign storage. The `Borrowed` variant makes the whole
/// `IOBuf` `!Send + !Sync` so per-worker borrows can't accidentally
/// cross workers — see [`OwnedIOBuf`] for the `Send` counterpart that
/// the cross-core path uses.
pub struct IOBuf {
    inner: Inner,
}

/// Storage backing an [`IOBuf`]. Private: `IOBuf`'s public surface is
/// its methods. A flat enum over the four per-variant structs — the
/// per-variant logic lives on each struct (`storage.rs`); the arms
/// here only forward.
enum Inner {
    /// Heap-owned `Box<[u8]>`.
    Heap(HeapStorage),
    /// A `&'static [u8]` borrow. Immutable.
    Static(StaticView),
    /// A foreign region owned via a drop callback (NIC RX, pools).
    External(ExternalOwned),
    /// A non-owning view of foreign storage — the `!Send` variant.
    Borrowed(BorrowedView),
}

/// Forward an `IOBuf` method to the active variant struct. The
/// per-variant logic is written once on the struct (`storage.rs`);
/// this is the thin, mechanical dispatch the doc calls "written
/// twice" — once here for `&self`, once for `&mut self`.
macro_rules! dispatch {
    ($self:ident, $b:ident => $body:expr) => {
        match &$self.inner {
            Inner::Heap($b) => $body,
            Inner::Static($b) => $body,
            Inner::External($b) => $body,
            Inner::Borrowed($b) => $body,
        }
    };
    (mut $self:ident, $b:ident => $body:expr) => {
        match &mut $self.inner {
            Inner::Heap($b) => $body,
            Inner::Static($b) => $body,
            Inner::External($b) => $body,
            Inner::Borrowed($b) => $body,
        }
    };
}

impl IOBuf {
    /// Allocate a heap-backed buffer with `headroom` bytes reserved
    /// at the front and `tailroom` at the end. Total allocation is
    /// `headroom + payload_capacity + tailroom`; the visible payload
    /// starts empty (`len = 0`) at offset `headroom`.
    pub fn new_with_reserved(
        headroom: usize,
        payload_capacity: usize,
        tailroom: usize,
    ) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // Zero-fill: nobody reads headroom / tailroom, but the
        // allocator's free-list returns this memory eventually so
        // initial-zeroing keeps info-leak-class bugs away.
        let storage = alloc::vec![0u8; cap].into_boxed_slice();
        IOBuf {
            inner: Inner::Heap(HeapStorage::new(storage, headroom as u32, 0)),
        }
    }

    /// Zero-init-free variant of [`Self::new_with_reserved`]. Saves
    /// the memset at the price of an unsafe contract: the caller must
    /// write to every byte before reading it.
    ///
    /// SAFETY: the caller must ensure no byte is read via `data()`
    /// before it's been written through one of `append_slice`,
    /// `writer`, `extend_uninit`, or a `prepend` that moves the
    /// visible window over it. The IOBuf API enforces this for
    /// callers that only use the public mutation entry points.
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
            inner: Inner::Heap(HeapStorage::new(storage, headroom as u32, 0)),
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

    /// Wrap a foreign region that this IOBuf takes ownership of via a
    /// drop callback. On drop, `drop_fn(base, capacity, drop_ctx)`
    /// runs exactly once, with the original `(base, capacity)`
    /// regardless of how offset/len shifted.
    ///
    /// The result is an *owned* IOBuf. The owned, `Send` shape is
    /// [`OwnedIOBuf`] — and that is exactly what
    /// [`OwnedIOBuf::wrap_owned`] produces; this `IOBuf`-returning
    /// form widens it via `From<OwnedIOBuf>` for callers that build
    /// a (possibly borrow-mixing) `IOBuf` chain. For a non-owning
    /// view use [`borrow`](Self::borrow) instead.
    ///
    /// SAFETY: the caller MUST guarantee:
    ///   * `base..base+capacity` is a valid, exclusively-owned byte
    ///     region for the IOBuf's lifetime.
    ///   * `offset + len <= capacity`.
    ///   * `drop_fn(base, capacity, drop_ctx)` is sound to invoke
    ///     once at IOBuf-drop time.
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
        // SAFETY: forwarded to `OwnedIOBuf::wrap_owned` verbatim —
        // the caller's contract above is exactly its contract.
        let owned = unsafe {
            OwnedIOBuf::wrap_owned(base, capacity, offset, len, drop_fn, drop_ctx)
        };
        owned.into()
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
    /// SAFETY: the caller MUST guarantee:
    ///   * `base..base+capacity` is a valid byte region for the
    ///     entire lifetime of this IOBuf.
    ///   * `offset + len <= capacity`.
    ///   * No other route concurrently mutates the borrowed region
    ///     while this IOBuf exists.
    ///   * If multiple IOBufs view the same storage, their visible
    ///     regions do not overlap when any is mutated.
    pub unsafe fn borrow(
        base: NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
    ) -> Self {
        IOBuf {
            inner: Inner::Borrowed(BorrowedView::new(base, capacity, offset, len)),
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        dispatch!(self, b => b.data())
    }

    /// Visible payload length.
    #[inline]
    pub fn len(&self) -> usize {
        dispatch!(self, b => b.len())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available before the payload. `0` for static borrows.
    #[inline]
    pub fn headroom(&self) -> usize {
        dispatch!(self, b => b.headroom())
    }

    /// Bytes available after the payload. `0` for static borrows.
    #[inline]
    pub fn tailroom(&self) -> usize {
        dispatch!(self, b => b.tailroom())
    }

    /// Mutable access to the visible payload. Returns `None` for
    /// static borrows. Used by in-place crypto (ChaCha20-Poly1305
    /// seals into the source bytes).
    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        dispatch!(mut self, b => b.data_mut())
    }

    /// Prepend `data` into the headroom and grow the visible payload.
    /// `Err(NoHeadroom)` if headroom is too small; `Err(Immutable)`
    /// for static borrows.
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        dispatch!(mut self, b => b.prepend(data))
    }

    /// Append `data` into the tailroom and grow the visible payload.
    pub fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        dispatch!(mut self, b => b.append_slice(data))
    }

    /// Grow the visible payload by `n` bytes (contents
    /// uninitialised) and return a mutable slice over them. Used by
    /// AEAD seal: advance the visible len, write the tag in place.
    pub fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        dispatch!(mut self, b => b.extend_uninit(n))
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
        dispatch!(mut self, b => b.consume(n))
    }

    /// Trim `n` bytes from the BACK of the visible payload.
    #[inline]
    pub fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        dispatch!(mut self, b => b.trim_end(n))
    }

    /// `core::fmt::Write` adapter that appends formatted bytes into
    /// the IOBuf's tailroom — `write!(buf.writer(), "{}", value)`
    /// renders straight into the IOBuf with no intermediate `String`.
    pub fn writer(&mut self) -> IOBufWriter<'_> {
        IOBufWriter {
            buf: self,
            overflowed: false,
        }
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
        if matches!(self.inner, Inner::Borrowed(_)) {
            // Copy the visible payload into owned heap storage.
            // `data()`'s borrow ends at `.to_vec()`; the subsequent
            // `self.inner` write drops the old `Borrowed`, whose
            // `BorrowGuard` unregisters from the debug-mode aliasing
            // tracker — symmetric with the `borrow` that minted it.
            let owned: Box<[u8]> = self.data().to_vec().into_boxed_slice();
            let len = owned.len() as u32;
            self.inner = Inner::Heap(HeapStorage::new(owned, 0, len));
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
// IOBufWriter — `core::fmt::Write` adapter for IOBuf.
// ============================================================================

/// `core::fmt::Write` adapter for [`IOBuf`]. Appends formatted bytes
/// into the buffer's tailroom; if tailroom runs out mid-render the
/// writer silently truncates (see `overflowed`).
pub struct IOBufWriter<'a> {
    buf: &'a mut IOBuf,
    /// Set when an append inside `write_str` failed (tailroom
    /// exhausted). `core::fmt::Write`'s `Result` doesn't carry a
    /// buffer-out-of-space signal, so callers query this afterward.
    overflowed: bool,
}

impl IOBufWriter<'_> {
    /// True if any append during this writer's lifetime hit a
    /// tailroom exhaustion. The IOBuf should be treated as truncated.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
}

impl core::fmt::Write for IOBufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        match self.buf.append_slice(s.as_bytes()) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.overflowed = true;
                Err(core::fmt::Error)
            }
        }
    }
}

// ============================================================================
// OwnedIOBuf — the flat `Send`-by-derivation enum for the RX path.
// ============================================================================

/// An IOBuf restricted to the two **owning** storage variants —
/// `HeapStorage` and `ExternalOwned`. Both are `Send`, so `OwnedIOBuf`
/// is `Send` **by auto-derivation**: no `unsafe impl`, no container
/// invariant. `Chain<OwnedIOBuf>` is likewise `Send` for free.
///
/// This is the type the cross-core RX path is *born* in —
/// [`OwnedIOBuf::wrap_owned`] and [`IOBufPool::alloc`] produce it,
/// and it stays `OwnedIOBuf` through the `NicOps` callback, net
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
    inner: OwnedInner,
}

/// Storage backing an [`OwnedIOBuf`] — the owning subset of `Inner`.
enum OwnedInner {
    /// Heap-owned `Box<[u8]>`.
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

/// Forward an `OwnedIOBuf` read method to the active variant struct.
/// The two-arm counterpart of `IOBuf`'s `dispatch!`.
macro_rules! owned_dispatch {
    ($self:ident, $b:ident => $body:expr) => {
        match &$self.inner {
            OwnedInner::Heap($b) => $body,
            OwnedInner::External($b) => $body,
        }
    };
}

impl OwnedIOBuf {
    /// Wrap a foreign region this IOBuf takes ownership of via a drop
    /// callback — the owned, `Send` constructor for the cross-core RX
    /// path (NIC zero-copy RX, pool slabs). On drop, `drop_fn(base,
    /// capacity, drop_ctx)` runs exactly once.
    ///
    /// SAFETY: identical contract to [`IOBuf::wrap_owned`] — the
    /// region is valid + exclusively owned for the IOBuf's lifetime,
    /// `offset + len <= capacity`, and `(drop_fn, drop_ctx)` is
    /// Send-safe and sound to invoke once at drop time.
    pub unsafe fn wrap_owned(
        base: NonNull<u8>,
        capacity: u32,
        offset: u32,
        len: u32,
        drop_fn: IOBufDropFn,
        drop_ctx: *mut (),
    ) -> Self {
        OwnedIOBuf {
            inner: OwnedInner::External(ExternalOwned::new(
                base, capacity, offset, len, drop_fn, drop_ctx,
            )),
        }
    }

    /// Visible payload bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        owned_dispatch!(self, b => b.data())
    }

    /// Visible payload length.
    #[inline]
    pub fn len(&self) -> usize {
        owned_dispatch!(self, b => b.len())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available before the payload.
    #[inline]
    pub fn headroom(&self) -> usize {
        owned_dispatch!(self, b => b.headroom())
    }

    /// Bytes available after the payload.
    #[inline]
    pub fn tailroom(&self) -> usize {
        owned_dispatch!(self, b => b.tailroom())
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
        let inner = match o.inner {
            OwnedInner::Heap(h) => Inner::Heap(h),
            OwnedInner::External(e) => Inner::External(e),
        };
        IOBuf { inner }
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
            inner: Inner::Heap(HeapStorage::new(v.into_boxed_slice(), 0, len)),
        }
    }
}

impl From<alloc::string::String> for IOBuf {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock-NIC RX-delivery tests for the contract the `NicOps` poll
    /// callback depends on: a driver hands up a received frame as an
    /// **owned** `IOBufChain` whose `ExternalOwned` `IOBuf`, on drop,
    /// reposts the backing buffer via its drop callback — and that
    /// drop may run on a core other than the one that received the
    /// frame.
    ///
    /// The real drivers' drop callbacks touch `target_os = "none"`
    /// hardware state and can't run host-native; this mock
    /// reproduces the *shape* against the same `wrap_owned` /
    /// `IOBufChain` primitives, exercising the drop callback from a
    /// separate thread.
    mod mock_nic_rx {
        use crate::{IOBuf, IOBufChain, IOBufDropFn};
        extern crate std;
        use core::ptr::NonNull;
        use std::boxed::Box;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        /// Stand-in for a NIC's RX ring: a fixed buffer region plus
        /// the repost counter every real driver bumps, and a record
        /// of the `(base, capacity)` the drop callback was handed.
        struct MockNic {
            region: Box<[u8]>,
            repost_count: AtomicU64,
            last_base: AtomicUsize,
            last_capacity: AtomicUsize,
        }

        /// Drop callback installed on every mock RX `IOBuf`. Mirrors
        /// the real drivers' repost callbacks; panic-safe.
        ///
        /// SAFETY: `ctx` is an `Arc::<MockNic>::into_raw` pointer
        /// installed by `mock_poll_qp`, reclaimed exactly once here.
        unsafe fn mock_repost(base: NonNull<u8>, capacity: u32, ctx: *mut ()) {
            let nic: Arc<MockNic> = unsafe { Arc::from_raw(ctx as *const MockNic) };
            nic.last_base.store(base.as_ptr() as usize, Ordering::Relaxed);
            nic.last_capacity.store(capacity as usize, Ordering::Relaxed);
            nic.repost_count.fetch_add(1, Ordering::Relaxed);
        }

        /// Simulate a driver's `poll_qp`: wrap the mock device buffer
        /// as a one-part owned `IOBufChain` and hand it to `callback`.
        fn mock_poll_qp(nic: &Arc<MockNic>, frame_len: usize, callback: impl FnOnce(IOBufChain)) {
            let base = NonNull::new(nic.region.as_ptr() as *mut u8).unwrap();
            let capacity = nic.region.len() as u32;
            let ctx = Arc::into_raw(Arc::clone(nic)) as *mut ();
            // SAFETY: `region` outlives the IOBuf (kept alive by the
            // parked Arc ref); `0 + frame_len <= capacity`;
            // `mock_repost` is sound to invoke once at drop.
            let iobuf = unsafe {
                IOBuf::wrap_owned(
                    base,
                    capacity,
                    0,
                    frame_len as u32,
                    mock_repost as IOBufDropFn,
                    ctx,
                )
            };
            callback(IOBufChain::from(iobuf));
        }

        /// A one-part owned RX chain moved across a thread boundary.
        /// `IOBuf` is `!Send` (the `Borrowed` variant taints the
        /// whole enum), so a struct-level `unsafe impl Send` is
        /// needed here — the very thing the type-model split removes
        /// once the RX path is typed `Chain<OwnedIOBuf>`.
        ///
        /// SAFETY: the only `IOBuf` inside is an `External` one,
        /// produced by `mock_poll_qp` — never a `Borrowed` part.
        struct SendChain(IOBufChain);
        unsafe impl Send for SendChain {}

        #[test]
        fn rx_chain_drop_callback_reposts_cross_thread() {
            let nic = Arc::new(MockNic {
                region: std::vec![0u8; 2048].into_boxed_slice(),
                repost_count: AtomicU64::new(0),
                last_base: AtomicUsize::new(0),
                last_capacity: AtomicUsize::new(0),
            });
            let region_base = nic.region.as_ptr() as usize;

            let mut captured: Option<SendChain> = None;
            mock_poll_qp(&nic, 1400, |chain| {
                assert_eq!(chain.part_count(), 1, "single-buffer frame is a 1-part chain");
                assert_eq!(chain.total_len(), 1400);
                captured = Some(SendChain(chain));
            });
            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 0);

            let send_chain = captured.take().unwrap();
            let worker = thread::spawn(move || {
                drop(send_chain); // fires `mock_repost` on this thread
            });
            worker.join().unwrap();

            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 1);
            assert_eq!(nic.last_base.load(Ordering::Relaxed), region_base);
            assert_eq!(nic.last_capacity.load(Ordering::Relaxed), 2048);
        }

        #[test]
        fn rx_chain_walk_then_repost_same_thread() {
            let nic = Arc::new(MockNic {
                region: std::vec![7u8; 2048].into_boxed_slice(),
                repost_count: AtomicU64::new(0),
                last_base: AtomicUsize::new(0),
                last_capacity: AtomicUsize::new(0),
            });
            mock_poll_qp(&nic, 64, |chain| {
                let walked: usize = chain.iter().map(|p| p.data().len()).sum();
                assert_eq!(walked, 64);
            });
            assert_eq!(nic.repost_count.load(Ordering::Relaxed), 1);
            assert_eq!(nic.last_capacity.load(Ordering::Relaxed), 2048);
        }
    }

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
    fn iobuf_writer_renders_into_tailroom() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(8, 0, 64);
        assert_eq!(buf.len(), 0);
        write!(buf.writer(), "hello {}", 42).unwrap();
        assert_eq!(buf.data(), b"hello 42");
        buf.prepend(b"REC1").unwrap();
        assert_eq!(buf.data(), b"REC1hello 42");
    }

    #[test]
    fn iobuf_writer_signals_overflow() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(0, 0, 4);
        let mut w = buf.writer();
        let _ = write!(w, "ab");
        let r = write!(w, "cdefgh");
        assert!(r.is_err());
        assert!(w.overflowed());
    }

    #[test]
    fn external_buf_drop_runs_callback() {
        use core::ptr::NonNull;
        use core::sync::atomic::{AtomicBool, Ordering};
        extern crate std;
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));

        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> =
                unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 32];
        storage[5..13].copy_from_slice(b"abcdefgh");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf in this block; the
            // callback reconstructs the Arc from ctx and lets it drop.
            let mut buf = unsafe { IOBuf::wrap_owned(ptr, 32, 5, 8, cb, ctx) };
            assert_eq!(buf.data(), b"abcdefgh");
            assert_eq!(buf.headroom(), 5);
            assert_eq!(buf.tailroom(), 19);
            buf.prepend(b"PRE").unwrap();
            assert_eq!(buf.data(), b"PREabcdefgh");
            buf.append_slice(b"END").unwrap();
            assert_eq!(buf.data(), b"PREabcdefghEND");
            for byte in buf.data_mut().unwrap() {
                if (b'a'..=b'z').contains(byte) {
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
            if (b'a'..=b'z').contains(byte) {
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
        assert!(matches!(o.inner, Inner::Heap(_)));
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
        extern crate std;
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> =
                unsafe { Arc::from_raw(ctx as *const AtomicBool) };
            arc.store(true, Ordering::SeqCst);
        }

        let mut storage: alloc::vec::Vec<u8> = alloc::vec![0u8; 16];
        storage[0..4].copy_from_slice(b"data");
        let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
        let ctx = Arc::into_raw(released.clone()) as *mut ();
        {
            // SAFETY: storage outlives the IOBuf; the callback
            // reconstructs the Arc from ctx and lets it drop.
            let b = unsafe { IOBuf::wrap_owned(ptr, 16, 0, 4, cb, ctx) };
            let o = b.into_owned();
            assert!(matches!(o.inner, Inner::External(_)));
            assert_eq!(o.data(), b"data");
            assert!(!released.load(Ordering::SeqCst), "callback not yet run");
        }
        assert!(
            released.load(Ordering::SeqCst),
            "drop callback fires exactly once after into_owned"
        );
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
            assert!(matches!(b.inner, Inner::Borrowed(_)));
            b.into_owned()
        };
        assert!(matches!(owned.inner, Inner::Heap(_)));
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
        extern crate std;
        use std::sync::Arc;

        let released = Arc::new(AtomicBool::new(false));
        unsafe fn cb(_base: NonNull<u8>, _cap: u32, ctx: *mut ()) {
            let arc: Arc<AtomicBool> =
                unsafe { Arc::from_raw(ctx as *const AtomicBool) };
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
            assert!(matches!(widened.inner, Inner::External(_)));
            assert_eq!(widened.data(), b"owned-rx");
            assert!(!released.load(Ordering::SeqCst), "drop callback not yet run");
        }
        // The widened IOBuf dropped at scope end → the original
        // drop_fn fires exactly once: widening kept it intact.
        assert!(
            released.load(Ordering::SeqCst),
            "widening preserved the drop callback"
        );
    }
}
