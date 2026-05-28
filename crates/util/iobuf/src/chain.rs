// crates/util/iobuf/src/chain.rs — `Chain<B>`, a chain of byte segments.
//
// A chain of buffer segments with a `Cursor` that walks node
// boundaries transparently for readers. Each layer of the network
// stack can append/prepend parts (or prepend INTO the front part's
// headroom) without disturbing the rest.
//
// The chain is **generic over the buffer type** `B: IOBufRead`:
//
//   * `Chain<IOBuf>` — the TX-path chain (aliased `IOBufChain`).
//     `!Send`, because `IOBuf` is. Mixes owned and borrowed parts.
//   * `Chain<OwnedIOBuf>` — the cross-core RX chain. `Send` *by
//     derivation* — `OwnedIOBuf` is `Send`, so `VecDeque<OwnedIOBuf>`
//     is, so `Chain<OwnedIOBuf>` is, with no `unsafe impl`.
//
// `B: IOBufRead` is the minimum bound: maintaining the cached
// `total_len` alone needs `B::len()`. Read-only chain consumers are
// generic over `B: IOBufRead`; the few methods that *construct* or
// *mutate* `IOBuf` parts (`prepend_in_place`, `push_static`, …) live
// in a concrete `impl Chain<IOBuf>` block.

use alloc::collections::VecDeque;

use crate::{IOBuf, IOBufError, IOBufRead};

/// A chain of `B` segments. Push-front / push-back at the chain
/// level are amortised O(1); the [`Cursor`] walks part boundaries
/// transparently for readers.
///
/// Representation — a three-state value (see the private `Repr`):
///
///   * **`Empty`** — no parts.
///   * **`Single`** — exactly one part, stored inline. **Zero heap
///     allocation** for the chain machinery. The dominant shape on
///     both the TX and RX paths: a lone body buffer, a single
///     borrowed slice for a raw send, a single-buffer RX frame.
///   * **`Many`** — two or more parts, held in a `VecDeque<B>` (one
///     heap allocation). Genuine multi-part chains: layered framing
///     that can't prepend in place, multi-chunk bodies.
///
/// This deliberately specialises the *single-part* chain rather than
/// reserving a fixed inline array sized for some guessed part count
/// — so there is no `INLINE_PARTS`-style tuning knob to mis-set.
pub struct Chain<B: IOBufRead = IOBuf> {
    repr: Repr<B>,
}

/// The TX-path chain. `IOBuf` parts; `!Send`. Aliased so the
/// pre-split spelling (`IOBufChain`) keeps working unchanged.
pub type IOBufChain = Chain<IOBuf>;

/// Storage backing a [`Chain`]. Private: the chain's public surface
/// is its methods — callers never match this.
enum Repr<B: IOBufRead> {
    /// No parts. Produced by `new()` / `Default`, and by a fully
    /// drained or `clear`ed `Single` chain.
    Empty,
    /// Exactly one part, inline — no heap allocation for chain
    /// machinery. `push_*` never store an empty part, so a `Single`
    /// always holds a genuine part.
    Single(B),
    /// Two-or-more parts — or a `with_capacity`-preallocated chain.
    /// `parts` is a heap `VecDeque`; `total_len` caches the summed
    /// visible length so `total_len()` / `Cursor::remaining` stay
    /// O(1). After pops or `clear`, `parts` may transiently hold 0
    /// or 1 entries: the `VecDeque` allocation is kept for reuse
    /// rather than demoted back to `Single` / `Empty`.
    Many {
        parts: VecDeque<B>,
        total_len: usize,
    },
}

/// `VecDeque` capacity reserved when a `Single` chain first upgrades
/// to `Many`. Covers the common layered shape (a body part plus a
/// couple of framing parts) without an immediate reallocation.
const MANY_INIT_CAP: usize = 4;

impl<B: IOBufRead> Chain<B> {
    pub const fn new() -> Self {
        Chain { repr: Repr::Empty }
    }

    /// Hint that the chain will hold at least `part_capacity` parts.
    /// A hint of 0 or 1 is free — the chain starts `Empty` and the
    /// first push lands in the zero-allocation `Single` state. A
    /// hint of 2+ pre-allocates the `Many` `VecDeque`.
    pub fn with_capacity(part_capacity: usize) -> Self {
        if part_capacity <= 1 {
            Chain { repr: Repr::Empty }
        } else {
            Chain {
                repr: Repr::Many {
                    parts: VecDeque::with_capacity(part_capacity),
                    total_len: 0,
                },
            }
        }
    }

    /// Total visible-payload bytes summed across every part. O(1).
    pub fn total_len(&self) -> usize {
        match &self.repr {
            Repr::Empty => 0,
            Repr::Single(b) => b.len(),
            Repr::Many { total_len, .. } => *total_len,
        }
    }

    /// True when the chain holds no parts.
    pub fn is_empty(&self) -> bool {
        match &self.repr {
            Repr::Empty => true,
            Repr::Single(_) => false,
            Repr::Many { parts, .. } => parts.is_empty(),
        }
    }

    pub fn part_count(&self) -> usize {
        match &self.repr {
            Repr::Empty => 0,
            Repr::Single(_) => 1,
            Repr::Many { parts, .. } => parts.len(),
        }
    }

    /// Borrow part `i` in front-to-back order, or `None` past the
    /// last part. Backs both [`iter`](Self::iter) and the `Cursor`.
    #[inline]
    fn get_part(&self, i: usize) -> Option<&B> {
        match &self.repr {
            Repr::Empty => None,
            Repr::Single(b) => (i == 0).then_some(b),
            Repr::Many { parts, .. } => parts.get(i),
        }
    }

    /// Append a buf to the back of the chain. Empty bufs are dropped
    /// — a chain never carries a zero-length part.
    pub fn push_back(&mut self, buf: B) {
        if buf.is_empty() {
            return;
        }
        // Fast path: an existing `Many` just pushes — no repr swap.
        if let Repr::Many { parts, total_len } = &mut self.repr {
            *total_len += buf.len();
            parts.push_back(buf);
            return;
        }
        // `Empty` -> `Single`, or `Single` -> `Many`.
        self.repr = match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => Repr::Single(buf),
            Repr::Single(existing) => {
                let total_len = existing.len() + buf.len();
                let mut parts = VecDeque::with_capacity(MANY_INIT_CAP);
                parts.push_back(existing);
                parts.push_back(buf);
                Repr::Many { parts, total_len }
            }
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        };
    }

    /// Prepend a buf to the front of the chain. Empty bufs are
    /// dropped. Amortised O(1).
    pub fn push_front(&mut self, buf: B) {
        if buf.is_empty() {
            return;
        }
        if let Repr::Many { parts, total_len } = &mut self.repr {
            *total_len += buf.len();
            parts.push_front(buf);
            return;
        }
        self.repr = match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => Repr::Single(buf),
            Repr::Single(existing) => {
                let total_len = existing.len() + buf.len();
                let mut parts = VecDeque::with_capacity(MANY_INIT_CAP);
                parts.push_back(buf); // new buf becomes the front
                parts.push_back(existing);
                Repr::Many { parts, total_len }
            }
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        };
    }

    /// Iterate the chain front-to-back.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &B> {
        (0..self.part_count()).map(move |i| self.get_part(i).expect("i < part_count"))
    }

    /// Mutable iterate front-to-back. Lets the caller mutate
    /// individual parts without consuming the chain.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut B> {
        match &mut self.repr {
            Repr::Empty => ChainIterMut::Empty,
            Repr::Single(b) => ChainIterMut::Single(Some(b)),
            Repr::Many { parts, .. } => ChainIterMut::Many(parts.iter_mut()),
        }
    }

    /// Pop the front part. Returns `None` when the chain is empty.
    pub fn pop_front(&mut self) -> Option<B> {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            let buf = parts.pop_front()?;
            *total_len = total_len.saturating_sub(buf.len());
            return Some(buf);
        }
        match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => None,
            Repr::Single(buf) => Some(buf),
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        }
    }

    /// Mutable access to the front part. Used by partial-send
    /// recovery paths that advance the head buf's visible payload
    /// when the transport committed only `n < head.len()` bytes. The
    /// caller keeps `total_len` in sync via
    /// [`shrink_total_len`](Self::shrink_total_len).
    pub fn front_mut(&mut self) -> Option<&mut B> {
        match &mut self.repr {
            Repr::Empty => None,
            Repr::Single(b) => Some(b),
            Repr::Many { parts, .. } => parts.front_mut(),
        }
    }

    /// Mutable access to the back part. Used by sealing paths that
    /// append (e.g. an AEAD tag) onto the last buf. Caller calls
    /// [`bump_total_len`](Self::bump_total_len) after growing it.
    pub fn back_mut(&mut self) -> Option<&mut B> {
        match &mut self.repr {
            Repr::Empty => None,
            Repr::Single(b) => Some(b),
            Repr::Many { parts, .. } => parts.back_mut(),
        }
    }

    /// Pop the back part. Mirror of `pop_front`.
    pub fn pop_back(&mut self) -> Option<B> {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            let buf = parts.pop_back()?;
            *total_len = total_len.saturating_sub(buf.len());
            return Some(buf);
        }
        match core::mem::replace(&mut self.repr, Repr::Empty) {
            Repr::Empty => None,
            Repr::Single(buf) => Some(buf),
            Repr::Many { .. } => unreachable!("Many handled by the fast path"),
        }
    }

    /// Decrease the cached `total_len` by `n`. Pair with a
    /// `front_mut().consume(n)` when the caller shrank a buf's
    /// visible payload without going through `pop_front`.
    ///
    /// A no-op for `Empty` / `Single`: those derive `total_len`
    /// straight from the (single, or zero) part.
    pub fn shrink_total_len(&mut self, n: usize) {
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len = total_len.saturating_sub(n);
        }
    }

    /// Increase the cached `total_len` by `n`. Pair with a
    /// `back_mut()` append that grew a buf's visible payload without
    /// going through `push_back` / `push_front`.
    ///
    /// A no-op for `Empty` / `Single` — see
    /// [`shrink_total_len`](Self::shrink_total_len).
    pub fn bump_total_len(&mut self, n: usize) {
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len += n;
        }
    }

    /// Drop every part still in the chain. The drops run
    /// front-to-back — same ordering as a `pop_front` loop, which
    /// matters for `ExternalOwned` parts whose drop callbacks return
    /// descriptors / slabs to driver pools. A `Many` chain keeps its
    /// `VecDeque` allocation for reuse.
    pub fn clear(&mut self) {
        if let Repr::Many { parts, total_len } = &mut self.repr {
            parts.clear();
            *total_len = 0;
            return;
        }
        self.repr = Repr::Empty;
    }

    /// Move all parts out, consuming the chain. Returns an iterator
    /// yielding parts front-to-back.
    pub fn into_parts(self) -> impl Iterator<Item = B> {
        // `Empty` / `Single` collapse to `(Option, empty deque)`;
        // `Many` to `(None, parts)`. `VecDeque::new()` is
        // allocation-free, so the non-`Many` arms cost nothing.
        let (single, many) = match self.repr {
            Repr::Empty => (None, VecDeque::new()),
            Repr::Single(b) => (Some(b), VecDeque::new()),
            Repr::Many { parts, .. } => (None, parts),
        };
        single.into_iter().chain(many)
    }

    /// Construct a [`Cursor`] for reading.
    pub fn cursor(&self) -> Cursor<'_, B> {
        Cursor {
            chain: self,
            node_idx: 0,
            in_node_off: 0,
            consumed: 0,
        }
    }
}

impl IOBufChain {
    /// Prepend `data` directly into the FRONT part's headroom,
    /// without allocating a new part. Returns `Err` if the front
    /// part is missing or static (no headroom). Lets a layer
    /// prepend a small fixed header (TLS record header, H3 frame
    /// header) without growing the chain.
    ///
    /// `IOBuf`-specific: prepending mutates a part, which the
    /// read-only `IOBufRead` bound does not permit — TX mutation
    /// stays concrete-typed.
    pub fn prepend_in_place(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let front = self.front_mut().ok_or(IOBufError::NoHeadroom)?;
        front.prepend(data)?;
        // A `Single`'s `total_len` is derived from the part itself,
        // so the `prepend` above already accounts for the bytes;
        // only `Many`'s cached `total_len` needs the adjustment.
        if let Repr::Many { total_len, .. } = &mut self.repr {
            *total_len += data.len();
        }
        Ok(())
    }

    /// Convenience: append a `&'static [u8]` part.
    pub fn push_static(&mut self, s: &'static [u8]) {
        self.push_back(IOBuf::from_static(s));
    }

    /// Convenience: append a `Vec<u8>` part. Move-no-copy when
    /// `len == capacity`; reallocates to fit otherwise.
    pub fn push_owned(&mut self, v: alloc::vec::Vec<u8>) {
        self.push_back(IOBuf::from(v));
    }

    /// Convenience: append a `String`'s underlying bytes.
    pub fn push_string(&mut self, s: alloc::string::String) {
        self.push_back(IOBuf::from(s.into_bytes()));
    }

    /// Append a payload as a heap-owned `IOBuf` with reserved
    /// `headroom` and `tailroom` for layers below to prepend or
    /// append in place. One heap alloc per chunk.
    pub fn push_with_reserve(&mut self, payload: &[u8], headroom: usize, tailroom: usize) {
        self.push_back(IOBuf::from_slice_with_headroom(headroom, payload, tailroom));
    }

    /// Ensure the first `n` bytes of the chain are contiguous in the
    /// front part, then return them as a borrowed slice. Equivalent
    /// to Linux's `pskb_may_pull`: a header parser calls `pull` to
    /// get a linear region it can index directly.
    ///
    /// Cheap when the front part already holds `n` bytes (the common
    /// case) — just hands back `&front.data()[..n]`. Otherwise pops
    /// parts off the front, copies their first `n` bytes into a
    /// fresh heap-backed `IOBuf`, and pushes that as the new front:
    /// the chain's logical bytes are unchanged, only their physical
    /// layout. A part that contributes only some of its bytes stays
    /// on the chain with its remainder via `consume`.
    ///
    /// The coalesced front (slow path) carries no headroom or
    /// tailroom — it's a tight `Vec<u8>`-backed IOBuf. A caller that
    /// pulls a header and then layer-prepends in place needs to
    /// `push_front` its own headroom buffer instead.
    ///
    /// Returns `IOBufError::OutOfBounds` if the chain holds fewer
    /// than `n` total bytes. `n == 0` always succeeds and yields
    /// `&[]`.
    pub fn pull(&mut self, n: usize) -> Result<&[u8], IOBufError> {
        if n == 0 {
            return Ok(&[]);
        }
        if n > self.total_len() {
            return Err(IOBufError::OutOfBounds);
        }
        let front_len = self.get_part(0).map_or(0, |b| b.len());
        if front_len < n {
            // Slow path: coalesce front parts into a fresh heap IOBuf.
            // `total_len() >= n` (checked above) bounds the loop.
            let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(n);
            while buf.len() < n {
                let mut part = self
                    .pop_front()
                    .expect("total_len() >= n bounds the loop");
                let take = (n - buf.len()).min(part.len());
                buf.extend_from_slice(&part.data()[..take]);
                if take < part.len() {
                    // `take < part.len()` ⇒ `consume(take)` is in-range.
                    part.consume(take)
                        .expect("take < part.len() keeps consume in-range");
                    self.push_front(part);
                }
            }
            self.push_front(IOBuf::from(buf));
        }
        Ok(&self
            .get_part(0)
            .expect("front exists: n > 0 and total_len >= n")
            .data()[..n])
    }
}

/// `iter_mut`'s return type. A hand-rolled enum iterator: the three
/// `Repr` arms yield differently-typed iterators, and this unifies
/// them behind one `impl Iterator` with no heap allocation and no
/// `dyn` dispatch.
enum ChainIterMut<'a, B> {
    Empty,
    Single(Option<&'a mut B>),
    Many(alloc::collections::vec_deque::IterMut<'a, B>),
}

impl<'a, B> Iterator for ChainIterMut<'a, B> {
    type Item = &'a mut B;
    fn next(&mut self) -> Option<&'a mut B> {
        match self {
            ChainIterMut::Empty => None,
            ChainIterMut::Single(slot) => slot.take(),
            ChainIterMut::Many(it) => it.next(),
        }
    }
}

impl<B: IOBufRead> Default for Chain<B> {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Chain From<X> conversions --------------------------------------
//
// A buffer widens into a 1-part chain via `From<B>`; the `IOBuf`
// body shapes (static literals, owned Vec/String) flatten through
// `IOBuf::from`. Two explicit `From<B>` impls rather than a blanket
// — the two buffer types we actually chain are known, and explicit
// impls keep the conversion surface unambiguous.

impl From<IOBuf> for Chain<IOBuf> {
    fn from(b: IOBuf) -> Self {
        let mut c = Chain::with_capacity(1);
        c.push_back(b);
        c
    }
}

impl From<crate::OwnedIOBuf> for Chain<crate::OwnedIOBuf> {
    fn from(b: crate::OwnedIOBuf) -> Self {
        let mut c = Chain::with_capacity(1);
        c.push_back(b);
        c
    }
}

impl From<&'static [u8]> for Chain<IOBuf> {
    fn from(s: &'static [u8]) -> Self {
        IOBuf::from_static(s).into()
    }
}

impl<const N: usize> From<&'static [u8; N]> for Chain<IOBuf> {
    fn from(s: &'static [u8; N]) -> Self {
        IOBuf::from_static(s).into()
    }
}

impl From<&'static str> for Chain<IOBuf> {
    fn from(s: &'static str) -> Self {
        IOBuf::from_static(s.as_bytes()).into()
    }
}

impl From<alloc::vec::Vec<u8>> for Chain<IOBuf> {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        IOBuf::from(v).into()
    }
}

impl From<alloc::boxed::Box<[u8]>> for Chain<IOBuf> {
    fn from(b: alloc::boxed::Box<[u8]>) -> Self {
        IOBuf::from(b.into_vec()).into()
    }
}

impl From<alloc::string::String> for Chain<IOBuf> {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes()).into()
    }
}

// ============================================================================
// Cursor
// ============================================================================

/// Read-side traversal of a [`Chain`]. Walks node boundaries
/// transparently — `read` and `next_chunk` hop nodes when the
/// current one is exhausted. `advance` can skip ahead without
/// copying.
///
/// Generic over `B: IOBufRead`; the default `B = IOBuf` keeps the
/// pre-split spelling `Cursor<'_>` resolving for TX-path callers.
pub struct Cursor<'a, B: IOBufRead = IOBuf> {
    chain: &'a Chain<B>,
    /// Index of the current part within the chain.
    node_idx: usize,
    /// Bytes already consumed from the current node.
    in_node_off: usize,
    /// Total bytes consumed so far across all nodes.
    consumed: usize,
}

impl<'a, B: IOBufRead> Cursor<'a, B> {
    /// Bytes still available from the current cursor position to the
    /// end of the chain.
    pub fn remaining(&self) -> usize {
        self.chain.total_len().saturating_sub(self.consumed)
    }

    pub fn position(&self) -> usize {
        self.consumed
    }

    /// Resolve a part index to a borrowed part, or `None` past the
    /// chain's end.
    #[inline]
    fn node_at(&self, idx: usize) -> Option<&'a B> {
        self.chain.get_part(idx)
    }

    /// Advance the cursor by `n` bytes without reading. Caps at
    /// `remaining()`; returns the number of bytes actually advanced.
    pub fn advance(&mut self, n: usize) -> usize {
        let mut to_skip = n.min(self.remaining());
        let advanced = to_skip;
        while to_skip > 0 {
            let node = match self.node_at(self.node_idx) {
                Some(n) => n,
                None => break,
            };
            let avail = node.len() - self.in_node_off;
            if to_skip < avail {
                self.in_node_off += to_skip;
                to_skip = 0;
            } else {
                to_skip -= avail;
                self.node_idx += 1;
                self.in_node_off = 0;
            }
        }
        self.consumed += advanced;
        advanced
    }

    /// Read up to `dst.len()` bytes into `dst`, hopping node
    /// boundaries as needed. Returns bytes copied. The "one memcpy
    /// into the destination" property is what the NIC TX driver
    /// wants — copy chain bytes straight into the TX descriptor
    /// without an intermediate Vec.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let mut written = 0;
        while written < dst.len() {
            let node = match self.node_at(self.node_idx) {
                Some(n) => n,
                None => break,
            };
            let node_data = node.data();
            let avail = node_data.len() - self.in_node_off;
            if avail == 0 {
                self.node_idx += 1;
                self.in_node_off = 0;
                continue;
            }
            let n = (dst.len() - written).min(avail);
            dst[written..written + n]
                .copy_from_slice(&node_data[self.in_node_off..self.in_node_off + n]);
            self.in_node_off += n;
            written += n;
            if self.in_node_off == node_data.len() {
                self.node_idx += 1;
                self.in_node_off = 0;
            }
        }
        self.consumed += written;
        written
    }

    /// Return a borrowed slice for the next contiguous chunk of up
    /// to `max_len` bytes (or `None` at end-of-chain), and advance
    /// past it. The returned slice borrows directly from the
    /// underlying buffer — zero copy — valid for the cursor's
    /// lifetime parameter `'a`.
    ///
    /// The returned chunk may be shorter than `max_len` if the
    /// current node ends first; callers that need exactly `max_len`
    /// call repeatedly or use `read`.
    pub fn next_chunk(&mut self, max_len: usize) -> Option<&'a [u8]> {
        loop {
            let node = self.node_at(self.node_idx)?;
            let node_data = node.data();
            let avail = node_data.len() - self.in_node_off;
            if avail == 0 {
                self.node_idx += 1;
                self.in_node_off = 0;
                continue;
            }
            let n = avail.min(max_len);
            let slice = &node_data[self.in_node_off..self.in_node_off + n];
            self.in_node_off += n;
            self.consumed += n;
            if self.in_node_off == node_data.len() {
                self.node_idx += 1;
                self.in_node_off = 0;
            }
            return Some(slice);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IOBuf, IOBufDropFn, IOBufError, OwnedIOBuf};
    use core::ptr::NonNull;

    /// Drop callback that reconstructs and frees a `Box<[u8]>` whose
    /// region was handed to `wrap_owned`. `capacity` is the slice
    /// length, so `Box::from_raw` round-trips exactly.
    ///
    /// SAFETY: `base`/`capacity` must be the `(ptr, len)` of a
    /// `Box::<[u8]>::into_raw`'d allocation, reclaimed once here.
    unsafe fn free_box(base: NonNull<u8>, capacity: u32, _ctx: *mut ()) {
        let slice = core::ptr::slice_from_raw_parts_mut(base.as_ptr(), capacity as usize);
        drop(unsafe { alloc::boxed::Box::from_raw(slice) });
    }

    /// Build an owned (heap-backed, `ExternalOwned`) `OwnedIOBuf`
    /// holding `bytes` — the cross-core RX shape, for exercising
    /// `Chain<OwnedIOBuf>` in the host test.
    fn owned_buf(bytes: &[u8]) -> OwnedIOBuf {
        let boxed: alloc::boxed::Box<[u8]> = bytes.to_vec().into_boxed_slice();
        let cap = boxed.len() as u32;
        let raw = alloc::boxed::Box::into_raw(boxed);
        // SAFETY: `raw` is non-null (came from a Box) and points at
        // `cap` bytes; `free_box` reclaims exactly that region once;
        // offset 0 + len cap fits the capacity.
        unsafe {
            let base = NonNull::new_unchecked(raw as *mut u8);
            OwnedIOBuf::wrap_owned(
                base,
                cap,
                0,
                cap,
                free_box as IOBufDropFn,
                core::ptr::null_mut(),
            )
        }
    }

    #[test]
    fn chain_push_total_len() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"hello"));
        c.push_back(IOBuf::from_static(b" "));
        c.push_back(IOBuf::from_static(b"world"));
        assert_eq!(c.total_len(), 11);
        assert_eq!(c.part_count(), 3);
    }

    #[test]
    fn chain_push_front_o1() {
        // Build the body, then framing prepends in front.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"BODY"));
        c.push_front(IOBuf::from_static(b"HEADERS"));
        let mut out = [0u8; 16];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"HEADERSBODY");
    }

    #[test]
    fn chain_prepend_in_place() {
        // Front node has 8 B headroom → TLS record header fits.
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_slice_with_headroom(8, b"plaintext", 16));
        c.prepend_in_place(b"REC1").unwrap();
        let mut out = [0u8; 32];
        let n = c.cursor().read(&mut out);
        assert_eq!(&out[..n], b"REC1plaintext");
    }

    #[test]
    fn chain_prepend_in_place_no_headroom_errors() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"static"));
        assert_eq!(c.prepend_in_place(b"x"), Err(IOBufError::Immutable));
    }

    #[test]
    fn cursor_read_across_nodes() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        c.push_back(IOBuf::from_static(b"ghi"));
        let mut cur = c.cursor();
        let mut out = [0u8; 5];
        let n = cur.read(&mut out);
        assert_eq!(n, 5);
        assert_eq!(&out, b"abcde");
        let n = cur.read(&mut out);
        assert_eq!(n, 4);
        assert_eq!(&out[..n], b"fghi");
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn cursor_next_chunk_returns_node_at_a_time() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        let mut cur = c.cursor();
        assert_eq!(cur.next_chunk(100), Some(b"abc".as_ref()));
        assert_eq!(cur.next_chunk(100), Some(b"def".as_ref()));
        assert_eq!(cur.next_chunk(100), None);
    }

    #[test]
    fn cursor_next_chunk_caps_at_max_len() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abcdefgh"));
        let mut cur = c.cursor();
        assert_eq!(cur.next_chunk(3), Some(b"abc".as_ref()));
        assert_eq!(cur.next_chunk(3), Some(b"def".as_ref()));
        assert_eq!(cur.next_chunk(10), Some(b"gh".as_ref()));
        assert_eq!(cur.next_chunk(10), None);
    }

    #[test]
    fn cursor_advance_skips_into_later_node() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        c.push_back(IOBuf::from_static(b"def"));
        let mut cur = c.cursor();
        let skipped = cur.advance(4);
        assert_eq!(skipped, 4);
        assert_eq!(cur.position(), 4);
        let mut out = [0u8; 4];
        let n = cur.read(&mut out);
        assert_eq!(n, 2);
        assert_eq!(&out[..n], b"ef");
    }

    #[test]
    fn cursor_advance_caps_at_remaining() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"abc"));
        let mut cur = c.cursor();
        let skipped = cur.advance(100);
        assert_eq!(skipped, 3);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn full_layer_stack_simulation() {
        // Simulate a layered prepend pattern: app puts a body in a
        // chain, HTTP/1.1 prepends a status line, TLS prepends a
        // record header — all in place into reserved headroom of the
        // same IOBuf.
        let mut chain = IOBufChain::new();
        let body = IOBuf::from_slice_with_headroom(64, b"<html>...</html>", 0);
        chain.push_back(body);
        chain.prepend_in_place(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        chain.prepend_in_place(b"\x17\x03\x03\x00\x10").unwrap();
        let mut out = [0u8; 256];
        let n = chain.cursor().read(&mut out);
        assert_eq!(
            &out[..n],
            b"\x17\x03\x03\x00\x10HTTP/1.1 200 OK\r\n\r\n<html>...</html>"
        );
        assert_eq!(chain.total_len(), n);
    }

    /// The chain is generic over `B: IOBufRead`. Exercise the same
    /// surface (`push_back`, `total_len`, `iter`, `cursor`) against
    /// `B = IOBuf` (TX) and `B = OwnedIOBuf` (cross-core RX), so a
    /// regression on either monomorphisation is caught here.
    #[test]
    fn chain_generic_over_iobuf_and_owned() {
        // B = IOBuf
        let mut tx: Chain<IOBuf> = Chain::new();
        tx.push_back(IOBuf::from_static(b"tx-"));
        tx.push_back(IOBuf::from_static(b"chain"));
        assert_eq!(tx.total_len(), 8);
        assert_eq!(tx.part_count(), 2);
        assert_eq!(tx.iter().map(|p| p.len()).sum::<usize>(), 8);
        let mut out = [0u8; 16];
        let n = tx.cursor().read(&mut out);
        assert_eq!(&out[..n], b"tx-chain");

        // B = OwnedIOBuf — `Send` by derivation; same chain surface.
        let mut rx: Chain<OwnedIOBuf> = Chain::new();
        rx.push_back(owned_buf(b"rx-"));
        rx.push_back(owned_buf(b"chain"));
        assert_eq!(rx.total_len(), 8);
        assert_eq!(rx.part_count(), 2);
        assert_eq!(rx.iter().map(|p| p.len()).sum::<usize>(), 8);
        let n = rx.cursor().read(&mut out);
        assert_eq!(&out[..n], b"rx-chain");

        // `Chain::from(owned)` builds a 1-part owned chain.
        let single: Chain<OwnedIOBuf> = Chain::from(owned_buf(b"solo"));
        assert_eq!(single.part_count(), 1);
        assert_eq!(single.total_len(), 4);
    }

    /// A `Chain<OwnedIOBuf>` dropped (or `clear`ed) fires every
    /// part's drop callback front-to-back — the auto-repost the RX
    /// path relies on. `free_box`'s success is observable as "no
    /// leak / no double-free" under the test allocator; here we just
    /// confirm the chain drops cleanly across the `Many` boundary.
    #[test]
    fn owned_chain_drops_every_part() {
        let mut c: Chain<OwnedIOBuf> = Chain::new();
        for _ in 0..5 {
            c.push_back(owned_buf(b"frame"));
        }
        assert_eq!(c.part_count(), 5);
        c.clear();
        assert!(c.is_empty());
        // Drop a fresh chain at scope end too.
        let mut c2: Chain<OwnedIOBuf> = Chain::new();
        c2.push_back(owned_buf(b"x"));
        drop(c2);
    }

    /// Fast path: the front part already holds `n` contiguous bytes.
    /// `pull` is a no-op — the returned slice borrows directly from
    /// the existing front part (pointer-equal), no coalesce, no copy.
    #[test]
    fn pull_linear_already_is_noop() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HEADERtail"));
        c.push_back(IOBuf::from_static(b"more"));
        let front_ptr = c.get_part(0).unwrap().data().as_ptr();

        let head = c.pull(6).unwrap();
        assert_eq!(head, b"HEADER");
        assert_eq!(
            head.as_ptr(),
            front_ptr,
            "fast path returns a borrow of the original front part"
        );
        // The chain shape is unchanged: still 2 parts, same totals.
        assert_eq!(c.part_count(), 2);
        assert_eq!(c.total_len(), 14);
    }

    /// Coalesce-from-second-part: the front part is shorter than the
    /// requested header. `pull` materialises a fresh heap front part
    /// of exactly the requested length, with the leftover of the
    /// second part still on the chain.
    #[test]
    fn pull_coalesces_from_second_part() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HEA"));
        c.push_back(IOBuf::from_static(b"DERtail"));

        let head = c.pull(6).unwrap();
        assert_eq!(head, b"HEADER");
        // Coalesced front (6) + leftover ("tail") of the second part.
        assert_eq!(c.part_count(), 2);
        assert_eq!(c.total_len(), 10);
        assert_eq!(c.get_part(0).unwrap().data(), b"HEADER");
        assert_eq!(c.get_part(1).unwrap().data(), b"tail");
    }

    /// Coalesce-across-N-parts: front three parts together cover the
    /// header. `pull` absorbs the first two whole and the prefix of
    /// the third, leaving the third's leftover on the chain.
    #[test]
    fn pull_coalesces_across_n_parts() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HE"));
        c.push_back(IOBuf::from_static(b"AD"));
        c.push_back(IOBuf::from_static(b"ERtail"));
        c.push_back(IOBuf::from_static(b"trailing"));

        let head = c.pull(6).unwrap();
        assert_eq!(head, b"HEADER");
        // Two whole parts absorbed, third's prefix absorbed; the
        // third's leftover ("tail") + the untouched fourth remain.
        assert_eq!(c.part_count(), 3);
        assert_eq!(c.total_len(), 6 + 4 + 8);
        assert_eq!(c.get_part(0).unwrap().data(), b"HEADER");
        assert_eq!(c.get_part(1).unwrap().data(), b"tail");
        assert_eq!(c.get_part(2).unwrap().data(), b"trailing");
    }

    /// A coalesce that consumes the front parts exactly — no
    /// leftover to push back. The new front part is the only one
    /// covering the pulled range; later parts are untouched.
    #[test]
    fn pull_coalesces_exact_part_boundary() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HE"));
        c.push_back(IOBuf::from_static(b"AD"));
        c.push_back(IOBuf::from_static(b"ER"));
        c.push_back(IOBuf::from_static(b"body"));

        let head = c.pull(6).unwrap();
        assert_eq!(head, b"HEADER");
        assert_eq!(c.part_count(), 2);
        assert_eq!(c.total_len(), 10);
        assert_eq!(c.get_part(0).unwrap().data(), b"HEADER");
        assert_eq!(c.get_part(1).unwrap().data(), b"body");
    }

    /// Cursor reads of the chain after `pull` see the same bytes in
    /// the same order — `pull` reorganises layout without changing
    /// the chain's logical content.
    #[test]
    fn pull_preserves_logical_bytes() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HE"));
        c.push_back(IOBuf::from_static(b"ADER"));
        c.push_back(IOBuf::from_static(b"body"));

        let before: alloc::vec::Vec<u8> = {
            let mut out = alloc::vec![0u8; c.total_len()];
            let n = c.cursor().read(&mut out);
            out.truncate(n);
            out
        };
        let _ = c.pull(6).unwrap();
        let after: alloc::vec::Vec<u8> = {
            let mut out = alloc::vec![0u8; c.total_len()];
            let n = c.cursor().read(&mut out);
            out.truncate(n);
            out
        };
        assert_eq!(before, after);
    }

    /// `pull(0)` always succeeds with an empty slice, including on
    /// an empty chain.
    #[test]
    fn pull_zero_is_empty_slice() {
        let mut c = IOBufChain::new();
        assert_eq!(c.pull(0).unwrap(), b"");
        assert!(c.is_empty());

        c.push_back(IOBuf::from_static(b"abc"));
        assert_eq!(c.pull(0).unwrap(), b"");
        assert_eq!(c.part_count(), 1);
    }

    /// `pull(n)` errors when the chain holds fewer than `n` bytes,
    /// and leaves the chain untouched.
    #[test]
    fn pull_past_end_errors() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"ab"));
        c.push_back(IOBuf::from_static(b"cd"));
        assert_eq!(c.pull(5), Err(IOBufError::OutOfBounds));
        assert_eq!(c.part_count(), 2);
        assert_eq!(c.total_len(), 4);

        // Empty chain: any non-zero pull is OutOfBounds.
        let mut empty = IOBufChain::new();
        assert_eq!(empty.pull(1), Err(IOBufError::OutOfBounds));
    }

    /// `pull` works against a Single-repr chain too: when the lone
    /// part already holds the requested bytes, fast path; if it
    /// holds fewer, the chain has too few bytes total and we err.
    #[test]
    fn pull_on_single_repr_chain() {
        let mut c = IOBufChain::new();
        c.push_back(IOBuf::from_static(b"HEADER"));
        // Single repr ⇒ fast path.
        let head = c.pull(6).unwrap();
        assert_eq!(head, b"HEADER");
        assert_eq!(c.part_count(), 1);
    }
}
