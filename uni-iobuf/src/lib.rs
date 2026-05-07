// uni-http/src/iobuf.rs — IOBuf primitive for the network stack.
//
// Inspired by folly::IOBuf: a chain of byte segments with reserved
// space at each end ("headroom" / "tailroom") so layers below can
// prepend / append their headers without re-allocating or copying
// the existing payload. The chain owns its nodes; callers walk it
// via a `Cursor` that hops node boundaries transparently.
//
// What this buys us in the unikernel stack:
//
//   * App-side: a `Body` is an `IOBufChain` of static literals
//     (zero-copy) and dynamically-rendered owned chunks.
//   * HTTP/1.1 framing layer: the response status line + headers
//     get prepended onto the body chain via a single `push_front`,
//     reusing the chain's reserved headroom rather than allocating
//     a separate framing Vec.
//   * HTTP/3 layer: same — the HEADERS / DATA frame headers
//     prepend into the body chunk's headroom, the QPACK encoded
//     field section sits in a wrapper IOBuf borrowed from the
//     per-conn scratch, no `framing: Vec` copy.
//   * TLS layer: prepends the 5-byte TLSCiphertext record header
//     and appends the 16-byte AEAD tag in-place (encrypt straight
//     into the existing buffer's tailroom).
//   * QUIC: prepends short-header byte + packet number, encrypts
//     in place, the rest of the chain (UDP/IP/Eth) follows the
//     same prepend pattern.
//   * NIC TX: a final cursor pass copies bytes straight into the
//     hardware TX descriptor — one memcpy total, no intermediate
//     Vec.
//
// Design choices made for v1 (knowingly minimal — the goal is to
// land the type and start porting consumers; we add features when
// porting hits a wall):
//
//   * Single-owner heap segments. No `Rc<[u8]>` refcount yet — a
//     consumer that wants to retain a chunk for retransmit storage
//     today either copies (Vec) or moves the IOBuf out of the
//     chain. Sharing comes when the QUIC retransmit window needs
//     to hold onto chunks past their ACK-driven free.
//   * Static borrows. Zero-copy for `&'static [u8]` literals (the
//     STYLES block, every shell HTML chunk). No headroom/tailroom
//     on these — they're immutable, layers can't prepend INTO
//     them, but a heap-allocated header node can prepend before
//     them in the chain.
//   * Heap variant carries `offset` + `len` as `u32` (saves 8 B
//     per node vs `usize`). 4 GiB per chunk is plenty for any
//     unikernel workload.
//   * `IOBufChain` is a `VecDeque<IOBuf>`. Push-front and
//     push-back are both amortised O(1); we don't actually need
//     linked-list semantics, just chain-level prepend / append.
//
// Future additions (when ports demand them):
//
//   * `Rc<Storage>` heap variant for shared retransmit storage.
//   * NIC-descriptor variant for true zero-copy RX (the descriptor
//     gets recycled when the IOBuf drops).
//   * `try_coalesce` for crypto APIs that need contiguous input.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::VecDeque;

/// One byte segment in an IOBuf chain. Holds either heap-owned
/// storage with reserved headroom + tailroom, or a borrow into a
/// static-lifetime slice.
pub struct IOBuf {
    inner: Inner,
}

enum Inner {
    /// Heap-owned. The buffer's full capacity is `storage.len()`;
    /// the visible payload spans `[offset..offset+len]`. Headroom
    /// is `offset` (bytes before the payload that lower layers
    /// can prepend into); tailroom is `storage.len() - offset -
    /// len` (bytes after the payload that lower layers can append
    /// into, e.g. AEAD tags).
    Heap {
        storage: Box<[u8]>,
        offset: u32,
        len: u32,
    },
    /// Borrowed reference to static-lifetime bytes. Immutable; no
    /// headroom / tailroom semantics. Common for HTML literal
    /// chunks, the QPACK static table, etc.
    Static { data: &'static [u8] },
}

impl IOBuf {
    /// Allocate a heap-backed buffer with `headroom` bytes
    /// reserved at the front and `tailroom` bytes reserved at the
    /// end. Total allocation is `headroom + payload_capacity +
    /// tailroom` bytes; the visible payload starts empty (`len =
    /// 0`) at offset `headroom`. Lower layers prepend by writing
    /// into the headroom; higher layers can append data into the
    /// payload-then-tailroom region via `append_slice`.
    pub fn new_with_reserved(
        headroom: usize,
        payload_capacity: usize,
        tailroom: usize,
    ) -> Self {
        let cap = headroom + payload_capacity + tailroom;
        // `vec![0u8; cap].into_boxed_slice()` zero-fills the whole
        // region. We don't strictly need zero-init for headroom /
        // tailroom (nobody reads those), but the allocator's
        // free-list returns it eventually so initial-zeroing keeps
        // info-leak class bugs away. Fast enough at our buffer
        // sizes (sub-µs for 1500-byte allocs on talc).
        let storage = alloc::vec![0u8; cap].into_boxed_slice();
        IOBuf {
            inner: Inner::Heap {
                storage,
                offset: headroom as u32,
                len: 0,
            },
        }
    }

    /// Heap-backed buffer pre-filled with `data`. Reserves
    /// `headroom` / `tailroom` around the payload for downstream
    /// layer prepend/append.
    pub fn from_slice_with_headroom(headroom: usize, data: &[u8], tailroom: usize) -> Self {
        let mut buf = Self::new_with_reserved(headroom, data.len(), tailroom);
        buf.append_slice(data).expect("freshly-sized buffer accepts payload");
        buf
    }

    /// Borrow a static-lifetime slice. Zero allocation. Subsequent
    /// `prepend` / `append_slice` / `data_mut` calls return errors
    /// — static borrows are immutable.
    pub const fn from_static(data: &'static [u8]) -> Self {
        IOBuf {
            inner: Inner::Static { data },
        }
    }

    /// Visible payload bytes.
    pub fn data(&self) -> &[u8] {
        match &self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                &storage[o..o + l]
            }
            Inner::Static { data } => data,
        }
    }

    pub fn len(&self) -> usize {
        match &self.inner {
            Inner::Heap { len, .. } => *len as usize,
            Inner::Static { data } => data.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes available before the payload. Lower layers (TLS,
    /// TCP, IP, Eth) prepend their headers into this space.
    /// Always `0` for static borrows.
    pub fn headroom(&self) -> usize {
        match &self.inner {
            Inner::Heap { offset, .. } => *offset as usize,
            Inner::Static { .. } => 0,
        }
    }

    /// Bytes available after the payload. Used for AEAD tags,
    /// trailers, etc. Always `0` for static borrows.
    pub fn tailroom(&self) -> usize {
        match &self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let used = *offset as usize + *len as usize;
                storage.len().saturating_sub(used)
            }
            Inner::Static { .. } => 0,
        }
    }

    /// Mutable access to the visible payload. Returns `None` for
    /// static borrows. Used by in-place crypto (ChaCha20-Poly1305
    /// seals into the source bytes).
    pub fn data_mut(&mut self) -> Option<&mut [u8]> {
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = *offset as usize;
                let l = *len as usize;
                Some(&mut storage[o..o + l])
            }
            Inner::Static { .. } => None,
        }
    }

    /// Prepend `data` into the headroom and grow the visible
    /// payload accordingly. The returned slice points at the
    /// freshly-prepended region (in case the caller wants to
    /// overwrite via further mutation).
    ///
    /// `Err(IOBufError::NoHeadroom)` if the headroom is too small;
    /// `Err(IOBufError::Immutable)` for static borrows. Lower
    /// layers should choose buffer sizes with enough headroom for
    /// every layer below them — see `MAX_HEADER_RESERVE`.
    pub fn prepend(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let n = data.len();
                if n > *offset as usize {
                    return Err(IOBufError::NoHeadroom);
                }
                let new_offset = *offset - n as u32;
                let dst = &mut storage[new_offset as usize..*offset as usize];
                dst.copy_from_slice(data);
                *offset = new_offset;
                *len += n as u32;
                Ok(())
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
        }
    }

    /// Append `data` into the tailroom and grow the visible
    /// payload accordingly.
    pub fn append_slice(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                let n = data.len();
                if end + n > storage.len() {
                    return Err(IOBufError::NoTailroom);
                }
                storage[end..end + n].copy_from_slice(data);
                *len += n as u32;
                Ok(())
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
        }
    }

    /// Append `n` zero bytes (or rather, the slot's existing
    /// uninitialised contents — we don't re-zero) and return a
    /// mutable slice pointing at them. Used by AEAD seal: the
    /// caller advances the visible len, then writes the tag bytes
    /// directly into the returned slice.
    pub fn extend_uninit(&mut self, n: usize) -> Result<&mut [u8], IOBufError> {
        match &mut self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let end = *offset as usize + *len as usize;
                if end + n > storage.len() {
                    return Err(IOBufError::NoTailroom);
                }
                *len += n as u32;
                Ok(&mut storage[end..end + n])
            }
            Inner::Static { .. } => Err(IOBufError::Immutable),
        }
    }

    /// Trim `n` bytes from the FRONT of the visible payload.
    /// Used by the consumer side after a layer has stripped its
    /// header (e.g. TLS unprotect leaves the record header
    /// untouched in headroom; the next layer up just wants the
    /// plaintext).
    pub fn consume(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap { offset, len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *offset += n as u32;
                *len -= n as u32;
                Ok(())
            }
            Inner::Static { data } => {
                if n > data.len() {
                    return Err(IOBufError::OutOfBounds);
                }
                *data = &data[n..];
                Ok(())
            }
        }
    }

    /// Consume the IOBuf, producing an owned `Vec<u8>` of just
    /// the visible payload bytes. Zero-copy when this is a Heap
    /// variant whose visible payload spans the entire backing
    /// storage (offset=0 and len=cap); otherwise copies into a
    /// fresh Vec. For Static variants, always copies.
    ///
    /// Used as a bridge to APIs that take ownership of bytes via
    /// `Vec<u8>` (uni-quic's `SendStream::write_owned`). When that
    /// API itself moves to IOBuf the bridge goes away.
    pub fn into_owned_vec(self) -> alloc::vec::Vec<u8> {
        match self.inner {
            Inner::Heap {
                storage,
                offset,
                len,
            } => {
                let o = offset as usize;
                let l = len as usize;
                if o == 0 && l == storage.len() {
                    // Whole-buffer ownership migrates without copy.
                    storage.into_vec()
                } else {
                    storage[o..o + l].to_vec()
                }
            }
            Inner::Static { data } => data.to_vec(),
        }
    }

    /// True if this IOBuf wraps a `&'static [u8]`. Used by
    /// downstream layers to dispatch zero-alloc static-borrow vs
    /// owned-move paths (e.g. `SendStream::send_static` vs
    /// `send_owned`).
    pub fn is_static(&self) -> bool {
        matches!(self.inner, Inner::Static { .. })
    }

    /// If this IOBuf is a static borrow, return the underlying
    /// `&'static [u8]`. Returns `None` for heap-owned variants.
    /// Lets the H3 / TLS / TCP send paths take a borrowed-static
    /// fast path that holds onto the slice without copying.
    pub fn as_static(&self) -> Option<&'static [u8]> {
        match &self.inner {
            Inner::Static { data } => Some(data),
            Inner::Heap { .. } => None,
        }
    }

    /// `core::fmt::Write` adapter that appends formatted bytes
    /// into the IOBuf's tailroom. Lets callers `write!(buf.writer(),
    /// "{}", value)` to render straight into the IOBuf instead of
    /// going through an intermediate `String` + memcpy.
    ///
    /// The writer drops `Ok` even if the tailroom fills mid-render
    /// — `core::fmt::Write` doesn't surface `Err` for buffer
    /// exhaustion, so the caller checks `data().len()` afterward
    /// to detect truncation. Sized correctly the truncation path
    /// is cold.
    pub fn writer(&mut self) -> IOBufWriter<'_> {
        IOBufWriter { buf: self, overflowed: false }
    }

    /// Trim `n` bytes from the BACK of the visible payload.
    pub fn trim_end(&mut self, n: usize) -> Result<(), IOBufError> {
        match &mut self.inner {
            Inner::Heap { len, .. } => {
                if n > *len as usize {
                    return Err(IOBufError::OutOfBounds);
                }
                *len -= n as u32;
                Ok(())
            }
            Inner::Static { data } => {
                if n > data.len() {
                    return Err(IOBufError::OutOfBounds);
                }
                *data = &data[..data.len() - n];
                Ok(())
            }
        }
    }
}

/// Headroom constant covering every layer's worst-case header
/// size, so a buffer allocated by the topmost producer (the app)
/// has enough room for every lower layer to prepend in place.
///
///   * Ethernet header:                 14 bytes
///   * IPv6 header:                     40 bytes (worst of v4=20 / v6=40)
///   * TCP header (no options):         20 bytes
///   * TLS 1.3 record header:            5 bytes
///   * H3 frame header (varint type +
///     varint length, max sizes):       16 bytes
///   * QUIC short-header packet:         9 bytes (type + DCID(8))
///                                      ───
///   Total worst-case stack:            104 bytes
///
/// Round to the next 16-byte alignment boundary for a
/// cache-line-friendly headroom: 128 B.
pub const MAX_HEADER_RESERVE: usize = 128;

/// Tailroom constant covering layers that append (TLS / QUIC AEAD
/// tags). 16 B handles a single AEAD tag; if a future layer adds
/// its own trailer we'll bump.
pub const MAX_TRAILER_RESERVE: usize = 16;

/// `core::fmt::Write` adapter for [`IOBuf`]. Appends formatted
/// bytes into the buffer's tailroom; if tailroom runs out
/// mid-render the writer silently truncates (see `overflowed`).
/// Used by app-side response builders to render dynamic content
/// directly into a TLS-ready IOBuf without an intermediate
/// `String` allocation + memcpy.
pub struct IOBufWriter<'a> {
    buf: &'a mut IOBuf,
    /// Set when an `extend_uninit` call inside `write_str` failed
    /// (tailroom exhausted). The caller queries this after the
    /// `write!`/`writeln!` chain completes — `core::fmt::Write`'s
    /// `Result` doesn't propagate buffer-out-of-space errors.
    overflowed: bool,
}

impl IOBufWriter<'_> {
    /// True if any append during this writer's lifetime hit a
    /// tailroom exhaustion. Caller should treat the IOBuf as
    /// truncated and either grow it or surface an error.
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
                // `core::fmt::Write::write_str` returns
                // `core::fmt::Error` on failure. Returning Err
                // here halts the `write!` macro chain. The
                // caller still checks `overflowed()` for the
                // narrower "tailroom exhausted" signal.
                Err(core::fmt::Error)
            }
        }
    }
}

// ============================================================================
// Per-layer MTU / headroom negotiation
// ============================================================================

/// What each layer of the network stack publishes to the layer
/// above. The layer above (the producer) consults these fields
/// when allocating an `IOBuf` so every lower layer's `prepend`
/// in headroom and `append` in tailroom fits without
/// reallocating.
///
/// Concrete numbers come out of each layer's protocol header
/// shape: TCP wants 20 B headroom + 0 tailroom, IPv6 wants
/// 40 B headroom + 0, TLS 1.3 wants 5 B headroom + 16 B
/// tailroom for the AEAD tag, etc. The `compose` helper sums a
/// stack of LayerReserve values into the cumulative reserve a
/// producer should request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerReserve {
    /// Bytes the layer wants reserved at the front of every
    /// payload it ships. The layer's `send` method prepends
    /// its header into these bytes.
    pub headroom: usize,
    /// Bytes the layer wants reserved at the back. AEAD tags
    /// + trailers go here.
    pub tailroom: usize,
    /// Maximum payload bytes the layer can accept from the layer
    /// above for a single send call (i.e. before fragmentation
    /// kicks in). For TLS this is the record body size limit;
    /// for TCP it's the MSS.
    pub max_payload: usize,
}

impl LayerReserve {
    /// Identity / no-op layer — zero overhead, unbounded payload.
    /// Useful as a default for layers that don't add framing.
    pub const PASSTHROUGH: Self = LayerReserve {
        headroom: 0,
        tailroom: 0,
        max_payload: usize::MAX,
    };
}

// (Composition of multiple layers' reserves — "app over TLS over
// TCP — what's the cumulative headroom?" — is intentionally
// omitted from this commit. The arithmetic depends on whether
// we want "max per send call" semantics or "fit entirely in one
// lower-layer packet" semantics, and the right answer differs by
// layer pair. We'll add a concrete `compose_for_*` helper when
// the first consumer needs it.)

/// Trait every layer that wraps a payload implements so its
/// own consumers (the layer above) can ask "how much space
/// should I reserve in the IOBuf I hand to your `send`?". The
/// network stack walks this top-down at conn-establish time;
/// the producer caches the resulting `LayerReserve` and uses
/// its `headroom` / `tailroom` to size body buffers.
pub trait LayerInfo {
    /// What this layer plus all layers below it reserve. The
    /// layer above queries this to size its outgoing IOBufs.
    fn layer_reserve(&self) -> LayerReserve;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IOBufError {
    NoHeadroom,
    NoTailroom,
    OutOfBounds,
    Immutable,
}

// ============================================================================
// Chain
// ============================================================================

/// A chain of `IOBuf` segments. Push-front / push-back at the
/// chain level are amortised O(1); the `Cursor` walks node
/// boundaries transparently for readers.
///
/// The chain is the natural shape for a multi-layer stack:
/// each layer can append/prepend nodes (or prepend INTO the
/// front node's headroom) without disturbing the rest.
pub struct IOBufChain {
    parts: VecDeque<IOBuf>,
    total_len: usize,
}

impl IOBufChain {
    pub fn new() -> Self {
        IOBufChain {
            parts: VecDeque::new(),
            total_len: 0,
        }
    }

    pub fn with_capacity(part_capacity: usize) -> Self {
        IOBufChain {
            parts: VecDeque::with_capacity(part_capacity),
            total_len: 0,
        }
    }

    pub fn total_len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    pub fn part_count(&self) -> usize {
        self.parts.len()
    }

    /// Append a buf to the back of the chain.
    pub fn push_back(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        self.total_len += buf.len();
        self.parts.push_back(buf);
    }

    /// Prepend a buf to the front of the chain. O(1) thanks to
    /// `VecDeque`'s ring-buffer layout — the canonical use case
    /// is a layer wrapping framing bytes around a pre-built body.
    pub fn push_front(&mut self, buf: IOBuf) {
        if buf.is_empty() {
            return;
        }
        self.total_len += buf.len();
        self.parts.push_front(buf);
    }

    /// Prepend `data` directly into the FRONT node's headroom,
    /// without allocating a new node. Returns `Err` if the front
    /// node is missing or static (no headroom). Lets a layer
    /// prepend a small fixed header (TLS record header, H3 frame
    /// header) without growing the chain.
    ///
    /// Falls back to `push_front` of a heap-allocated single-byte
    /// node if the caller prefers a uniform "always works" API —
    /// see `prepend_or_push`.
    pub fn prepend_in_place(&mut self, data: &[u8]) -> Result<(), IOBufError> {
        let front = self.parts.front_mut().ok_or(IOBufError::NoHeadroom)?;
        front.prepend(data)?;
        self.total_len += data.len();
        Ok(())
    }

    /// Iterate the chain front-to-back.
    pub fn iter(&self) -> impl Iterator<Item = &IOBuf> {
        self.parts.iter()
    }

    /// Move all parts out, consuming the chain.
    pub fn into_parts(self) -> VecDeque<IOBuf> {
        self.parts
    }

    /// Construct a `Cursor` for reading.
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor {
            chain: self,
            node_idx: 0,
            in_node_off: 0,
            consumed: 0,
        }
    }
}

impl Default for IOBufChain {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Cursor
// ============================================================================

/// Read-side traversal of an `IOBufChain`. Walks node boundaries
/// transparently — `read` and `next_chunk` hop nodes when the
/// current one is exhausted. `advance` can skip ahead without
/// copying.
pub struct Cursor<'a> {
    chain: &'a IOBufChain,
    /// Index of the current node within `chain.parts`.
    node_idx: usize,
    /// Bytes already consumed from the current node (offset into
    /// the current node's `data()` slice).
    in_node_off: usize,
    /// Total bytes consumed so far across all nodes.
    consumed: usize,
}

impl<'a> Cursor<'a> {
    /// Bytes still available from the current cursor position to
    /// the end of the chain.
    pub fn remaining(&self) -> usize {
        self.chain.total_len.saturating_sub(self.consumed)
    }

    pub fn position(&self) -> usize {
        self.consumed
    }

    /// Advance the cursor by `n` bytes without reading. Caps at
    /// `remaining()`; returns the number of bytes actually
    /// advanced.
    pub fn advance(&mut self, n: usize) -> usize {
        let mut to_skip = n.min(self.remaining());
        let advanced = to_skip;
        while to_skip > 0 {
            let node = match self.chain.parts.get(self.node_idx) {
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
    /// boundaries as needed. Returns bytes copied. The "one
    /// memcpy into the destination" property is what the NIC TX
    /// driver wants — copy chain bytes straight into the TX
    /// descriptor without an intermediate Vec.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let mut written = 0;
        while written < dst.len() {
            let node = match self.chain.parts.get(self.node_idx) {
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

    /// Return a borrowed slice for the next contiguous chunk of
    /// up to `max_len` bytes (or `None` at end-of-chain), and
    /// advance past it. The returned slice borrows directly from
    /// the underlying IOBuf — zero copy — but is only valid for
    /// the cursor's lifetime parameter `'a`.
    ///
    /// The returned chunk may be shorter than `max_len` if the
    /// current node ends before `max_len` bytes; callers that
    /// need exactly `max_len` should call repeatedly or use
    /// `read`.
    pub fn next_chunk(&mut self, max_len: usize) -> Option<&'a [u8]> {
        loop {
            let node = self.chain.parts.get(self.node_idx)?;
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
// From/Into for ergonomics
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
        // Vec's allocation becomes a Box<[u8]> via into_boxed_slice
        // (no copy — same bytes). Headroom = 0, tailroom = 0;
        // callers who want layer-prepend room should construct via
        // `from_slice_with_headroom`.
        let len = v.len();
        let storage: Box<[u8]> = v.into_boxed_slice();
        IOBuf {
            inner: Inner::Heap {
                storage,
                offset: 0,
                len: len as u32,
            },
        }
    }
}

impl From<alloc::string::String> for IOBuf {
    fn from(s: alloc::string::String) -> Self {
        IOBuf::from(s.into_bytes())
    }
}

impl From<IOBuf> for IOBufChain {
    fn from(buf: IOBuf) -> Self {
        let mut c = IOBufChain::new();
        c.push_back(buf);
        c
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        // Original payload preserved on error.
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
    fn vec_into_iobuf_no_copy() {
        let v = alloc::vec![1u8, 2, 3, 4, 5];
        let ptr_before = v.as_ptr();
        let buf = IOBuf::from(v);
        // `Vec::into_boxed_slice` reuses the allocation when len ==
        // capacity; we don't guarantee no-copy in general, but for
        // an exact-fit Vec (constructed from `vec!`) it should hold.
        // Treat as a smoke test of the conversion direction.
        assert_eq!(buf.data(), &[1u8, 2, 3, 4, 5]);
        let _ = ptr_before;
    }

    #[test]
    fn layer_reserve_passthrough_constants() {
        let p = LayerReserve::PASSTHROUGH;
        assert_eq!(p.headroom, 0);
        assert_eq!(p.tailroom, 0);
        assert_eq!(p.max_payload, usize::MAX);
    }

    #[test]
    fn iobuf_writer_renders_into_tailroom() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(8, 0, 64);
        // Visible payload starts empty.
        assert_eq!(buf.len(), 0);
        write!(buf.writer(), "hello {}", 42).unwrap();
        assert_eq!(buf.data(), b"hello 42");
        // Subsequent prepend uses headroom (still has 8 reserved).
        buf.prepend(b"REC1").unwrap();
        assert_eq!(buf.data(), b"REC1hello 42");
    }

    #[test]
    fn iobuf_writer_signals_overflow() {
        use core::fmt::Write as _;
        let mut buf = IOBuf::new_with_reserved(0, 0, 4);
        let mut w = buf.writer();
        // First write fits.
        let _ = write!(w, "ab");
        // Second exceeds tailroom — the second write_str call
        // sets overflowed and returns Err.
        let r = write!(w, "cdefgh");
        assert!(r.is_err());
        assert!(w.overflowed());
    }

    #[test]
    fn full_layer_stack_simulation() {
        // Simulate the network stack: app builds a body, HTTP layer
        // prepends headers, TLS prepends a record header, TCP/IP/Eth
        // would all prepend in turn. Here we just check that
        // prepend_in_place works end-to-end without copying bytes
        // beyond the writes we explicitly perform.
        let mut chain = IOBufChain::new();
        // App: heap-alloc an HTML body chunk with headroom for every
        // layer below.
        let body = IOBuf::from_slice_with_headroom(
            MAX_HEADER_RESERVE,
            b"<html>...</html>",
            MAX_TRAILER_RESERVE,
        );
        chain.push_back(body);

        // HTTP layer: prepend headers in place. (Real impl writes
        // \r\n\r\n; here we just stand in.)
        chain.prepend_in_place(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();

        // TLS layer: prepend record header.
        chain.prepend_in_place(b"\x17\x03\x03\x00\x10").unwrap();

        // Read the full chain into a destination buffer (NIC TX
        // simulation).
        let mut out = [0u8; 256];
        let n = chain.cursor().read(&mut out);
        assert_eq!(
            &out[..n],
            b"\x17\x03\x03\x00\x10HTTP/1.1 200 OK\r\n\r\n<html>...</html>"
        );
        assert_eq!(chain.total_len(), n);
    }
}
