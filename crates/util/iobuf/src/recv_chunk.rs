//! `RecvChunkGuard` — the zero-copy chunk-read guard shared by every
//! `recv_chunk` surface (`TcpStream`, `TlsStream`, `HttpStream`).
//!
//! Lives here in `iobuf` (the buffer-currency leaf) rather than in
//! the reactor because it is a pure wrapper over [`IOBuf`](crate::IOBuf)
//! with a borrow phantom — no transport state — and protocol crates
//! name it in their trait signatures. Homing it in the leaf lets
//! `proto/http`'s `HttpStream` and `proto/tls` reference the read
//! type without depending on a specific runtime (the layering
//! inversion called out in docs/stack-architecture.md).

use core::marker::PhantomData;

/// RAII guard returned by a stream's `recv_chunk`. Owns the
/// surfaced [`IOBuf`](crate::IOBuf) and carries the `&'a mut`
/// borrow of the stream it came from.
///
/// The borrow is the load-bearing part: it makes "at most one
/// outstanding IOBuf per stream" a compile-time fact rather than a
/// runtime invariant, and — for transports that surface a
/// `Borrowed` view (TLS plaintext, a later RX-path item) — it
/// prevents the stream from being re-read, and those bytes
/// overwritten, while the guard is live.
pub struct RecvChunkGuard<'a> {
    iobuf: crate::IOBuf,
    /// Ties the guard to the `&'a mut self` of `recv_chunk`. The
    /// inner type is opaque (`()`) so one guard type can serve
    /// every stream — `TcpStream` here, `TlsStream` later.
    _borrow: PhantomData<&'a mut ()>,
}

impl<'a> RecvChunkGuard<'a> {
    /// Wrap a transport-surfaced [`IOBuf`](crate::IOBuf) in a
    /// guard. The guard's `'a` is inferred at the call site — a
    /// `recv_chunk` binds it to the `&'a mut self` it took, so the
    /// borrow checker keeps that stream mutably borrowed (hence
    /// un-re-readable) for the guard's whole life.
    ///
    /// `pub` because the guard is the *one* type shared across
    /// every `recv_chunk` surface, and the constructions live in
    /// different crates: the `TcpStream` backend builds it from the
    /// `do_recv_chunk` hook in `executor` (an owned
    /// `External`/`Heap` IOBuf), and `TlsStream::recv_chunk` in
    /// `tls` builds it from a `Borrowed` view of decrypted
    /// plaintext (RX item G). A single guard type — not a parallel
    /// `TlsRecvChunkGuard` — is what lets item H's `BodyReader`
    /// stay generic over the stream.
    #[inline]
    pub fn new(iobuf: crate::IOBuf) -> Self {
        RecvChunkGuard {
            iobuf,
            _borrow: PhantomData,
        }
    }

    /// The chunk's bytes, read in place. Zero copy. Callers that
    /// need the length use `data().len()`.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.iobuf.data()
    }

    /// Mutable view of the chunk's bytes — the same window as
    /// [`Self::data`], unique-access. Used by the TLS RX path to
    /// hand the chunk's ciphertext straight to `record::open`,
    /// which AEAD-decrypts in place (overwriting the ciphertext
    /// with plaintext) without staging the bytes through any
    /// intermediate buffer.
    ///
    /// After the call returns, the chunk's bytes are scrambled
    /// (the AEAD ran over them); the chunk must be dropped before
    /// any consumer expects to re-read the original ciphertext.
    ///
    /// Panics if the underlying IOBuf is the immutable `Static`
    /// variant — RX chunks surfaced through `recv_chunk` are
    /// always `Heap` / `External` / `Borrowed` (owned by the NIC
    /// driver or a per-conn pool), never `Static`. The unwrap is
    /// therefore total in production; a Static chunk would be a
    /// backend bug.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.iobuf
            .data_mut()
            .expect("RecvChunkGuard never wraps an immutable Static IOBuf")
    }

    /// Take owned possession of the chunk. Zero copy when the
    /// surfaced `IOBuf` already owns its storage (`Heap`, or the
    /// NIC-RX `ExternalOwned` device buffer); one memcpy into a
    /// fresh heap buffer when it is a `Borrowed` view (TLS
    /// plaintext). The escape hatch for holding the bytes past the
    /// guard's borrow — e.g. a proxy forwarding the chunk into an
    /// outbound `send`.
    #[inline]
    pub fn into_owned(self) -> crate::IOBuf {
        self.iobuf.into_owned()
    }

    /// Consume the first `n` bytes and return the rest as an owned
    /// IOBuf, or `Ok(None)` if nothing remains. The "I parsed K
    /// bytes off the front of this chunk; carry the tail past the
    /// recv borrow" primitive — used by `serve_conn` when a chunk
    /// runs past a request-HEAD terminator into the body / next
    /// pipelined request.
    ///
    /// Runs the `consume(n)` advance BEFORE `into_owned`, so for
    /// `Borrowed` chunks (TLS plaintext) the copy is sized to the
    /// leftover only — not the whole pre-consume chunk. NIC-RX
    /// `ExternalOwned` chunks stay zero-copy through both steps.
    ///
    /// Returns `Err(IOBufError)` if `n` exceeds the chunk's visible
    /// length; the panic-vs-propagate choice stays at the call site.
    #[inline]
    pub fn into_remainder(self, n: usize) -> Result<Option<crate::IOBuf>, crate::IOBufError> {
        Ok(self.iobuf.into_remainder(n)?.map(|t| t.into_owned()))
    }
}
