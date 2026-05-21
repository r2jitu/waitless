// Byte-level transport abstraction for the HTTP server.
//
// `HttpStream` is the trait `serve_conn` drives — plain HTTP uses
// `TcpStream` directly; HTTPS wraps it in `tls::TlsStream`; HTTP/3
// hands a pre-buffered `NullStream` so the same handler signature
// works across all three.

use iobuf::IOBufChain;

use crate::body::BodyReader;

// ---- HttpStream abstraction --------------------------------------------------
//
// `HttpStream` is the byte-level interface the conn handler uses
// to talk to a peer. Plain HTTP impls it directly over
// `TcpStream`; HTTPS impls it via `tls::TlsStream`, which
// pumps the TLS state machine inside `recv` / `send` so the
// handler stays protocol-agnostic.
//
// Static dispatch: `serve_conn<S: HttpStream>` is monomorphised
// per impl, so trait method calls inline. Plain and TLS paths
// share the same connection-loop machinery; the only thing
// changing is the byte-level transport.

/// `async_fn_in_trait` lints because the lint can't see that
/// our connection futures are `!Send` by design — `TcpStream` is
/// per-worker. Allow at the trait level: callers always use this
/// trait through static dispatch (see `serve_conn<S: HttpStream>`),
/// and the per-conn task spawns onto the same worker that
/// accepted the connection, so cross-worker Send is never needed.
#[allow(async_fn_in_trait)]
pub trait HttpStream {
    /// Read up to `buf.len()` bytes from the peer (after
    /// decryption, for TLS streams). Returns `0` on EOF / fatal
    /// transport error. Implementors decide whether to wake on
    /// partial reads or drain a full segment first.
    async fn recv(&mut self, buf: &mut [u8]) -> usize;

    /// Zero-copy sibling of [`recv`](Self::recv): resolve the next
    /// inbound run of bytes as a [`RecvChunkGuard`] over the
    /// transport's *own* buffer, instead of copying into a caller
    /// slice. `None` on peer close / EOF, or on a transport with no
    /// streaming chunk path.
    ///
    /// [`BodyReader::chunk`] calls this once its prebuf is drained,
    /// so request-body bytes past the prebuf reach the handler with
    /// no intermediate copy — item H of
    /// `docs/rx-path-optimizations.md`.
    ///
    /// The default returns `None`: a transport that hands the whole
    /// request body to the HTTP layer pre-buffered ([`NullStream`],
    /// the HTTP/3 case) has no streaming chunk path, and
    /// `BodyReader` then serves the body from its prebuf alone.
    /// `waitless::runtime::TcpStream` and `tls::TlsStream` override
    /// this with their real `recv_chunk` implementations.
    ///
    /// `&mut self` is load-bearing, not incidental — the returned
    /// [`RecvChunkGuard`] carries that borrow for its whole life, so
    /// the transport cannot re-read (hence overwrite) the surfaced
    /// buffer while the chunk is still held. See item F's write-up.
    ///
    /// [`RecvChunkGuard`]: waitless::runtime::RecvChunkGuard
    async fn recv_chunk(&mut self) -> Option<waitless::runtime::RecvChunkGuard<'_>> {
        None
    }

    /// Send a chain of IOBuf parts. The transport decides how to
    /// chunk the bytes onto the wire — TCP coalesces parts into
    /// MSS-bounded segments, TLS encrypts each part as a record
    /// (in-place when the part has reserved headroom + tailroom).
    /// Producers (the HTTP framing layer + apps) build the chain
    /// out of the layered pieces — header IOBuf prepended to the
    /// app's body chain — and let the transport own the layout
    /// decision.
    ///
    /// `IOBufChain` is the standard send surface; takes `&mut`
    /// so the caller can amortise the `VecDeque` allocation
    /// across many requests on the same connection. The
    /// implementation drains the chain (each part `pop_front`'d,
    /// then dropped after its bytes are committed); on return
    /// the chain is empty but the underlying `VecDeque` capacity
    /// is preserved.
    ///
    /// `Err(())` on fatal transport error; the conn handler tears
    /// down on error.
    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()>;

    /// Cleanly signal end-of-stream to the peer before the
    /// underlying transport closes. Plain TCP is already correct
    /// with the implicit FIN-on-drop, so the default is a no-op.
    /// TLS streams override to emit a `close_notify` alert: rustls
    /// (and most spec-compliant TLS clients) treat a TCP close
    /// without close_notify as an unclean shutdown and discard any
    /// session ticket they were about to cache, blocking resumption.
    async fn close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

/// `HttpStream` impl for transports that hand the request body to
/// the HTTP layer pre-buffered in one go (HTTP/3 reassembles DATA
/// frames before invoking the handler). [`BodyReader`] draws stream
/// bytes (via `recv_chunk`) only once its `prebuf` is exhausted —
/// for an h3 body constructed with `prebuf.len() == total`, that
/// path never fires. `NullStream` exists so the generic type
/// parameter is satisfied for those transports: it inherits the
/// default `recv_chunk` (returns `None`, so `BodyReader` serves
/// from the prebuf alone) and the trivial `recv` return-0; calling
/// `send` panics — that transport does not write through
/// `HttpStream`.
pub struct NullStream;

/// Friendly alias for a [`BodyReader`] over [`NullStream`] — i.e.
/// a body whose bytes are entirely in the prebuf and won't trigger
/// any stream refill. Used by transports that buffer the request
/// body before handing control to the application (HTTP/3 today).
pub type BufferedBody<'a> = BodyReader<'a, NullStream>;

impl HttpStream for NullStream {
    async fn recv(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    async fn send(&mut self, _chain: &mut IOBufChain) -> Result<(), ()> {
        panic!("NullStream::send: this transport does not write through HttpStream")
    }
    async fn close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl HttpStream for waitless::runtime::TcpStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        (*self).recv(buf).await
    }

    /// Forwards to the inherent `waitless::runtime::TcpStream::recv_chunk`.
    ///
    /// Deliberately a plain `fn` returning the *concrete* `RecvChunk`
    /// future — not an `async fn` block, and not the trait's opaque
    /// `impl Future` — so the forward is type-checked against the
    /// inherent method: the inherent method is the only thing that
    /// produces a `RecvChunk`. Were it ever removed,
    /// `waitless::runtime::TcpStream::recv_chunk` here would resolve to
    /// *this* trait method, whose return type is opaque, and the
    /// mismatch against `-> RecvChunk<'_>` is a compile error —
    /// rather than the silent infinite recursion an `impl Future`
    /// return type would let through. That is why the
    /// `refining_impl_trait_reachable` allow below is intentional:
    /// the refinement *is* the footgun guard.
    #[allow(refining_impl_trait_reachable)]
    fn recv_chunk(&mut self) -> waitless::runtime::RecvChunk<'_> {
        waitless::runtime::TcpStream::recv_chunk(self)
    }

    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
        // Hand the chain to the runtime's chain-shaped send,
        // which calls into the backend. Bare-metal walks the
        // chain via its cursor and copies bytes directly into
        // MSS-sized TCP segments (no user-space scratch
        // coalesce); native uses `writev(2)` so a multi-part
        // shape ships in one syscall. This layer is a thin
        // trait wire-up — the transport-side decisions live
        // in `tcp::async_try_send_chain` (bare-metal) and
        // `native_tcp_try_send_chain` (POSIX).
        (*self).send(chain).await
    }
}
