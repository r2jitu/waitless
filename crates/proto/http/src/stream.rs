// Byte-level transport abstraction for the HTTP server.
//
// `HttpStream` is the trait the per-connection loop drives for its own
// I/O — plain HTTP uses `TcpStream` directly; HTTPS wraps it in
// `http2::TlsStream`. The serve loop reads the request head and writes
// the response through `HttpStream` (monomorphised per transport, so
// those calls inline).
//
// The request *body* past the prebuf reaches the handler through a
// transport-erased seam — [`BodySource`] + `&mut dyn BodySource` on
// `BodyReader` — so the handler signature is `(&Request, &mut
// BodyReader<'_>)` with **no** stream type parameter, identical for
// HTTP/1.1, HTTP/2, and HTTP/3. That's what lets one handler value
// serve every transport (and the `https::serve` facade take a single
// handler) without a per-protocol `Service` trait or `NullStream` stub.

use core::future::Future;
use core::pin::Pin;

use alloc::boxed::Box;

use iobuf::{IOBuf, IOBufChain};

// ---- HttpStream abstraction --------------------------------------------------
//
// `HttpStream` is the byte-level interface the conn loop uses to talk
// to a peer. Plain HTTP impls it directly over `TcpStream`; HTTPS impls
// it via `http2::TlsStream`, which pumps the TLS state machine inside
// `recv` / `send` so the loop stays protocol-agnostic.
//
// Static dispatch: `serve_conn<S: HttpStream>` is monomorphised per
// impl, so trait method calls inline. Plain and TLS paths share the
// same connection-loop machinery; only the byte-level transport changes.

/// `async_fn_in_trait` lints because the lint can't see that
/// our connection futures are `!Send` by design — `TcpStream` is
/// per-worker. Allow at the trait level: callers always use this
/// trait through static dispatch (see `serve_conn<S: HttpStream>`),
/// and the per-conn task spawns onto the same worker that
/// accepted the connection, so cross-worker Send is never needed.
#[allow(async_fn_in_trait)]
pub trait HttpStream {
    /// Resolve the next inbound run of bytes as a [`RecvChunkGuard`]
    /// over the transport's *own* buffer, with no copy into a caller
    /// slice. `None` on peer close / EOF, or on a transport with no
    /// streaming chunk path.
    ///
    /// The serve loop calls this for the request head, and
    /// [`BodyReader`](crate::BodyReader) reaches it (via the
    /// [`BodySource`] blanket impl) for request-body bytes past the
    /// prebuf — both zero-copy from the device buffer (item H of
    /// `docs/rx-path-optimizations.md`).
    ///
    /// The default returns `None` (a transport with no streaming chunk
    /// path); `waitless::runtime::TcpStream` and `http2::TlsStream`
    /// override it with their real implementations.
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

// ---- BodySource: the transport-erased request-body seam ----------------------

/// Object-safe source of request-body bytes, held by
/// [`BodyReader`](crate::BodyReader) as `&mut dyn BodySource` so the
/// handler never names the transport stream type.
///
/// There is a blanket impl for every [`HttpStream`], so transports get
/// this for free — `BodyReader` works over `&mut dyn BodySource` while
/// the serve loops keep their concrete `S` for head/response I/O.
///
/// `next_chunk` returns a **boxed** future. The box is the price of
/// object-safety (async methods aren't `dyn`-compatible on stable), and
/// it lands **only on the cold request-body path**: a GET never calls
/// it, and HTTP/2 / HTTP/3 buffer their body and pass *no* source. The
/// body *bytes* stay zero-copy — the returned `IOBuf` owns the device
/// buffer (`into_owned` is a move for `External`/`Heap`). Eliminating
/// even the per-chunk box would mean a poll-based source replicating the
/// reactor's chunk-slot/waker/cancel contract; deferred as a perf
/// follow-up since the body path is cold.
pub trait BodySource {
    /// Next run of body bytes as an owned `IOBuf`, or `None` at
    /// end-of-body / peer close.
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<IOBuf>> + '_>>;
}

impl<T: HttpStream + ?Sized> BodySource for T {
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<IOBuf>> + '_>> {
        // Reuse the transport's zero-copy `recv_chunk` and take owned
        // possession of the surfaced buffer. `into_owned` is a move for
        // an owned device buffer; a copy only for a borrowed view.
        Box::pin(async move { self.recv_chunk().await.map(|g| g.into_owned()) })
    }
}

// ---- ResponseSink: the transport-erased response-write seam ------------------

/// The TX write seam a [`Response`](crate::Response) holds so a handler
/// can **push** body chunks to the wire as it produces them —
/// `res.write(chunk).await` routes straight here. The TX counterpart of
/// [`BodySource`]: the response never names the transport (object-safe,
/// boxed futures), and `res.write` awaits each `write_chunk`, so the
/// handler is paced by the wire (backpressure) and per-connection peak
/// memory stays `O(chunk)` rather than `O(body)`.
///
/// `send_head` is invoked once, lazily, on the first `write_chunk` (the
/// head stays editable until then); a streamed body has no up-front
/// length, so h1 sends it close-delimited. `finish` ends the body.
///
/// Wired by the transport for the duration of the handler when the
/// connection can stream a response (h1, request bodyless so the read
/// half is idle); otherwise the response has no sink and `res.write`
/// buffers (h2/h3, or h1 with a request body in flight).
pub trait ResponseSink {
    /// Emit the response head (status line + headers), once, before the
    /// first chunk.
    fn send_head(
        &mut self,
        status: i32,
        content_type: &[u8],
        extra_headers: &[(&[u8], &[u8])],
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;

    /// Write one body chunk to the wire (awaited → backpressure).
    fn write_chunk(&mut self, buf: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;

    /// End the response body.
    fn finish(&mut self) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>>;
}

impl HttpStream for waitless::runtime::TcpStream {
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
