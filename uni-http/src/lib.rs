// HTTP/1.1 server. Cooperative non-blocking: the kernel event loop
// accepts, reads, parses, dispatches, and writes back.
//
// Per-core listener + connection set; routes are shared read-only.
// This crate is TLS-agnostic: HTTPS lives in `uni_tls`, which
// defines its own `HttpStream` impl (TLS over TCP) and calls
// `serve_conn` to drive the same request/response machinery.

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;
extern crate uni;
extern crate uni_iobuf;

// Re-export the shared IOBuf primitive so `uni_http::IOBuf` /
// `uni_http::IOBufChain` keep working at every existing call
// site. The crate moved out so `uni-quic` (transport, can't
// depend on `uni-http`) can use the same type without crossing
// the transport↛app dependency boundary.
pub use uni_iobuf::{
    Cursor as IOBufCursor, IOBuf, IOBufChain, IOBufError, IOBufWriter, OwnedIOBuf,
};

use alloc::sync::Arc;

/// Allocate an IOBuf for a response body part with `cap` bytes
/// of usable payload capacity. The returned IOBuf's visible
/// payload (`buf.data()`) starts empty and grows up to `cap`
/// bytes via [`IOBuf::append_slice`] / [`IOBuf::writer`] /
/// [`IOBuf::extend_uninit`].
///
/// No headroom or tailroom is reserved — every framing layer in
/// the stack prepends its header as a *separate* IOBuf
/// (`push_front` onto the response chain) rather than writing
/// into a body part's reserved space:
///   * HTTP/1.1: response head IOBuf goes in front of the body
///     parts (see `serve_conn`'s `out_chain`).
///   * TLS: encrypts the chain into a fresh record buffer.
///   * HTTP/3: HEADERS/DATA frame headers are wrapped in a
///     separate IOBuf the H3 framer pushes ahead of body parts.
/// So body IOBufs only need to hold their own bytes.
///
/// One per-request heap allocation (typically a few-KiB
/// `Box<[u8]>`). The bytes are uninitialised — the IOBuf API's
/// write-before-read entry points (`append_slice`, `writer`,
/// `extend_uninit`, `prepend` consuming from headroom into the
/// visible window) ensure no uninit byte ever becomes visible
/// via `data()`. Caller doesn't need to think about this.
///
/// Apps:
///
/// ```ignore
/// async fn page(_req: &Request) -> Response {
///     let mut body = uni_http::body_iobuf(12 * 1024);
///     {
///         let mut w = body.writer();
///         // render content
///     }
///     Response::ok(b"text/html", body)
/// }
/// ```
pub fn body_iobuf(cap: usize) -> IOBuf {
    // SAFETY: visible payload starts empty; the public IOBuf
    // mutation entry points used to grow it (append_slice /
    // writer / extend_uninit / prepend) all write before
    // exposing bytes through `data()`.
    unsafe { IOBuf::new_with_reserved_uninit(0, cap, 0) }
}

// ---- HTTP types -------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Head = 4,
    Unknown = 5,
}

pub struct Header {
    name: [u8; 64],
    name_len: usize,
    value: [u8; 256],
    value_len: usize,
}

impl Header {
    const fn new() -> Self {
        Header {
            name: [0; 64],
            name_len: 0,
            value: [0; 256],
            value_len: 0,
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

pub struct Request {
    pub method: Method,
    path: [u8; 256],
    path_len: usize,
    headers: [Header; 16],
    header_count: usize,
    /// Content-Length from the request headers, or 0 if absent.
    /// Authoritative count of body bytes that follow the headers
    /// on the wire — the `BodyReader` handed to the handler will
    /// deliver exactly this many bytes.
    content_length: usize,
    /// Set by the HTTP/1.1 parser when the request is malformed
    /// in a way that must be answered with a hard `400 Bad
    /// Request` + `Connection: close` instead of being dispatched
    /// to a handler. The sole trigger today is a `Transfer-
    /// Encoding: chunked` request — chunked framing is not yet
    /// implemented (item E in docs/rx-path-optimizations.md), and
    /// silently treating its body as length-0 is a request-
    /// smuggling hole. `serve_conn` reads this flag right after
    /// the parse. Always `false` for requests built by the
    /// HTTP/3 frontend, which never sees chunked framing.
    reject: bool,
}

impl Request {
    pub fn new() -> Self {
        Request {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            content_length: 0,
            reject: false,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Total body length in bytes (declared by the Content-Length
    /// header). The handler reads the body via the `BodyReader`
    /// passed as the second argument; this is the count it will
    /// deliver in total.
    pub fn content_length(&self) -> usize {
        self.content_length
    }

    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name().eq_ignore_ascii_case(name) {
                return Some(self.headers[i].value());
            }
        }
        None
    }

    /// Parse the port number out of the request's `Host` header.
    /// Returns `None` if the header is missing or has no `:port`
    /// suffix. Handles both `host:port` and `[v6-literal]:port`
    /// shapes (RFC 7230 §5.4). Useful for apps that want to emit
    /// `Alt-Svc: h3=":<port>"` advertising the same port the
    /// client used to reach us — typical in dev where the host-
    /// to-guest mapping puts HTTPS on a non-default port.
    pub fn host_port(&self) -> Option<u16> {
        host_header_port(self.header(b"Host")?)
    }

    /// Overwrite the request-target path. Truncates if longer than
    /// the fixed `path` buffer. Used by the HTTP/3 frontend to
    /// install the `:path` pseudo-header into the same `Request`
    /// shape the HTTP/1.1 parser fills in.
    pub fn set_path(&mut self, path: &[u8]) {
        let n = path.len().min(self.path.len());
        self.path[..n].copy_from_slice(&path[..n]);
        self.path_len = n;
    }

    /// Used by the HTTP/3 frontend to install the Content-Length
    /// value it parsed from the QPACK-decoded `content-length`
    /// pseudo-header into the same `Request` shape the HTTP/1.1
    /// parser fills in.
    pub fn set_content_length(&mut self, n: usize) {
        self.content_length = n;
    }

    /// Append a header line `(name, value)`. Drops silently if the
    /// per-Request 16-header cap is full (matches the HTTP/1.1
    /// parser's truncation policy).
    pub fn push_header(&mut self, name: &[u8], value: &[u8]) {
        if self.header_count >= self.headers.len() {
            return;
        }
        let h = &mut self.headers[self.header_count];
        let n = name.len().min(h.name.len());
        h.name[..n].copy_from_slice(&name[..n]);
        h.name_len = n;
        let v = value.len().min(h.value.len());
        h.value[..v].copy_from_slice(&value[..v]);
        h.value_len = v;
        self.header_count += 1;
    }

    fn clear(&mut self) {
        self.method = Method::Unknown;
        self.path_len = 0;
        self.header_count = 0;
        self.content_length = 0;
        self.reject = false;
    }
}

// ---- Streaming request body --------------------------------------------------

/// Streaming reader for the request body.
///
/// Bytes are exposed via [`chunk`] as borrowed slices that alias
/// either:
///   * the per-connection parse buffer (`prebuf`) — for body bytes
///     that arrived in the same TCP/TLS read that delivered the
///     headers; zero-copy from the handler's perspective.
///   * the reader's own [`refill`] scratch — populated by direct
///     stream reads after `prebuf` is exhausted; the bytes are
///     copied once from the transport's user-supplied recv buffer
///     into `refill`, then handed to the handler as a borrowed
///     slice.
///
/// The reader knows the total body length (from the request's
/// `Content-Length`) and stops handing out bytes after exactly
/// that many have been delivered, so the underlying transport
/// stream is left positioned at the start of the next pipelined
/// request.
///
/// If the handler returns without consuming all bytes,
/// `serve_conn` calls [`discard`] before sending the response so
/// the keep-alive contract holds. Handlers that intentionally
/// want to abort a large unwanted upload should return a response
/// with `Connection: close` set; `serve_conn` then skips the
/// drain and tears down the conn.
pub struct BodyReader<'a, S: HttpStream> {
    stream: &'a mut S,
    /// Bytes from `serve_conn`'s parse buffer that belong to the
    /// body — already received from the wire by the time the
    /// handler runs.
    prebuf: &'a [u8],
    prebuf_consumed: usize,
    /// Scratch for stream-pumped bytes once `prebuf` is exhausted.
    /// 4 KiB matches a typical MSS-sized chunk; small bodies that
    /// fit in `prebuf` never touch this.
    refill: [u8; 4096],
    refill_start: usize,
    refill_end: usize,
    /// Total body length declared by the request's Content-Length.
    total: usize,
    /// Bytes already handed to the handler via `chunk`.
    delivered: usize,
}

impl<'a, S: HttpStream> BodyReader<'a, S> {
    /// Construct a reader against `stream`, with `prebuf` carrying
    /// any body bytes already received during the parse step.
    /// `total` is the declared body length; the reader delivers
    /// exactly that many bytes (possibly fewer on EOF) and refuses
    /// to read past it into the next pipelined request.
    pub fn new(stream: &'a mut S, prebuf: &'a [u8], total: usize) -> Self {
        // Trim `prebuf` to at most `total` so the reader never
        // reaches into post-body bytes (next pipelined request).
        let prebuf_avail = prebuf.len().min(total);
        BodyReader {
            stream,
            prebuf: &prebuf[..prebuf_avail],
            prebuf_consumed: 0,
            refill: [0; 4096],
            refill_start: 0,
            refill_end: 0,
            total,
            delivered: 0,
        }
    }

    /// Total body length (Content-Length).
    pub fn len(&self) -> usize {
        self.total
    }

    /// Bytes still to be delivered.
    pub fn remaining(&self) -> usize {
        self.total - self.delivered
    }

    /// True once the body is fully consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Get the next chunk of body bytes as a borrowed slice. An
    /// empty slice signals either "body fully delivered" (the
    /// expected end state — caller stops) or "transport EOF before
    /// Content-Length was reached" — distinguish via `remaining()`.
    pub async fn chunk(&mut self) -> &[u8] {
        if self.delivered >= self.total {
            return &[];
        }
        let want_max = self.total - self.delivered;

        // 1. Drain prebuf first — zero-copy, the bytes are already
        //    sitting in serve_conn's parse buffer.
        if self.prebuf_consumed < self.prebuf.len() {
            let start = self.prebuf_consumed;
            let avail = self.prebuf.len() - start;
            let take = avail.min(want_max);
            self.prebuf_consumed += take;
            self.delivered += take;
            return &self.prebuf[start..start + take];
        }

        // 2. Drain refill if any bytes are left over from a prior
        //    pump that returned more than the previous `chunk`
        //    request could deliver.
        if self.refill_start < self.refill_end {
            let start = self.refill_start;
            let avail = self.refill_end - start;
            let take = avail.min(want_max);
            self.refill_start += take;
            self.delivered += take;
            return &self.refill[start..start + take];
        }

        // 3. Refill from the transport. Cap at `want_max` so the
        //    `recv` doesn't read past Content-Length into the
        //    next pipelined request.
        let cap = want_max.min(self.refill.len());
        let got = self.stream.recv(&mut self.refill[..cap]).await;
        if got == 0 {
            // Transport closed before body fully arrived.
            return &[];
        }
        self.refill_start = got;
        self.refill_end = got;
        self.delivered += got;
        &self.refill[..got]
    }

    /// Drain the rest of the body, dropping every byte. Returns
    /// `Err` if the transport closed before delivering all
    /// `Content-Length` bytes — caller's contract is to tear the
    /// connection down in that case.
    pub async fn discard(&mut self) -> Result<(), ()> {
        while self.delivered < self.total {
            let chunk = self.chunk().await;
            if chunk.is_empty() {
                return Err(());
            }
        }
        Ok(())
    }
}

// ---- Response ---------------------------------------------------------------

/// One byte chunk — either borrowed against the program's
/// static data segment or heap-owned with optional headroom /
/// tailroom for layer-prepend. Re-export of [`IOBuf`] under the
/// historical `Bytes` name so existing call sites (and the
/// `impl Into<Bytes>` type bounds throughout this crate) keep
/// compiling. Future cleanup may rename callsites to `IOBuf`
/// directly; for now the alias keeps the diff small while the
/// underlying primitive switches to the chain-aware type.
pub type Bytes = IOBuf;

/// Maximum number of additional headers (beyond the framework's
/// always-emitted Content-Type / Content-Length / Connection) that
/// a Response can carry. 4 covers the common cases (Alt-Svc, Cache-
/// Control, ETag, Set-Cookie) without bloating the struct. Past
/// this the builder silently drops further `with_header` calls,
/// matching the Request-side header-cap behaviour.
pub const MAX_EXTRA_HEADERS: usize = 4;

pub struct Response {
    pub status: i32,
    /// Content-Type header value. `Bytes` (Cow<'static, [u8]>) so
    /// the common `Response::ok(b"text/plain", ...)` case stays
    /// borrowed-static (no alloc), while dynamically-built MIME
    /// strings can flow through Cow::Owned.
    content_type: Bytes,
    /// The response body, as a chain of IOBuf parts. Uniform
    /// shape — `Response::ok(ct, b"static")` builds a 1-part
    /// chain; multi-part templates push static + dynamic parts
    /// without ever materialising a single contiguous buffer.
    /// `IOBufChain` is the standard transport-side buffer type
    /// (`HttpStream::send`, `TcpStream::send`) so
    /// the body flows through to the wire with no enum dispatch
    /// or shape-flattening on the way down.
    body: IOBufChain,
    /// Optional extra response headers (Alt-Svc, Cache-Control,
    /// etc.) that the app sets via `with_header`. Inline storage
    /// — no Vec allocation per response. Both name and value are
    /// `Bytes` so static literals stay zero-alloc.
    extra_headers: [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
}

// Note: no `unsafe impl Send/Sync for Response` needed —
// `IOBuf` and `ResponseBody` are themselves Send + Sync (the
// static-borrow branch has 'static lifetime, the heap branch
// holds Box<[u8]>; no thread-local interior mutability).

impl Response {
    /// Build a 200 OK. `body` accepts anything convertible into
    /// an [`IOBufChain`]:
    ///
    ///   * `&'static [u8]` / `&'static str` — zero-alloc 1-part chain.
    ///   * `Vec<u8>` / `String` / `Box<[u8]>` — heap-rendered, moved.
    ///   * `IOBuf` — pre-built chunk.
    ///   * `IOBufChain` — multi-part body the app composed itself.
    ///
    /// `content_type` is `Bytes` — pass `b"text/plain"` for a
    /// static value or build dynamically as `Cow::Owned`.
    pub fn ok(content_type: impl Into<Bytes>, body: impl Into<IOBufChain>) -> Self {
        Response {
            status: 200,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Not Found").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    /// Build a `400 Bad Request`. Used by `serve_conn` to answer a
    /// request the HTTP/1.1 parser flagged as malformed — today a
    /// `Transfer-Encoding: chunked` request, which the parser
    /// rejects rather than mis-frame (item E in
    /// docs/rx-path-optimizations.md). `serve_conn` pairs this
    /// response with `Connection: close`.
    pub fn bad_request() -> Self {
        Response {
            status: 400,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Bad Request").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    /// Add an extra response header. Use for `Alt-Svc`,
    /// `Cache-Control`, `Set-Cookie`, etc. Both `name` and
    /// `value` are `Bytes` (Cow<'static, [u8]>) so static
    /// literals stay zero-alloc; dynamically-built values
    /// flow through `Cow::Owned`. Builder-style — chains.
    /// Silently drops past `MAX_EXTRA_HEADERS` (4 today).
    pub fn with_header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        for slot in self.extra_headers.iter_mut() {
            if slot.is_none() {
                *slot = Some((name.into(), value.into()));
                return self;
            }
        }
        self
    }

    /// Iterate the extra headers set via `with_header`. Used by
    /// the HTTP/1.1 response writer and the H3 frontend's QPACK
    /// encoder to emit them on the wire.
    pub fn extra_headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.extra_headers
            .iter()
            .filter_map(|slot| slot.as_ref().map(|(n, v)| (n.data(), v.data())))
    }

    /// Consume the response and yield its body chain. Frontends
    /// drain it via `pop_front`, `iter`, or by appending it to
    /// an outbound chain (`stream.send(&mut out_chain)`).
    pub fn into_body(self) -> IOBufChain {
        self.body
    }

    /// Borrow the body chain without consuming the response.
    /// Used by frontends that want to inspect length / parts
    /// before deciding whether to inline / stream / coalesce.
    pub fn body(&self) -> &IOBufChain {
        &self.body
    }

    /// Total body length in bytes. Used by frontends to write
    /// the Content-Length header (HTTP/1.1) or DATA-frame
    /// length prefix (HTTP/3) without walking the parts twice.
    pub fn body_len(&self) -> usize {
        self.body.total_len()
    }

    pub fn content_type_bytes(&self) -> &[u8] {
        self.content_type.data()
    }
}

/// Convenience: bytes_static(b"...") produces a borrowed-static
/// `IOBuf`. Equivalent to `IOBuf::from_static(s)`; kept for
/// symmetry with the historical `Bytes` API.
pub fn bytes_static(s: &'static [u8]) -> IOBuf {
    IOBuf::from_static(s)
}

/// Convenience: bytes_owned(v) wraps a Vec as `IOBuf`.
pub fn bytes_owned(v: alloc::vec::Vec<u8>) -> IOBuf {
    IOBuf::from(v)
}

// ---- Server -----------------------------------------------------------------

/// Per-connection parse buffer. Sized for the request HEAD only —
/// status line + headers, terminated by `\r\n\r\n`. Bodies are
/// delivered to the handler via [`BodyReader`] which streams from
/// the transport stream (with any body bytes that happened to land
/// in this buffer as a prefix). 16 KiB covers worst-case header
/// sets we expect from bench / browser clients plus headroom for
/// the leading bytes of a POST body.
const BUF_SIZE: usize = 16 * 1024;

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

// ---- HttpStream abstraction --------------------------------------------------
//
// `HttpStream` is the byte-level interface the conn handler uses
// to talk to a peer. Plain HTTP impls it directly over
// `TcpStream`; HTTPS impls it via `uni_tls::TlsStream`, which
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
/// frames before invoking the handler). [`BodyReader`] only ever
/// calls `recv` once its `prebuf` is exhausted — for an h3 body
/// constructed with `prebuf.len() == total`, that path never
/// fires. `NullStream` exists so the generic type parameter is
/// satisfied for those transports; calling its methods past the
/// trivial `recv` return-0 case panics.
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

impl HttpStream for uni::runtime::TcpStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        (*self).recv(buf).await
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


// ---- Public entry points -----------------------------------------------------

/// Listen for plain HTTP on `port`. The returned `TcpHandle`
/// owns the per-worker accept fan-out; drop it to stop accepting
/// new connections (in-flight conns drain at their idle
/// timeout).
///
/// `handler` is called for every parsed request; apps that want
/// path routing match `req.path()` inside it. Many ports can be
/// bound — call this multiple times — and each `TcpHandle` is
/// independent.
/// Listen for plain HTTP on `port`. `handler` is any async closure
/// or `async fn` taking `&Request` and producing `Response` — e.g.
/// `async fn handle(req: &Request) -> Response { ... }`. The
/// closure is shared across every accepted connection (wrapped in
/// `Arc` once internally) and the per-conn task awaits it inline,
/// so a slow handler suspends only its own connection.
pub fn listen<H>(port: u16, handler: H) -> Result<(), uni::runtime::TcpBindError>
where
    H: for<'a, 'b> AsyncFn(
            &'a Request,
            &'a mut BodyReader<'b, uni::runtime::TcpStream>,
        ) -> Response
        + Send
        + Sync
        + 'static,
{
    let listener = uni::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |stream| {
        let handler = Arc::clone(&handler);
        async move {
            serve_conn(handler, stream).await;
        }
    });
    uni::_retain(h);
    Ok(())
}

// ---- Unified per-connection handler ------------------------------------------

/// Per-conn keep-alive loop. Reads bytes from `stream` (plain or
/// TLS — same code path), parses pipelined requests, calls
/// `handler`, sends responses. Returns when the peer closes,
/// idle timeout fires, or the buffer overflows on a too-large
/// request.
///
/// Public so transport-specific listeners (HTTPS in `uni_tls`,
/// HTTP/3 in `uni_http3`) can drive their own `HttpStream` impls
/// through the same request/response machinery.
pub async fn serve_conn<S, H>(
    handler: Arc<H>,
    mut stream: S,
) where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    // Inline request-parse buffer in the future state. The
    // async runtime allocates the future once (as a
    // `Pin<Box<dyn Future>>` per accepted conn); folding `buf` in
    // turns the previous "future alloc + Box<[u8]> alloc" pair
    // into a single alloc per conn-accept. Sized to BODY_CAP +
    // header headroom so a full bulk-upload request fits in one
    // parse pass.
    let mut buf = [0u8; BUF_SIZE];
    let mut buf_len = 0usize;
    // Per-connection scratch reused across every request on this
    // conn — `Request` carries BODY_CAP of body buffer and 256 B
    // of path. Allocating + zero-initing it per request was costing
    // ~1 GB/s of memory bandwidth per core at peak request rate.
    // `parse_request` resets length fields up front, so a stale
    // tail is invisible to the read path; only the
    // writes-then-reads-back range is observed.
    let mut req = Request::new();
    // Outbound chain is amortised across every response on this
    // connection — `send` drains it via `pop_front`, leaving
    // the chain empty but with its `VecDeque` allocation
    // preserved. Capacity 4 covers the common shapes (header +
    // 1 body part, header + 2-3 chunked body parts) without
    // forcing the deque to grow.
    let mut out_chain = IOBufChain::with_capacity(4);
    // Inline storage for the response-header IOBuf, sized for the
    // typical header set plus the worst-case transport reserve.
    // Folded into the future state so each iteration wraps it as
    // an a `Borrowed` IOBuf rather than allocating a fresh
    // `Box<[u8]>` per response. 1 KiB covers HTTP/1.1 status line
    // + Content-Type + Content-Length + Connection + a handful
    // of `with_header`-set extras (Alt-Svc, Cache-Control,
    // Set-Cookie) with room to spare.
    const HEADER_BUF_SIZE: usize = 1024;
    let mut header_storage = [0u8; HEADER_BUF_SIZE];
    // Carries the parser's progress (`scan_pos`) across calls
    // when a request arrives in multiple recv'd segments — the
    // `find_header_end` scan resumes from the last position
    // instead of restarting at byte 0. Reset to default after
    // each successfully-consumed request so the next pipelined
    // request starts a fresh scan.
    let mut parser_state = ParserState::default();
    loop {
        if buf_len == BUF_SIZE {
            // Parse buffer full and no complete request in it —
            // client sent something larger than we handle.
            return;
        }
        let recv_fut = stream.recv(&mut buf[buf_len..]);
        let got = match uni::runtime::timeout_us(IDLE_TIMEOUT_US, recv_fut).await {
            Some(n) => n,
            None => return, // idle timeout
        };
        if got == 0 {
            return; // EOF / fatal recv
        }
        buf_len += got;

        // Drain every complete request sitting in the buffer.
        while buf_len > 0 {
            let body_start =
                parse_request_with_state(&buf[..buf_len], &mut req, &mut parser_state);
            if body_start == 0 {
                break; // need more bytes
            }
            let content_length = req.content_length;

            // A request the HTTP/1.1 parser flagged as malformed —
            // today only a `Transfer-Encoding: chunked` request,
            // which we don't frame yet (item E in
            // docs/rx-path-optimizations.md). Answer it with a
            // hard `400 Bad Request` and force the connection
            // closed. Falling through to the keep-alive path would
            // be a request-smuggling hole: the chunk-framed body
            // bytes still sit in `buf` and the next loop iteration
            // would misparse them as a second pipelined request.
            // So skip the handler and the `BodyReader` entirely
            // and drop into the shared send path below with
            // `want_close` forced on — that emits `Connection:
            // close` and `return`s without touching the
            // post-header bytes.
            let want_close;
            let resp;
            if req.reject {
                resp = Response::bad_request();
                want_close = true;
            } else {
                want_close = match req.header(b"Connection") {
                    Some(v) => v.eq_ignore_ascii_case(b"close"),
                    None => false,
                };

                // Construct the streaming body reader. `prebuf` is
                // the body bytes already sitting in `buf` after the
                // headers; the reader will draw stream bytes for
                // any tail that didn't fit. Restrict the prebuf to
                // body-only bytes (the slice may otherwise include
                // the start of the next pipelined request).
                let prebuf_end = (body_start + content_length).min(buf_len);
                let body_drained_ok;
                {
                    let prebuf = &buf[body_start..prebuf_end];
                    let mut body = BodyReader::new(&mut stream, prebuf, content_length);
                    resp = (&*handler)(&req, &mut body).await;
                    // Drain any leftover body bytes the handler
                    // didn't consume. Keep-alive contract requires
                    // the connection to be positioned at the start
                    // of the next request before we ship the
                    // response; skipping bytes mid-body would let
                    // them be mis-parsed as the next request's
                    // bytes. If the handler asked for
                    // `Connection: close` we tear down without
                    // draining (the conn is going away anyway).
                    body_drained_ok = want_close || body.is_empty()
                        || body.discard().await.is_ok();
                }
                if !body_drained_ok {
                    return;
                }
            }

            // Wrap the per-conn `header_storage` array as an
            // a `Borrowed` IOBuf so the framing layer can build
            // headers in stack-resident memory without a heap
            // allocation per response. SAFETY contract:
            //   * `header_storage` outlives every IOBuf wrapping
            //     it (it's a future-state field, the future is
            //     pinned, and we drop the IOBuf inside this
            //     iteration before constructing the next one).
            //   * No two IOBufs ever alias the same bytes — the
            //     IOBuf is `push_back`'d into `out_chain`,
            //     drained by `send` (which drops it after
            //     committing the bytes to the wire), and only
            //     then does the next iteration construct a fresh
            //     IOBuf wrapping the same storage.
            //   * No drop callback (`drop_fn = None`) — the
            //     storage is borrowed, not owned, so the IOBuf's
            //     drop should be a no-op for the array.
            let header = unsafe {
                IOBuf::borrow(
                    core::ptr::NonNull::new_unchecked(header_storage.as_mut_ptr()),
                    HEADER_BUF_SIZE as u32,
                    0,
                    0,
                )
            };
            // SAFETY: the only IOBuf currently aliasing
            // `header_storage` is `header` itself (we just
            // constructed it). `write_response_into_iobuf` writes
            // through `header` exclusively.
            let mut header = header;
            write_response_into_iobuf(&mut header, &resp, !want_close);

            // Stage the response into the per-conn outbound chain.
            // Order: header IOBuf first, then body parts. The
            // transport (TCP / TLS) drains the chain and decides
            // the wire chunking — TCP coalesces parts into
            // MSS-bounded segments so this header-plus-body shape
            // ships in one TCP segment for tiny replies; TLS
            // encrypts each part as its own record (in-place when
            // reserves match).
            //
            // `out_chain` is empty here (`send` drains it
            // each iteration). Move the body's parts in via
            // `into_parts()`, then `push_front` the header so the
            // wire order is [header, body0, body1, ...].
            debug_assert!(out_chain.is_empty());
            for part in resp.into_body().into_parts() {
                out_chain.push_back(part);
            }
            out_chain.push_front(header);

            if stream.send(&mut out_chain).await.is_err() {
                return;
            }

            if want_close {
                // Send TLS close_notify (no-op for plain TCP) before
                // the conn drops. Without this, TLS clients tear
                // down their session-resumption state on the
                // perceived unclean close — which is why every
                // post-resumption-PR fresh handshake from rustls or
                // openssl was unable to follow up with a resumed
                // one despite tickets flowing correctly on the wire.
                let _ = stream.close().await;
                return;
            }
            // Shift any post-body bytes (start of the next
            // pipelined request) to the front of `buf`. The body
            // may have extended past the parse buffer's end (in
            // which case `BodyReader` pulled the tail from the
            // transport directly); compute the end-of-body offset
            // capped at the current `buf_len`.
            let body_end_in_buf = (body_start + content_length).min(buf_len);
            let remaining = buf_len - body_end_in_buf;
            if remaining > 0 {
                buf.copy_within(body_end_in_buf..buf_len, 0);
            }
            buf_len = remaining;
            // The next pipelined request starts at byte 0 of the
            // shifted buffer, so the parser state has to forget
            // its "already scanned" cursor.
            parser_state = ParserState::default();
        }
    }
}

// ---- HTTP request parser ----------------------------------------------------

/// Parser state retained across `parse_request` calls on the same
/// pipelined request. Lets `find_header_end` skip bytes it's
/// already scanned — the previous implementation re-walked the
/// whole accumulated buffer on every recv, costing O(N²) on
/// requests that arrive in many small segments. With this state
/// the scan is amortised O(N) regardless of segment shape.
///
/// `serve_conn` keeps one of these per connection and resets it
/// to `Default::default()` after each successfully-consumed
/// request so the next pipelined request starts a fresh scan.
#[derive(Default)]
pub struct ParserState {
    /// Bytes 0..scan_pos already scanned without finding the
    /// `\r\n\r\n` terminator. New recv data extends past
    /// `scan_pos`; the scan resumes from `scan_pos.saturating_sub(3)`
    /// so a terminator straddling the recv boundary still matches.
    scan_pos: usize,
}

fn parse_request_with_state(data: &[u8], req: &mut Request, state: &mut ParserState) -> usize {
    req.clear();

    // Find end of headers ("\r\n\r\n"). Resume from the last
    // scanned position (minus 3 so a terminator straddling the
    // previous-call buffer boundary is caught).
    let resume = state.scan_pos.saturating_sub(3);
    let header_end = find_header_end_from(data, resume);
    if header_end.is_none() {
        // Mark how far we've scanned so the next call doesn't
        // redo this work.
        state.scan_pos = data.len();
        return 0;
    }
    let header_end_pos = header_end.unwrap();

    // Parse request line: "METHOD /path HTTP/1.x\r\n"
    let mut pos = 0;

    if data[pos..].starts_with(b"GET ") {
        req.method = Method::Get;
        pos += 4;
    } else if data[pos..].starts_with(b"POST ") {
        req.method = Method::Post;
        pos += 5;
    } else if data[pos..].starts_with(b"PUT ") {
        req.method = Method::Put;
        pos += 4;
    } else if data[pos..].starts_with(b"DELETE ") {
        req.method = Method::Delete;
        pos += 7;
    } else if data[pos..].starts_with(b"HEAD ") {
        req.method = Method::Head;
        pos += 5;
    } else {
        req.method = Method::Unknown;
    }

    // Extract path
    let mut path_len = 0;
    while pos < data.len()
        && data[pos] != b' '
        && data[pos] != b'\r'
        && data[pos] != b'\n'
        && path_len < 255
    {
        req.path[path_len] = data[pos];
        path_len += 1;
        pos += 1;
    }
    req.path_len = path_len;

    // Skip to end of request line
    while pos < data.len() && data[pos] != b'\n' {
        pos += 1;
    }
    if pos < data.len() {
        pos += 1; // skip \n
    }

    // Parse headers
    while pos < header_end_pos {
        if data[pos] == b'\r' || data[pos] == b'\n' {
            break;
        }

        if req.header_count < 16 {
            let h = &mut req.headers[req.header_count];

            // Header name (up to ':')
            let mut ni = 0;
            while pos < data.len() && data[pos] != b':' && data[pos] != b'\r' && ni < 63 {
                h.name[ni] = data[pos];
                ni += 1;
                pos += 1;
            }
            h.name_len = ni;

            // Skip ':' and spaces
            while pos < data.len() && (data[pos] == b':' || data[pos] == b' ') {
                pos += 1;
            }

            // Header value
            let mut vi = 0;
            while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' && vi < 255 {
                h.value[vi] = data[pos];
                vi += 1;
                pos += 1;
            }
            h.value_len = vi;

            req.header_count += 1;
        }

        // Skip to next line
        while pos < data.len() && data[pos] != b'\n' {
            pos += 1;
        }
        if pos < data.len() {
            pos += 1;
        }
    }

    let body_start = header_end_pos + 4; // skip \r\n\r\n

    // Extract Content-Length into the Request so the handler's
    // `BodyReader` knows how many body bytes to deliver. The body
    // bytes themselves stay in the caller's parse buffer (and the
    // transport stream); `serve_conn` constructs the reader against
    // them after this function returns. Bodies that span more than
    // one recv are handled by the streaming reader, NOT by waiting
    // here for all bytes to arrive.
    req.content_length = match req.header(b"Content-Length") {
        Some(cl_val) => parse_usize(cl_val),
        None => 0,
    };

    // Reject `Transfer-Encoding: chunked`. Chunked framing is not
    // implemented yet (deferred to the Phase 4 parser refresh);
    // ignoring the header — which is what the parser did before
    // item E — silently treats the chunk-framed body as a
    // length-0 body, leaving the chunk bytes in the caller's
    // buffer to be misparsed as the next pipelined request: an
    // HTTP request-smuggling vector. Flag it so `serve_conn`
    // answers `400 Bad Request` + `Connection: close` and reads
    // no body. `req.header` already matches the header *name*
    // case-insensitively; `transfer_encoding_is_chunked` matches
    // `chunked` case-insensitively anywhere in the comma-separated
    // transfer-coding list (e.g. `gzip, chunked`).
    req.reject = match req.header(b"Transfer-Encoding") {
        Some(te) => transfer_encoding_is_chunked(te),
        None => false,
    };

    body_start
}

// ---- Response sender --------------------------------------------------------

/// Serialise an HTTP/1.1 response head (status line + headers,
/// terminated by `\r\n\r\n`) into a heap-backed `IOBuf` whose
/// reserves were sized for the transport stack. The body is NOT
/// appended here — the caller `push_front`s this IOBuf onto the
/// response body chain and lets the transport stitch the parts.
///
/// Hot path — called once per HTTP request. `core::fmt`'s
/// machinery (format-string walker, Display vtable dispatch,
/// padding logic) adds up at hundreds of thousands of req/s; the
/// manual byte-level `append_slice` calls here plus a small itoa
/// for the only variable integer (`Content-Length`) measurably
/// outperform `write!(...)`.
///
/// Extra headers (`Alt-Svc`, `Cache-Control`, `Set-Cookie`, etc.)
/// are pulled from `resp.extra_headers()` — apps add them via
/// `Response::with_header`. The framework no longer hardcodes any
/// optional header itself; per-response branches live in app code.
fn write_response_into_iobuf(buf: &mut IOBuf, resp: &Response, keep_alive: bool) {
    // `append_slice` returns `Err(NoTailroom)` if we exceed the
    // IOBuf's reserved capacity. The caller picks `HEADER_BUF_SIZE`
    // bytes well above the realistic header total (~ a few hundred
    // bytes), so an `Err` here means the producer truncated the
    // response head. `debug_assert` panics in tests; release builds
    // silently truncate.
    macro_rules! push {
        ($data:expr) => {{
            let r = buf.append_slice($data);
            debug_assert!(r.is_ok(), "response header overflow (raise HEADER_CAP)");
            let _ = r;
        }};
    }

    push!(b"HTTP/1.1 ");
    let mut status_buf = [0u8; 4];
    let status_len = write_status_code(&mut status_buf, resp.status);
    push!(&status_buf[..status_len]);
    push!(b" ");
    push!(status_text(resp.status).as_bytes());
    push!(b"\r\nContent-Type: ");
    push!(resp.content_type_bytes());
    push!(b"\r\nContent-Length: ");
    let mut len_buf = [0u8; 20];
    let len_len = write_usize(&mut len_buf, resp.body_len());
    push!(&len_buf[..len_len]);
    push!(b"\r\nConnection: ");
    push!(if keep_alive { b"keep-alive" } else { b"close" });
    push!(b"\r\n");
    for (name, value) in resp.extra_headers() {
        push!(name);
        push!(b": ");
        push!(value);
        push!(b"\r\n");
    }
    push!(b"\r\n");
}

/// Extract the port from an HTTP `Host` header value. Handles:
///   `localhost:8443`           → 8443
///   `localhost`                → None (caller defaults)
///   `[::1]:8443`               → 8443 (v6-literal form, RFC 7230 §5.4)
///   `[::1]`                    → None
/// Anything malformed or out-of-range returns `None`.
fn host_header_port(host: &[u8]) -> Option<u16> {
    let after_host = if host.first() == Some(&b'[') {
        // IPv6 literal: scan past the closing `]` before looking
        // for the `:` separator, otherwise the address's own colons
        // would match first.
        let close = host.iter().position(|&b| b == b']')?;
        &host[close + 1..]
    } else {
        host
    };
    let colon = after_host.iter().position(|&b| b == b':')?;
    let digits = &after_host[colon + 1..];
    if digits.is_empty() { return None; }
    let mut acc: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() { return None; }
        acc = acc * 10 + (b - b'0') as u32;
        if acc > 65535 { return None; }
    }
    Some(acc as u16)
}

#[cfg(test)]
mod host_port_tests {
    use super::host_header_port;
    #[test] fn plain_host_with_port() {
        assert_eq!(host_header_port(b"localhost:8443"), Some(8443));
    }
    #[test] fn plain_host_no_port() {
        assert_eq!(host_header_port(b"localhost"), None);
    }
    #[test] fn ipv6_with_port() {
        assert_eq!(host_header_port(b"[::1]:8443"), Some(8443));
        assert_eq!(host_header_port(b"[fe80::1%eth0]:443"), Some(443));
    }
    #[test] fn ipv6_no_port() {
        assert_eq!(host_header_port(b"[::1]"), None);
    }
    #[test] fn malformed() {
        assert_eq!(host_header_port(b"localhost:"), None);
        assert_eq!(host_header_port(b"localhost:abc"), None);
        assert_eq!(host_header_port(b"localhost:65536"), None);
    }
}

/// Item E — the request parser must flag a `Transfer-Encoding:
/// chunked` request for a `400` rejection rather than silently
/// mis-frame its body (an HTTP request-smuggling vector). These
/// tests pin both the value-matching helper and the parser flag.
#[cfg(test)]
mod chunked_reject_tests {
    use super::{parse_request_with_state, transfer_encoding_is_chunked, ParserState, Request};

    /// Parse one request out of `raw` and report `(body_start,
    /// reject)` — `body_start` is the parser's return value (0
    /// means "headers incomplete, need more bytes"), `reject` is
    /// the flag `serve_conn` turns into a 400.
    fn parse(raw: &[u8]) -> (usize, bool) {
        let mut req = Request::new();
        let mut state = ParserState::default();
        let body_start = parse_request_with_state(raw, &mut req, &mut state);
        (body_start, req.reject)
    }

    #[test]
    fn helper_matches_chunked_case_insensitively() {
        assert!(transfer_encoding_is_chunked(b"chunked"));
        assert!(transfer_encoding_is_chunked(b"Chunked"));
        assert!(transfer_encoding_is_chunked(b"CHUNKED"));
    }

    #[test]
    fn helper_matches_chunked_anywhere_in_the_coding_list() {
        assert!(transfer_encoding_is_chunked(b"gzip, chunked"));
        assert!(transfer_encoding_is_chunked(b"chunked, gzip"));
        assert!(transfer_encoding_is_chunked(b"gzip , chunked , deflate"));
    }

    #[test]
    fn helper_ignores_non_chunked_codings() {
        assert!(!transfer_encoding_is_chunked(b""));
        assert!(!transfer_encoding_is_chunked(b"gzip"));
        assert!(!transfer_encoding_is_chunked(b"identity"));
    }

    #[test]
    fn chunked_request_is_flagged_for_rejection() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (body_start, reject) = parse(raw);
        assert!(reject, "a chunked-TE request must be flagged for a 400");
        assert!(body_start > 0, "headers are complete, body_start must be set");
    }

    #[test]
    fn transfer_encoding_header_name_match_is_case_insensitive() {
        let raw = b"POST / HTTP/1.1\r\ntRaNsFeR-eNcOdInG: chunked\r\n\r\n";
        let (_, reject) = parse(raw);
        assert!(reject);
    }

    #[test]
    fn chunked_in_a_coding_list_is_flagged() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let (_, reject) = parse(raw);
        assert!(reject);
    }

    #[test]
    fn plain_content_length_request_is_not_flagged() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let (body_start, reject) = parse(raw);
        assert!(!reject, "a normal Content-Length request must not be flagged");
        assert!(body_start > 0);
    }

    #[test]
    fn incomplete_headers_are_not_flagged() {
        // No CRLF-CRLF terminator yet: the parser returns 0
        // ("need more bytes") before it inspects any header.
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n";
        let (body_start, reject) = parse(raw);
        assert_eq!(body_start, 0, "incomplete headers => need more bytes");
        assert!(!reject);
    }
}

/// Write the decimal digits of a 3-digit HTTP status code into `out`,
/// returning the number of bytes written. Limited to 100..=999, which
/// is the entire HTTP status range; anything outside falls back to a
/// `0` so the response stays well-formed.
fn write_status_code(out: &mut [u8; 4], status: i32) -> usize {
    if !(100..=999).contains(&status) {
        out[0] = b'0';
        return 1;
    }
    let s = status as usize;
    out[0] = b'0' + (s / 100) as u8;
    out[1] = b'0' + ((s / 10) % 10) as u8;
    out[2] = b'0' + (s % 10) as u8;
    3
}

/// Minimal usize → ASCII decimal. Writes into `out` from the right,
/// returns the number of bytes written. Avoids `core::fmt::Display`'s
/// padding/precision machinery, which dominates the per-request
/// formatting cost on the static-body path.
fn write_usize(out: &mut [u8; 20], mut n: usize) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = tmp.len() - i;
    out[..len].copy_from_slice(&tmp[i..]);
    len
}

// ---- Helper functions -------------------------------------------------------

/// Locate `\r\n\r\n` (the headers/body terminator) starting from
/// byte `start`. The caller has already scanned `data[..start]`
/// without finding it; this restarts there to avoid the O(N²)
/// re-scan when a request arrives in many small recv segments.
/// Returns the absolute index of the terminator within `data`.
fn find_header_end_from(data: &[u8], start: usize) -> Option<usize> {
    let suffix = data.get(start..)?;
    suffix.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + start)
}


fn parse_usize(data: &[u8]) -> usize {
    let mut n: usize = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            n = n * 10 + (b - b'0') as usize;
        } else {
            break;
        }
    }
    n
}

/// True if a `Transfer-Encoding` header value names `chunked` as
/// one of its transfer codings. The value is a comma-separated
/// list (RFC 7230 §3.3.1); each entry is compared case-
/// insensitively with its surrounding optional whitespace
/// trimmed, so `chunked`, `Chunked`, and `gzip, chunked` all
/// return `true` while `gzip` or `identity` return `false`. The
/// caller has already matched the header *name* case-
/// insensitively via `Request::header`.
fn transfer_encoding_is_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}


fn status_text(status: i32) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
