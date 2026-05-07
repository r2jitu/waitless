// HTTP/1.1 server. Cooperative non-blocking: the kernel event loop
// accepts, reads, parses, dispatches, and writes back.
//
// Per-core listener + connection set; routes are shared read-only.
// HTTPS injection happens via the `Tls` trait object below so this
// crate has no compile-time dep on TLS or crypto code — apps that
// don't import a TLS provider link zero TLS bytes.

#![no_std]

extern crate alloc;
extern crate uni;

mod iobuf;
pub use iobuf::{
    Cursor as IOBufCursor, IOBuf, IOBufChain, IOBufError, MAX_HEADER_RESERVE,
    MAX_TRAILER_RESERVE,
};

use alloc::boxed::Box;
use alloc::sync::Arc;


// TLS injection boundary. `uni-tls` is the (currently sole) impl,
// adapting its TLS 1.3 state machine onto these methods.

/// TLS provider for `listen_https`. Implementations own per-
/// connection-config state (cert + key + per-handshake scratch);
/// `new_connection` is called once per accepted HTTPS connection
/// to mint a fresh handshake state machine.
pub trait Tls: Send + Sync + 'static {
    /// `seed` is 32 bytes of platform entropy the caller has
    /// already pulled from the RNG.
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn TlsConn>;
}

/// Per-connection TLS state. `push_rx` / `pop_tx` move ciphertext
/// bytes; `pop_plaintext` / `send_app_data` move plaintext bytes;
/// `advance` runs the state machine after `push_rx`.
pub trait TlsConn: Send + 'static {
    fn push_rx(&mut self, bytes: &[u8]);
    /// `Err(())` is fatal — caller drops the connection.
    fn advance(&mut self) -> Result<(), ()>;
    fn pop_tx(&mut self, out: &mut [u8]) -> usize;
    fn pop_plaintext(&mut self, out: &mut [u8]) -> usize;
    fn send_app_data(&mut self, data: &[u8]) -> Result<(), ()>;
    fn close_notify(&mut self) -> Result<(), ()>;
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
    body: [u8; 8192],
    body_len: usize,
}

impl Request {
    pub fn new() -> Self {
        Request {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            body: [0; 8192],
            body_len: 0,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    pub fn body(&self) -> &[u8] {
        &self.body[..self.body_len]
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

    /// Overwrite the request body. Truncates if longer than the
    /// fixed `body` buffer. Used by the HTTP/3 frontend after it
    /// reassembles DATA frames.
    pub fn set_body(&mut self, body: &[u8]) {
        let n = body.len().min(self.body.len());
        self.body[..n].copy_from_slice(&body[..n]);
        self.body_len = n;
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
        self.body_len = 0;
    }
}

// ---- Response ---------------------------------------------------------------

/// One byte chunk — either borrowed against the program's
/// static data segment or heap-owned. The whole HTTP/QUIC stack
/// uses this type as its byte-buffer primitive: `Response`
/// bodies, `Body` builder parts, QUIC SendStream chunks, etc.
/// Cow<'static, [u8]> already gives us:
///   - Send + Sync (Borrowed has 'static lifetime, Owned is Vec)
///   - Deref to &[u8] for transparent slice access
///   - Cheap pattern-matching on Borrowed vs Owned
/// so we use it directly with a type alias for readability
/// rather than wrapping in another enum. A future Shared(Arc<[u8]>)
/// variant — useful for cached responses — would mean swapping
/// the alias for our own enum, but isn't worth the complexity now.
pub type Bytes = alloc::borrow::Cow<'static, [u8]>;

/// Body storage for a `Response`. Either a single `Bytes`
/// chunk (the common case — zero-alloc when constructed from
/// `&'static [u8]`, one-alloc when from `Vec<u8>`) or a
/// `Chain` for multi-part composition built via [`Body`].
pub enum ResponseBody {
    Single(Bytes),
    /// A chain of byte chunks assembled at handler time. Each
    /// chunk is queued as its own SendChunk on the QUIC stream,
    /// so a static template prefix gets a borrowed-static chunk
    /// (zero alloc) sitting alongside the dynamic middle's
    /// owned chunk — no `Vec::extend_from_slice`-style merge.
    /// VecDeque so frontends (or the next layer down) can
    /// O(1)-prepend if they want to wrap framing around a
    /// pre-sized body.
    Chain {
        parts: alloc::collections::VecDeque<Bytes>,
        total_len: usize,
    },
}

/// Builder for a multi-part response body. Apps that want to
/// wrap a dynamic middle in a static template can do so
/// without memcpying everything into one buffer:
///
/// ```ignore
/// let body = Body::new()
///     .push_static(STATIC_HTML_PREFIX)
///     .push_owned(rendered_middle.into_bytes())
///     .push_static(STATIC_HTML_SUFFIX);
/// Response::ok(b"text/html; charset=utf-8", body)
/// ```
///
/// Backing storage is `VecDeque<Bytes>` so both `push` (back)
/// and `prepend` (front) are O(1) — the latter is useful when
/// a frontend wants to add a header after the body is sized.
/// Each part reaches the wire with at most one memcpy per
/// packet (into the AEAD-target datagram region).
pub struct Body {
    pub parts: alloc::collections::VecDeque<Bytes>,
    pub total_len: usize,
}

impl Body {
    pub fn new() -> Self {
        Body { parts: alloc::collections::VecDeque::new(), total_len: 0 }
    }

    pub fn with_capacity(n: usize) -> Self {
        Body {
            parts: alloc::collections::VecDeque::with_capacity(n),
            total_len: 0,
        }
    }

    /// Append any byte chunk (Borrowed-static or Owned). The
    /// generic bound lets callers pass `&'static [u8]`,
    /// `&'static str`, `Vec<u8>`, `String`, or any pre-built
    /// `Bytes` directly.
    pub fn push(mut self, chunk: impl Into<Bytes>) -> Self {
        let b: Bytes = chunk.into();
        if !b.is_empty() {
            self.total_len += b.len();
            self.parts.push_back(b);
        }
        self
    }

    /// Prepend a chunk to the front of the chain — O(1) thanks
    /// to VecDeque's ring-buffer layout. Useful for frontends
    /// that build a body from the inside out and add the
    /// outermost framing last (e.g. HTTP/1.1 chunked-transfer
    /// length prefixes, TLS record headers added after the
    /// payload is sealed).
    pub fn prepend(mut self, chunk: impl Into<Bytes>) -> Self {
        let b: Bytes = chunk.into();
        if !b.is_empty() {
            self.total_len += b.len();
            self.parts.push_front(b);
        }
        self
    }

    /// Convenience: borrowed-static append.
    pub fn push_static(self, s: &'static [u8]) -> Self {
        self.push(s)
    }

    /// Convenience: owned-Vec append (move).
    pub fn push_owned(self, v: alloc::vec::Vec<u8>) -> Self {
        self.push(v)
    }

    /// Convenience: String append (re-uses the underlying Vec
    /// via String::into_bytes — no copy).
    pub fn push_string(self, s: alloc::string::String) -> Self {
        self.push(s.into_bytes())
    }

    pub fn len(&self) -> usize { self.total_len }
    pub fn is_empty(&self) -> bool { self.total_len == 0 }
}

impl Default for Body {
    fn default() -> Self { Body::new() }
}

impl From<&'static [u8]> for Body { fn from(s: &'static [u8]) -> Self { Body::new().push(s) } }
impl From<&'static str>  for Body { fn from(s: &'static str)  -> Self { Body::new().push(s.as_bytes()) } }
impl From<alloc::vec::Vec<u8>>    for Body { fn from(v: alloc::vec::Vec<u8>)    -> Self { Body::new().push(v) } }
impl From<alloc::string::String>  for Body { fn from(s: alloc::string::String)  -> Self { Body::new().push(s.into_bytes()) } }
impl From<Bytes> for Body { fn from(b: Bytes) -> Self { Body::new().push(b) } }

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
    body: ResponseBody,
    /// Optional extra response headers (Alt-Svc, Cache-Control,
    /// etc.) that the app sets via `with_header`. Inline storage
    /// — no Vec allocation per response. Both name and value are
    /// `Bytes` so static literals stay zero-alloc.
    extra_headers: [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
}

// Note: no `unsafe impl Send/Sync for Response` needed — Bytes
// (Cow<'static, [u8]>) and ResponseBody are themselves
// Send + Sync because the borrowed branch has 'static lifetime
// and the owned branch holds Vec<u8>.

/// Anything a handler can return as a `Response` body.
/// Implemented for `&'static [u8]` / `&'static str` (zero-alloc
/// static resources), `Box<[u8]>` / `Vec<u8>` / `String`
/// (heap-rendered), [`Bytes`] (pre-built chunk), and [`Body`]
/// (multi-part composition). Apps call `Response::ok(ct, body)`
/// without picking a method based on the body type.
pub trait IntoBody {
    fn into_body(self) -> ResponseBody;
}

impl IntoBody for &'static [u8] {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(alloc::borrow::Cow::Borrowed(self))
    }
}

impl<const N: usize> IntoBody for &'static [u8; N] {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(alloc::borrow::Cow::Borrowed(self))
    }
}

impl IntoBody for &'static str {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(alloc::borrow::Cow::Borrowed(self.as_bytes()))
    }
}

impl IntoBody for alloc::boxed::Box<[u8]> {
    fn into_body(self) -> ResponseBody {
        // Box<[u8]> -> Vec<u8> reinterprets the heap allocation
        // (same memory, no copy).
        ResponseBody::Single(alloc::borrow::Cow::Owned(self.into_vec()))
    }
}

impl IntoBody for alloc::vec::Vec<u8> {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(alloc::borrow::Cow::Owned(self))
    }
}

impl IntoBody for alloc::string::String {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(alloc::borrow::Cow::Owned(self.into_bytes()))
    }
}

impl IntoBody for Bytes {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Single(self)
    }
}

impl IntoBody for Body {
    fn into_body(self) -> ResponseBody {
        // Collapse trivial cases so single-part Body builders
        // don't pay the Chain enum's Vec overhead — a builder
        // that pushed exactly one chunk flattens to
        // ResponseBody::Single (zero alloc).
        match self.parts.len() {
            0 => ResponseBody::Single(alloc::borrow::Cow::Borrowed(b"")),
            1 => {
                let mut parts = self.parts;
                ResponseBody::Single(parts.pop_front().unwrap())
            }
            _ => ResponseBody::Chain {
                parts: self.parts,
                total_len: self.total_len,
            },
        }
    }
}

// (single canonical IntoBody for Body lives below alongside
// the other IntoBody impls)

impl Response {
    /// Build a 200 OK. `body` accepts any [`IntoBody`] —
    /// `&'static [u8]` (zero alloc), `Vec<u8>` / `String` /
    /// `Box<[u8]>` (heap-rendered), [`Bytes`] (pre-built chunk),
    /// or [`Body`] (multi-part composition).
    /// `content_type` is also Bytes — pass `b"text/plain"` for
    /// a static value or build dynamically as Cow::Owned.
    pub fn ok(content_type: impl Into<Bytes>, body: impl IntoBody) -> Self {
        Response {
            status: 200,
            content_type: content_type.into(),
            body: body.into_body(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
        }
    }

    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: alloc::borrow::Cow::Borrowed(b"text/plain"),
            body: ResponseBody::Single(alloc::borrow::Cow::Borrowed(b"Not Found")),
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
            .filter_map(|slot| slot.as_ref().map(|(n, v)| (&**n, &**v)))
    }

    /// Consume the response and yield its body. Frontends match
    /// on `ResponseBody::Single` (one Bytes chunk) or
    /// `ResponseBody::Chain` (a `Vec<Bytes>`). Each Bytes
    /// derefs to `&[u8]`, and patterns can match on
    /// `Cow::Borrowed(s)` vs `Cow::Owned(v)` if the frontend
    /// wants to take a static-borrow path vs. a move.
    pub fn into_body(self) -> ResponseBody {
        self.body
    }

    /// Total body length in bytes. Used by frontends to write
    /// the Content-Length header (HTTP/1.1) or DATA-frame
    /// length prefix (HTTP/3) without walking the parts twice.
    pub fn body_len(&self) -> usize {
        match &self.body {
            ResponseBody::Single(b) => b.len(),
            ResponseBody::Chain { total_len, .. } => *total_len,
        }
    }

    /// Borrow the body as a contiguous slice if it's a single
    /// chunk. Returns `&[]` for Chain bodies — frontends that
    /// need to walk multi-part bodies use `into_body()` and
    /// pattern-match.
    pub fn body_bytes(&self) -> &[u8] {
        match &self.body {
            ResponseBody::Single(b) => b,
            ResponseBody::Chain { .. } => &[],
        }
    }

    pub fn content_type_bytes(&self) -> &[u8] {
        &self.content_type
    }
}

/// Convenience: bytes_static(b"...") produces a borrowed-static
/// `Bytes`, the no_std equivalent of `Bytes::from_static` in
/// the `bytes` crate. Useful when a callsite has many static
/// chunks to pass.
pub fn bytes_static(s: &'static [u8]) -> Bytes {
    alloc::borrow::Cow::Borrowed(s)
}

/// Convenience: bytes_owned(v) wraps a Vec as `Bytes`.
pub fn bytes_owned(v: alloc::vec::Vec<u8>) -> Bytes {
    alloc::borrow::Cow::Owned(v)
}

// ---- Server -----------------------------------------------------------------

const BUF_SIZE: usize = 8192;

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

// ---- HttpStream abstraction --------------------------------------------------
//
// `HttpStream` is the byte-level interface the conn handler uses
// to talk to a peer. Plain HTTP impls it directly over
// `TcpStream`; HTTPS impls it via `TlsStream`, which owns a
// `TlsConn` and pumps the TLS state machine inside `recv` / `send`
// so the handler stays protocol-agnostic.
//
// Static dispatch: `handle_conn<S: HttpStream>` is monomorphised
// per impl, so trait method calls inline. Plain path is identical
// to the pre-trait code; TLS path performs the same TLS pump
// work, just relocated inside `TlsStream`.

/// `async_fn_in_trait` lints because the lint can't see that
/// our connection futures are `!Send` by design — `TcpStream` is
/// per-worker. Allow at the trait level: callers always use this
/// trait through static dispatch (see `handle_conn<S: HttpStream>`),
/// and the per-conn task spawns onto the same worker that
/// accepted the connection, so cross-worker Send is never needed.
#[allow(async_fn_in_trait)]
pub trait HttpStream {
    /// Read up to `buf.len()` bytes from the peer (after
    /// decryption, for `TlsStream`). Returns `0` on EOF / fatal
    /// transport error. Implementors decide whether to wake on
    /// partial reads or drain a full segment first.
    async fn recv(&mut self, buf: &mut [u8]) -> usize;

    /// Send all of `data` to the peer (encrypted, for `TlsStream`).
    /// `Err(())` on fatal transport error; the conn handler tears
    /// down on error.
    async fn send(&mut self, data: &[u8]) -> Result<(), ()>;

    /// Cleanly signal end-of-stream to the peer before the
    /// underlying transport closes. Plain TCP is already correct
    /// with the implicit FIN-on-drop, so the default is a no-op.
    /// `TlsStream` overrides to emit a `close_notify` alert: rustls
    /// (and most spec-compliant TLS clients) treat a TCP close
    /// without close_notify as an unclean shutdown and discard any
    /// session ticket they were about to cache, blocking resumption.
    async fn close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl HttpStream for uni::runtime::TcpStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        (*self).recv(buf).await
    }
    async fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        (*self).send(data).await
    }
}

/// HTTPS-side `HttpStream`: owns the `TcpStream` + `TlsConn` and
/// drives the TLS state machine. `recv` blocks until decrypted
/// plaintext is available (pumping handshake records as needed);
/// `send` encrypts via `send_app_data` and flushes ciphertext to
/// TCP.
pub struct TlsStream {
    tcp: uni::runtime::TcpStream,
    tls: Box<dyn TlsConn>,
    /// Heap-allocated ciphertext scratch reused across recvs.
    cipher_buf: Box<[u8]>,
    /// Stack-friendly scratch for draining `pop_tx` output.
    tx_scratch: [u8; 2048],
}

impl TlsStream {
    pub fn new(tcp: uni::runtime::TcpStream, tls: Box<dyn TlsConn>) -> Self {
        TlsStream {
            tcp,
            tls,
            cipher_buf: alloc::vec![0u8; BUF_SIZE].into_boxed_slice(),
            tx_scratch: [0u8; 2048],
        }
    }

    /// Drain any pending TLS TX (handshake flight, alerts, queued
    /// app-data) to the underlying TCP stream. `Err(())` is fatal.
    async fn drain_tx(&mut self) -> Result<(), ()> {
        loop {
            let n = self.tls.pop_tx(&mut self.tx_scratch);
            if n == 0 {
                return Ok(());
            }
            self.tcp.send(&self.tx_scratch[..n]).await?;
        }
    }
}

impl HttpStream for TlsStream {
    async fn recv(&mut self, buf: &mut [u8]) -> usize {
        loop {
            // Try to satisfy from already-decrypted plaintext.
            let n = self.tls.pop_plaintext(buf);
            if n > 0 {
                return n;
            }
            // Pump TLS: drain pending tx, recv ciphertext, advance,
            // drain again, then loop to pop_plaintext.
            if self.drain_tx().await.is_err() {
                return 0;
            }
            let cipher_len = self.cipher_buf.len();
            let got = self.tcp.recv(&mut self.cipher_buf[..cipher_len]).await;
            if got == 0 {
                return 0;
            }
            self.tls.push_rx(&self.cipher_buf[..got]);
            if self.tls.advance().is_err() {
                return 0;
            }
            if self.drain_tx().await.is_err() {
                return 0;
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        // The TLS server's TX buffer is finite (~4 KiB today), and
        // `send_app_data` seals into it without any awareness of the
        // ciphertext drain. If we hand it a body larger than that
        // buffer it fails outright with `TxBufTooSmall`. Chunk
        // plaintext into pieces small enough that headers + ciphertext
        // overhead per record (≤ ~80 B) still fit, draining between
        // chunks so steady streaming of multi-KiB bodies (e.g. our
        // multi-page HTML) just works.
        const PLAINTEXT_CHUNK: usize = 3 * 1024;
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + PLAINTEXT_CHUNK).min(data.len());
            self.tls.send_app_data(&data[offset..end])?;
            self.drain_tx().await?;
            offset = end;
        }
        // Empty body still gets a no-op drain so any pre-queued TLS
        // bytes (e.g. a NewSessionTicket sealed during handshake but
        // not yet drained) reach the wire promptly.
        if data.is_empty() {
            self.drain_tx().await?;
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ()> {
        // Best-effort: the alert is only meaningful when the TLS
        // state machine is in `Established`. `close_notify` itself
        // handles other states by no-op'ing and moving to Closed,
        // so we just drain whatever it produced (if anything).
        let _ = self.tls.close_notify();
        self.drain_tx().await
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
    H: AsyncFn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = uni::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |stream| {
        let handler = Arc::clone(&handler);
        async move {
            handle_conn(handler, stream).await;
        }
    });
    uni::_retain(h);
    Ok(())
}

/// Listen for HTTPS (TLS 1.3) on `port`. `tls` is a TLS provider
/// — typically `uni_tls::acceptor(cert, key)?`. The provider is
/// shared across every accepted connection on this port; for
/// multi-port HTTPS reusing the same cert, pass `tls.clone()`
/// (`Arc::clone` is cheap).
///
/// To advertise an HTTP/3 endpoint via `Alt-Svc` on responses,
/// the app's handler should emit it itself per-response — read
/// `req.host_port()` and add a `with_header(b"Alt-Svc", ...)`
/// to the `Response`. The framework no longer hardcodes this
/// (the previous `listen_https_advertising_h3` plumbing); apps
/// that don't use HTTP/3 don't pay the per-response Host-header
/// re-parse, and apps that do retain full control over the
/// advertised port and TTL.
pub fn listen_https<H>(
    port: u16,
    handler: H,
    tls: Arc<dyn Tls>,
) -> Result<(), uni::runtime::TcpBindError>
where
    H: AsyncFn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = uni::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |tcp| {
        let handler = Arc::clone(&handler);
        let tls = Arc::clone(&tls);
        async move {
            let mut seed = [0u8; 32];
            uni::rng::fill_bytes(&mut seed);
            let stream = TlsStream::new(tcp, tls.new_connection(seed));
            handle_conn(handler, stream).await;
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
async fn handle_conn<S, H>(
    handler: Arc<H>,
    mut stream: S,
) where
    S: HttpStream,
    H: AsyncFn(&Request) -> Response,
{
    let mut buf: Box<[u8]> = alloc::vec![0u8; BUF_SIZE].into_boxed_slice();
    let mut buf_len = 0usize;
    // Per-connection scratch reused across every request on this
    // conn — `Request` carries 8 KiB of body buffer and 256 B of
    // path, `BufWriter` another 2 KiB. Allocating + zero-initing
    // them per request was costing ~1 GB/s of memory bandwidth per
    // core at peak request rate. `parse_request` and
    // `write_response_into` both reset their target's length
    // fields up front, so a stale tail in the array is invisible
    // to the read path; only the writes-then-reads-back range is
    // observed.
    let mut req = Request::new();
    let mut w = BufWriter::new();
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
            let consumed = parse_request(&buf[..buf_len], &mut req);
            if consumed == 0 {
                break; // need more bytes
            }
            let want_close = match req.header(b"Connection") {
                Some(v) => v.eq_ignore_ascii_case(b"close"),
                None => false,
            };
            let resp = (&*handler)(&req).await;

            w.clear();
            // Extra response headers (Alt-Svc / Cache-Control / etc.)
            // are now app-side: the handler can call
            // `Response::with_header(...)` and `write_response_into`
            // emits them inline. Apps that want to advertise h3
            // read `req.host_port()` themselves — keeps the
            // per-response branch and Host-reparse out of the
            // framework when no extra headers are set.
            write_response_into(&mut w, &resp, !want_close);
            // Two writes: headers (always small, in `w`'s 2 KiB
            // buffer) then the body (potentially large — multi-KiB
            // HTML pages, JSON dumps, etc.). Streaming body
            // separately lets a single response carry as much data
            // as the underlying stream can take, with no
            // intermediate copy and no header-buffer cap on body
            // length.
            if stream.send(w.as_bytes()).await.is_err() {
                return;
            }
            // Walk body. For a Single chunk we send once; for a
            // Chain we send each part separately — TCP coalesces
            // at the segment layer so the wire receives the same
            // byte sequence as if we'd concatenated, but we
            // don't pay the concat memcpy. Cow auto-derefs to
            // &[u8] for both Borrowed and Owned variants.
            match resp.into_body() {
                ResponseBody::Single(b) => {
                    if !b.is_empty() && stream.send(&b).await.is_err() {
                        return;
                    }
                }
                ResponseBody::Chain { parts, .. } => {
                    for part in &parts {
                        if stream.send(part).await.is_err() {
                            return;
                        }
                    }
                }
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
            let remaining = buf_len - consumed;
            if remaining > 0 {
                buf.copy_within(consumed..buf_len, 0);
            }
            buf_len = remaining;
        }
    }
}

// ---- HTTP request parser ----------------------------------------------------

/// Parse an HTTP request from `data`. Returns bytes consumed (>0) on success,
/// 0 if the request is incomplete.
fn parse_request(data: &[u8], req: &mut Request) -> usize {
    req.clear();

    // Find end of headers ("\r\n\r\n")
    let header_end = find_header_end(data);
    if header_end.is_none() {
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
    let mut consumed = body_start;

    // Handle Content-Length
    if let Some(cl_val) = req.header(b"Content-Length") {
        let body_len = parse_usize(cl_val);
        let avail = data.len() - body_start;
        if avail < body_len {
            return 0; // incomplete body
        }
        let copy_len = body_len.min(8191);
        req.body[..copy_len].copy_from_slice(&data[body_start..body_start + copy_len]);
        req.body_len = copy_len;
        consumed += body_len;
    }

    consumed
}

// ---- Response sender --------------------------------------------------------

struct BufWriter {
    buf: [u8; 2048],
    pos: usize,
}

impl BufWriter {
    fn new() -> Self {
        BufWriter { buf: [0u8; 2048], pos: 0 }
    }

    /// Reset the cursor without touching the backing array. Bytes
    /// past the new `pos` are stale but unreachable through
    /// `as_bytes`.
    fn clear(&mut self) {
        self.pos = 0;
    }

    fn push(&mut self, data: &[u8]) {
        // Headers only — bodies are sent separately by `handle_conn`
        // via a second `stream.send`. The 2 KiB cap is plenty for any
        // realistic header set (HTTP/1.1 + Content-Type + Content-Length
        // + Connection + optional Alt-Svc ≈ 200 bytes), but if a future
        // change pushes header bytes past it the response would
        // truncate silently and the peer would hang waiting for body.
        // `debug_assert` makes that show up in tests rather than as a
        // mystery timeout in production.
        debug_assert!(
            self.pos + data.len() <= 2048,
            "BufWriter overflow: header bytes exceed 2 KiB cap (pos={}, push={}). \
             Bodies are streamed separately, so this means your headers got too \
             big — bump the buffer or trim them.",
            self.pos, data.len()
        );
        let n = data.len().min(2048 - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
        self.pos += n;
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }
}

impl core::fmt::Write for BufWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push(s.as_bytes());
        Ok(())
    }
}


/// Serialise an HTTP/1.1 response into a `BufWriter`. Split out so
/// the TLS path can reuse it and feed the bytes through `TlsServer`
/// instead of straight to `conn.send`.
///
/// Hot path — called once per HTTP request. `core::fmt`'s machinery
/// (format-string walker, Display vtable dispatch, padding logic)
/// adds up at hundreds of thousands of req/s; manual byte-level
/// pushes for the constant headers and a small itoa for the only
/// variable integer (`Content-Length`) measurably outperform
/// `write!(...)` here.
///
/// Extra headers (`Alt-Svc`, `Cache-Control`, `Set-Cookie`, etc.)
/// are pulled from `resp.extra_headers()` — apps add them via
/// `Response::with_header`. The framework no longer hardcodes
/// any optional header itself; per-response branches and Host-
/// header reparses live in app code now if at all.
fn write_response_into(
    w: &mut BufWriter,
    resp: &Response,
    keep_alive: bool,
) {
    let body_len = resp.body_len();
    let content_type = resp.content_type_bytes();

    w.push(b"HTTP/1.1 ");
    let mut status_buf = [0u8; 4];
    let status_len = write_status_code(&mut status_buf, resp.status);
    w.push(&status_buf[..status_len]);
    w.push(b" ");
    w.push(status_text(resp.status).as_bytes());
    w.push(b"\r\nContent-Type: ");
    w.push(content_type);
    w.push(b"\r\nContent-Length: ");
    let mut len_buf = [0u8; 20];
    let len_len = write_usize(&mut len_buf, body_len);
    w.push(&len_buf[..len_len]);
    w.push(b"\r\nConnection: ");
    w.push(if keep_alive { b"keep-alive" } else { b"close" });
    w.push(b"\r\n");
    for (name, value) in resp.extra_headers() {
        w.push(name);
        w.push(b": ");
        w.push(value);
        w.push(b"\r\n");
    }
    w.push(b"\r\n");
    // body is NOT pushed here; `handle_conn` ships it via
    // separate stream.send calls — one per body part for
    // multi-part Chain bodies — so arbitrarily-large bodies
    // don't overflow the 2 KiB header buffer.
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

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
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
