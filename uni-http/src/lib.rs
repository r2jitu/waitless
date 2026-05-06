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

/// One segment of a multi-part response body. Static parts are
/// borrowed `&'static` slices (zero alloc, zero copy); Owned
/// parts are heap-allocated and moved.
pub enum BodyPart {
    Static(&'static [u8]),
    Owned(alloc::vec::Vec<u8>),
}

impl BodyPart {
    pub fn len(&self) -> usize {
        match self {
            BodyPart::Static(s) => s.len(),
            BodyPart::Owned(v) => v.len(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        match self {
            BodyPart::Static(s) => s,
            BodyPart::Owned(v) => v,
        }
    }
}

/// Body storage for a `Response`. Three shapes:
///   - `Static`: a borrowed `&'static` slice — zero alloc, zero
///     copy until the wire.
///   - `Owned`: a heap-allocated single buffer — one alloc, no
///     copy at API boundaries.
///   - `Chain`: a sequence of [BodyPart]s, each independently
///     static or owned. Apps build this via the [Body] builder
///     to compose a response from a static template prefix +
///     dynamic middle + static suffix without memcpying
///     everything into one buffer first.
pub enum ResponseBody {
    /// A borrowed byte slice with lifetime that outlives `Response`.
    /// Stored as a raw pointer pair so the struct keeps its current
    /// `Send + Sync` properties without needing a lifetime parameter.
    /// Callers must ensure the bytes outlive the handler return /
    /// `send_response` call, which is always true for the `&'static`
    /// case that `Response::ok` covers.
    Static { ptr: *const u8, len: usize },
    /// A heap-owned byte slice. Dropped when `Response` drops, which
    /// happens after `send_response` has copied the bytes into the
    /// outbound TCP/TLS buffer.
    Owned(alloc::boxed::Box<[u8]>),
    /// A chain of body parts assembled at handler time. Each part
    /// is queued as its own SendChunk on the QUIC stream, so a
    /// static template prefix gets a borrowed-static chunk (zero
    /// alloc) sitting alongside the dynamic middle's owned chunk.
    Chain {
        parts: alloc::vec::Vec<BodyPart>,
        total_len: usize,
    },
}

/// Builder for a chained / composable response body. Apps that
/// want to wrap a dynamic middle in a static template can do so
/// without memcpying the whole thing into one buffer:
///
/// ```ignore
/// let body = Body::new()
///     .push_static(STATIC_HTML_PREFIX)
///     .push_owned(rendered_middle.into_bytes())
///     .push_static(STATIC_HTML_SUFFIX);
/// Response::ok(b"text/html; charset=utf-8", body)
/// ```
///
/// Each part is queued as a separate SendChunk on the QUIC stream
/// and reaches the wire with at most one memcpy per packet
/// (into the AEAD-target datagram region).
pub struct Body {
    pub parts: alloc::vec::Vec<BodyPart>,
    pub total_len: usize,
}

impl Body {
    pub fn new() -> Self {
        Body { parts: alloc::vec::Vec::new(), total_len: 0 }
    }

    pub fn with_capacity(n: usize) -> Self {
        Body {
            parts: alloc::vec::Vec::with_capacity(n),
            total_len: 0,
        }
    }

    pub fn push_static(mut self, s: &'static [u8]) -> Self {
        if !s.is_empty() {
            self.total_len += s.len();
            self.parts.push(BodyPart::Static(s));
        }
        self
    }

    pub fn push_owned(mut self, v: alloc::vec::Vec<u8>) -> Self {
        if !v.is_empty() {
            self.total_len += v.len();
            self.parts.push(BodyPart::Owned(v));
        }
        self
    }

    pub fn push_string(self, s: alloc::string::String) -> Self {
        self.push_owned(s.into_bytes())
    }

    pub fn len(&self) -> usize { self.total_len }
    pub fn is_empty(&self) -> bool { self.total_len == 0 }
}

impl Default for Body {
    fn default() -> Self { Body::new() }
}

impl From<&'static [u8]> for Body {
    fn from(s: &'static [u8]) -> Self {
        Body::new().push_static(s)
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Body::new().push_static(s.as_bytes())
    }
}

impl From<alloc::vec::Vec<u8>> for Body {
    fn from(v: alloc::vec::Vec<u8>) -> Self {
        Body::new().push_owned(v)
    }
}

impl From<alloc::string::String> for Body {
    fn from(s: alloc::string::String) -> Self {
        Body::new().push_string(s)
    }
}

/// Output of [`Response::into_body_parts`]. Flattens trivial
/// single-part bodies so frontends don't pay Chain overhead in
/// the common case.
pub enum BodyParts {
    /// Single static slice — zero alloc, zero copy at the
    /// frontend boundary.
    Static(&'static [u8]),
    /// Single owned Vec — one alloc when the response was
    /// built, no copy at the frontend boundary.
    Owned(alloc::vec::Vec<u8>),
    /// Multi-part chain — frontend walks parts, queueing each
    /// as a SendChunk.
    Chain {
        parts: alloc::vec::Vec<BodyPart>,
        total_len: usize,
    },
}

impl BodyParts {
    pub fn total_len(&self) -> usize {
        match self {
            BodyParts::Static(s) => s.len(),
            BodyParts::Owned(v) => v.len(),
            BodyParts::Chain { total_len, .. } => *total_len,
        }
    }
}

pub struct Response {
    pub status: i32,
    content_type: *const u8,
    content_type_len: usize,
    body: ResponseBody,
}

// Response is Send/Sync: the Static variant stores borrowed raw
// pointers whose targets live as long as the handler, and Owned
// holds a Box<[u8]> which is itself Send/Sync.
unsafe impl Send for Response {}
unsafe impl Sync for Response {}

/// Anything a handler can return as a `Response` body.
/// Implemented for `&'static [u8]` (zero-allocation static
/// resources), `Box<[u8]>` / `Vec<u8>` / `String` (heap-rendered
/// JSON, text, etc.). Apps just call `Response::ok(ct, body)`
/// without picking a method based on the body type.
pub trait IntoBody {
    fn into_body(self) -> ResponseBody;
}

impl IntoBody for &'static [u8] {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Static { ptr: self.as_ptr(), len: self.len() }
    }
}

impl<const N: usize> IntoBody for &'static [u8; N] {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Static { ptr: self.as_ptr(), len: N }
    }
}

impl IntoBody for alloc::boxed::Box<[u8]> {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Owned(self)
    }
}

impl IntoBody for alloc::vec::Vec<u8> {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Owned(self.into_boxed_slice())
    }
}

impl IntoBody for alloc::string::String {
    fn into_body(self) -> ResponseBody {
        ResponseBody::Owned(self.into_bytes().into_boxed_slice())
    }
}

impl IntoBody for Body {
    fn into_body(self) -> ResponseBody {
        // Collapse trivial cases so single-part Body builders
        // don't pay the Chain enum's Vec overhead — a builder
        // that pushed exactly one Static slice flattens to
        // ResponseBody::Static (zero alloc).
        match self.parts.len() {
            0 => ResponseBody::Static {
                ptr: b"".as_ptr(),
                len: 0,
            },
            1 => {
                let mut parts = self.parts;
                let only = parts.pop().unwrap();
                // `parts` Vec drops here.
                match only {
                    BodyPart::Static(s) => ResponseBody::Static {
                        ptr: s.as_ptr(),
                        len: s.len(),
                    },
                    BodyPart::Owned(v) => ResponseBody::Owned(v.into_boxed_slice()),
                }
            }
            _ => ResponseBody::Chain {
                parts: self.parts,
                total_len: self.total_len,
            },
        }
    }
}

impl Response {
    /// Build a 200 OK. `body` accepts any [`IntoBody`] —
    /// `&'static [u8]` for zero-allocation static responses,
    /// `Vec<u8>` / `String` / `Box<[u8]>` for heap-rendered ones.
    pub fn ok(content_type: &[u8], body: impl IntoBody) -> Self {
        Response {
            status: 200,
            content_type: content_type.as_ptr(),
            content_type_len: content_type.len(),
            body: body.into_body(),
        }
    }


    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: b"text/plain".as_ptr(),
            content_type_len: 10,
            body: ResponseBody::Static {
                ptr: b"Not Found".as_ptr(),
                len: 9,
            },
        }
    }

    /// Consume the response and return its body as a list of
    /// parts. Frontends (HTTP/1.1 or HTTP/3) walk the list and
    /// emit each part on the wire — for Static parts via
    /// borrowed-slice APIs (zero alloc, zero copy until the
    /// final wire memcpy), for Owned parts by move.
    ///
    /// The returned [BodyParts] flattens the single-part case
    /// to its underlying variant so callers don't pay the
    /// `Vec<BodyPart>` overhead when the body is one buffer.
    pub fn into_body_parts(self) -> BodyParts {
        match self.body {
            ResponseBody::Static { ptr, len } => {
                // SAFETY: Static was constructed from a `&'static [u8]`.
                let s = unsafe { core::slice::from_raw_parts(ptr, len) };
                BodyParts::Static(s)
            }
            ResponseBody::Owned(b) => BodyParts::Owned(b.into_vec()),
            ResponseBody::Chain { parts, total_len } => {
                BodyParts::Chain { parts, total_len }
            }
        }
    }

    /// Total body length in bytes — sums all parts of a Chain.
    /// Used by frontends to write the Content-Length header
    /// (HTTP/1.1) or DATA-frame length prefix (HTTP/3) without
    /// having to walk the parts twice.
    pub fn body_len(&self) -> usize {
        match &self.body {
            ResponseBody::Static { len, .. } => *len,
            ResponseBody::Owned(b) => b.len(),
            ResponseBody::Chain { total_len, .. } => *total_len,
        }
    }

    /// Borrow the response body as a contiguous slice. For
    /// `Chain` bodies this would require flattening, which the
    /// HTTP/1.1 and HTTP/3 frontends explicitly avoid — they
    /// use `into_body_parts` instead. Callers that genuinely
    /// need a single contiguous slice (e.g. passing to a
    /// hash function) can use `body_flatten()` to allocate.
    /// `body_bytes()` returns an empty slice for Chain bodies
    /// to surface the API mismatch loudly rather than silently
    /// flattening behind the caller's back.
    pub fn body_bytes(&self) -> &[u8] {
        match &self.body {
            ResponseBody::Static { ptr, len } => unsafe {
                core::slice::from_raw_parts(*ptr, *len)
            },
            ResponseBody::Owned(b) => b,
            ResponseBody::Chain { .. } => &[],
        }
    }

    /// Walk a Chain body's parts (or yield the single-part
    /// equivalent) into the caller's closure. Useful for
    /// frontends that want to inspect parts without consuming
    /// the response.
    pub fn for_each_body_part<F: FnMut(&BodyPart)>(&self, mut f: F) {
        match &self.body {
            ResponseBody::Static { ptr, len } => {
                let s = unsafe { core::slice::from_raw_parts(*ptr, *len) };
                f(&BodyPart::Static(unsafe {
                    core::slice::from_raw_parts(s.as_ptr(), s.len())
                }))
            }
            ResponseBody::Owned(_) => {
                // Skipping this case in the walker — callers that
                // need the bytes can use body_bytes() since Owned
                // is contiguous.
            }
            ResponseBody::Chain { parts, .. } => {
                for p in parts {
                    f(p);
                }
            }
        }
    }
    /// Borrow the content-type header value. Public for the HTTP/3
    /// frontend (mirror of `body_bytes`).
    pub fn content_type_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.content_type, self.content_type_len) }
    }
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
            handle_conn(handler, stream, false).await;
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
pub fn listen_https<H>(
    port: u16,
    handler: H,
    tls: Arc<dyn Tls>,
) -> Result<(), uni::runtime::TcpBindError>
where
    H: AsyncFn(&Request) -> Response + Send + Sync + 'static,
{
    listen_https_advertising_h3(port, handler, tls, false)
}

/// Like [`listen_https`] but every response includes
/// `Alt-Svc: h3=":<port>"; ma=86400` whenever `advertise_h3` is
/// true. The `<port>` is derived per-response from the request's
/// `Host` header, so it always matches whatever port the client
/// actually connected to (e.g. `https://localhost:8443/` →
/// `h3=":8443"`). This handles the bazel-run default that maps
/// host `:8443` → guest `:443` — a static `h3=":443"` would point
/// browsers at a port nothing's listening on and silently disable
/// HTTP/3 upgrade.
///
/// Caller is responsible for only setting `advertise_h3 = true`
/// when an H3 endpoint actually bound on the corresponding UDP
/// port; otherwise the browser's alt-svc cache gets poisoned for
/// up to 24 h with a non-functional advertisement.
pub fn listen_https_advertising_h3<H>(
    port: u16,
    handler: H,
    tls: Arc<dyn Tls>,
    advertise_h3: bool,
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
            handle_conn(handler, stream, advertise_h3).await;
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
    advertise_h3: bool,
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
            // Per-request Alt-Svc: when H3 is up, advertise it on
            // whatever port the client actually used to reach us.
            // Read the Host header here (after parse, before
            // handler may have mutated `req` — handlers receive
            // `&Request`, but defensively recompute each loop).
            let alt_svc_port = if advertise_h3 {
                req.header(b"Host").and_then(host_header_port).or(Some(443))
            } else {
                None
            };
            write_response_into(&mut w, &resp, !want_close, alt_svc_port);
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
            // Walk body parts. For Static/Owned (single buffer)
            // we send once. For Chain (multi-part), we send each
            // part separately — TCP coalesces the segments at
            // its layer, so the wire receives the same byte
            // sequence as if we'd concatenated, but we don't
            // pay the concat memcpy.
            let body_parts = resp.into_body_parts();
            match body_parts {
                BodyParts::Static(s) => {
                    if !s.is_empty() && stream.send(s).await.is_err() {
                        return;
                    }
                }
                BodyParts::Owned(v) => {
                    if !v.is_empty() && stream.send(&v).await.is_err() {
                        return;
                    }
                }
                BodyParts::Chain { parts, .. } => {
                    for part in &parts {
                        if stream.send(part.as_slice()).await.is_err() {
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
/// `alt_svc_port`, if `Some`, emits
/// `Alt-Svc: h3=":<port>"; ma=86400` so HTTP/3-capable browsers
/// learn to upgrade on the next visit. Caller resolves the port
/// from the request's `Host` header so the advertisement matches
/// whatever port the client actually used (e.g. the bazel-run
/// default of `:8443`, not the unikernel's internal `:443`).
fn write_response_into(
    w: &mut BufWriter,
    resp: &Response,
    keep_alive: bool,
    alt_svc_port: Option<u16>,
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
    if let Some(port) = alt_svc_port {
        w.push(b"Alt-Svc: h3=\":");
        let mut port_buf = [0u8; 5];
        let port_len = write_u16(&mut port_buf, port);
        w.push(&port_buf[..port_len]);
        w.push(b"\"; ma=86400\r\n");
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

/// Decimal-encode a `u16` into `out`, returning byte count.
/// Mirror of `write_usize` but bounded so the buffer can be 5 bytes.
fn write_u16(out: &mut [u8; 5], mut n: u16) -> usize {
    if n == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 5];
    let mut len = 0;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
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
