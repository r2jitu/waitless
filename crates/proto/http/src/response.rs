// HTTP/1.1 response types and head serialiser.
//
// Owns the `Response` builder used by every handler, the small
// `bytes_static` / `bytes_owned` `IOBuf` convenience constructors,
// and the byte-level head serialiser the connection loop calls to
// stage the wire bytes — plus its private `status_text` /
// `write_status_code` / `write_usize` itoa helpers.

use iobuf::{IOBuf, IOBufChain};

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

/// The outbound message a handler writes — symmetric with [`Request`],
/// the in-message it reads. The handler receives `&mut Response` and
/// either sets a one-shot buffered body (`res.ok(ct, body)`, the common
/// case) or streams it (`res.write(chunk).await` / `res.finish().await`).
///
/// Head fields (status / content-type / extra headers) are editable
/// until the first body byte goes out; for a buffered response that's at
/// handler return, for a streaming one it's the first `write`.
///
/// Phase 0 (this commit) is buffering-only on every transport: `write`
/// appends to `body` and the transport serialises + sends the whole
/// `Response` after the handler returns — byte-identical to the old
/// returned-`Response` path. Real per-transport streaming (a
/// `ResponseSink` the writes go to immediately, with backpressure) lands
/// in later phases; see `docs/streaming-response.md`.
///
/// [`Request`]: crate::Request
pub struct Response {
    pub status: i32,
    /// Content-Type header value. `Bytes` (Cow<'static, [u8]>) so the
    /// common `res.ok(b"text/plain", ...)` case stays borrowed-static
    /// (no alloc), while dynamically-built MIME strings flow through
    /// Cow::Owned.
    content_type: Bytes,
    /// The response body, as a chain of IOBuf parts. `res.ok(ct,
    /// b"static")` is a 1-part chain; streaming `write`s push parts.
    body: IOBufChain,
    /// Optional extra response headers (Alt-Svc, Cache-Control, etc.)
    /// the app sets via `header`. Inline storage — no per-response Vec.
    extra_headers: [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
    /// Set once the handler streams via `write` (vs a one-shot buffered
    /// body). Phase 0 ignores it (both paths buffer); later phases use
    /// it to route writes to the live `ResponseSink`.
    streaming: bool,
    /// A lazily-pulled streaming body (`stream_body`). When set, the
    /// transport drives the producer chunk-by-chunk onto the wire with
    /// backpressure instead of sending a materialised `body` — so peak
    /// memory stays `O(chunk)`. Mutually exclusive with a buffered
    /// `body` in practice (a handler picks one).
    producer: Option<alloc::boxed::Box<dyn crate::stream::ResponseBodyProducer>>,
}

// Note: no `unsafe impl Send/Sync` needed — `IOBuf` is Send + Sync
// (static-borrow branch is 'static, heap branch is Box<[u8]>; no
// thread-local interior mutability).

impl Default for Response {
    fn default() -> Self {
        Self::new()
    }
}

impl Response {
    /// A blank `200` the transport hands to the handler as `&mut
    /// Response`; the handler overwrites the head + body via the
    /// builder methods (`ok` / `status` / `write` / …).
    pub fn new() -> Self {
        Response {
            status: 200,
            content_type: IOBuf::from_static(b"application/octet-stream"),
            body: IOBufChain::new(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            streaming: false,
            producer: None,
        }
    }

    /// Build a `200 OK` value with the given content-type and buffered
    /// body — the common case. The handler installs it with `*res =
    /// Response::ok(..)`. `body` accepts `&'static [u8]` / `Vec<u8>` /
    /// `IOBuf` / `IOBufChain` (anything `Into<IOBufChain>`).
    pub fn ok(content_type: impl Into<Bytes>, body: impl Into<IOBufChain>) -> Self {
        Response {
            status: 200,
            content_type: content_type.into(),
            body: body.into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            streaming: false,
            producer: None,
        }
    }

    /// Build a `404 Not Found` value.
    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Not Found").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            streaming: false,
            producer: None,
        }
    }

    /// Build a `400 Bad Request` value. `serve_conn` uses it to answer a
    /// request the HTTP/1.1 parser flagged as malformed (a `Transfer-
    /// Encoding: chunked` request — item E in
    /// docs/rx-path-optimizations.md); it pairs the response with
    /// `Connection: close`.
    pub fn bad_request() -> Self {
        Response {
            status: 400,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Bad Request").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            streaming: false,
            producer: None,
        }
    }

    /// Build a `301 Moved Permanently` value with an empty body and a
    /// `Location` header — the redirect for HTTP→HTTPS upgrades /
    /// permanent renames.
    pub fn moved_permanently(location: impl Into<Bytes>) -> Self {
        Response {
            status: 301,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            streaming: false,
            producer: None,
        }
        .with_header(b"Location", location)
    }

    /// Add an extra header to a `Response` value, consuming + returning
    /// it — the chaining builder for the `*res = Response::ok(..)
    /// .with_header(..)` value path (`Alt-Svc`, `Cache-Control`,
    /// `Set-Cookie`, …). Silently drops past `MAX_EXTRA_HEADERS` (4).
    pub fn with_header(mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        self.header(name, value);
        self
    }

    /// Set the status code in place (streaming/out-object path).
    pub fn status(&mut self, status: i32) -> &mut Self {
        self.status = status;
        self
    }

    /// Set the Content-Type in place — set the head before the first
    /// `write` on the streaming path.
    pub fn content_type(&mut self, content_type: impl Into<Bytes>) -> &mut Self {
        self.content_type = content_type.into();
        self
    }

    /// Add an extra header in place (the `&mut` out-object form of
    /// `with_header`). Silently drops past `MAX_EXTRA_HEADERS` (4).
    pub fn header(&mut self, name: impl Into<Bytes>, value: impl Into<Bytes>) -> &mut Self {
        for slot in self.extra_headers.iter_mut() {
            if slot.is_none() {
                *slot = Some((name.into(), value.into()));
                break;
            }
        }
        self
    }

    /// Hand the response a **lazily-pulled streaming body** — the
    /// transport drives `producer.next()` chunk-by-chunk onto the wire
    /// with backpressure, so peak memory stays `O(chunk)` rather than
    /// `O(response size)`. Sets the content-type + producer; set
    /// `status`/`header` first if non-default. For generated / computed
    /// large bodies; see [`ResponseBodyProducer`](crate::ResponseBodyProducer).
    pub fn stream_body(
        &mut self,
        content_type: impl Into<Bytes>,
        producer: alloc::boxed::Box<dyn crate::stream::ResponseBodyProducer>,
    ) -> &mut Self {
        self.content_type = content_type.into();
        self.producer = Some(producer);
        self.streaming = true;
        self
    }

    /// `true` if the handler installed a streaming-body producer.
    pub fn has_stream(&self) -> bool {
        self.producer.is_some()
    }

    /// Take the streaming-body producer for the transport to drive
    /// (leaving `None`). The transport pulls `next()` + writes each
    /// chunk with backpressure.
    pub fn take_stream(
        &mut self,
    ) -> Option<alloc::boxed::Box<dyn crate::stream::ResponseBodyProducer>> {
        self.producer.take()
    }

    /// Drain any streaming-body producer into the buffered `body`,
    /// turning a streaming response into a materialised one. The
    /// fallback for transports that don't (yet) stream on the wire
    /// (h2/h3 today): correct output, but `O(response size)` memory —
    /// the bounded-memory win is h1-only until the per-transport
    /// streaming sinks land. No-op when there's no producer.
    pub async fn materialize(&mut self) {
        if let Some(mut producer) = self.producer.take() {
            while let Some(chunk) = producer.next().await {
                self.body.push_back(chunk);
            }
        }
    }

    /// Stream one body chunk. **Phase 0**: appends to the buffered body
    /// (the transport sends it after the handler returns). Later phases
    /// route this to the transport's live `ResponseSink` so the bytes
    /// hit the wire immediately and backpressure applies here. Set the
    /// head (status / content-type / headers) before the first `write`.
    pub async fn write(&mut self, buf: &[u8]) -> Result<(), ()> {
        self.streaming = true;
        self.body.push_back(IOBuf::from_slice_with_headroom(0, buf, 0));
        Ok(())
    }

    /// Finish a streamed response. **Phase 0**: a no-op (the buffered
    /// body is sent at handler return); later phases flush the sink's
    /// end-of-stream marker.
    pub async fn finish(&mut self) -> Result<(), ()> {
        Ok(())
    }

    /// Iterate the extra headers set via `header`. Used by the HTTP/1.1
    /// response writer and the H3 QPACK encoder to emit them.
    pub fn extra_headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.extra_headers
            .iter()
            .filter_map(|slot| slot.as_ref().map(|(n, v)| (n.data(), v.data())))
    }

    /// Consume the response and yield its body chain. Transports drain
    /// it (`pop_front` / append to an outbound chain).
    pub fn into_body(self) -> IOBufChain {
        self.body
    }

    /// Borrow the body chain without consuming the response.
    pub fn body(&self) -> &IOBufChain {
        &self.body
    }

    /// Total body length in bytes — for the Content-Length header (h1)
    /// or DATA-frame length (h2/h3).
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
pub(crate) fn write_response_into_iobuf(buf: &mut IOBuf, resp: &Response, keep_alive: bool) {
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

/// Serialise the head for an HTTP/1.1 **streaming** response — no
/// `Content-Length` (the producer-driven length is unknown up front),
/// so the body is delimited by connection close and `Connection: close`
/// is forced. The transport writes this head, then drives the producer
/// chunk-by-chunk, then closes. (A future revision could switch to
/// `Transfer-Encoding: chunked` to keep the connection alive across a
/// streamed response.)
pub(crate) fn write_streaming_head_into_iobuf(buf: &mut IOBuf, resp: &Response) {
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
    push!(b"\r\nConnection: close\r\n");
    for (name, value) in resp.extra_headers() {
        push!(name);
        push!(b": ");
        push!(value);
        push!(b"\r\n");
    }
    push!(b"\r\n");
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
