// HTTP/1.1 response types and head serialiser.
//
// Owns the `Response` builder used by every handler and the byte-level
// head serialiser the connection loop calls to stage the wire bytes —
// plus its private `status_text` / `write_status_code` / `write_usize`
// itoa helpers.

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
/// Two modes, picked by the transport per connection:
///   - **Buffered** (no `sink`): `write` appends to `body`; the handler
///     usually installs a complete response with `res.set(Response::ok(..))`
///     and the transport serialises + sends it after the handler returns.
///   - **Streaming** (`sink` wired — h1 always, via the serve loop's
///     `RefCell` duplex so it can stream alongside an in-flight request
///     body; h2/h3 per stream): the first `write` flushes the head, each
///     subsequent `write` awaits a `ResponseSink::write_chunk` straight to
///     the wire, so peak memory stays `O(chunk)`. See
///     `docs/streaming-response.md`.
///
/// [`Request`]: crate::Request
pub struct Response<'s> {
    pub status: i32,
    /// Content-Type header value. `Bytes` (Cow<'static, [u8]>) so the
    /// common `res.ok(b"text/plain", ...)` case stays borrowed-static
    /// (no alloc), while dynamically-built MIME strings flow through
    /// Cow::Owned.
    content_type: Bytes,
    /// The response body, as a chain of IOBuf parts. `res.ok(ct,
    /// b"static")` is a 1-part chain. Holds the **buffered** body; when
    /// a live `sink` is wired and the handler `write`s, bytes go to the
    /// wire instead and this stays empty.
    body: IOBufChain,
    /// Optional extra response headers (Alt-Svc, Cache-Control, etc.)
    /// the app sets via `header`. Inline storage — no per-response Vec.
    extra_headers: [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
    /// Live write sink, wired by the transport for the handler call (h1
    /// via the serve loop's shared-stream duplex; h2/h3 per request
    /// stream). When set, `write`/`finish` push to the wire (bounded
    /// `O(chunk)`); a handler that buffers (`res.set(..)`) leaves the sink
    /// unused and the transport sends the buffered `body` afterward.
    sink: Option<&'s mut dyn crate::stream::ResponseSink>,
    /// Set once the head has gone out via the `sink` (first `write`), so
    /// `finish` and the transport know the response is already on the
    /// wire (streamed) vs still buffered.
    head_sent: bool,
}

// Note: no `unsafe impl Send/Sync` needed — `IOBuf` is Send + Sync
// (static-borrow branch is 'static, heap branch is Box<[u8]>; no
// thread-local interior mutability).

impl Default for Response<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'s> Response<'s> {
    /// A blank `200` the transport hands to the handler as `&mut
    /// Response`; the handler overwrites the head + body via the
    /// builder methods (`ok` / `status` / `write` / …).
    pub fn new() -> Self {
        Response {
            status: 200,
            content_type: IOBuf::from_static(b"application/octet-stream"),
            body: IOBufChain::new(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            sink: None,
            head_sent: false,
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
            sink: None,
            head_sent: false,
        }
    }

    /// Build a `404 Not Found` value.
    pub fn not_found() -> Self {
        Response {
            status: 404,
            content_type: IOBuf::from_static(b"text/plain"),
            body: IOBuf::from_static(b"Not Found").into(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            sink: None,
            head_sent: false,
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
            sink: None,
            head_sent: false,
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
            sink: None,
            head_sent: false,
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

    /// Build a `200` wired to a live write `sink` — the transport hands
    /// this to the handler when the connection can stream a response
    /// in-handler. The handler then either `write`s (streams, bounded)
    /// or sets a buffered body (`*res = Response::ok(..)`, which clears
    /// the sink; the transport sends the buffer afterward).
    pub fn with_sink(sink: &'s mut dyn crate::stream::ResponseSink) -> Self {
        Response {
            status: 200,
            content_type: IOBuf::from_static(b"application/octet-stream"),
            body: IOBufChain::new(),
            extra_headers: [const { None }; MAX_EXTRA_HEADERS],
            sink: Some(sink),
            head_sent: false,
        }
    }

    /// `true` once the handler streamed via `write` (the head went out
    /// over the sink). The transport uses this to finish the streamed
    /// response vs send the still-buffered one.
    pub fn is_streamed(&self) -> bool {
        self.head_sent
    }

    /// Consume the response into its buffered parts `(status,
    /// content_type, body, extra_headers)`, dropping the sink borrow.
    /// The transport calls this on the buffered path to send the parts
    /// after releasing the (now unused) sink.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (i32, Bytes, IOBufChain, [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS]) {
        (self.status, self.content_type, self.body, self.extra_headers)
    }

    /// Rebuild an owned, sink-less `Response<'static>` from the parts
    /// [`into_parts`](Self::into_parts) yields — the inverse. A transport
    /// whose handler ran with a live sink (so `res` is `Response<'a>`, not
    /// `'static`) but *buffered* its body uses this to recover a `'static`
    /// value it can hand to a deferred framing queue. `head_sent` resets
    /// to `false` (the recovered value is buffered, not yet on the wire).
    #[allow(clippy::type_complexity)]
    pub fn from_parts(
        parts: (i32, Bytes, IOBufChain, [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS]),
    ) -> Response<'static> {
        let (status, content_type, body, extra_headers) = parts;
        Response {
            status,
            content_type,
            body,
            extra_headers,
            sink: None,
            head_sent: false,
        }
    }

    /// Install an owned, fully-built response's data into this slot,
    /// leaving the live `sink` borrow intact. This is how a handler
    /// returns a *buffered* response through the `&mut Response` API:
    /// `res.set(Response::ok(ct, body))` or `res.set(match path { .. })`.
    ///
    /// It exists because `Response<'s>` is **invariant** in `'s` (the
    /// `&'s mut dyn ResponseSink` sink) — `*res = other` can't coerce an
    /// owned `Response<'static>` into the handler's `Response<'c>`. Moving
    /// only the data fields (status / content-type / body / headers)
    /// sidesteps that and keeps the slot's sink usable. `head_sent` is
    /// untouched (the buffered path runs with it `false`).
    pub fn set(&mut self, other: Response<'static>) {
        let (status, content_type, body, extra_headers) = other.into_parts();
        self.status = status;
        self.content_type = content_type;
        self.body = body;
        self.extra_headers = extra_headers;
    }

    /// Flush the response head over the live `sink`, once (lazy — on the
    /// first `write`, or on `finish` for an empty streamed body). Gathers
    /// the extra headers into a stack slice and calls `send_head`;
    /// `status` / `content_type` / `extra_headers` and `sink` are disjoint
    /// fields so the borrows are clean. No-op if already sent.
    async fn flush_head(&mut self) -> Result<(), ()> {
        if self.head_sent {
            return Ok(());
        }
        let mut hdrs: [(&[u8], &[u8]); MAX_EXTRA_HEADERS] =
            [(&[][..], &[][..]); MAX_EXTRA_HEADERS];
        let n = flatten_extra_headers(&self.extra_headers, &mut hdrs);
        let (status, ct) = (self.status, self.content_type.data());
        self.sink
            .as_mut()
            .expect("flush_head called with a sink")
            .send_head(status, ct, &hdrs[..n])
            .await?;
        self.head_sent = true;
        Ok(())
    }

    /// Push one body chunk. When a live `sink` is wired (h1 duplex, or
    /// h2/h3 streaming) the chunk goes **straight to the wire** — the head
    /// is flushed lazily on the first `write`, then each chunk is awaited
    /// (backpressure), so peak memory is `O(chunk)`. With no sink it
    /// appends to the buffered `body` instead (correct, `O(body)`). Set
    /// the head (status / content-type / headers) before the first `write`.
    pub async fn write(&mut self, buf: impl Into<IOBuf>) -> Result<(), ()> {
        // IOBuf is the currency: `&'static [u8]` borrows (zero-copy), `Vec`/
        // `String`/an owned `IOBuf` (e.g. `chunk.into_owned()` from the
        // request body — an RX→TX splice) move in. A transient `&[u8]` has no
        // `Into<IOBuf>`, so the caller makes ownership (and the copy) explicit.
        let buf = buf.into();
        if self.sink.is_some() {
            self.flush_head().await?;
            self.sink.as_mut().unwrap().write_chunk(buf).await
        } else {
            self.body.push_back(buf);
            Ok(())
        }
    }

    /// End a streamed response. Over a live sink, flushes the head first
    /// if the handler wrote no body (an empty streamed response), then
    /// ends the body. A no-op when there's no sink (the buffered body is
    /// sent by the transport after the handler returns).
    pub async fn finish(&mut self) -> Result<(), ()> {
        if self.sink.is_some() {
            self.flush_head().await?;
            self.sink.as_mut().unwrap().finish().await
        } else {
            Ok(())
        }
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

    /// Total body length in bytes — for the Content-Length header (h1)
    /// or DATA-frame length (h2/h3).
    pub fn body_len(&self) -> usize {
        self.body.total_len()
    }

    pub fn content_type_bytes(&self) -> &[u8] {
        self.content_type.data()
    }
}

/// Flatten the inline `extra_headers` slots (`with_header` storage) into
/// a `(name, value)` byte-slice array + count — the shape `flush_head`,
/// the buffered serve loop, and the head writers consume. Single source
/// for the flatten that previously lived inline at three call sites.
pub(crate) fn flatten_extra_headers<'a>(
    src: &'a [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS],
    dst: &mut [(&'a [u8], &'a [u8]); MAX_EXTRA_HEADERS],
) -> usize {
    let mut n = 0;
    for (name, value) in src.iter().flatten() {
        dst[n] = (name.data(), value.data());
        n += 1;
    }
    n
}

// ---- Response head serialisers ----------------------------------------------

/// Append `data` to the head buffer. `append_slice` returns
/// `Err(NoTailroom)` past the IOBuf's reserved capacity; the caller picks
/// `HEADER_BUF_SIZE` (or `body_iobuf(512)`) well above the realistic head
/// total, so an `Err` means truncation — `debug_assert` panics in tests,
/// release builds silently truncate.
///
/// Hot path (once per request): the manual byte-level appends + a small
/// itoa for `Content-Length` measurably outperform `write!(...)`'s
/// format-walker / Display-vtable / padding machinery.
pub(crate) fn hpush(buf: &mut IOBuf, data: &[u8]) {
    let r = buf.append_slice(data);
    debug_assert!(r.is_ok(), "response header overflow (raise HEADER_CAP)");
    let _ = r;
}

/// Emit the shared head prefix `HTTP/1.1 <status> <reason>\r\nContent-Type: <ct>`
/// (no trailing CRLF — the caller appends the framing line + headers).
fn write_head_status_ct(buf: &mut IOBuf, status: i32, content_type: &[u8]) {
    hpush(buf, b"HTTP/1.1 ");
    let mut status_buf = [0u8; 4];
    let status_len = write_status_code(&mut status_buf, status);
    hpush(buf, &status_buf[..status_len]);
    hpush(buf, b" ");
    hpush(buf, status_text(status).as_bytes());
    hpush(buf, b"\r\nContent-Type: ");
    hpush(buf, content_type);
}

/// Emit the app's extra headers then the terminating blank line.
fn write_head_extra_end(buf: &mut IOBuf, extra_headers: &[(&[u8], &[u8])]) {
    for (name, value) in extra_headers {
        hpush(buf, name);
        hpush(buf, b": ");
        hpush(buf, value);
        hpush(buf, b"\r\n");
    }
    hpush(buf, b"\r\n");
}

/// Buffered-response head from explicit parts (status / content-type /
/// extra headers / body length) into the caller's `IOBuf`, terminated by
/// `\r\n\r\n`. The body is NOT appended — the h1 serve loop chains the
/// response body parts after this head. Fed from [`Response::into_parts`].
pub(crate) fn write_response_head_parts(
    buf: &mut IOBuf,
    status: i32,
    content_type: &[u8],
    extra_headers: &[(&[u8], &[u8])],
    content_length: usize,
    keep_alive: bool,
) {
    write_head_status_ct(buf, status, content_type);
    hpush(buf, b"\r\nContent-Length: ");
    let mut len_buf = [0u8; 20];
    let len_len = write_usize(&mut len_buf, content_length);
    hpush(buf, &len_buf[..len_len]);
    hpush(buf, b"\r\nConnection: ");
    hpush(buf, if keep_alive { b"keep-alive" } else { b"close" });
    hpush(buf, b"\r\n");
    write_head_extra_end(buf, extra_headers);
}

/// Streamed-response head (no `Content-Length`, `Connection: close`)
/// from explicit parts — the `ResponseSink::send_head` head writer.
pub(crate) fn write_streaming_head_parts(
    buf: &mut IOBuf,
    status: i32,
    content_type: &[u8],
    extra_headers: &[(&[u8], &[u8])],
) {
    write_head_status_ct(buf, status, content_type);
    hpush(buf, b"\r\nConnection: close\r\n");
    write_head_extra_end(buf, extra_headers);
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
pub(crate) fn write_usize(out: &mut [u8; 20], mut n: usize) -> usize {
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
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}
