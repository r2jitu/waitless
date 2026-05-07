// uni-http3/src/server.rs — HTTP/3 server over //uni-quic.
//
// Per QUIC connection:
//   1. Open server-side unidirectional CONTROL stream
//      (stream type byte = 0x00) and emit a SETTINGS frame
//      with no entries (defaults are fine).
//   2. For each accepted peer stream:
//      - Bidi (id & 0x3 == 0): a request stream. Read HEADERS +
//        DATA frames until FIN, build `uni_http::Request`, hand
//        to the user handler, encode response (HEADERS + DATA +
//        FIN), close stream.
//      - Uni (id & 0x3 == 0x2): peer's control / QPACK encoder /
//        QPACK decoder stream. We accept and discard everything
//        on these (control stream's SETTINGS frame is ignored,
//        QPACK streams stay empty since we negotiated capacity 0).
//
// Sans-allocation hot path: each request reuses `Request` /
// `BufWriter`-style scratch buffers from the conn handler.

#![allow(dead_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;

use uni_quic::{quic_listen, QuicConn, QuicListenError};

use uni_http::{Method, Request, Response};

use crate::frame::{self, ftype as h3_ftype};
use crate::qpack::{self, FieldSink};

/// Stream-type byte for HTTP/3 control streams (RFC 9114 §6.2.1).
const STREAM_TYPE_CONTROL: u64 = 0x00;
const STREAM_TYPE_PUSH: u64 = 0x01;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

#[derive(Debug)]
pub enum ListenError {
    Bind(uni_quic::QuicListenError),
    CertOrKey,
}

impl From<QuicListenError> for ListenError {
    fn from(e: QuicListenError) -> Self {
        match e {
            QuicListenError::Bind(_) => ListenError::Bind(e),
            QuicListenError::CertOrKey => ListenError::CertOrKey,
        }
    }
}

/// One-call HTTP/3 server. Binds a UDP port, terminates QUIC
/// connections, dispatches every parsed `Request` to `handler`.
/// `handler` returns a `Response`; the framework sends it back as
/// HEADERS + DATA + FIN on the request stream.
///
/// `cert_der` and `key_pkcs8_der` are the same blobs `uni_tls::
/// acceptor` accepts.
///
/// Returns once the server is bound; the listener stays alive for
/// the duration of the program (uni's task system retains it).
pub fn listen<H, F>(
    port: u16,
    handler: H,
    cert_der: &'static [u8],
    key_pkcs8_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: Fn(Request) -> F + Send + Sync + Clone + 'static,
    F: core::future::Future<Output = Response> + 'static,
{
    let handler = Arc::new(handler);
    let listener = quic_listen(port, cert_der, key_pkcs8_der, move |conn: QuicConn| {
        let handler = Arc::clone(&handler);
        async move {
            handle_conn(conn, handler).await;
        }
    })?;
    uni::_retain(listener);
    Ok(())
}

async fn handle_conn<H, F>(conn: QuicConn, handler: Arc<H>)
where
    H: Fn(Request) -> F + 'static,
    F: core::future::Future<Output = Response> + 'static,
{
    // 1. Open control stream and send SETTINGS.
    //    Server-initiated unidirectional streams use IDs 3, 7, 11, ...
    //    (id & 0x3 == 0x3). The stream-type byte (varint 0x00) goes
    //    on the wire first, then frames.
    let control_id = 3u64;
    {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        // stream type byte (varint).
        buf.push(STREAM_TYPE_CONTROL as u8);
        // SETTINGS frame with empty body.
        let mut settings = [0u8; 8];
        let n = frame::write_empty_settings(&mut settings).expect("write settings");
        buf.extend_from_slice(&settings[..n]);
        conn.send(control_id, &buf);
    }

    // 2. Loop accepting streams.
    //
    // Peer uni streams (control + QPACK encoder + QPACK decoder)
    // are accepted ONCE per (conn, sid). After that, their
    // RecvStream stays alive and `dispatch_frames` re-pushes the
    // sid into `opened_streams` whenever new bytes arrive — so
    // accept_stream would re-yield the same sid forever, and
    // each refresh's QPACK encoder bytes would pile up in the
    // recv buffer. To avoid that, track which uni sids we've
    // already accepted and drop their buffers on each re-yield
    // so the recv buffer can't grow without bound.
    use alloc::collections::BTreeSet;
    let mut uni_seen: BTreeSet<u64> = BTreeSet::new();
    // Per-connection scratch buffers. Each `handle_request` /
    // `write_response` `clear()`s them on entry and reuses the
    // existing capacity — instead of allocating a fresh Vec per
    // request. For a refresh-spamming session this saves the
    // five Vec allocs that previously fired per H3 GET (recv
    // buffer, HEADERS frame copy, request body, QPACK output,
    // H3 framing prefix). The capacities below cover the worst
    // case for a typical browser request — they grow if exceeded
    // (rare) but never shrink.
    let mut scratch = Scratch::new();
    loop {
        let sid = match conn.accept_stream().await {
            Some(s) => s,
            None => return, // conn failed
        };
        // Bidi peer stream (id & 0x3 == 0): request stream.
        if sid & 0x3 == 0 {
            let h = Arc::clone(&handler);
            // Drive request handling inline. We'd ideally spawn a
            // task per request, but the conn task already
            // multiplexes; doing it inline keeps lifetimes simple
            // and matches the shape of //uni-http's handle_conn.
            handle_request(&conn, sid, h.as_ref(), &mut scratch).await;
        } else if sid & 0x3 == 0x2 {
            // Peer unidirectional streams — control, QPACK
            // encoder, QPACK decoder. We can't actively drain
            // them via `recv` (that would block the accept loop
            // until FIN, which never arrives), so instead we
            // discard any bytes the QUIC layer has buffered for
            // them whenever the accept loop re-yields the sid.
            // We only count NEW peer uni streams in the event
            // counter, so it stays at ~3 per conn rather than
            // climbing per refresh.
            let new_uni = uni_seen.insert(sid);
            if new_uni {
                crate::h3_event!(peer_uni_streams_seen, "sid={}", sid);
            }
            conn.discard_recv(sid);
        } else {
            // sid & 0x3 == 0x1 → server-initiated bidi (we
            // don't open any), or 0x3 → server-initiated uni.
            crate::h3_drop!(unexpected_bidi, "sid={}", sid);
        }
    }
}

/// Per-connection scratch buffers, retained across requests on
/// the same QUIC conn. Each request `clear()`s the buffers it
/// uses and refills via `extend_from_slice` — capacity stays put,
/// so the steady-state per-request alloc count for the request-
/// parsing path drops to zero (no fresh `Vec::new()` per request).
/// Response framing is now built directly inside an IOBuf with
/// reserved headroom/tailroom (see `write_response`) — the old
/// `qpack_buf` + `framing` Vec scratches are gone.
pub(crate) struct Scratch {
    /// H3 stream-bytes accumulator — successive `recv` chunks
    /// concatenate here until enough bytes form a complete frame.
    pub(crate) recv_buf: Vec<u8>,
    /// HEADERS-frame body, copied out of `recv_buf` before the
    /// outer `drain` invalidates the borrow into it.
    pub(crate) headers_value: Vec<u8>,
    /// Reassembled request body across DATA frames (POST/PUT).
    /// Empty path for GET. Kept as scratch so an occasional POST
    /// on the same conn doesn't allocate.
    pub(crate) data: Vec<u8>,
}

impl Scratch {
    pub(crate) fn new() -> Self {
        Scratch {
            // 16 KiB matches the previous `recv_scratch` cap and
            // covers a worst-case single request (8 KiB body +
            // headers + framing).
            recv_buf: Vec::with_capacity(16 * 1024),
            // 4 KiB covers Chrome's typical HEADERS frame size
            // (compressed pseudo + a dozen literal headers).
            headers_value: Vec::with_capacity(4 * 1024),
            // Empty by default; will allocate if a request body
            // arrives.
            data: Vec::new(),
        }
    }
}

async fn handle_request<H, F>(
    conn: &QuicConn,
    sid: u64,
    handler: &H,
    scratch: &mut Scratch,
) where
    H: Fn(Request) -> F,
    F: core::future::Future<Output = Response>,
{
    // Accumulate stream bytes until we have a complete H3 frame
    // sequence: HEADERS frame, then 0+ DATA frames, then FIN.
    //
    // Buffer cap: enough for our worst-case single request (path +
    // headers + small body). Match `uni_http::Request`'s 8 KiB body.
    // `scratch` is per-conn; we clear and reuse capacity across
    // requests on the same connection.
    const RECV_CAP: usize = 16 * 1024;
    scratch.recv_buf.clear();
    scratch.headers_value.clear();
    scratch.data.clear();
    let buf = &mut scratch.recv_buf;
    let headers_value = &mut scratch.headers_value;
    let data = &mut scratch.data;
    let mut chunk = [0u8; 4096];
    let mut headers_seen = false;
    let mut eof = false;

    crate::h3_event!(requests_received, "sid={}", sid);
    while !eof {
        let (n, end) = conn.recv(sid, &mut chunk).await;
        if n > 0 {
            if buf.len() + n > RECV_CAP {
                crate::h3_drop!(recv_buffer_overflow,
                    "sid={} buf_len={} cap={}", sid, buf.len(), RECV_CAP);
                conn.close_stream(sid);
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if end {
            eof = true;
        }

        // Try to parse complete frames off the front.
        loop {
            let (f, used) = match frame::parse_frame(&buf) {
                Ok(x) => x,
                Err(frame::FrameError::Truncated) => break,
                Err(e) => {
                    crate::h3_drop!(frame_parse_error,
                        "sid={} err={:?} buf_len={}", sid, e, buf.len());
                    conn.close_stream(sid);
                    return;
                }
            };
            match f {
                frame::Frame::Headers(body) => {
                    // Copy into per-conn scratch BEFORE the outer
                    // `buf.drain` invalidates the borrow.
                    headers_value.clear();
                    headers_value.extend_from_slice(body);
                    headers_seen = true;
                }
                frame::Frame::Data(body) => {
                    data.extend_from_slice(body);
                }
                frame::Frame::Settings(_) | frame::Frame::GoAway(_) => {
                    // Illegal on a request stream — but be lenient.
                }
                frame::Frame::Skipped { .. } => {}
            }
            buf.drain(..used);
        }
        if eof && headers_seen {
            break;
        }
    }
    crate::diag::bump(&crate::diag::COUNTERS.read_loop_completed);
    if !headers_seen {
        crate::h3_drop!(no_headers_seen, "sid={}", sid);
        conn.close_stream(sid);
        return;
    }

    // Decode QPACK headers via the streaming sink — names and
    // values land directly in `Request`'s fixed-size arrays
    // (set_path, push_header) without going through an
    // intermediate `Vec<Field>`. Saves one heap alloc per
    // QPACK literal value (≈ 8-12 per Chrome request); no
    // intermediate `Cow::Owned(Vec<u8>)` per header. Stack-
    // allocated 4 KiB Huffman scratches cover the worst-case
    // expansion of any single header in browser traffic.
    //
    // Pattern matches the nghttp3/lsqpack approach: decoder
    // emits header callbacks, consumer copies into final
    // storage immediately, decoder owns nothing.
    struct RequestSink<'r> {
        req: &'r mut Request,
    }
    impl FieldSink for RequestSink<'_> {
        fn on_field(&mut self, name: &[u8], value: &[u8]) {
            // Pseudo-headers go to dedicated Request fields.
            // Static-table indexed `:method` / `:path` /
            // `:scheme` / `:authority` arrive here with the
            // borrowed-static name from the QPACK static table,
            // so the byte comparison is against pointer-stable
            // data (still a memcmp for safety).
            match name {
                b":method" => {
                    self.req.method = match value {
                        b"GET" => Method::Get,
                        b"HEAD" => Method::Head,
                        b"POST" => Method::Post,
                        b"PUT" => Method::Put,
                        b"DELETE" => Method::Delete,
                        _ => Method::Unknown,
                    };
                }
                b":path" => self.req.set_path(value),
                // :scheme / :authority — we don't currently
                // use either; drop on the floor.
                n if n.starts_with(b":") => {}
                // Regular header — copy into the fixed-size
                // 16-slot table. Truncates silently past the
                // cap, matching the HTTP/1.1 parser's behavior.
                _ => self.req.push_header(name, value),
            }
        }
    }
    let mut req = Request::new();
    {
        let mut sink = RequestSink { req: &mut req };
        // 4 KiB on the stack covers ≥99th percentile
        // worst-case Huffman expansion (4× the input length)
        // for any header in normal browser traffic. A literal
        // header that exceeds this surfaces as
        // `qpack_decode_error` and the stream is closed.
        let mut name_scratch = [0u8; 4096];
        let mut value_scratch = [0u8; 4096];
        if let Err(e) = qpack::decode_field_section_into(
            &headers_value,
            &mut name_scratch,
            &mut value_scratch,
            &mut sink,
        ) {
            crate::h3_drop!(qpack_decode_error,
                "sid={} err={:?} header_len={}",
                sid, e, headers_value.len());
            conn.close_stream(sid);
            return;
        }
    }
    req.set_body(&data[..]);

    crate::diag::bump(&crate::diag::COUNTERS.user_handler_invoked);
    let response = handler(req).await;
    crate::diag::bump(&crate::diag::COUNTERS.user_handler_returned);
    let status = response.status;
    // Encode response: HEADERS + DATA + FIN.
    write_response(conn, sid, response);
    crate::diag::bump(&crate::diag::COUNTERS.write_response_completed);
    crate::h3_event!(requests_handled, "sid={} status={}", sid, status);
    crate::diag::bump(&crate::diag::COUNTERS.responses_sent);
}

/// Maximum bytes an H3 frame header (type varint + length
/// varint) can take. Both varints are at most 8 bytes (RFC 9000
/// §16) but in practice our types are 1-byte and our lengths
/// fit in 4-byte varints. Round to 16 to give the IOBuf payload
/// alignment-friendly bookends.
const H3_FRAME_HEADER_MAX: usize = 16;

/// Cap on the QPACK body for a typical response. The default
/// 3-header response (`:status`, `content-type`, `content-
/// length`) encodes to ~25-30 bytes; each app-side
/// `Response::with_header` adds a literal-name + value (≈
/// `2 + name.len() + value.len()` bytes). 256 covers the
/// default + ~6 typical extra headers (Alt-Svc, Cache-Control,
/// ETag, etc.) before overflow; oversize headers surface as
/// `qpack_encode_overflow` and the stream closes cleanly.
///
/// Sized small intentionally — this is the per-request IOBuf's
/// payload region, allocated fresh per response. Smaller bucket
/// → smaller fragmentation footprint → cheaper allocator
/// path. Trim further if profiling shows headroom.
const QPACK_BODY_RESERVE: usize = 256;

fn write_response(conn: &QuicConn, sid: u64, resp: Response) {
    // Build the response framing as a single IOBuf with
    // reserved headroom for the H3 HEADERS frame header and
    // tailroom for the optional H3 DATA frame header. QPACK
    // encodes directly into the IOBuf's payload region, so:
    //
    //   * No separate `qpack_buf: Vec` scratch (was per-conn).
    //   * No `qpack_buf → framing` memcpy (was ~150-300 B/request).
    //   * The H3 frame headers prepend / append IN PLACE.
    //
    // One heap alloc per response (the IOBuf), same alloc
    // count as the previous `framing: Vec<u8>` approach, but
    // the response is built end-to-end with no intermediate
    // buffers and no copies between them.
    let status_str = status_to_bytes(resp.status);
    let body_len = resp.body_len();
    let mut len_buf = [0u8; 20];
    let len_off = format_usize_into(body_len, &mut len_buf);

    // Allocate the framing IOBuf: `[headroom][qpack body
    // capacity][tailroom]`. The headroom holds the HEADERS
    // frame header after we know the QPACK length; the
    // tailroom holds the DATA frame header (when there's a
    // body).
    let mut framing = uni_http::IOBuf::new_with_reserved(
        H3_FRAME_HEADER_MAX,
        QPACK_BODY_RESERVE,
        H3_FRAME_HEADER_MAX,
    );

    // Encode the QPACK field section directly into the IOBuf's
    // tailroom region (the space we just reserved as
    // payload-capacity). `extend_uninit` returns a `&mut [u8]`
    // pointing at that region; we then trim it back to the
    // exact encoded length.
    let qpack_len = {
        let region = framing
            .extend_uninit(QPACK_BODY_RESERVE)
            .expect("qpack reserve fits in fresh IOBuf");
        match qpack::encode_field_section_into(
            &[
                (&b":status"[..], status_str.as_slice()),
                (&b"content-type"[..], resp.content_type_bytes()),
                (&b"content-length"[..], &len_buf[len_off..]),
            ],
            region,
        ) {
            Ok(n) => n,
            Err(_) => {
                crate::h3_drop!(qpack_encode_overflow,
                    "sid={} status={} qpack_reserve={}",
                    sid, resp.status, QPACK_BODY_RESERVE);
                conn.close_stream(sid);
                return;
            }
        }
    };
    // Shrink the visible payload to just the encoded QPACK
    // bytes; the unused remainder stays as tailroom for the
    // DATA frame header below.
    framing
        .trim_end(QPACK_BODY_RESERVE - qpack_len)
        .expect("qpack_len <= reserve");

    // Prepend the H3 HEADERS frame header into the IOBuf's
    // reserved headroom — no allocation, no copy of the QPACK
    // body. Slice-target frame writer keeps this stack-only.
    let mut hdr_buf = [0u8; H3_FRAME_HEADER_MAX];
    let hdr_len = frame::write_frame_header(h3_ftype::HEADERS, qpack_len, &mut hdr_buf)
        .expect("headers frame header fits");
    framing
        .prepend(&hdr_buf[..hdr_len])
        .expect("HEADERS hdr fits in reserved headroom");

    // Append the H3 DATA frame header into the tailroom (if
    // there's a body to follow).
    if body_len > 0 {
        let dlen = frame::write_frame_header(h3_ftype::DATA, body_len, &mut hdr_buf)
            .expect("data frame header fits");
        framing
            .append_slice(&hdr_buf[..dlen])
            .expect("DATA hdr fits in reserved tailroom");
    }

    // Move the framing IOBuf into the SendStream as a single
    // chunk. SendStream now natively holds IOBufs (no Vec
    // conversion), so reserved headroom/tailroom on body parts
    // also passes through cleanly for downstream layers.
    conn.send_iobuf(sid, framing);

    // Queue each body chunk on the QUIC stream. Static borrows
    // stay borrowed; heap-owned chunks move via send_iobuf.
    if body_len > 0 {
        match resp.into_body() {
            uni_http::ResponseBody::Single(b) => queue_chunk(conn, sid, b),
            uni_http::ResponseBody::Chain(chain) => {
                for part in chain.into_parts() {
                    queue_chunk(conn, sid, part);
                }
            }
        }
    }
    // FIN is set by close_stream; the next pop_chunk_into emits
    // it on the last queued chunk.
    conn.close_stream(sid);
}

/// Push one IOBuf chunk onto stream `sid`. SendStream now holds
/// IOBufs natively, so we can move the chunk through without
/// converting to a Vec. Saves the `into_owned_vec()` materialisation
/// (which copied for non-trivial offset/len) plus preserves any
/// reserved headroom/tailroom for layers below to prepend / append.
fn queue_chunk(conn: &QuicConn, sid: u64, b: uni_http::IOBuf) {
    conn.send_iobuf(sid, b);
}

fn status_to_bytes(status: i32) -> [u8; 3] {
    let s = status.clamp(0, 999) as u32;
    [
        b'0' + ((s / 100) as u8),
        b'0' + (((s / 10) % 10) as u8),
        b'0' + ((s % 10) as u8),
    ]
}

/// Format `n` as ASCII decimal into the caller's stack buffer.
/// Returns the offset where the digits start; the slice
/// `&buf[off..]` is the formatted number. Callers use this
/// instead of returning a Vec so the per-response Content-Length
/// rendering doesn't allocate.
fn format_usize_into(n: usize, buf: &mut [u8; 20]) -> usize {
    if n == 0 {
        buf[19] = b'0';
        return 19;
    }
    let mut i = buf.len();
    let mut v = n;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    i
}

