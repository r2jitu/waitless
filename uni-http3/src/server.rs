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
use crate::qpack;

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
    // Per-connection scratch for the request-recv buffer. Each
    // handle_request `clear()`s it on entry — capacity stays —
    // instead of allocating a fresh 16 KiB Vec per request. For
    // a refresh-spamming session this saves one 16 KiB alloc
    // per refresh (the largest single alloc on the request hot
    // path).
    let mut recv_scratch: Vec<u8> = Vec::with_capacity(16 * 1024);
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
            handle_request(&conn, sid, h.as_ref(), &mut recv_scratch).await;
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

async fn handle_request<H, F>(
    conn: &QuicConn,
    sid: u64,
    handler: &H,
    buf: &mut Vec<u8>,
) where
    H: Fn(Request) -> F,
    F: core::future::Future<Output = Response>,
{
    // Accumulate stream bytes until we have a complete H3 frame
    // sequence: HEADERS frame, then 0+ DATA frames, then FIN.
    //
    // Buffer cap: enough for our worst-case single request (path +
    // headers + small body). Match `uni_http::Request`'s 8 KiB body.
    // The buf is per-conn scratch; we clear() and reuse capacity
    // across requests on the same connection.
    const RECV_CAP: usize = 16 * 1024;
    buf.clear();
    let mut chunk = [0u8; 4096];
    let mut headers_seen = false;
    let mut headers_value: Vec<u8> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
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
                    headers_value = body.to_vec();
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

    // Decode QPACK headers.
    let fields = match qpack::decode_field_section(&headers_value) {
        Ok(f) => f,
        Err(e) => {
            crate::h3_drop!(qpack_decode_error,
                "sid={} err={:?} header_len={}",
                sid, e, headers_value.len());
            conn.close_stream(sid);
            return;
        }
    };

    // Translate to uni_http::Request. Field name/value are
    // Cow<'static, [u8]> — deref to &[u8] for the comparisons.
    let mut req = Request::new();
    let mut method_bytes: &[u8] = b"";
    let mut path_bytes: &[u8] = b"";
    for f in &fields {
        let name: &[u8] = &f.name;
        if name == b":method" {
            method_bytes = &f.value;
        } else if name == b":path" {
            path_bytes = &f.value;
        }
    }
    req.method = match method_bytes {
        b"GET" => Method::Get,
        b"HEAD" => Method::Head,
        b"POST" => Method::Post,
        b"PUT" => Method::Put,
        b"DELETE" => Method::Delete,
        _ => Method::Unknown,
    };
    req.set_path(path_bytes);
    req.set_body(&data);
    // Pass through user headers (excluding pseudo-headers, which
    // start with ':').
    for f in &fields {
        let name: &[u8] = &f.name;
        if !name.starts_with(b":") {
            req.push_header(name, &f.value);
        }
    }

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

fn write_response(conn: &QuicConn, sid: u64, resp: Response) {
    // Build the response wire stream as a sequence of chunks.
    //   1. A small "framing" Vec containing [H3 HEADERS frame
    //      complete + qpack-encoded fields][H3 DATA frame
    //      header — type+length, no body].
    //   2. Each body part — Static (borrowed slice, zero alloc),
    //      Owned (Vec by move), or several of each in a Chain.
    //
    // The framing knows the total body length up front, so a
    // multi-part body still ships as one DATA frame with the
    // sum of part lengths in its length-prefix; parts get
    // queued as separate SendChunks but reach the wire as
    // contiguous bytes inside the QUIC STREAM frame.
    let status_str = status_to_bytes(resp.status);
    let body_len = resp.body_len();
    let mut len_buf = [0u8; 20];
    let len_off = format_usize_into(body_len, &mut len_buf);

    let mut qpack_buf: Vec<u8> = Vec::with_capacity(128);
    qpack::encode_field_section(
        &[
            (&b":status"[..], status_str.as_slice()),
            (&b"content-type"[..], resp.content_type_bytes()),
            (&b"content-length"[..], &len_buf[len_off..]),
        ],
        &mut qpack_buf,
    );

    let mut framing: Vec<u8> = Vec::with_capacity(qpack_buf.len() + 16);
    frame::append_frame_header(h3_ftype::HEADERS, qpack_buf.len(), &mut framing)
        .expect("headers frame header fits");
    framing.extend_from_slice(&qpack_buf);
    if body_len > 0 {
        frame::append_frame_header(h3_ftype::DATA, body_len, &mut framing)
            .expect("data frame header fits");
    }

    conn.send_owned(sid, framing);

    // Queue each body chunk on the QUIC stream. Cow::Borrowed
    // → send_static (zero alloc); Cow::Owned → send_owned (move).
    if body_len > 0 {
        match resp.into_body() {
            uni_http::ResponseBody::Single(b) => queue_chunk(conn, sid, b),
            uni_http::ResponseBody::Chain { parts, .. } => {
                for part in parts {
                    queue_chunk(conn, sid, part);
                }
            }
        }
    }
    // FIN is set by close_stream; the next pop_chunk_into emits
    // it on the last queued chunk.
    conn.close_stream(sid);
}

/// Push one Bytes chunk onto stream `sid`. Pattern-matches on
/// the Cow variant to pick the zero-alloc borrowed-static path
/// or the by-move owned path.
fn queue_chunk(conn: &QuicConn, sid: u64, b: uni_http::Bytes) {
    match b {
        alloc::borrow::Cow::Borrowed(s) => conn.send_static(sid, s),
        alloc::borrow::Cow::Owned(v) => conn.send_owned(sid, v),
    }
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

