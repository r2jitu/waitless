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
use alloc::vec;
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
            handle_request(&conn, sid, h.as_ref()).await;
        }
        // Peer unidirectional streams (id & 0x3 == 0x2) — control,
        // QPACK encoder, QPACK decoder. Don't actively drain them
        // — they'd block the accept loop until they FIN, which
        // doesn't happen for the lifetime of the connection.
        // Inbound bytes accumulate in their per-stream recv
        // buffers harmlessly; we never read them.
        // sid & 0x3 == 0x1 → server-initiated bidi (we don't open
        // any), or sid & 0x3 == 0x3 → server-initiated uni (we
        // opened the control stream above; peers don't echo).
    }
}

async fn handle_request<H, F>(conn: &QuicConn, sid: u64, handler: &H)
where
    H: Fn(Request) -> F,
    F: core::future::Future<Output = Response>,
{
    // Accumulate stream bytes until we have a complete H3 frame
    // sequence: HEADERS frame, then 0+ DATA frames, then FIN.
    //
    // Buffer cap: enough for our worst-case single request (path +
    // headers + small body). Match `uni_http::Request`'s 8 KiB body.
    const RECV_CAP: usize = 16 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(RECV_CAP);
    let mut chunk = [0u8; 4096];
    let mut headers_seen = false;
    let mut headers_value: Vec<u8> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    let mut eof = false;

    while !eof {
        let (n, end) = conn.recv(sid, &mut chunk).await;
        if n > 0 {
            if buf.len() + n > RECV_CAP {
                return; // request too large; drop conn
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
                Err(_) => return, // malformed; bail
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
    if !headers_seen {
        return;
    }

    // Decode QPACK headers.
    let fields = match qpack::decode_field_section(&headers_value) {
        Ok(f) => f,
        Err(_) => return,
    };

    // Translate to uni_http::Request.
    let mut req = Request::new();
    let mut method_bytes: &[u8] = b"";
    let mut path_bytes: &[u8] = b"";
    for f in &fields {
        if f.name == b":method" {
            method_bytes = &f.value;
        } else if f.name == b":path" {
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
        if !f.name.starts_with(b":") {
            req.push_header(&f.name, &f.value);
        }
    }

    let response = handler(req).await;
    // Encode response: HEADERS + DATA + FIN.
    write_response(conn, sid, &response);
}

fn write_response(conn: &QuicConn, sid: u64, resp: &Response) {
    // Build HEADERS payload via QPACK.
    let status_str = status_to_bytes(resp.status);
    let content_type = resp.content_type_bytes();
    let body = resp.body_bytes();
    let len_str = format_usize(body.len());

    let headers: alloc::vec::Vec<(&[u8], &[u8])> = alloc::vec![
        (&b":status"[..], status_str.as_slice()),
        (&b"content-type"[..], content_type),
        (&b"content-length"[..], len_str.as_slice()),
    ];
    let mut qpack_buf: Vec<u8> = Vec::with_capacity(64 + body.len() / 8);
    qpack::encode_field_section(&headers, &mut qpack_buf);

    // Bundle HEADERS + DATA into a single byte buffer so the
    // stream layer ships them in as few QUIC packets as possible.
    let mut payload: Vec<u8> = Vec::with_capacity(qpack_buf.len() + body.len() + 16);
    {
        let mut tmp = vec![0u8; qpack_buf.len() + 8];
        let n = frame::write_frame(h3_ftype::HEADERS, &qpack_buf, &mut tmp)
            .expect("headers frame fits");
        payload.extend_from_slice(&tmp[..n]);
    }
    if !body.is_empty() {
        let mut tmp = vec![0u8; body.len() + 8];
        let n = frame::write_frame(h3_ftype::DATA, body, &mut tmp).expect("data frame fits");
        payload.extend_from_slice(&tmp[..n]);
    }

    // One-shot send+FIN: bundles HEADERS+DATA bytes and the FIN
    // marker into a single STREAM frame (and ideally a single
    // 1-RTT packet). Avoids the FIN-without-data corner case
    // where some H3 clients may discard the request stream
    // before observing the data half.
    conn.send_fin(sid, &payload);
}

fn status_to_bytes(status: i32) -> [u8; 3] {
    let s = status.clamp(0, 999) as u32;
    [
        b'0' + ((s / 100) as u8),
        b'0' + (((s / 10) % 10) as u8),
        b'0' + ((s % 10) as u8),
    ]
}

fn format_usize(n: usize) -> Vec<u8> {
    if n == 0 {
        return alloc::vec![b'0'];
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut v = n;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    buf[i..].to_vec()
}

