// crates/proto/http3/src/client.rs — client-role HTTP/3 over one QUIC
// connection.
//
// The client mirror of `server.rs`, shaped like the h2 client
// (proto/http2/src/client.rs): where the server answers requests,
// [`H3ClientConn`] issues them — same frame codec (`frame.rs`), same
// static-only QPACK (`qpack.rs`), opposite side of the wire:
//
//   * WE open the client control stream (uni id 2: stream-type 0x00 +
//     an empty SETTINGS, RFC 9114 §6.2.1) and put each request on a
//     client bidi stream (0, 4, 8, …): QPACK-encoded pseudo-headers in
//     a HEADERS frame, the optional body as one DATA frame, FIN.
//   * The response is HEADERS (`:status` + fields) then DATA until
//     FIN. 1xx interim heads are skipped; trailers are discarded.
//   * The server's uni streams (control / QPACK encoder / decoder)
//     are drained opportunistically between reads; a GOAWAY on its
//     control stream is surfaced on the NEXT request (§5.2), matching
//     the h2 client's convention.
//   * A peer RESET_STREAM surfaces as [`H3ClientError::StreamReset`]
//     (the S1 abort surface) — a clean error, never a hang or a
//     truncated-but-200 response.
//
// v1 scope (the h2 client's ledger, transposed):
//   * One request in flight at a time — sequential keep-alive.
//   * The request body is buffered (`Option<&[u8]>`), bounded by the
//     peer's flow-control windows via the QUIC send path.
//   * No 0-RTT, no server push (we never send MAX_PUSH_ID, so the
//     server MUST NOT push).
//
// Generic over [`ClientTransport`] — the slice of
// [`quic::QuicClientConn`] the client consumes. Production
// monomorphises to the real connector; the loopback tests below
// implement it over a raw client-role `Connection` pumped against the
// REAL h3 server-role processing (`server::handle_request`) on a raw
// server-role `Connection` — the E1 in-process pump, one layer up.

use alloc::vec::Vec;

use tls::client::{ServerAuth, TlsClientConfig};

use crate::frame::{self, ftype as h3_ftype};
use crate::qpack::{self, FieldSink};
use crate::server::STREAM_TYPE_CONTROL;

/// Decoded response head: status + owned (name, value) header pairs.
type ResponseHead = (u16, Vec<(Vec<u8>, Vec<u8>)>);
use quic::wire::read_varint;

/// ALPN offer for HTTP/3 (RFC 9114 §3.1).
pub const ALPN_H3: &[&[u8]] = &[b"h3"];

/// Cap on a response HEADERS frame (QPACK field section) — the same
/// guard class as the server's pre-HEADERS accumulation cap.
const RESP_HEADERS_CAP: usize = 64 * 1024;

/// QPACK decode scratch sizes (mirror the server's request path).
const NAME_SCRATCH_LEN: usize = 4096;
const VALUE_SCRATCH_LEN: usize = 4096;

/// Most peer uni streams tracked (control + QPACK encoder + decoder
/// is 3; headroom for duplicates).
const MAX_PEER_UNI: usize = 6;

// ── Errors ─────────────────────────────────────────────────────────

/// Why an HTTP/3 request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ClientError {
    /// The QUIC connection is dead (failed / closed) — reconnect.
    Closed,
    /// The server reset the request stream (its h3 error code). The
    /// connection survives.
    StreamReset(u64),
    /// The server sent GOAWAY; no new requests on this connection.
    GoAway,
    /// The response was malformed (no/invalid `:status`, DATA before
    /// HEADERS, QPACK/frame parse failure).
    Malformed,
    /// The response body exceeded the caller's cap; the stream was
    /// cancelled (STOP_SENDING). The connection survives.
    BodyTooLarge,
}

/// One-shot [`h3_get`] failure: which half died.
#[derive(Debug)]
pub enum H3FetchError {
    /// QUIC connect/handshake stage (socket bind, TLS, timeout).
    Connect(quic::QuicConnectError),
    /// The h3 request/response exchange.
    H3(H3ClientError),
}

// ── Response ───────────────────────────────────────────────────────

/// A complete, buffered HTTP/3 response — mirrors `H2Response`.
pub struct H3Response {
    pub status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl core::fmt::Debug for H3Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("H3Response")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl H3Response {
    /// Case-insensitive header lookup (first occurrence).
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// All decoded `(name, value)` response headers, wire order.
    pub fn headers(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.headers.iter().map(|(n, v)| (n.as_slice(), v.as_slice()))
    }
}

// ── Transport seam ─────────────────────────────────────────────────

/// The h3 client's view of a QUIC client connection — exactly the
/// slice of [`quic::QuicClientConn`] it consumes. The loopback tests
/// implement this over a raw client-role `Connection` so the REAL
/// client code runs against the REAL server-role processing with no
/// sockets or runtime.
#[allow(async_fn_in_trait)] // single-threaded per-worker futures; no Send bound wanted
pub trait ClientTransport {
    fn open_bidi_stream(&self) -> u64;
    fn open_uni_stream(&self) -> u64;
    fn send_owned(&self, sid: u64, data: Vec<u8>);
    fn close_stream(&self, sid: u64);
    async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool);
    /// Non-blocking recv — `None` when nothing is buffered.
    fn try_recv(&self, sid: u64, out: &mut [u8]) -> Option<(usize, bool)>;
    /// Non-blocking accept of a peer-opened (server uni) stream.
    fn try_accept_stream(&self) -> Option<u64>;
    fn stream_reset_code(&self, sid: u64) -> Option<u64>;
    fn stop_sending(&self, sid: u64, app_error_code: u64);
    fn is_failed(&self) -> bool;
    /// Orderly connection close (CONNECTION_CLOSE).
    fn close(&self);
}

impl ClientTransport for quic::QuicClientConn {
    fn open_bidi_stream(&self) -> u64 {
        quic::QuicClientConn::open_bidi_stream(self)
    }
    fn open_uni_stream(&self) -> u64 {
        quic::QuicClientConn::open_uni_stream(self)
    }
    fn send_owned(&self, sid: u64, data: Vec<u8>) {
        quic::QuicClientConn::send_owned(self, sid, data);
    }
    fn close_stream(&self, sid: u64) {
        quic::QuicClientConn::close_stream(self, sid);
    }
    async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        quic::QuicClientConn::recv(self, sid, out).await
    }
    fn try_recv(&self, sid: u64, out: &mut [u8]) -> Option<(usize, bool)> {
        quic::QuicClientConn::try_recv(self, sid, out)
    }
    fn try_accept_stream(&self) -> Option<u64> {
        quic::QuicClientConn::try_accept_stream(self)
    }
    fn stream_reset_code(&self, sid: u64) -> Option<u64> {
        quic::QuicClientConn::stream_reset_code(self, sid)
    }
    fn stop_sending(&self, sid: u64, app_error_code: u64) {
        quic::QuicClientConn::stop_sending(self, sid, app_error_code);
    }
    fn is_failed(&self) -> bool {
        quic::QuicClientConn::is_failed(self)
    }
    fn close(&self) {
        quic::QuicClientConn::close(self, 0x0, b"done");
    }
}

// ── Connection state ───────────────────────────────────────────────

/// One peer (server-initiated) uni stream being tracked: bytes
/// accumulate until the stream-type varint identifies it; the control
/// stream's frames are then parsed (SETTINGS ignored, GOAWAY
/// surfaced), everything else is discarded.
struct PeerUni {
    sid: u64,
    buf: Vec<u8>,
    /// Stream type once decoded; `None` until the varint is complete.
    kind: Option<u64>,
}

/// One client-role HTTP/3 connection over `T`. Construct via
/// [`h3_connect`] (or [`H3ClientConn::new`] over a custom transport);
/// issue requests with [`H3ClientConn::request`] / [`h3_fetch`].
/// Sequential: one request in flight at a time (v1).
pub struct H3ClientConn<T: ClientTransport> {
    conn: T,
    /// Largest request-stream id named by a server GOAWAY, if any.
    goaway: Option<u64>,
    /// Peer uni streams (control / QPACK enc / QPACK dec).
    peer_uni: Vec<PeerUni>,
}

impl<T: ClientTransport> H3ClientConn<T> {
    /// Wrap an established QUIC client connection: opens our control
    /// stream (uni) and ships the stream-type byte + empty SETTINGS
    /// (RFC 9114 §6.2.1 — defaults: no QPACK dynamic table).
    pub fn new(conn: T) -> Self {
        let ctrl = conn.open_uni_stream();
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        buf.push(STREAM_TYPE_CONTROL as u8);
        let mut settings = [0u8; 8];
        let n = frame::write_empty_settings(&mut settings).expect("write settings");
        buf.extend_from_slice(&settings[..n]);
        conn.send_owned(ctrl, buf);
        H3ClientConn {
            conn,
            goaway: None,
            peer_uni: Vec::new(),
        }
    }

    /// Issue one request and await its complete response. `headers`
    /// are regular fields only (pseudo-headers come from the explicit
    /// parameters, encoded first per RFC 9114 §4.3.1); the response
    /// body is bounded by `body_cap`.
    pub async fn request(
        &mut self,
        method: &[u8],
        authority: &[u8],
        path: &[u8],
        headers: &[(&[u8], &[u8])],
        body: Option<&[u8]>,
        body_cap: usize,
    ) -> Result<H3Response, H3ClientError> {
        if self.conn.is_failed() {
            return Err(H3ClientError::Closed);
        }
        self.poll_control();
        if self.goaway.is_some() {
            // §5.2: the server is winding down — a new (higher)
            // request stream would not be processed.
            return Err(H3ClientError::GoAway);
        }

        // ── Send: HEADERS (+ DATA) + FIN on a fresh bidi stream ────
        let sid = self.conn.open_bidi_stream();
        let mut list: Vec<(&[u8], &[u8])> = Vec::with_capacity(4 + headers.len());
        list.push((&b":method"[..], method));
        list.push((&b":scheme"[..], &b"https"[..]));
        list.push((&b":authority"[..], authority));
        list.push((&b":path"[..], path));
        list.extend_from_slice(headers);
        let mut block = Vec::with_capacity(96);
        qpack::encode_field_section(&list, &mut block);
        let mut req_buf =
            Vec::with_capacity(16 + block.len() + body.map_or(0, |b| 16 + b.len()));
        frame::append_frame_header(h3_ftype::HEADERS, block.len(), &mut req_buf)
            .expect("headers frame header");
        req_buf.extend_from_slice(&block);
        if let Some(b) = body {
            frame::append_frame_header(h3_ftype::DATA, b.len(), &mut req_buf)
                .expect("data frame header");
            req_buf.extend_from_slice(b);
        }
        self.conn.send_owned(sid, req_buf);
        self.conn.close_stream(sid); // FIN — the request is complete

        // ── Receive: HEADERS → DATA* → FIN ─────────────────────────
        let mut acc: Vec<u8> = Vec::with_capacity(2048);
        let mut chunk = [0u8; 4096];
        let mut head: Option<ResponseHead> = None;
        let mut resp_body: Vec<u8> = Vec::new();
        let mut eof = false;
        loop {
            // Parse complete frames off the front of the accumulator.
            loop {
                let (consumed, done) = match frame::parse_frame(&acc) {
                    Ok((frame::Frame::Headers(blockb), used)) => {
                        if head.is_none() {
                            let (status, fields) = decode_response_head(blockb)?;
                            if !(100..200).contains(&status) {
                                head = Some((status, fields));
                            }
                            // 1xx interim head: discard, await the
                            // final one (RFC 9114 §4.1).
                        }
                        // Post-body HEADERS = trailers — discarded (v1).
                        (used, false)
                    }
                    Ok((frame::Frame::Data(payload), used)) => {
                        if head.is_none() {
                            // DATA before HEADERS is malformed (§4.1).
                            return Err(H3ClientError::Malformed);
                        }
                        if resp_body.len() + payload.len() > body_cap {
                            // Over budget: cancel our interest in the
                            // stream, keep the connection.
                            self.conn
                                .stop_sending(sid, crate::errcode::H3_REQUEST_CANCELLED);
                            return Err(H3ClientError::BodyTooLarge);
                        }
                        resp_body.extend_from_slice(payload);
                        (used, false)
                    }
                    // Control-stream-only / push frames on a request
                    // stream are skipped leniently, like the server's
                    // pre-HEADERS skip.
                    Ok((_, used)) => (used, false),
                    Err(frame::FrameError::Truncated) => (0, true),
                    Err(_) => return Err(H3ClientError::Malformed),
                };
                if done {
                    break;
                }
                if acc.len() > RESP_HEADERS_CAP && head.is_none() {
                    return Err(H3ClientError::Malformed);
                }
                acc.drain(..consumed);
            }
            if eof {
                return match head {
                    Some((status, headers)) => Ok(H3Response {
                        status,
                        headers,
                        body: resp_body,
                    }),
                    None => {
                        if let Some(code) = self.conn.stream_reset_code(sid) {
                            Err(H3ClientError::StreamReset(code))
                        } else if self.conn.is_failed() {
                            Err(H3ClientError::Closed)
                        } else {
                            Err(H3ClientError::Malformed)
                        }
                    }
                };
            }
            let (n, end) = self.conn.recv(sid, &mut chunk).await;
            // S1 surface: a peer RESET_STREAM ends the read with a
            // clean error — never a truncated-but-OK response.
            if let Some(code) = self.conn.stream_reset_code(sid) {
                return Err(H3ClientError::StreamReset(code));
            }
            if n > 0 {
                acc.extend_from_slice(&chunk[..n]);
            }
            if end {
                if n == 0 && acc.is_empty() && head.is_none() && self.conn.is_failed() {
                    return Err(H3ClientError::Closed);
                }
                eof = true;
            }
            // Keep the server's control stream drained (GOAWAY etc.).
            self.poll_control();
        }
    }

    /// Whether the server has sent GOAWAY (no new requests).
    pub fn goaway_received(&mut self) -> bool {
        self.poll_control();
        self.goaway.is_some()
    }

    /// Orderly wind-down: close the QUIC connection.
    pub fn close(&self) {
        self.conn.close();
    }

    /// Drain the server's uni streams without blocking: identify each
    /// by its stream-type varint, parse control-stream frames
    /// (SETTINGS ignored, GOAWAY surfaced), discard QPACK streams
    /// (static-only — their bytes are uninteresting but must not
    /// accumulate).
    fn poll_control(&mut self) {
        while let Some(sid) = self.conn.try_accept_stream() {
            let known = self.peer_uni.iter().any(|u| u.sid == sid);
            if sid & 0x3 == 0x3 && !known && self.peer_uni.len() < MAX_PEER_UNI {
                self.peer_uni.push(PeerUni {
                    sid,
                    buf: Vec::new(),
                    kind: None,
                });
            }
        }
        let mut chunk = [0u8; 1024];
        for u in &mut self.peer_uni {
            loop {
                match self.conn.try_recv(u.sid, &mut chunk) {
                    Some((n, _eof)) if n > 0 => u.buf.extend_from_slice(&chunk[..n]),
                    _ => break,
                }
            }
            if u.kind.is_none()
                && let Ok((ty, n)) = read_varint(&u.buf)
            {
                u.kind = Some(ty);
                u.buf.drain(..n);
            }
            match u.kind {
                Some(STREAM_TYPE_CONTROL) => {
                    // Parse complete frames; GOAWAY carries the
                    // largest request id the server will process.
                    loop {
                        match frame::parse_frame(&u.buf) {
                            Ok((frame::Frame::GoAway(id), used)) => {
                                self.goaway = Some(id);
                                u.buf.drain(..used);
                            }
                            Ok((_, used)) => {
                                u.buf.drain(..used);
                            }
                            Err(_) => break, // truncated → wait for more
                        }
                    }
                }
                Some(_) => u.buf.clear(),  // QPACK / unknown: discard
                None => {}                 // type varint incomplete
            }
        }
    }
}

/// Decode a response HEADERS block: `:status` (exactly once, 3 ASCII
/// digits) + regular fields. The client cousin of the server's
/// `RequestSink`.
fn decode_response_head(
    block: &[u8],
) -> Result<ResponseHead, H3ClientError> {
    struct RespSink {
        status: u16,
        fields: Vec<(Vec<u8>, Vec<u8>)>,
        malformed: bool,
    }
    impl FieldSink for RespSink {
        fn on_field(&mut self, name: &[u8], value: &[u8]) {
            if name == b":status" {
                if self.status != 0
                    || value.len() != 3
                    || !value.iter().all(u8::is_ascii_digit)
                {
                    self.malformed = true;
                    return;
                }
                self.status = (value[0] - b'0') as u16 * 100
                    + (value[1] - b'0') as u16 * 10
                    + (value[2] - b'0') as u16;
                return;
            }
            if name.first() == Some(&b':') {
                // `:status` is the only response pseudo-header (§4.3.2).
                self.malformed = true;
                return;
            }
            self.fields.push((name.to_vec(), value.to_vec()));
        }
    }
    let mut sink = RespSink {
        status: 0,
        fields: Vec::new(),
        malformed: false,
    };
    let mut name_scratch = [0u8; NAME_SCRATCH_LEN];
    let mut value_scratch = [0u8; VALUE_SCRATCH_LEN];
    qpack::decode_field_section_into(block, &mut name_scratch, &mut value_scratch, &mut sink)
        .map_err(|_| H3ClientError::Malformed)?;
    if sink.malformed || sink.status == 0 {
        return Err(H3ClientError::Malformed);
    }
    Ok((sink.status, sink.fields))
}

// ============================================================================
// h3_connect / h3_fetch / h3_get — the connect + single-shot facades
// ============================================================================

/// Dial an HTTP/3 server: QUIC connect (ALPN "h3") + the client
/// control stream. Entropy by value; `auth` pins the server's SPKI
/// (or `InsecureSkipVerify` for dev probes).
pub async fn h3_connect(
    ip: waitless::runtime::IpAddr,
    port: u16,
    auth: ServerAuth,
    seed: [u8; 32],
) -> Result<H3ClientConn<quic::QuicClientConn>, quic::QuicConnectError> {
    let config = TlsClientConfig {
        auth,
        server_name: None,
        alpn: ALPN_H3,
    };
    let conn = quic::quic_connect(ip, port, &config, seed).await?;
    Ok(H3ClientConn::new(conn))
}

/// One request/response exchange on an established [`H3ClientConn`],
/// reusing the h1/h2 clients' [`http::client::FetchRequest`] shape:
/// `host` → `:authority`, the scheme is `https` (h3 is QUIC-only),
/// `close` is ignored (wind down via [`H3ClientConn::close`]).
pub async fn h3_fetch<T: ClientTransport>(
    conn: &mut H3ClientConn<T>,
    req: &http::client::FetchRequest<'_>,
    body_cap: usize,
) -> Result<H3Response, H3ClientError> {
    conn.request(req.method, req.host, req.path, req.headers, req.body, body_cap)
        .await
}

/// One-shot HTTPS-over-QUIC GET: connect, fetch, close. Returns
/// `(status, body)` — the h3 sibling of `http2::https_fetch`.
pub async fn h3_get(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    auth: ServerAuth,
    seed: [u8; 32],
    body_cap: usize,
) -> Result<(u16, Vec<u8>), H3FetchError> {
    let mut conn = h3_connect(ip, port, auth, seed)
        .await
        .map_err(H3FetchError::Connect)?;
    let req = http::client::FetchRequest::get(host, path);
    let resp = h3_fetch(&mut conn, &req, body_cap)
        .await
        .map_err(H3FetchError::H3)?;
    conn.close();
    Ok((resp.status, resp.body))
}

// ============================================================================
// Tests — the in-process h3 loopback (the E2 centerpiece)
// ============================================================================

/// REAL h3 client (this module) over a REAL client-role QUIC
/// `Connection`, pumped against the REAL h3 server-role request
/// processing (`server::handle_request` — frame parse, QPACK decode,
/// handler dispatch, response framing, S1 reset wiring) on a REAL
/// server-role `Connection` — the E1 in-process pump extended one
/// layer up. No sockets, no runtime: futures are hand-polled with a
/// noop waker and datagrams are pumped between polls.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use crate::server::{self, Scratch, ServerConn};
    use alloc::rc::Rc;
    use core::cell::{Cell, RefCell};
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use http::{IOBuf, Request, Response};
    use quic::{ConnState, Connection, ConnectionId};
    use tls::TlsServerConfig;
    use tls::client::spki_pin_from_cert_der;

    const CERT: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_key.der");
    const HEADROOM: usize = quic::MAX_L2_HEADROOM;

    fn noop_waker() -> Waker {
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        fn nop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, nop, nop, nop);
        // SAFETY: every vtable entry is a no-op over a null pointer.
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    /// Poll-function future: re-evaluates `f` on every poll; Pending
    /// until it yields a value. The loopback's park-point — the
    /// driver pumps datagrams between polls, so "Pending" simply
    /// means "give the other side a turn".
    struct WaitFor<F>(F);
    impl<T, F: FnMut() -> Option<T> + Unpin> Future for WaitFor<F> {
        type Output = T;
        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
            match (self.0)() {
                Some(v) => Poll::Ready(v),
                None => Poll::Pending,
            }
        }
    }
    fn wait_for<T, F: FnMut() -> Option<T> + Unpin>(f: F) -> WaitFor<F> {
        WaitFor(f)
    }

    /// The two raw QUIC connections + the datagram pump between them.
    struct Pair {
        client: Rc<RefCell<Connection>>,
        server: Rc<RefCell<Connection>>,
        cfg: Rc<TlsServerConfig>,
    }

    impl Pair {
        /// Handshake a fresh client↔server pair to Established.
        fn new(seed: u8) -> Pair {
            quic::sim_clock::pin_at_least(1_000_000 + seed as u64 * 1_000_000);
            let cfg = Rc::new(TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert"));
            let ccfg = TlsClientConfig {
                auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
                server_name: Some(b"localhost"),
                alpn: ALPN_H3,
            };
            let client = Rc::new(RefCell::new(
                Connection::new_client([seed; 32], &ccfg).expect("new_client"),
            ));
            let server = Rc::new(RefCell::new(Connection::new_server(
                ConnectionId::new(&[0xab; 8]),
                [0x42u8; 32],
            )));
            let pair = Pair {
                client,
                server,
                cfg,
            };
            pair.pump();
            assert_eq!(pair.client.borrow().state(), ConnState::Established);
            assert_eq!(pair.server.borrow().state(), ConnState::Established);
            pair
        }

        /// Move every queued datagram in both directions until
        /// quiescent.
        fn pump(&self) {
            for _ in 0..256 {
                let mut progressed = false;
                loop {
                    let pkt = self.client.borrow_mut().pop_packet_owned();
                    let Some(pkt) = pkt else { break };
                    let mut w = pkt.vec()[HEADROOM..].to_vec();
                    self.server
                        .borrow_mut()
                        .process_datagram(&mut w, &self.cfg)
                        .expect("server processes client datagram");
                    progressed = true;
                }
                loop {
                    let pkt = self.server.borrow_mut().pop_packet_owned();
                    let Some(pkt) = pkt else { break };
                    let mut w = pkt.vec()[HEADROOM..].to_vec();
                    self.client
                        .borrow_mut()
                        .client_process_datagram(&mut w)
                        .expect("client processes server datagram");
                    progressed = true;
                }
                if !progressed {
                    return;
                }
            }
            panic!("pump did not converge");
        }
    }

    // ── Client transport over the raw client-role Connection ──────

    struct LoopClient {
        conn: Rc<RefCell<Connection>>,
        next_bidi: Cell<u64>,
        next_uni: Cell<u64>,
    }

    impl LoopClient {
        fn new(conn: Rc<RefCell<Connection>>) -> Self {
            LoopClient {
                conn,
                next_bidi: Cell::new(0),
                next_uni: Cell::new(2),
            }
        }
    }

    impl ClientTransport for LoopClient {
        fn open_bidi_stream(&self) -> u64 {
            let sid = self.next_bidi.get();
            self.next_bidi.set(sid + 4);
            sid
        }
        fn open_uni_stream(&self) -> u64 {
            let sid = self.next_uni.get();
            self.next_uni.set(sid + 4);
            sid
        }
        fn send_owned(&self, sid: u64, data: Vec<u8>) {
            let mut c = self.conn.borrow_mut();
            c.stream_send_owned(sid, data);
            let _ = c.client_flush();
        }
        fn close_stream(&self, sid: u64) {
            let mut c = self.conn.borrow_mut();
            c.stream_close(sid);
            let _ = c.client_flush();
        }
        async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
            let conn = &self.conn;
            wait_for(move || {
                let mut c = conn.borrow_mut();
                let (n, eof) = c.stream_recv(sid, out);
                if n > 0
                    || eof
                    || matches!(c.state(), ConnState::Failed)
                    || c.stream_reset_code(sid).is_some()
                {
                    Some((n, eof))
                } else {
                    None
                }
            })
            .await
        }
        fn try_recv(&self, sid: u64, out: &mut [u8]) -> Option<(usize, bool)> {
            let mut c = self.conn.borrow_mut();
            let (n, eof) = c.stream_recv(sid, out);
            (n > 0 || eof).then_some((n, eof))
        }
        fn try_accept_stream(&self) -> Option<u64> {
            self.conn.borrow_mut().pop_accepted_stream()
        }
        fn stream_reset_code(&self, sid: u64) -> Option<u64> {
            self.conn.borrow().stream_reset_code(sid)
        }
        fn stop_sending(&self, sid: u64, app_error_code: u64) {
            let mut c = self.conn.borrow_mut();
            c.stop_sending(sid, app_error_code);
            let _ = c.client_flush();
        }
        fn is_failed(&self) -> bool {
            matches!(self.conn.borrow().state(), ConnState::Failed)
        }
        fn close(&self) {
            let mut c = self.conn.borrow_mut();
            c.close_with_error(0x0, b"done");
            c.flush_close();
        }
    }

    // ── Server transport over the raw server-role Connection ──────

    struct LoopServer {
        conn: Rc<RefCell<Connection>>,
        cfg: Rc<TlsServerConfig>,
    }

    impl ServerConn for LoopServer {
        async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
            let conn = &self.conn;
            wait_for(move || {
                let mut c = conn.borrow_mut();
                let (n, eof) = c.stream_recv(sid, out);
                if n > 0
                    || eof
                    || matches!(c.state(), ConnState::Failed)
                    || c.stream_reset_code(sid).is_some()
                {
                    Some((n, eof))
                } else {
                    None
                }
            })
            .await
        }
        fn queue_iobuf(&self, sid: u64, data: IOBuf) {
            self.conn.borrow_mut().stream_send_iobuf(sid, data);
        }
        fn send_iobuf(&self, sid: u64, data: IOBuf) {
            let mut c = self.conn.borrow_mut();
            c.stream_send_iobuf(sid, data);
            let _ = c.flush(&self.cfg);
        }
        fn close_stream(&self, sid: u64) {
            let mut c = self.conn.borrow_mut();
            c.stream_close(sid);
            let _ = c.flush(&self.cfg);
        }
        fn discard_recv(&self, sid: u64) {
            self.conn.borrow_mut().discard_recv(sid);
        }
        fn stream_buffered(&self, sid: u64) -> usize {
            self.conn.borrow().stream_send_buffered(sid)
        }
        async fn stream_drain_below(&self, sid: u64, cap: usize) {
            let conn = &self.conn;
            wait_for(move || {
                let c = conn.borrow();
                (c.stream_send_buffered(sid) <= cap
                    || matches!(c.state(), ConnState::Failed))
                .then_some(())
            })
            .await
        }
        fn is_failed(&self) -> bool {
            matches!(self.conn.borrow().state(), ConnState::Failed)
        }
        fn reset_stream(&self, sid: u64, app_error_code: u64) {
            let mut c = self.conn.borrow_mut();
            c.reset_stream(sid, app_error_code);
            let _ = c.flush(&self.cfg);
        }
    }

    /// The server side: accept request streams and run the REAL
    /// `server::handle_request` on each — the same per-request path
    /// production's `handle_conn` drives.
    async fn server_task<H>(ls: LoopServer, handler: H)
    where
        H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()>,
    {
        let mut scratch = Scratch::new();
        loop {
            let conn = &ls.conn;
            let sid = wait_for(move || conn.borrow_mut().pop_accepted_stream()).await;
            if sid & 0x3 == 0 {
                server::handle_request(&ls, sid, &handler, &mut scratch).await;
            } else {
                ls.discard_recv(sid);
            }
        }
    }

    /// Drive the client future to completion, interleaving polls of
    /// the (never-ending) server task and the datagram pump.
    fn drive<R>(
        pair: &Pair,
        client_fut: impl Future<Output = R>,
        server_fut: impl Future<Output = ()>,
    ) -> R {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut cf = core::pin::pin!(client_fut);
        let mut sf = core::pin::pin!(server_fut);
        for _ in 0..10_000 {
            if let Poll::Ready(r) = cf.as_mut().poll(&mut cx) {
                // Let the server settle (consume trailing FIN/ACKs).
                for _ in 0..8 {
                    let _ = sf.as_mut().poll(&mut cx);
                    pair.pump();
                }
                return r;
            }
            let _ = sf.as_mut().poll(&mut cx);
            pair.pump();
        }
        panic!("loopback did not converge");
    }

    fn h3_pair(seed: u8) -> (Pair, H3ClientConn<LoopClient>, LoopServer) {
        let pair = Pair::new(seed);
        let h3 = H3ClientConn::new(LoopClient::new(Rc::clone(&pair.client)));
        let ls = LoopServer {
            conn: Rc::clone(&pair.server),
            cfg: Rc::clone(&pair.cfg),
        };
        (pair, h3, ls)
    }

    /// THE CENTERPIECE: GET through the real h3 client against the
    /// real h3 server-role processing — the handler's buffered
    /// response comes back byte-exact with its status + headers.
    #[test]
    fn h3_loopback_get_roundtrips_real_server() {
        async fn handler(
            req: &mut Request<'_>,
            res: &mut Response<'_>,
        ) -> Result<(), ()> {
            assert_eq!(req.path(), b"/hello");
            res.set(Response::ok(
                &b"text/plain; charset=utf-8"[..],
                &b"hello from the real h3 server"[..],
            ));
            Ok(())
        }
        let (pair, mut h3, ls) = h3_pair(0x61);
        let req_fut = h3.request(b"GET", b"loop", b"/hello", &[], None, 64 * 1024);
        let resp = drive(&pair, req_fut, server_task(ls, handler)).expect("response");
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body[..], b"hello from the real h3 server");
        assert_eq!(
            resp.header(b"content-type"),
            Some(&b"text/plain; charset=utf-8"[..])
        );
        assert_eq!(resp.header(b"content-length"), Some(&b"29"[..]));
    }

    /// POST upload: the handler streams the request body back through
    /// the REAL streaming sink (`H3Sink` over the seam) — echo
    /// byte-exact, exercising request DATA framing, the BodyReader
    /// path, and the streamed-response path in one go.
    #[test]
    fn h3_loopback_post_echo_round_trips() {
        async fn echo(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
            res.content_type(b"application/octet-stream".to_vec());
            while let Some(chunk) = req.read_chunk().await {
                res.write(chunk.into_owned()).await?;
            }
            res.finish().await
        }
        let payload: Vec<u8> = (0..4096u32).map(|i| (i * 31 % 251) as u8).collect();
        let (pair, mut h3, ls) = h3_pair(0x62);
        let extra_hdrs: &[(&[u8], &[u8])] =
            &[(b"content-type", b"application/octet-stream")];
        let req_fut = h3.request(
            b"POST",
            b"loop",
            b"/echo",
            extra_hdrs,
            Some(&payload),
            1 << 20,
        );
        let resp = drive(&pair, req_fut, server_task(ls, echo)).expect("response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, payload, "echo body byte-exact");
    }

    /// S1 end-to-end: a streaming handler that errors mid-response
    /// makes the server RESET_STREAM(H3_INTERNAL_ERROR) — and the
    /// client surfaces it as a clean `StreamReset` error rather than
    /// a truncated 200 or a hang.
    #[test]
    fn h3_loopback_midstream_reset_surfaces_cleanly() {
        async fn failing(
            _req: &mut Request<'_>,
            res: &mut Response<'_>,
        ) -> Result<(), ()> {
            // Stream the head + one chunk, then fail mid-body.
            res.write(&b"partial body the client must not trust"[..])
                .await?;
            Err(())
        }
        let (pair, mut h3, ls) = h3_pair(0x63);
        let req_fut = h3.request(b"GET", b"loop", b"/stream", &[], None, 64 * 1024);
        let err = drive(&pair, req_fut, server_task(ls, failing))
            .expect_err("mid-stream failure must not look like success");
        assert_eq!(
            err,
            H3ClientError::StreamReset(crate::errcode::H3_INTERNAL_ERROR),
            "the S1 reset reaches the client as a clean error"
        );
    }

    /// GOAWAY on the server's control stream is surfaced: the next
    /// request is refused with `GoAway`.
    #[test]
    fn h3_loopback_goaway_blocks_new_requests() {
        let (pair, mut h3, _ls) = h3_pair(0x64);
        // Server opens its control stream (uni id 3) carrying
        // stream-type 0x00 + GOAWAY(0) — built with the real codec.
        {
            let mut buf: Vec<u8> = alloc::vec![STREAM_TYPE_CONTROL as u8];
            let mut tmp = [0u8; 16];
            let n = frame::write_frame(h3_ftype::GOAWAY, &[0x00], &mut tmp).unwrap();
            buf.extend_from_slice(&tmp[..n]);
            let mut s = pair.server.borrow_mut();
            s.stream_send_owned(3, buf);
            let _ = s.flush(&pair.cfg);
        }
        pair.pump();
        assert!(h3.goaway_received(), "GOAWAY parsed off the control stream");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let fut = h3.request(b"GET", b"loop", b"/late", &[], None, 1024);
        let mut fut = core::pin::pin!(fut);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(Err(H3ClientError::GoAway)) => {}
            other => panic!("expected GoAway refusal, got {:?}", other.map(|r| r.map(|_| ()))),
        }
    }
}
