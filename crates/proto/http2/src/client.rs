// crates/proto/http2/src/client.rs — client-role HTTP/2 over one byte stream.
//
// The client mirror of `server.rs`: where `serve_conn` answers requests,
// [`H2ClientConn`] issues them — over any `http::HttpStream` (typically
// the [`TlsClientStream`] from `connect.rs` after ALPN selected "h2",
// which is how this crate's own `listen` is dialled). Same frame codec
// (`frame.rs`), same HPACK pair (`hpack.rs` — the stateful `Decoder` for
// the server's response blocks, the stateless `encode_header_list` for
// our request blocks), opposite side of the wire:
//
//   * WE send the 24-byte connection preface + our SETTINGS (RFC 9113
//     §3.4) and open streams with **odd** ids 1, 3, 5… (§5.1.1).
//   * The server's first frame must be its SETTINGS; we apply it
//     (INITIAL_WINDOW_SIZE retroactively shifts the open stream's send
//     window per §6.9.2, MAX_FRAME_SIZE caps our DATA) and ACK.
//   * Flow control runs in both directions: our DATA is paced by the
//     peer-granted connection + stream send windows, and inbound DATA
//     is **strictly** checked against the windows we advertised
//     (overrun ⇒ FLOW_CONTROL_ERROR — the S1 hardening item, both
//     roles; the server-side counterpart lives in `process_data`).
//
// v1 scope (each a deliberate cut, mirroring the h1 client's ledger):
//   * **One request in flight at a time.** Multiple requests on one
//     connection work *sequentially* (the keep-alive shape); concurrent
//     streams are a non-goal until a consumer needs them, which keeps
//     the conn loop synchronous — no demux task, no per-stream spawn.
//   * A request body larger than the peer-granted send window is not
//     an error: the send loop **waits**, processing inbound frames
//     (WINDOW_UPDATE / early response) until the window opens. The
//     caller owns the deadline (`timeout_us`), like `tcp_connect` /
//     `tls_client_handshake`.
//   * Response trailers are decoded (HPACK table sync) and DISCARDED;
//     1xx interim responses are skipped; `content-length` is not
//     cross-checked against the body (END_STREAM delimits it).
//   * No `/obs` diag block yet — the client is a probe/sim surface,
//     not a serving path.

use alloc::vec::Vec;

use http::{HttpStream, IOBuf, IOBufChain};
use tls::client::{ServerAuth, TlsClientConfig};

use crate::connect::{ALPN_H2, TlsClientError, tls_client_handshake};
use crate::frame::{self, FrameHeader, error, flags, ftype, settings_id};
use crate::hpack::{self, FieldSink, HpackError};
use crate::server::{data_payload, headers_fragment};

// ── Tunables / advertised limits (mirror the server where symmetric) ──

/// Largest frame payload we accept (`SETTINGS_MAX_FRAME_SIZE` we
/// advertise — the protocol minimum / default, like the server's).
const MAX_FRAME_SIZE: usize = 16_384;

/// HPACK decoder table cap we advertise (`SETTINGS_HEADER_TABLE_SIZE`).
const HEADER_TABLE_SIZE: usize = 4_096;

/// Decompressed header-list cap (`SETTINGS_MAX_HEADER_LIST_SIZE`) — the
/// response-side HPACK-bomb guard.
const MAX_HEADER_LIST_SIZE: usize = 64 * 1024;

/// Initial flow-control window (RFC 9113 §6.9.2 default, both
/// directions). We advertise the default, so inbound accounting starts
/// here too.
const INITIAL_WINDOW: i64 = 65_535;

/// Cap on one response header block (HEADERS + CONTINUATIONs) before
/// END_HEADERS — same CONTINUATION-flood budget as the server's.
const HEADER_BLOCK_CAP: usize = 64 * 1024;

/// HPACK decode scratch sizes (mirror the server's).
const NAME_SCRATCH_LEN: usize = 256;
const VALUE_SCRATCH_LEN: usize = 16 * 1024;

// ── Errors ─────────────────────────────────────────────────────────

/// Why an HTTP/2 client connection / request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H2ClientError {
    /// Transport failed (send error, or EOF mid-exchange).
    Transport,
    /// WE detected a protocol violation by the server — GOAWAY(code)
    /// was sent and the connection is dead. Includes receive-window
    /// overruns (FLOW_CONTROL_ERROR).
    Protocol(u32),
    /// The server reset the request's stream (RST_STREAM error code).
    /// The connection survives.
    StreamReset(u32),
    /// The server sent GOAWAY (its error code); this request was not
    /// (and will not be) processed. No new requests on this conn.
    GoAway(u32),
    /// The response was malformed (§8.1.2: bad/missing `:status`,
    /// uppercase names, connection-specific headers, DATA before
    /// HEADERS). The stream was reset; the connection survives.
    MalformedResponse,
    /// The response body exceeded the caller's cap; the stream was
    /// cancelled (RST_STREAM CANCEL). The connection survives.
    BodyTooLarge,
    /// The caller passed a connection-specific or pseudo header
    /// (RFC 9113 §8.2.2 — they must not appear in HTTP/2 requests).
    BadHeader,
    /// The connection is already dead (earlier error) — reconnect.
    Closed,
}

// ── Response ───────────────────────────────────────────────────────

/// A complete, buffered HTTP/2 response: status + decoded header list
/// (lowercase names, pseudo-headers stripped) + body.
pub struct H2Response {
    pub status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Compact manual `Debug` (mirrors `http::client::ResponseHead`'s):
/// status + shape facts, not the raw header/body bytes.
impl core::fmt::Debug for H2Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("H2Response")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl H2Response {
    /// Case-insensitive header lookup (first occurrence) — names are
    /// already lowercase on the h2 wire; the fold is for caller comfort.
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

// ── Connection state ───────────────────────────────────────────────

/// One client-role HTTP/2 connection over `S`. Construct via
/// [`H2ClientConn::connect`]; issue requests with [`H2ClientConn::request`]
/// (or the [`h2_fetch`] facade); requests are sequential (v1 — see the
/// module comment).
pub struct H2ClientConn<S: HttpStream> {
    stream: S,
    /// Decodes the SERVER's header blocks (stateful — real servers may
    /// use the dynamic table). Our encoder is the stateless
    /// `hpack::encode_header_list`, so there is no encoder table.
    hpack: hpack::Decoder,
    /// Inbound byte accumulator (raw frames not yet parsed).
    inbuf: Vec<u8>,
    /// Current frame's payload (filled by `read_frame_raw`, reused).
    payload: Vec<u8>,
    /// HPACK decode scratch (heap — kept off the future's inline state).
    name_scratch: Vec<u8>,
    value_scratch: Vec<u8>,
    /// Pending control frames (SETTINGS/PING ACKs, WINDOW_UPDATE,
    /// RST_STREAM, GOAWAY) awaiting flush. Not flow-controlled.
    ctrl_out: Vec<u8>,
    /// In-progress response header block (HEADERS without END_HEADERS).
    header_asm: Option<HeaderAsm>,
    /// Next stream id WE open — odd, monotonic (RFC 9113 §5.1.1).
    next_stream_id: u32,
    /// Connection-level send window (peer-granted).
    conn_send_window: i64,
    /// Peer's `SETTINGS_INITIAL_WINDOW_SIZE` — each new stream's send
    /// window starts here.
    peer_initial_window: i64,
    /// Peer's `SETTINGS_MAX_FRAME_SIZE` — caps the DATA frames we emit.
    peer_max_frame_size: usize,
    /// S1 strict receive accounting: what remains of the *connection*
    /// window WE advertised. Debited on DATA arrival, credited when we
    /// queue the replenishing WINDOW_UPDATE. With the credit queued in
    /// the same dispatch the check can only trip on a frame larger
    /// than the whole window — kept for strictness and for any future
    /// deferred-credit policy (the per-stream window is the live one).
    conn_recv_window: i64,
    /// Peer GOAWAY: `(last_stream_id, error_code)`.
    goaway: Option<(u32, u32)>,
    /// Set on transport/protocol death — every later call fails fast.
    dead: bool,
}

/// Compact manual `Debug` (the stream `S` has none): connection-level
/// facts only — enough for `expect_err` output in tests.
impl<S: HttpStream> core::fmt::Debug for H2ClientConn<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("H2ClientConn")
            .field("next_stream_id", &self.next_stream_id)
            .field("conn_send_window", &self.conn_send_window)
            .field("goaway", &self.goaway)
            .field("dead", &self.dead)
            .finish()
    }
}

/// In-progress response header block spanning HEADERS + CONTINUATIONs.
struct HeaderAsm {
    sid: u32,
    buf: Vec<u8>,
    end_stream: bool,
}

/// Per-request state: the stream's two windows + the response
/// accumulator. Lives in `request`'s frame, not on the conn — one
/// in-flight request at a time (v1).
struct InFlight {
    sid: u32,
    /// Peer-granted send window for this stream.
    send_window: i64,
    /// S1 strict receive accounting for this stream (we advertised
    /// `INITIAL_WINDOW`); debit on DATA arrival, credit with the
    /// WINDOW_UPDATE we queue.
    recv_window: i64,
    resp: RespAccum,
}

/// The response being assembled for one request.
struct RespAccum {
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Vec<u8>,
    body_cap: usize,
    /// Final (non-1xx) header block decoded.
    headers_done: bool,
    /// END_STREAM seen (or the stream was reset / cancelled) — the
    /// request's receive loop exits.
    complete: bool,
    /// Peer RST_STREAM error code.
    reset: Option<u32>,
    malformed: bool,
    too_large: bool,
}

impl RespAccum {
    fn new(body_cap: usize) -> Self {
        RespAccum {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
            body_cap,
            headers_done: false,
            complete: false,
            reset: None,
            malformed: false,
            too_large: false,
        }
    }
}

enum ReadErr {
    Eof,
    TooLarge,
}

impl<S: HttpStream> H2ClientConn<S> {
    /// Open an HTTP/2 connection over an established byte stream
    /// (typically a `TlsClientStream` whose ALPN selected "h2"): send
    /// the client connection preface + our SETTINGS, read + apply the
    /// server's SETTINGS (its mandatory first frame, RFC 9113 §3.4),
    /// and ACK it. The caller owns deadline policy (`timeout_us`).
    pub async fn connect(stream: S) -> Result<Self, H2ClientError> {
        field_huffman::preinit();
        let mut conn = H2ClientConn {
            stream,
            hpack: hpack::Decoder::new(HEADER_TABLE_SIZE, MAX_HEADER_LIST_SIZE),
            inbuf: Vec::with_capacity(2048),
            payload: Vec::new(),
            name_scratch: alloc::vec![0u8; NAME_SCRATCH_LEN],
            value_scratch: alloc::vec![0u8; VALUE_SCRATCH_LEN],
            ctrl_out: Vec::new(),
            header_asm: None,
            next_stream_id: 1,
            conn_send_window: INITIAL_WINDOW,
            peer_initial_window: INITIAL_WINDOW,
            peer_max_frame_size: MAX_FRAME_SIZE,
            conn_recv_window: INITIAL_WINDOW,
            goaway: None,
            dead: false,
        };

        // Preface + SETTINGS in one send. ENABLE_PUSH=0 — PUSH_PROMISE
        // becomes a connection error; the rest mirrors the server's
        // advertisement (defaults made explicit).
        let mut s = Vec::with_capacity(frame::PREFACE.len() + frame::FRAME_HEADER_LEN + 5 * 6);
        s.extend_from_slice(frame::PREFACE);
        frame::push_settings(
            &mut s,
            &[
                (settings_id::ENABLE_PUSH, 0),
                (settings_id::HEADER_TABLE_SIZE, HEADER_TABLE_SIZE as u32),
                (settings_id::INITIAL_WINDOW_SIZE, INITIAL_WINDOW as u32),
                (settings_id::MAX_FRAME_SIZE, MAX_FRAME_SIZE as u32),
                (settings_id::MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST_SIZE as u32),
            ],
        );
        conn.send_vec(s).await?;

        // The server's first frame MUST be its (non-ACK) SETTINGS.
        let hdr = match conn.read_frame_raw().await {
            Ok(h) => h,
            Err(ReadErr::Eof) => {
                conn.dead = true;
                return Err(H2ClientError::Transport);
            }
            Err(ReadErr::TooLarge) => return Err(conn.fail_conn(error::FRAME_SIZE_ERROR).await),
        };
        if hdr.ty != ftype::SETTINGS || hdr.has_flag(flags::ACK) {
            return Err(conn.fail_conn(error::PROTOCOL_ERROR).await);
        }
        let payload = core::mem::take(&mut conn.payload);
        let r = conn.process_frame(None, hdr, &payload);
        conn.payload = payload;
        if let Err(code) = r {
            return Err(conn.fail_conn(code).await);
        }
        // Ship our SETTINGS ACK. The server's ACK of OUR settings
        // arrives whenever; the dispatch accepts it mid-request.
        conn.flush_ctrl().await?;
        Ok(conn)
    }

    /// Issue one request and await its complete response. Sequential:
    /// one stream in flight at a time (v1 — see the module comment).
    ///
    /// `headers` are regular fields only (the four pseudo-headers come
    /// from the explicit parameters and are encoded FIRST, per
    /// §8.3); connection-specific names are rejected (§8.2.2). The
    /// response body is bounded by `body_cap`.
    #[allow(clippy::too_many_arguments)] // the request target, spelled out
    pub async fn request(
        &mut self,
        method: &[u8],
        scheme: &[u8],
        authority: &[u8],
        path: &[u8],
        headers: &[(&[u8], &[u8])],
        body: Option<&[u8]>,
        body_cap: usize,
    ) -> Result<H2Response, H2ClientError> {
        if self.dead {
            return Err(H2ClientError::Closed);
        }
        if let Some((_, code)) = self.goaway {
            // The peer is winding down — a new (higher) stream id would
            // never be processed (§6.8).
            return Err(H2ClientError::GoAway(code));
        }
        for (name, value) in headers {
            if header_is_forbidden(name, value) {
                return Err(H2ClientError::BadHeader);
            }
        }

        let sid = self.next_stream_id;
        self.next_stream_id += 2;
        let mut flight = InFlight {
            sid,
            send_window: self.peer_initial_window,
            recv_window: INITIAL_WINDOW,
            resp: RespAccum::new(body_cap),
        };

        // HPACK-encode the header block: pseudo-headers first (§8.3),
        // then the regular fields (the encoder lowercases names).
        let mut list: Vec<(&[u8], &[u8])> = Vec::with_capacity(4 + headers.len());
        list.push((b":method", method));
        list.push((b":scheme", scheme));
        list.push((b":authority", authority));
        list.push((b":path", path));
        list.extend_from_slice(headers);
        let mut block = Vec::with_capacity(64);
        hpack::encode_header_list(&list, &mut block);

        // HEADERS (+ CONTINUATION past the peer's max frame size), with
        // any queued control frames ahead of it (wire order).
        let mut out = core::mem::take(&mut self.ctrl_out);
        push_header_block(&mut out, sid, &block, body.is_none(), self.peer_max_frame_size);
        self.send_vec(out).await?;

        // DATA under BOTH send windows; when blocked, process inbound
        // frames until WINDOW_UPDATE credit (or an early response /
        // reset) unblocks us. The caller owns the deadline.
        if let Some(body) = body {
            self.send_body(&mut flight, body).await?;
        }

        // Receive until the response completes.
        loop {
            if flight.resp.complete {
                break;
            }
            if let Some((last_sid, code)) = self.goaway
                && sid > last_sid
            {
                return Err(H2ClientError::GoAway(code));
            }
            self.pump_one(&mut flight).await?;
        }
        // Ship anything queued at completion (final window credit, a
        // RST for a malformed/cancelled stream) before returning.
        self.flush_ctrl().await?;

        if let Some(code) = flight.resp.reset {
            return Err(H2ClientError::StreamReset(code));
        }
        if flight.resp.too_large {
            return Err(H2ClientError::BodyTooLarge);
        }
        if flight.resp.malformed || flight.resp.status == 0 {
            return Err(H2ClientError::MalformedResponse);
        }
        Ok(H2Response {
            status: flight.resp.status,
            headers: core::mem::take(&mut flight.resp.headers),
            body: core::mem::take(&mut flight.resp.body),
        })
    }

    /// Wind the connection down: GOAWAY(NO_ERROR) + transport close
    /// (close_notify on TLS). Best-effort — the conn is done either way.
    pub async fn close(&mut self) {
        if !self.dead {
            // As a client we processed no server-initiated streams.
            frame::push_goaway(&mut self.ctrl_out, 0, error::NO_ERROR);
            let _ = self.flush_ctrl().await;
            self.dead = true;
        }
        let _ = self.stream.close().await;
    }

    // ── Send half ──────────────────────────────────────────────────

    /// Stream the request body as DATA frames under
    /// `min(conn_send_window, stream send window, peer_max_frame_size)`,
    /// END_STREAM on the final frame. Window-blocked ⇒ pump inbound
    /// frames (credit arrives as WINDOW_UPDATE). A response that
    /// completes before the body is fully sent aborts the rest
    /// (RST_STREAM NO_ERROR per §8.1's early-response rule).
    async fn send_body(&mut self, flight: &mut InFlight, body: &[u8]) -> Result<(), H2ClientError> {
        let sid = flight.sid;
        let mut off = 0usize;
        let mut end_sent = false;
        while !end_sent {
            if flight.resp.complete {
                if flight.resp.reset.is_none() {
                    frame::push_rst_stream(&mut self.ctrl_out, sid, error::NO_ERROR);
                    self.flush_ctrl().await?;
                }
                return Ok(());
            }
            let remaining = body.len() - off;
            if remaining == 0 {
                // Only reachable for an empty `Some` body — a non-empty
                // one rides END_STREAM on its last chunk below.
                let mut out = Vec::with_capacity(frame::FRAME_HEADER_LEN);
                frame::push_frame_header(&mut out, 0, ftype::DATA, flags::END_STREAM, sid);
                self.send_vec(out).await?;
                end_sent = true;
                continue;
            }
            let allowed = self
                .conn_send_window
                .min(flight.send_window)
                .min(self.peer_max_frame_size as i64)
                .min(remaining as i64);
            if allowed <= 0 {
                // Window-blocked: wait for WINDOW_UPDATE (or an early
                // response) — the caller's deadline bounds this.
                self.pump_one(flight).await?;
                continue;
            }
            let n = allowed as usize;
            let fin = n == remaining;
            let mut out = Vec::with_capacity(frame::FRAME_HEADER_LEN + n);
            frame::push_frame(
                &mut out,
                ftype::DATA,
                if fin { flags::END_STREAM } else { 0 },
                sid,
                &body[off..off + n],
            );
            flight.send_window -= n as i64;
            self.conn_send_window -= n as i64;
            off += n;
            end_sent = fin;
            self.send_vec(out).await?;
        }
        Ok(())
    }

    /// Send an owned byte buffer as one chain. Marks the conn dead on
    /// transport failure.
    async fn send_vec(&mut self, bytes: Vec<u8>) -> Result<(), H2ClientError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut chain = IOBufChain::new();
        chain.push_back(IOBuf::from(bytes));
        if self.stream.send(&mut chain).await.is_err() {
            self.dead = true;
            return Err(H2ClientError::Transport);
        }
        Ok(())
    }

    /// Flush queued control frames (ACKs, WINDOW_UPDATE, RST, GOAWAY).
    async fn flush_ctrl(&mut self) -> Result<(), H2ClientError> {
        if self.ctrl_out.is_empty() {
            return Ok(());
        }
        let out = core::mem::take(&mut self.ctrl_out);
        self.send_vec(out).await
    }

    /// Queue a GOAWAY with `code`, flush best-effort, kill the conn,
    /// and return the error to propagate.
    async fn fail_conn(&mut self, code: u32) -> H2ClientError {
        if !self.dead {
            frame::push_goaway(&mut self.ctrl_out, 0, code);
            let _ = self.flush_ctrl().await;
            self.dead = true;
        }
        H2ClientError::Protocol(code)
    }

    // ── Receive half ───────────────────────────────────────────────

    /// Read one complete frame: header returned, payload left in
    /// `self.payload`. Frames over our advertised MAX_FRAME_SIZE are
    /// rejected before buffering the payload.
    async fn read_frame_raw(&mut self) -> Result<FrameHeader, ReadErr> {
        loop {
            if self.inbuf.len() >= frame::FRAME_HEADER_LEN {
                let hdr = FrameHeader::parse(&self.inbuf[..frame::FRAME_HEADER_LEN]);
                if hdr.length as usize > MAX_FRAME_SIZE {
                    return Err(ReadErr::TooLarge);
                }
                let total = frame::FRAME_HEADER_LEN + hdr.length as usize;
                if self.inbuf.len() >= total {
                    self.payload.clear();
                    self.payload
                        .extend_from_slice(&self.inbuf[frame::FRAME_HEADER_LEN..total]);
                    self.inbuf.drain(..total);
                    return Ok(hdr);
                }
            }
            let Some(guard) = self.stream.recv_chunk().await else {
                return Err(ReadErr::Eof);
            };
            self.inbuf.extend_from_slice(guard.data());
        }
    }

    /// One receive step: flush queued control, read one frame, process
    /// it, flush whatever that queued. Any protocol violation tears the
    /// connection down (GOAWAY + dead).
    async fn pump_one(&mut self, flight: &mut InFlight) -> Result<(), H2ClientError> {
        self.flush_ctrl().await?;
        let hdr = match self.read_frame_raw().await {
            Ok(h) => h,
            Err(ReadErr::Eof) => {
                self.dead = true;
                return Err(H2ClientError::Transport);
            }
            Err(ReadErr::TooLarge) => return Err(self.fail_conn(error::FRAME_SIZE_ERROR).await),
        };
        let payload = core::mem::take(&mut self.payload);
        let r = self.process_frame(Some(flight), hdr, &payload);
        self.payload = payload;
        if let Err(code) = r {
            return Err(self.fail_conn(code).await);
        }
        self.flush_ctrl().await
    }

    /// Process one inbound frame. `Ok(())` = handled; `Err(code)` =
    /// connection error (caller sends GOAWAY). Pure sync — fuzzable.
    fn process_frame(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        // A header block in mid-assembly forbids interleaving (§6.2).
        if let Some(asm) = &self.header_asm {
            if hdr.ty != ftype::CONTINUATION || hdr.stream_id != asm.sid {
                return Err(error::PROTOCOL_ERROR);
            }
            return self.continue_headers(flight, hdr, payload);
        }
        if hdr.ty == ftype::CONTINUATION {
            return Err(error::PROTOCOL_ERROR);
        }
        match hdr.ty {
            ftype::SETTINGS => self.process_settings(flight, hdr, payload),
            ftype::HEADERS => self.process_headers(flight, hdr, payload),
            ftype::DATA => self.process_data(flight, hdr, payload),
            ftype::WINDOW_UPDATE => self.process_window_update(flight, hdr, payload),
            ftype::RST_STREAM => self.process_rst_stream(flight, hdr, payload),
            ftype::PING => self.process_ping(hdr, payload),
            ftype::GOAWAY => self.process_goaway(hdr, payload),
            // ENABLE_PUSH=0 was advertised — a push is a hard violation.
            ftype::PUSH_PROMISE => Err(error::PROTOCOL_ERROR),
            ftype::PRIORITY => Ok(()), // deprecated — parse-and-ignore.
            _ => Ok(()),               // unknown types are ignored (§4.1).
        }
    }

    fn process_settings(
        &mut self,
        mut flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        if hdr.stream_id != 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        if hdr.has_flag(flags::ACK) {
            // ACK of OUR settings — must be empty.
            if hdr.length != 0 {
                return Err(error::FRAME_SIZE_ERROR);
            }
            return Ok(());
        }
        let params = frame::parse_settings(payload).ok_or(error::FRAME_SIZE_ERROR)?;
        for (id, val) in params {
            self.apply_setting(flight.as_deref_mut(), id, val)?;
        }
        frame::push_settings_ack(&mut self.ctrl_out);
        Ok(())
    }

    fn apply_setting(
        &mut self,
        flight: Option<&mut InFlight>,
        id: u16,
        val: u32,
    ) -> Result<(), u32> {
        match id {
            settings_id::INITIAL_WINDOW_SIZE => {
                if val > 0x7fff_ffff {
                    return Err(error::FLOW_CONTROL_ERROR);
                }
                // §6.9.2: retroactively shift the open stream's send
                // window by the delta (may go negative; past 2^31−1 is
                // a connection error).
                let new_iw = val as i64;
                let delta = new_iw - self.peer_initial_window;
                if delta != 0
                    && let Some(f) = flight
                {
                    f.send_window += delta;
                    if f.send_window > 0x7fff_ffff {
                        return Err(error::FLOW_CONTROL_ERROR);
                    }
                }
                self.peer_initial_window = new_iw;
            }
            settings_id::MAX_FRAME_SIZE => {
                if !(16_384..=16_777_215).contains(&val) {
                    return Err(error::PROTOCOL_ERROR);
                }
                self.peer_max_frame_size = val as usize;
            }
            settings_id::ENABLE_PUSH => {
                // §6.5.2: a server MUST NOT advertise ENABLE_PUSH=1
                // (and >1 is always invalid).
                if val != 0 {
                    return Err(error::PROTOCOL_ERROR);
                }
            }
            // HEADER_TABLE_SIZE caps OUR encoder's dynamic table — the
            // stateless encoder uses none. MAX_CONCURRENT_STREAMS /
            // MAX_HEADER_LIST_SIZE bound what WE send; one sequential
            // stream with small request heads stays under any sane
            // value. Unknown ids are ignored (§6.5.2).
            _ => {}
        }
        Ok(())
    }

    fn process_headers(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        let sid = hdr.stream_id;
        // The only HEADERS a client can receive ride streams IT opened
        // (odd ids); a server-initiated (even / zero) id is a violation
        // (pushes are banned above at the PUSH_PROMISE gate).
        if sid == 0 || sid.is_multiple_of(2) {
            return Err(error::PROTOCOL_ERROR);
        }
        if sid >= self.next_stream_id {
            // A stream we never opened.
            return Err(error::PROTOCOL_ERROR);
        }
        let frag = headers_fragment(payload, hdr.flags).ok_or(error::PROTOCOL_ERROR)?;
        let end_stream = hdr.has_flag(flags::END_STREAM);
        if hdr.has_flag(flags::END_HEADERS) {
            self.complete_headers(flight, sid, end_stream, frag)
        } else {
            if frag.len() > HEADER_BLOCK_CAP {
                return Err(error::ENHANCE_YOUR_CALM);
            }
            self.header_asm = Some(HeaderAsm {
                sid,
                buf: frag.to_vec(),
                end_stream,
            });
            Ok(())
        }
    }

    fn continue_headers(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        {
            let asm = self.header_asm.as_mut().expect("checked by caller");
            if asm.buf.len() + payload.len() > HEADER_BLOCK_CAP {
                return Err(error::ENHANCE_YOUR_CALM);
            }
            asm.buf.extend_from_slice(payload);
        }
        if hdr.has_flag(flags::END_HEADERS) {
            let asm = self.header_asm.take().expect("present");
            self.complete_headers(flight, asm.sid, asm.end_stream, &asm.buf)
        } else {
            Ok(())
        }
    }

    /// Decode a finished header block. Three cases: the in-flight
    /// response's head (possibly a discarded 1xx interim), its trailers
    /// (decoded for table sync, fields dropped, END_STREAM honoured),
    /// or a block for an old/finished stream (table sync only) — HPACK
    /// is decoded for *every* block to keep the dynamic table in sync,
    /// exactly like the server side.
    fn complete_headers(
        &mut self,
        flight: Option<&mut InFlight>,
        sid: u32,
        end_stream: bool,
        block: &[u8],
    ) -> Result<(), u32> {
        match flight {
            Some(f) if f.sid == sid && !f.resp.complete && !f.resp.headers_done => {
                let mut sink = RespHeadSink::new();
                self.decode_block(block, &mut sink)?;
                if sink.malformed || sink.status == 0 {
                    f.resp.malformed = true;
                    f.resp.complete = true;
                    frame::push_rst_stream(&mut self.ctrl_out, sid, error::PROTOCOL_ERROR);
                    return Ok(());
                }
                if (100..200).contains(&sink.status) {
                    // Interim response: discard and await the final
                    // head. END_STREAM on a 1xx is malformed (§8.1).
                    if end_stream {
                        f.resp.malformed = true;
                        f.resp.complete = true;
                        frame::push_rst_stream(&mut self.ctrl_out, sid, error::PROTOCOL_ERROR);
                    }
                    return Ok(());
                }
                f.resp.status = sink.status;
                f.resp.headers = sink.fields;
                f.resp.headers_done = true;
                if end_stream {
                    f.resp.complete = true;
                }
                Ok(())
            }
            Some(f) if f.sid == sid && !f.resp.complete => {
                // Trailers: must be the final block (§8.1). Fields are
                // discarded (v1) after the table-sync decode.
                self.decode_block(block, &mut NullSink)?;
                if end_stream {
                    f.resp.complete = true;
                } else {
                    f.resp.malformed = true;
                    f.resp.complete = true;
                    frame::push_rst_stream(&mut self.ctrl_out, sid, error::PROTOCOL_ERROR);
                }
                Ok(())
            }
            _ => {
                // A finished/cancelled stream we no longer track (e.g.
                // trailers racing our RST): keep the table in sync.
                self.decode_block(block, &mut NullSink)
            }
        }
    }

    /// Run one block through the stateful decoder, mapping HPACK
    /// failures to the same connection errors the server uses.
    fn decode_block<Sk: FieldSink>(&mut self, block: &[u8], sink: &mut Sk) -> Result<(), u32> {
        match self.hpack.decode(
            block,
            &mut self.name_scratch[..],
            &mut self.value_scratch[..],
            sink,
        ) {
            Ok(()) => Ok(()),
            Err(HpackError::HeaderListTooLarge) => Err(error::ENHANCE_YOUR_CALM),
            Err(_) => Err(error::COMPRESSION_ERROR),
        }
    }

    fn process_data(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        let sid = hdr.stream_id;
        if sid == 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        let data = data_payload(payload, hdr.flags).ok_or(error::PROTOCOL_ERROR)?;
        // The full frame length (incl. padding) counts against flow
        // control (§6.1).
        let full_len = hdr.length as i64;
        let end_stream = hdr.has_flag(flags::END_STREAM);

        // S1: strict receive-window enforcement, connection level. The
        // peer spends the window we advertised; a frame past it is a
        // FLOW_CONTROL_ERROR (§6.9.1) — connection error (a server that
        // overruns is broken/hostile, and v1 has no sibling streams to
        // shelter, so tearing down is the safe arm of §5.4.1's choice).
        self.conn_recv_window -= full_len;
        if self.conn_recv_window < 0 {
            return Err(error::FLOW_CONTROL_ERROR);
        }

        match flight {
            Some(f) if f.sid == sid && !f.resp.complete && f.resp.reset.is_none() => {
                // S1: stream-level enforcement, same verdict.
                f.recv_window -= full_len;
                if f.recv_window < 0 {
                    return Err(error::FLOW_CONTROL_ERROR);
                }
                if !f.resp.headers_done {
                    // DATA before the response HEADERS — malformed.
                    return Err(error::PROTOCOL_ERROR);
                }
                if f.resp.body.len() + data.len() > f.resp.body_cap
                    || f.resp.body.try_reserve(data.len()).is_err()
                {
                    // Over the caller's body budget — cancel the stream,
                    // keep the connection.
                    f.resp.too_large = true;
                    f.resp.complete = true;
                    frame::push_rst_stream(&mut self.ctrl_out, sid, error::CANCEL);
                } else {
                    f.resp.body.extend_from_slice(data);
                    if end_stream {
                        f.resp.complete = true;
                    }
                    // Replenish the stream window (credit-on-emit) while
                    // the stream lives.
                    if full_len > 0 && !end_stream {
                        frame::push_window_update(&mut self.ctrl_out, sid, full_len as u32);
                        f.recv_window += full_len;
                    }
                }
            }
            _ => {
                // DATA for a finished/cancelled/unknown stream is
                // leniently dropped; the connection credit below keeps
                // the peer's accounting consistent.
            }
        }
        // Replenish the connection window (credit-on-emit).
        if full_len > 0 {
            frame::push_window_update(&mut self.ctrl_out, 0, full_len as u32);
            self.conn_recv_window += full_len;
        }
        Ok(())
    }

    fn process_window_update(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        if hdr.length != 4 {
            return Err(error::FRAME_SIZE_ERROR);
        }
        let inc = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
        if inc == 0 {
            // §6.9: zero increment is an error; v1 escalates the
            // stream-level case to a connection error (§5.4.1 allows
            // it, and the lone in-flight stream dies either way).
            return Err(error::PROTOCOL_ERROR);
        }
        if hdr.stream_id == 0 {
            self.conn_send_window += inc as i64;
            if self.conn_send_window > 0x7fff_ffff {
                return Err(error::FLOW_CONTROL_ERROR);
            }
        } else if let Some(f) = flight
            && f.sid == hdr.stream_id
        {
            f.send_window += inc as i64;
            if f.send_window > 0x7fff_ffff {
                return Err(error::FLOW_CONTROL_ERROR);
            }
        }
        // Credit for a finished stream is ignored.
        Ok(())
    }

    fn process_rst_stream(
        &mut self,
        flight: Option<&mut InFlight>,
        hdr: FrameHeader,
        payload: &[u8],
    ) -> Result<(), u32> {
        if hdr.stream_id == 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        if hdr.length != 4 {
            return Err(error::FRAME_SIZE_ERROR);
        }
        let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if let Some(f) = flight
            && f.sid == hdr.stream_id
            && !f.resp.complete
        {
            f.resp.reset = Some(code);
            f.resp.complete = true;
        }
        Ok(())
    }

    fn process_ping(&mut self, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
        if hdr.stream_id != 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        if hdr.length != 8 {
            return Err(error::FRAME_SIZE_ERROR);
        }
        if !hdr.has_flag(flags::ACK) {
            let mut op = [0u8; 8];
            op.copy_from_slice(&payload[..8]);
            frame::push_ping_ack(&mut self.ctrl_out, &op);
        }
        Ok(())
    }

    fn process_goaway(&mut self, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
        if hdr.stream_id != 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        if hdr.length < 8 {
            return Err(error::FRAME_SIZE_ERROR);
        }
        let last_sid =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
        let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        self.goaway = Some((last_sid, code));
        Ok(())
    }
}

/// Frame a request header block as HEADERS (+ CONTINUATIONs past
/// `max_frame`): END_STREAM (stream semantics) rides the HEADERS frame,
/// END_HEADERS (block semantics) rides the final fragment.
fn push_header_block(out: &mut Vec<u8>, sid: u32, block: &[u8], end_stream: bool, max_frame: usize) {
    let mut off = 0usize;
    let mut first = true;
    loop {
        let n = (block.len() - off).min(max_frame);
        let last = off + n == block.len();
        let ty = if first { ftype::HEADERS } else { ftype::CONTINUATION };
        let mut fl = 0u8;
        if first && end_stream {
            fl |= flags::END_STREAM;
        }
        if last {
            fl |= flags::END_HEADERS;
        }
        frame::push_frame(out, ty, fl, sid, &block[off..off + n]);
        off += n;
        first = false;
        if last {
            return;
        }
    }
}

/// §8.2.2: connection-specific fields (and raw pseudo-headers) must not
/// be passed as regular request headers.
fn header_is_forbidden(name: &[u8], value: &[u8]) -> bool {
    name.first() == Some(&b':')
        || name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
        || (name.eq_ignore_ascii_case(b"te") && value != b"trailers")
}

/// Sink for the response head: `:status` (first, exactly once, 3
/// digits) then regular lowercase fields — the client cousin of the
/// server's `RequestSink` (§8.1.2 validation, response side).
struct RespHeadSink {
    status: u16,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    seen_regular: bool,
    malformed: bool,
}

impl RespHeadSink {
    fn new() -> Self {
        RespHeadSink {
            status: 0,
            fields: Vec::new(),
            seen_regular: false,
            malformed: false,
        }
    }
}

impl FieldSink for RespHeadSink {
    fn on_field(&mut self, name: &[u8], value: &[u8]) {
        if name.iter().any(u8::is_ascii_uppercase) {
            self.malformed = true;
            return;
        }
        if name == b":status" {
            // §8.1.2.1: pseudo before regulars, no duplicates; §8.3.2:
            // exactly one `:status`, a 3-digit code.
            if self.status != 0
                || self.seen_regular
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
            // `:status` is the only response pseudo-header.
            self.malformed = true;
            return;
        }
        self.seen_regular = true;
        match name {
            // §8.2.2: connection-specific fields are malformed in h2.
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
            | b"upgrade" | b"te" => self.malformed = true,
            _ => self.fields.push((name.to_vec(), value.to_vec())),
        }
    }
}

/// Discards fields — used where a block must be decoded purely to keep
/// the HPACK dynamic table in sync (trailers, finished streams).
struct NullSink;
impl FieldSink for NullSink {
    fn on_field(&mut self, _name: &[u8], _value: &[u8]) {}
}

// ============================================================================
// h2_fetch — the single-shot request facade
// ============================================================================

/// One request/response exchange on an established [`H2ClientConn`],
/// reusing the h1 client's [`http::client::FetchRequest`] shape:
/// `host` → `:authority`, the scheme is `https` (h2 is TLS-only here),
/// and `close` is ignored (h2 winds down via GOAWAY — call
/// [`H2ClientConn::close`]). Call repeatedly for sequential requests on
/// one connection.
pub async fn h2_fetch<S: HttpStream>(
    conn: &mut H2ClientConn<S>,
    req: &http::client::FetchRequest<'_>,
    body_cap: usize,
) -> Result<H2Response, H2ClientError> {
    conn.request(req.method, b"https", req.host, req.path, req.headers, req.body, body_cap)
        .await
}

// ============================================================================
// https_get — ALPN-dispatching HTTPS GET (h2 with h1.1 fallback)
// ============================================================================

/// Failure stage of [`https_get`] — [`crate::HttpsGetH1Error`] plus the
/// h2 arm.
#[derive(Debug)]
pub enum HttpsGetError {
    /// TCP connect failed.
    Connect(waitless::runtime::TcpConnectError),
    /// TLS handshake failed.
    Tls(TlsClientError),
    /// The h2 exchange failed (connect/request).
    H2(H2ClientError),
    /// The h1.1 request/response exchange failed.
    Fetch(http::client::FetchError),
    /// The h1.1 body read failed.
    Body(http::client::BodyError),
}

/// Naming convention (repo-wide): `*_get` = ONE-SHOT — connect + TLS +
/// request + bounded body read; `*_fetch` (`http1_fetch` / `h2_fetch` /
/// `h3_fetch`) = a request over an ALREADY-ESTABLISHED conn/stream.
/// This is the negotiated one-shot; [`crate::https_get_h1`] pins
/// ALPN to http/1.1 (and can return the typed h1 response head).
///
/// One-shot HTTPS GET offering ALPN ["h2", "http/1.1"] and dispatching
/// on what the server selected: h2 → [`H2ClientConn`]; http/1.1 (or no
/// ALPN) → the existing h1 path — the client mirror of `listen.rs`'s
/// serve dispatch. Returns `(status, body)` (the protocol-specific
/// heads differ; callers needing headers use the layered APIs). Same
/// v1 scope as [`crate::https_get_h1`]: no URL parsing/redirects/SNI, the
/// caller owns the deadline.
pub async fn https_get(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    auth: ServerAuth,
    seed: [u8; 32],
    body_cap: usize,
) -> Result<(u16, Vec<u8>), HttpsGetError> {
    let tcp = waitless::tcp_connect(ip, port)
        .await
        .map_err(HttpsGetError::Connect)?;
    let config = TlsClientConfig {
        auth,
        server_name: None,
        alpn: ALPN_H2,
    };
    let mut stream = tls_client_handshake(tcp, seed, config)
        .await
        .map_err(HttpsGetError::Tls)?;
    if stream.negotiated_alpn() == Some(&b"h2"[..]) {
        let mut conn = H2ClientConn::connect(stream)
            .await
            .map_err(HttpsGetError::H2)?;
        let req = http::client::FetchRequest::get(host, path);
        let resp = h2_fetch(&mut conn, &req, body_cap)
            .await
            .map_err(HttpsGetError::H2)?;
        conn.close().await;
        Ok((resp.status, resp.body))
    } else {
        let mut req = http::client::FetchRequest::get(host, path);
        req.close = true;
        let (head, mut body) = http::client::http1_fetch(&mut stream, &req)
            .await
            .map_err(HttpsGetError::Fetch)?;
        let bytes = body
            .read_to_vec(body_cap)
            .await
            .map_err(HttpsGetError::Body)?;
        let _ = stream.close().await;
        Ok((head.status, bytes))
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Unit tests over a scripted in-memory stream: every inbound chunk is
/// pre-staged, every outbound byte captured — the client's frame
/// emission and dispatch are asserted against exact wire bytes (and
/// its request HEADERS are decoded back through the same stateful
/// `hpack::Decoder` type the server runs).
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;
    use core::future::Future;
    use core::task::{Context, Poll};
    use iobuf::RecvChunkGuard;

    use crate::connect::loopback_tests::noop_waker;

    // ---- Scripted stream + driver -------------------------------------------

    /// `recv_chunk` pops pre-staged inbound chunks (EOF when exhausted);
    /// `send` appends to the shared capture buffer.
    struct ScriptStream {
        rx: VecDeque<Vec<u8>>,
        tx: Rc<RefCell<Vec<u8>>>,
    }

    impl HttpStream for ScriptStream {
        async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>> {
            self.rx.pop_front().map(|v| RecvChunkGuard::new(IOBuf::from(v)))
        }
        async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
            let mut tx = self.tx.borrow_mut();
            while let Some(part) = chain.pop_front() {
                tx.extend_from_slice(part.data());
            }
            Ok(())
        }
    }

    /// Drive a future built over `ScriptStream` (it never pends — every
    /// await resolves or EOFs immediately).
    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = core::pin::pin!(fut);
        for _ in 0..10_000 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
        panic!("scripted future did not complete");
    }

    /// Walk framed bytes into `(type, flags, stream_id, payload)` —
    /// the same shape as the server tests' helper.
    fn frames(buf: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 9 <= buf.len() {
            let len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | buf[i + 2] as usize;
            let ty = buf[i + 3];
            let fl = buf[i + 4];
            let sid = u32::from_be_bytes([buf[i + 5] & 0x7f, buf[i + 6], buf[i + 7], buf[i + 8]]);
            out.push((ty, fl, sid, buf[i + 9..i + 9 + len].to_vec()));
            i += 9 + len;
        }
        out
    }

    fn settings_frame(params: &[(u16, u32)]) -> Vec<u8> {
        let mut v = Vec::new();
        frame::push_settings(&mut v, params);
        v
    }

    /// HPACK-encode a response head and frame it (HEADERS, given flags).
    fn response_headers_frame(sid: u32, fields: &[(&[u8], &[u8])], fl: u8) -> Vec<u8> {
        let mut block = Vec::new();
        hpack::encode_header_list(fields, &mut block);
        let mut v = Vec::new();
        frame::push_frame(&mut v, ftype::HEADERS, fl, sid, &block);
        v
    }

    fn data_frame(sid: u32, body: &[u8], fl: u8) -> Vec<u8> {
        let mut v = Vec::new();
        frame::push_frame(&mut v, ftype::DATA, fl, sid, body);
        v
    }

    /// Connect a client over a script whose FIRST chunk must be the
    /// server's SETTINGS. Returns the conn + the captured TX bytes.
    fn connected(script: Vec<Vec<u8>>) -> (H2ClientConn<ScriptStream>, Rc<RefCell<Vec<u8>>>) {
        let tx = Rc::new(RefCell::new(Vec::new()));
        let stream = ScriptStream {
            rx: script.into_iter().collect(),
            tx: Rc::clone(&tx),
        };
        let conn = block_on(H2ClientConn::connect(stream)).expect("connect");
        (conn, tx)
    }

    fn default_connected(extra_script: Vec<Vec<u8>>) -> (H2ClientConn<ScriptStream>, Rc<RefCell<Vec<u8>>>) {
        let mut script = vec![settings_frame(&[])];
        script.extend(extra_script);
        connected(script)
    }

    // ---- Connect sequence ---------------------------------------------------

    #[test]
    fn connect_sends_preface_then_settings_and_acks_the_servers() {
        let (conn, tx) = connected(vec![settings_frame(&[
            (settings_id::INITIAL_WINDOW_SIZE, 70_000),
            (settings_id::MAX_FRAME_SIZE, 20_000),
        ])]);
        let tx = tx.borrow();
        assert!(tx.starts_with(frame::PREFACE), "preface is the first thing on the wire");
        let fr = frames(&tx[frame::PREFACE.len()..]);
        assert_eq!(fr[0].0, ftype::SETTINGS, "our SETTINGS follows the preface");
        assert_eq!(fr[0].1 & flags::ACK, 0);
        let params: Vec<(u16, u32)> = frame::parse_settings(&fr[0].3).unwrap().collect();
        assert!(
            params.contains(&(settings_id::ENABLE_PUSH, 0)),
            "ENABLE_PUSH=0 advertised: {params:?}",
        );
        assert!(params.contains(&(settings_id::MAX_FRAME_SIZE, MAX_FRAME_SIZE as u32)));
        // The server's SETTINGS was applied and ACKed.
        assert_eq!(conn.peer_initial_window, 70_000);
        assert_eq!(conn.peer_max_frame_size, 20_000);
        assert_eq!(fr[1].0, ftype::SETTINGS);
        assert_eq!(fr[1].1 & flags::ACK, flags::ACK, "we ACK the server SETTINGS");
        assert_eq!(fr[1].3.len(), 0);
    }

    #[test]
    fn connect_rejects_a_non_settings_first_frame() {
        let tx = Rc::new(RefCell::new(Vec::new()));
        let mut ping = Vec::new();
        frame::push_frame(&mut ping, ftype::PING, 0, 0, &[0u8; 8]);
        let stream = ScriptStream {
            rx: [ping].into_iter().collect(),
            tx: Rc::clone(&tx),
        };
        let err = block_on(H2ClientConn::connect(stream)).expect_err("must reject");
        assert_eq!(err, H2ClientError::Protocol(error::PROTOCOL_ERROR));
        assert!(
            frames(&tx.borrow()[frame::PREFACE.len()..])
                .iter()
                .any(|f| f.0 == ftype::GOAWAY),
            "GOAWAY shipped",
        );
    }

    // ---- Request encoding ---------------------------------------------------

    /// The emitted HEADERS round-trips through the server's own
    /// (stateful) HPACK decoder: pseudo-headers first, names lowercased,
    /// END_STREAM on a bodyless GET; and stream ids sequence 1, 3, …
    #[test]
    fn request_headers_roundtrip_and_odd_id_sequencing() {
        let resp = &[(&b":status"[..], &b"200"[..])];
        let (mut conn, tx) = default_connected(vec![
            response_headers_frame(1, resp, flags::END_HEADERS | flags::END_STREAM),
            response_headers_frame(3, resp, flags::END_HEADERS | flags::END_STREAM),
        ]);
        for _ in 0..2 {
            let r = block_on(conn.request(
                b"GET",
                b"https",
                b"example.test",
                b"/x",
                &[(b"X-Custom", b"v1"), (b"accept", b"*/*")],
                None,
                4096,
            ))
            .expect("request");
            assert_eq!(r.status, 200);
        }
        let tx = tx.borrow();
        let fr = frames(&tx[frame::PREFACE.len()..]);
        let headers: Vec<_> = fr.iter().filter(|f| f.0 == ftype::HEADERS).collect();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].2, 1, "first client stream id is 1");
        assert_eq!(headers[1].2, 3, "second is 3 (odd, monotonic)");
        for h in &headers {
            assert_eq!(h.1 & flags::END_STREAM, flags::END_STREAM, "bodyless GET");
            assert_eq!(h.1 & flags::END_HEADERS, flags::END_HEADERS);
        }
        // Decode through the server's decoder type (stateful, fresh —
        // our encoder is stateless so any decoder state works).
        struct Collect(Vec<(Vec<u8>, Vec<u8>)>);
        impl FieldSink for Collect {
            fn on_field(&mut self, n: &[u8], v: &[u8]) {
                self.0.push((n.to_vec(), v.to_vec()));
            }
        }
        let mut dec = hpack::Decoder::new(4096, 1 << 20);
        let mut ns = [0u8; 4096];
        let mut vs = [0u8; 4096];
        let mut sink = Collect(Vec::new());
        dec.decode(&headers[0].3, &mut ns, &mut vs, &mut sink).expect("decode");
        let got: Vec<(&[u8], &[u8])> = sink
            .0
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
            .collect();
        assert_eq!(
            got,
            vec![
                (&b":method"[..], &b"GET"[..]),
                (b":scheme", b"https"),
                (b":authority", b"example.test"),
                (b":path", b"/x"),
                (b"x-custom", b"v1"), // lowercased on the wire
                (b"accept", b"*/*"),
            ],
            "pseudo-headers first, then regulars",
        );
    }

    #[test]
    fn connection_specific_request_headers_are_rejected() {
        let (mut conn, _tx) = default_connected(vec![]);
        for bad in [
            (&b"Connection"[..], &b"close"[..]),
            (b"transfer-encoding", b"chunked"),
            (b"te", b"gzip"),
            (b":fake", b"x"),
        ] {
            let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[bad], None, 64))
                .expect_err("forbidden header");
            assert_eq!(err, H2ClientError::BadHeader);
        }
        // `te: trailers` is the lone exception (§8.2.2).
        assert!(!header_is_forbidden(b"te", b"trailers"));
    }

    // ---- Bodies (send side) -------------------------------------------------

    #[test]
    fn post_body_ships_as_data_with_end_stream_split_at_max_frame() {
        let body = vec![7u8; MAX_FRAME_SIZE + 100]; // forces two DATA frames
        let resp = response_headers_frame(
            1,
            &[(&b":status"[..], &b"200"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let (mut conn, tx) = default_connected(vec![resp]);
        let r = block_on(conn.request(b"POST", b"https", b"h", b"/u", &[], Some(&body), 64))
            .expect("post");
        assert_eq!(r.status, 200);
        let tx = tx.borrow();
        let fr = frames(&tx[frame::PREFACE.len()..]);
        let h = fr.iter().find(|f| f.0 == ftype::HEADERS).unwrap();
        assert_eq!(h.1 & flags::END_STREAM, 0, "bodied request: no END_STREAM on HEADERS");
        let data: Vec<_> = fr.iter().filter(|f| f.0 == ftype::DATA).collect();
        assert_eq!(data.len(), 2, "split at the peer max frame size");
        assert_eq!(data[0].3.len(), MAX_FRAME_SIZE);
        assert_eq!(data[0].1 & flags::END_STREAM, 0);
        assert_eq!(data[1].3.len(), 100);
        assert_eq!(data[1].1 & flags::END_STREAM, flags::END_STREAM, "END_STREAM on the last DATA");
        let shipped: Vec<u8> = data.iter().flat_map(|f| f.3.iter().copied()).collect();
        assert_eq!(shipped, body);
    }

    #[test]
    fn send_window_blocked_waits_for_window_update() {
        // Peer grants a 10-byte initial window; the 25-byte body must
        // pause until WINDOW_UPDATEs (scripted) credit the stream.
        let resp = response_headers_frame(
            1,
            &[(&b":status"[..], &b"200"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let mut wu_stream = Vec::new();
        frame::push_window_update(&mut wu_stream, 1, 100);
        let (mut conn, tx) = connected(vec![
            settings_frame(&[(settings_id::INITIAL_WINDOW_SIZE, 10)]),
            wu_stream,
            resp,
        ]);
        let body = [9u8; 25];
        let r = block_on(conn.request(b"POST", b"https", b"h", b"/u", &[], Some(&body), 64))
            .expect("post");
        assert_eq!(r.status, 200);
        let tx = tx.borrow();
        let fr = frames(&tx[frame::PREFACE.len()..]);
        let data: Vec<_> = fr.iter().filter(|f| f.0 == ftype::DATA).collect();
        assert_eq!(data[0].3.len(), 10, "first DATA capped by the 10-byte window");
        assert_eq!(
            data.iter().map(|f| f.3.len()).sum::<usize>(),
            25,
            "whole body shipped once credited",
        );
        assert_eq!(
            data.last().unwrap().1 & flags::END_STREAM,
            flags::END_STREAM,
        );
    }

    // ---- Receive-window enforcement (S1, client role) ------------------------

    #[test]
    fn stream_recv_window_overrun_is_flow_control_error() {
        let (mut conn, _tx) = default_connected(vec![]);
        let mut flight = InFlight {
            sid: 1,
            send_window: conn.peer_initial_window,
            recv_window: 3, // as if all but 3 bytes were spent, uncredited
            resp: RespAccum::new(4096),
        };
        flight.resp.headers_done = true;
        let hdr = FrameHeader {
            length: 5,
            ty: ftype::DATA,
            flags: 0,
            stream_id: 1,
        };
        let code = conn
            .process_frame(Some(&mut flight), hdr, b"abcde")
            .expect_err("over-window DATA");
        assert_eq!(code, error::FLOW_CONTROL_ERROR);
    }

    #[test]
    fn conn_recv_window_overrun_is_flow_control_error() {
        let (mut conn, _tx) = default_connected(vec![]);
        conn.conn_recv_window = 3;
        let mut flight = InFlight {
            sid: 1,
            send_window: conn.peer_initial_window,
            recv_window: INITIAL_WINDOW,
            resp: RespAccum::new(4096),
        };
        flight.resp.headers_done = true;
        let hdr = FrameHeader {
            length: 5,
            ty: ftype::DATA,
            flags: 0,
            stream_id: 1,
        };
        let code = conn
            .process_frame(Some(&mut flight), hdr, b"abcde")
            .expect_err("over-window DATA");
        assert_eq!(code, error::FLOW_CONTROL_ERROR);
    }

    #[test]
    fn in_window_data_is_credited_back() {
        let (mut conn, _tx) = default_connected(vec![]);
        let mut flight = InFlight {
            sid: 1,
            send_window: conn.peer_initial_window,
            recv_window: INITIAL_WINDOW,
            resp: RespAccum::new(4096),
        };
        flight.resp.headers_done = true;
        let hdr = FrameHeader {
            length: 5,
            ty: ftype::DATA,
            flags: 0,
            stream_id: 1,
        };
        conn.process_frame(Some(&mut flight), hdr, b"abcde").unwrap();
        assert_eq!(flight.resp.body, b"abcde");
        // Credit was queued for both levels and the accounting restored.
        assert_eq!(conn.conn_recv_window, INITIAL_WINDOW);
        assert_eq!(flight.recv_window, INITIAL_WINDOW);
        let fr = frames(&conn.ctrl_out);
        assert!(fr.iter().any(|f| f.0 == ftype::WINDOW_UPDATE && f.2 == 0));
        assert!(fr.iter().any(|f| f.0 == ftype::WINDOW_UPDATE && f.2 == 1));
    }

    // ---- Response edge frames -------------------------------------------------

    #[test]
    fn rst_stream_mid_response_fails_the_request_not_the_conn() {
        let head = response_headers_frame(1, &[(&b":status"[..], &b"200"[..])], flags::END_HEADERS);
        let mut rst = Vec::new();
        frame::push_rst_stream(&mut rst, 1, error::INTERNAL_ERROR);
        let resp2 = response_headers_frame(
            3,
            &[(&b":status"[..], &b"204"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let (mut conn, _tx) = default_connected(vec![head, rst, resp2]);
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect_err("reset");
        assert_eq!(err, H2ClientError::StreamReset(error::INTERNAL_ERROR));
        // The connection survives a stream reset.
        let r = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64)).expect("next");
        assert_eq!(r.status, 204);
    }

    #[test]
    fn ping_is_acked_with_the_echoed_payload() {
        let mut ping = Vec::new();
        frame::push_frame(&mut ping, ftype::PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let resp = response_headers_frame(
            1,
            &[(&b":status"[..], &b"200"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let (mut conn, tx) = default_connected(vec![ping, resp]);
        block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64)).expect("request");
        let tx = tx.borrow();
        let fr = frames(&tx[frame::PREFACE.len()..]);
        let ack = fr
            .iter()
            .find(|f| f.0 == ftype::PING && f.1 & flags::ACK != 0)
            .expect("PING ACK shipped");
        assert_eq!(ack.3, [1, 2, 3, 4, 5, 6, 7, 8], "opaque bytes echoed");
    }

    #[test]
    fn goaway_fails_the_unprocessed_request_and_later_ones() {
        let mut ga = Vec::new();
        frame::push_goaway(&mut ga, 0, error::NO_ERROR);
        let (mut conn, _tx) = default_connected(vec![ga]);
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect_err("refused by GOAWAY (sid 1 > last 0)");
        assert_eq!(err, H2ClientError::GoAway(error::NO_ERROR));
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect_err("no new streams after GOAWAY");
        assert_eq!(err, H2ClientError::GoAway(error::NO_ERROR));
    }

    #[test]
    fn push_promise_is_a_connection_error() {
        let mut pp = Vec::new();
        frame::push_frame(&mut pp, ftype::PUSH_PROMISE, flags::END_HEADERS, 1, &[0, 0, 0, 2]);
        let (mut conn, tx) = default_connected(vec![pp]);
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect_err("push with ENABLE_PUSH=0");
        assert_eq!(err, H2ClientError::Protocol(error::PROTOCOL_ERROR));
        assert!(
            frames(&tx.borrow()[frame::PREFACE.len()..])
                .iter()
                .any(|f| f.0 == ftype::GOAWAY),
        );
    }

    #[test]
    fn continuation_reassembles_the_response_head() {
        // One response head split across HEADERS + 2 CONTINUATIONs.
        let mut block = Vec::new();
        hpack::encode_header_list(
            &[
                (b":status", b"200"),
                (b"content-type", b"text/plain"),
                (b"x-marker", b"split-head"),
            ],
            &mut block,
        );
        let cut1 = block.len() / 3;
        let cut2 = 2 * block.len() / 3;
        let mut wire = Vec::new();
        frame::push_frame(&mut wire, ftype::HEADERS, flags::END_STREAM, 1, &block[..cut1]);
        frame::push_frame(&mut wire, ftype::CONTINUATION, 0, 1, &block[cut1..cut2]);
        frame::push_frame(&mut wire, ftype::CONTINUATION, flags::END_HEADERS, 1, &block[cut2..]);
        let (mut conn, _tx) = default_connected(vec![wire]);
        let r = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect("reassembled");
        assert_eq!(r.status, 200);
        assert_eq!(r.header(b"x-marker"), Some(&b"split-head"[..]));
    }

    #[test]
    fn mid_conn_settings_shift_the_stream_send_window_and_ack() {
        let (mut conn, _tx) = default_connected(vec![]);
        let mut flight = InFlight {
            sid: 1,
            send_window: conn.peer_initial_window,
            recv_window: INITIAL_WINDOW,
            resp: RespAccum::new(64),
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(&settings_id::INITIAL_WINDOW_SIZE.to_be_bytes());
        payload.extend_from_slice(&100u32.to_be_bytes());
        let hdr = FrameHeader {
            length: payload.len() as u32,
            ty: ftype::SETTINGS,
            flags: 0,
            stream_id: 0,
        };
        conn.process_frame(Some(&mut flight), hdr, &payload).unwrap();
        // §6.9.2 retroactive shift: 65535 → 100 moves the open stream
        // window down by the delta.
        assert_eq!(flight.send_window, 100);
        assert_eq!(conn.peer_initial_window, 100);
        let fr = frames(&conn.ctrl_out);
        assert!(
            fr.iter().any(|f| f.0 == ftype::SETTINGS && f.1 & flags::ACK != 0),
            "mid-conn SETTINGS is ACKed",
        );
    }

    #[test]
    fn body_over_cap_cancels_the_stream() {
        let head = response_headers_frame(1, &[(&b":status"[..], &b"200"[..])], flags::END_HEADERS);
        let big = data_frame(1, &[0u8; 64], 0);
        let (mut conn, tx) = default_connected(vec![head, big]);
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 10))
            .expect_err("over cap");
        assert_eq!(err, H2ClientError::BodyTooLarge);
        let tx = tx.borrow();
        let rst = frames(&tx[frame::PREFACE.len()..])
            .into_iter()
            .find(|f| f.0 == ftype::RST_STREAM)
            .expect("stream cancelled");
        assert_eq!(u32::from_be_bytes([rst.3[0], rst.3[1], rst.3[2], rst.3[3]]), error::CANCEL);
    }

    #[test]
    fn interim_1xx_is_skipped() {
        let interim =
            response_headers_frame(1, &[(&b":status"[..], &b"103"[..])], flags::END_HEADERS);
        let fin = response_headers_frame(
            1,
            &[(&b":status"[..], &b"200"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let (mut conn, _tx) = default_connected(vec![interim, fin]);
        let r = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64)).expect("ok");
        assert_eq!(r.status, 200);
    }

    #[test]
    fn malformed_response_head_is_a_stream_error() {
        // No :status at all.
        let bad = response_headers_frame(
            1,
            &[(&b"content-type"[..], &b"text/plain"[..])],
            flags::END_HEADERS | flags::END_STREAM,
        );
        let (mut conn, tx) = default_connected(vec![bad]);
        let err = block_on(conn.request(b"GET", b"https", b"h", b"/", &[], None, 64))
            .expect_err("no :status");
        assert_eq!(err, H2ClientError::MalformedResponse);
        assert!(
            frames(&tx.borrow()[frame::PREFACE.len()..])
                .iter()
                .any(|f| f.0 == ftype::RST_STREAM),
        );
    }

    /// Fuzz-smoke (architecture-audit direction #2): the client's frame
    /// dispatch consumes server-controlled bytes — pin panic-freedom
    /// over fixed-seed random frames. The read path guarantees
    /// `hdr.length == payload.len()` (both come from the same wire
    /// prefix), so the fuzz keeps that invariant and randomises
    /// everything else.
    #[test]
    fn fuzz_smoke_dispatch_never_panics() {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let conn_and_flight = || {
            let (mut conn, _tx) = default_connected(vec![]);
            // Pretend streams 1..=9 were opened so HEADERS/DATA on
            // them exercise the deep paths, not just the early gates.
            conn.next_stream_id = 11;
            let mut flight = InFlight {
                sid: 1,
                send_window: conn.peer_initial_window,
                recv_window: INITIAL_WINDOW,
                resp: RespAccum::new(4096),
            };
            flight.resp.headers_done = true;
            (conn, flight)
        };
        let (mut conn, mut flight) = conn_and_flight();
        for i in 0..20_000u32 {
            if i % 256 == 0 {
                // Periodic fresh state so a poisoned conn (mid-asm,
                // huge windows) doesn't mask later paths.
                let (c, f) = conn_and_flight();
                conn = c;
                flight = f;
            }
            let len = (rnd() % 64) as usize;
            let payload: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let hdr = FrameHeader {
                length: payload.len() as u32,
                ty: (rnd() % 12) as u8,
                flags: rnd() as u8,
                stream_id: (rnd() % 8) as u32,
            };
            let _ = conn.process_frame(Some(&mut flight), hdr, &payload);
        }
    }
}

/// THE h2 loopback: the REAL `H2ClientConn` over the REAL
/// `TlsClientStream` (ALPN ["h2","http/1.1"] → "h2") against the REAL
/// `http2::serve_conn` + `TlsServer` over the in-memory pipe — the h2
/// sibling of `connect.rs`'s h1 loopback, sharing its harness. The
/// driver additionally ticks the executor so the server's spawned
/// per-stream handler tasks (bodied requests) run.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::task::{Context, Poll};
    use http::client::FetchRequest;
    use http::{Request, Response};
    use tls::server::AlpnProtocol;

    use crate::connect::loopback_tests::{
        ServerTlsPipe, loopback_gate, noop_waker, pinned_config_alpn, pipe_pair,
    };

    /// Alternating poller + executor tick (drives the h2 server's
    /// spawned per-stream handler tasks on worker 0's arena).
    fn run_loopback_h2<C, T, V>(client: C, server: T) -> V
    where
        C: Future<Output = V>,
        T: Future<Output = ()>,
    {
        let base = (
            crate::diag::COUNTERS.requests_received.get(),
            crate::diag::COUNTERS.requests_handled.get(),
            crate::diag::COUNTERS.responses_sent.get(),
            crate::diag::COUNTERS.connections_served.get(),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut client = core::pin::pin!(client);
        let mut server = core::pin::pin!(server);
        let mut server_done = false;
        for _ in 0..20_000 {
            if let Poll::Ready(v) = client.as_mut().poll(&mut cx) {
                return v;
            }
            if !server_done && server.as_mut().poll(&mut cx).is_ready() {
                server_done = true;
            }
            // Bounded: each tick drains the current ready set only.
            for _ in 0..16 {
                if !executor::tick(0) {
                    break;
                }
            }
        }
        panic!(
            "h2 loopback stalled: d_req_recv={} d_req_handled={} d_resp_sent={} d_conns={} server_done={}",
            crate::diag::COUNTERS.requests_received.get() - base.0,
            crate::diag::COUNTERS.requests_handled.get() - base.1,
            crate::diag::COUNTERS.responses_sent.get() - base.2,
            crate::diag::COUNTERS.connections_served.get() - base.3,
            server_done,
        );
    }

    const HELLO_BODY: &[u8] = b"hello from the real h2 serve_conn over TLS";

    async fn handler(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
        if req.path() == b"/echo" {
            // Buffered echo: drains the streamed request body the
            // demux feeds, then answers through `resp_sink`.
            let mut buf = Vec::new();
            while let Some(chunk) = req.read_chunk().await {
                buf.extend_from_slice(chunk.data());
            }
            res.set(Response::ok(b"application/octet-stream".as_slice(), buf));
            return Ok(());
        }
        match req.path() {
            b"/hello" => {
                res.set(Response::ok(b"text/plain".as_slice(), HELLO_BODY));
                Ok(())
            }
            _ => {
                res.set(Response::not_found());
                Ok(())
            }
        }
    }

    /// Full h2 exchange, in process, all-real both sides: pinned TLS
    /// handshake → ALPN "h2" → preface/SETTINGS → GET decoded
    /// byte-exact → a SECOND GET on the same conn (odd ids 1 then 3).
    #[test]
    fn loopback_h2_get_twice_against_real_serve_conn() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let client = async move {
            let stream =
                tls_client_handshake(client_pipe, [0xA1; 32], pinned_config_alpn(ALPN_H2))
                    .await
                    .expect("client handshake");
            assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]), "server selects h2");
            let mut conn = H2ClientConn::connect(stream).await.expect("h2 connect");
            let req = FetchRequest::get(b"loopback.test", b"/hello");
            for _ in 0..2 {
                let resp = h2_fetch(&mut conn, &req, 4096).await.expect("fetch");
                assert_eq!(resp.status, 200);
                assert_eq!(resp.body, HELLO_BODY, "byte-exact across TLS + h2 framing");
                assert_eq!(resp.header(b"content-type"), Some(&b"text/plain"[..]));
                assert_eq!(
                    resp.header(b"content-length"),
                    Some(alloc::format!("{}", HELLO_BODY.len()).as_bytes()),
                );
            }
            conn.close().await;
        };
        let server = async move {
            let mut stream = ServerTlsPipe::new(server_pipe, [0xB2; 32]);
            // Mirror `listen.rs`: handshake first (serve_conn writes
            // its SETTINGS immediately), then dispatch on the ALPN.
            let alpn = stream.drive_handshake().await.expect("server handshake");
            assert_eq!(alpn, AlpnProtocol::H2, "server side negotiated h2");
            crate::serve_conn(Arc::new(handler), stream).await;
        };

        run_loopback_h2(client, server);
    }

    /// POST with a request body: the client's DATA framing feeds the
    /// server's spawned streaming-body handler, which echoes it back.
    #[test]
    fn loopback_h2_post_echo() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let expect = payload.clone();
        let client = async move {
            let stream =
                tls_client_handshake(client_pipe, [0xC3; 32], pinned_config_alpn(ALPN_H2))
                    .await
                    .expect("client handshake");
            assert_eq!(stream.negotiated_alpn(), Some(&b"h2"[..]));
            let mut conn = H2ClientConn::connect(stream).await.expect("h2 connect");
            let mut req = FetchRequest::get(b"loopback.test", b"/echo");
            req.method = b"POST";
            req.body = Some(&payload);
            let resp = h2_fetch(&mut conn, &req, 256 * 1024).await.expect("post");
            assert_eq!(resp.status, 200);
            assert_eq!(resp.body.len(), expect.len());
            assert_eq!(resp.body, expect, "byte-exact echo through both flow-control sides");
            conn.close().await;
        };
        let server = async move {
            let mut stream = ServerTlsPipe::new(server_pipe, [0xD4; 32]);
            let alpn = stream.drive_handshake().await.expect("server handshake");
            assert_eq!(alpn, AlpnProtocol::H2, "server side negotiated h2");
            crate::serve_conn(Arc::new(handler), stream).await;
        };

        run_loopback_h2(client, server);
    }
}
