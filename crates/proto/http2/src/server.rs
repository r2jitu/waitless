// crates/proto/http2/src/server.rs — server-role HTTP/2 over one byte stream.
//
// `serve_conn` is the H2 sibling of `http::serve_conn`: it drives one
// connection through the shared `proto/http` handler API, generic over
// the byte stream (`HttpStream`), so the same TLS-over-TCP `TlsStream`
// that serves HTTP/1.1 serves HTTP/2 when ALPN selects "h2". It does
// *not* bind a port — `proto/tls`'s `listen` accepts the connection,
// runs the TLS handshake, and dispatches here on the negotiated ALPN.
//
// Multiplexing model (happy path): one connection task reads frames in
// order, assembles each request stream (HEADERS [+ CONTINUATION]
// [+ DATA] until END_STREAM), dispatches the handler inline when a
// stream completes, and enqueues the response. After every inbound
// frame the loop flushes queued responses subject to the HTTP/2
// connection + per-stream send windows — a cooperative single-writer
// over the one socket (the design the backlog favours over a task per
// stream). WINDOW_UPDATE frames credit the windows and the next flush
// drains more. Request bodies are buffered before dispatch (like the
// h3 server); streaming request bodies through `BodyReader` is a
// tracked tail item.
//
// Flow control here is the H2 layer's own min(stream_window,
// conn_window) discipline — distinct from, and stacked on top of, TCP's
// window underneath.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use http::{BodyReader, IOBuf, IOBufChain, Method, Request, Response, HttpStream};

use crate::frame::{self, FrameHeader, error, flags, ftype, settings_id};
use crate::hpack::{self, FieldSink, HpackError};

// ── Tunables / advertised limits ───────────────────────────────────

/// Idle timeout: tear the connection down after this long without a
/// frame. Matches the HTTP/1.1 keep-alive budget.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

/// Largest frame payload we accept (advertised `SETTINGS_MAX_FRAME_SIZE`,
/// also the protocol minimum / default). Frames larger than this are a
/// `FRAME_SIZE_ERROR`.
const MAX_FRAME_SIZE: usize = 16_384;

/// HPACK decoder table size we advertise (`SETTINGS_HEADER_TABLE_SIZE`,
/// RFC 7540 default). Bounds dynamic-table memory.
const HEADER_TABLE_SIZE: usize = 4_096;

/// Decompressed header-list cap (`SETTINGS_MAX_HEADER_LIST_SIZE`) — the
/// H2-2 HPACK-bomb guard.
const MAX_HEADER_LIST_SIZE: usize = 64 * 1024;

/// Concurrent-stream cap we advertise and enforce (H2-4). One
/// connection can't tie up more than this many in-flight streams.
const MAX_CONCURRENT_STREAMS: usize = 100;

/// Initial flow-control window (RFC 7540 §6.9.2 fixes this default for
/// both the connection and each stream).
const INITIAL_WINDOW: i64 = 65_535;

/// Largest request body we buffer before dispatch. Beyond this the
/// stream is reset — streaming large request bodies is a tail item.
const MAX_BODY: usize = 256 * 1024;

/// Cap on the bytes of one header block (HEADERS + CONTINUATIONs)
/// before END_HEADERS — the H2-5 CONTINUATION-flood guard.
const HEADER_BLOCK_CAP: usize = 64 * 1024;

/// Connection is torn down once this many stream resets accumulate —
/// the H2-1 Rapid-Reset (CVE-2023-44487) guard.
const RST_FLOOD_CAP: u32 = 200;

// ── Public entry point ─────────────────────────────────────────────

/// Serve one HTTP/2 connection to completion over `stream`. Mirrors
/// `http::serve_conn`'s shape and handler contract; `proto/tls` calls
/// this (instead of `http::serve_conn`) when ALPN negotiated "h2".
pub async fn serve_conn<S, H>(handler: Arc<H>, mut stream: S)
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    // One-time lazy-init of the shared Huffman tree (matches
    // http3::listen / tls::preinit — keeps the first request's alloc
    // out of the post-shutdown leak delta).
    field_huffman::preinit();

    crate::diag::COUNTERS.connections_served.bump();
    let mut conn = H2Conn::new();

    // Server connection preface: a SETTINGS frame is the first thing we
    // send (RFC 7540 §3.5).
    {
        let mut s = Vec::with_capacity(32);
        frame::push_settings(
            &mut s,
            &[
                (settings_id::MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS as u32),
                (settings_id::INITIAL_WINDOW_SIZE, INITIAL_WINDOW as u32),
                (settings_id::MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST_SIZE as u32),
            ],
        );
        if send_bytes(&mut stream, s).await.is_err() {
            return;
        }
    }

    // Read + validate the 24-byte client connection preface.
    if read_preface(&mut conn.inbuf, &mut stream).await.is_err() {
        crate::h2_drop!(bad_preface, "preface mismatch or eof");
        return;
    }

    let mut payload: Vec<u8> = Vec::with_capacity(MAX_FRAME_SIZE);
    loop {
        // 1. Flush queued control + response frames the windows allow.
        if flush(&mut conn, &mut stream).await.is_err() {
            return;
        }
        // 2. Done? (peer GOAWAY / our error after everything drained)
        if conn.closing && conn.out_queue.is_empty() && conn.ctrl_out.is_empty() {
            return;
        }
        // 3. Read the next frame.
        let hdr = match read_frame(&mut conn.inbuf, &mut stream, &mut payload).await {
            ReadResult::Frame(h) => h,
            ReadResult::FrameTooLarge => {
                conn.error_goaway(error::FRAME_SIZE_ERROR);
                let _ = flush(&mut conn, &mut stream).await;
                return;
            }
            ReadResult::Eof => return,
        };
        // 4. Process it.
        match process_frame(&mut conn, &mut stream, &handler, hdr, &payload).await {
            Ok(()) => {}
            Err(code) => {
                conn.error_goaway(code);
                let _ = flush(&mut conn, &mut stream).await;
                return;
            }
        }
    }
}

// ── Connection state ───────────────────────────────────────────────

struct H2Conn {
    hpack: hpack::Decoder,
    /// Inbound byte accumulator (raw frames not yet parsed).
    inbuf: Vec<u8>,
    /// Reusable HPACK decode scratch (heap, not in the future's inline
    /// state). Sized for the worst-case single name / value.
    name_scratch: Vec<u8>,
    value_scratch: Vec<u8>,
    /// Pending control frames (SETTINGS ack, WINDOW_UPDATE, PING ack,
    /// RST_STREAM, GOAWAY) awaiting flush. Not flow-controlled.
    ctrl_out: Vec<u8>,
    /// Responses being framed onto the wire, FIFO.
    out_queue: VecDeque<StreamOut>,
    /// Streams past HEADERS still accumulating a request body.
    pending_bodies: Vec<StreamReq>,
    /// In-progress header block (HEADERS without END_HEADERS); only one
    /// at a time per RFC 7540 §6.2 (no interleaving).
    header_asm: Option<HeaderAsm>,
    /// Connection-level send window (peer-granted; grows via
    /// WINDOW_UPDATE on stream 0).
    conn_send_window: i64,
    /// Peer's `SETTINGS_INITIAL_WINDOW_SIZE` — each new stream's send
    /// window starts here.
    peer_initial_window: i64,
    /// Peer's `SETTINGS_MAX_FRAME_SIZE` — caps the DATA frames we emit.
    peer_max_frame_size: usize,
    /// Highest client stream id seen (for ordering + GOAWAY).
    last_stream_id: u32,
    /// Cumulative RST_STREAM count (rapid-reset guard).
    streams_reset: u32,
    /// Set once we've decided to wind the connection down.
    closing: bool,
}

impl H2Conn {
    fn new() -> Self {
        H2Conn {
            hpack: hpack::Decoder::new(HEADER_TABLE_SIZE, MAX_HEADER_LIST_SIZE),
            inbuf: Vec::with_capacity(4096),
            name_scratch: alloc::vec![0u8; 256],
            value_scratch: alloc::vec![0u8; 16 * 1024],
            ctrl_out: Vec::new(),
            out_queue: VecDeque::new(),
            pending_bodies: Vec::new(),
            header_asm: None,
            conn_send_window: INITIAL_WINDOW,
            peer_initial_window: INITIAL_WINDOW,
            peer_max_frame_size: MAX_FRAME_SIZE,
            last_stream_id: 0,
            streams_reset: 0,
            closing: false,
        }
    }

    /// Streams that count against `MAX_CONCURRENT_STREAMS`: bodies being
    /// assembled plus responses still in flight.
    fn active_count(&self) -> usize {
        self.pending_bodies.len() + self.out_queue.len()
    }

    /// Queue a GOAWAY with the given error code and mark the connection
    /// closing.
    fn error_goaway(&mut self, code: u32) {
        if !self.closing {
            frame::push_goaway(&mut self.ctrl_out, self.last_stream_id, code);
            crate::diag::COUNTERS.goaway_sent.bump();
            self.closing = true;
        }
    }

    /// Build the next wire frame to emit across the out_queue, honouring
    /// the connection + per-stream send windows. Mutates accounting and
    /// removes finished streams. Returns `None` when nothing can make
    /// progress right now (all window-blocked or queue empty).
    fn next_output_frame(&mut self) -> Option<Vec<u8>> {
        let conn_win = self.conn_send_window;
        let peer_max = self.peer_max_frame_size as i64;
        let mut idx = 0;
        while idx < self.out_queue.len() {
            let item = &mut self.out_queue[idx];
            if !item.headers_sent {
                let end_stream = item.body_remaining == 0;
                let mut f = Vec::with_capacity(frame::FRAME_HEADER_LEN + item.header_block.len());
                let fl = flags::END_HEADERS | if end_stream { flags::END_STREAM } else { 0 };
                frame::push_frame(&mut f, ftype::HEADERS, fl, item.id, &item.header_block);
                item.headers_sent = true;
                if end_stream {
                    self.out_queue.remove(idx);
                }
                return Some(f);
            }
            if item.body_remaining > 0 {
                let allowed = conn_win
                    .min(item.send_window)
                    .min(peer_max)
                    .min(item.body_remaining as i64);
                if allowed > 0 {
                    let n = allowed as usize;
                    let chunk = item.take_body(n);
                    let end_stream = item.body_remaining == 0;
                    let id = item.id;
                    item.send_window -= n as i64;
                    let mut f = Vec::with_capacity(frame::FRAME_HEADER_LEN + chunk.len());
                    let fl = if end_stream { flags::END_STREAM } else { 0 };
                    frame::push_frame(&mut f, ftype::DATA, fl, id, &chunk);
                    self.conn_send_window -= n as i64;
                    if end_stream {
                        self.out_queue.remove(idx);
                    }
                    return Some(f);
                }
                // Window-blocked: try the next stream.
                idx += 1;
                continue;
            }
            // Headers sent and no body left — shouldn't linger; drop it.
            self.out_queue.remove(idx);
        }
        None
    }
}

/// A request stream still accumulating its body (HEADERS seen, awaiting
/// DATA + END_STREAM).
struct StreamReq {
    id: u32,
    req: Request,
    body: Vec<u8>,
}

/// A response being framed onto the wire.
struct StreamOut {
    id: u32,
    header_block: Vec<u8>,
    headers_sent: bool,
    /// Current front body part being drained.
    cur: Option<IOBuf>,
    cur_off: usize,
    /// Remaining body parts.
    body: IOBufChain,
    /// Total body bytes still to send.
    body_remaining: usize,
    /// Per-stream send window (peer-granted).
    send_window: i64,
}

impl StreamOut {
    /// Copy up to `n` body bytes out (advancing the cursor) for the next
    /// DATA frame. Single-part per call is unnecessary — we coalesce
    /// across parts up to `n`.
    fn take_body(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n.min(self.body_remaining));
        let mut need = n;
        while need > 0 {
            if self.cur.is_none() {
                self.cur = self.body.pop_front();
                self.cur_off = 0;
                if self.cur.is_none() {
                    break;
                }
            }
            let part = self.cur.as_ref().unwrap();
            let data = part.data();
            let avail = data.len() - self.cur_off;
            if avail == 0 {
                self.cur = None;
                continue;
            }
            let take = avail.min(need);
            out.extend_from_slice(&data[self.cur_off..self.cur_off + take]);
            self.cur_off += take;
            need -= take;
            if self.cur_off >= data.len() {
                self.cur = None;
            }
        }
        self.body_remaining -= out.len();
        out
    }
}

/// In-progress header block spanning HEADERS + CONTINUATION frames.
struct HeaderAsm {
    stream_id: u32,
    buf: Vec<u8>,
    end_stream: bool,
}

// ── Frame I/O ──────────────────────────────────────────────────────

enum ReadResult {
    Frame(FrameHeader),
    FrameTooLarge,
    Eof,
}

/// Ensure `inbuf` holds at least `n` bytes, reading chunks (with idle
/// timeout) as needed.
async fn fill_at_least<S: HttpStream>(
    inbuf: &mut Vec<u8>,
    stream: &mut S,
    n: usize,
) -> Result<(), ()> {
    while inbuf.len() < n {
        let fut = stream.recv_chunk();
        match waitless::runtime::timeout_us(IDLE_TIMEOUT_US, fut).await {
            Some(Some(g)) => inbuf.extend_from_slice(g.data()),
            _ => return Err(()),
        }
    }
    Ok(())
}

/// Read + validate the 24-byte client connection preface, consuming it
/// from `inbuf`.
async fn read_preface<S: HttpStream>(inbuf: &mut Vec<u8>, stream: &mut S) -> Result<(), ()> {
    fill_at_least(inbuf, stream, frame::PREFACE.len()).await?;
    if &inbuf[..frame::PREFACE.len()] != frame::PREFACE {
        return Err(());
    }
    inbuf.drain(..frame::PREFACE.len());
    Ok(())
}

/// Read one complete frame: its header into the return value, its
/// payload copied into `payload` (drained from `inbuf`).
async fn read_frame<S: HttpStream>(
    inbuf: &mut Vec<u8>,
    stream: &mut S,
    payload: &mut Vec<u8>,
) -> ReadResult {
    loop {
        if inbuf.len() >= frame::FRAME_HEADER_LEN {
            let hdr = FrameHeader::parse(&inbuf[..frame::FRAME_HEADER_LEN]);
            if hdr.length as usize > MAX_FRAME_SIZE {
                return ReadResult::FrameTooLarge;
            }
            let total = frame::FRAME_HEADER_LEN + hdr.length as usize;
            if inbuf.len() >= total {
                payload.clear();
                payload.extend_from_slice(&inbuf[frame::FRAME_HEADER_LEN..total]);
                inbuf.drain(..total);
                return ReadResult::Frame(hdr);
            }
        }
        let fut = stream.recv_chunk();
        match waitless::runtime::timeout_us(IDLE_TIMEOUT_US, fut).await {
            Some(Some(g)) => inbuf.extend_from_slice(g.data()),
            _ => return ReadResult::Eof,
        }
    }
}

/// Send an owned byte buffer as one chain.
async fn send_bytes<S: HttpStream>(stream: &mut S, bytes: Vec<u8>) -> Result<(), ()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let mut chain = IOBufChain::new();
    chain.push_back(IOBuf::from(bytes));
    stream.send(&mut chain).await
}

/// Flush pending control frames, then drain the response queue subject
/// to flow control.
async fn flush<S: HttpStream>(conn: &mut H2Conn, stream: &mut S) -> Result<(), ()> {
    if !conn.ctrl_out.is_empty() {
        let bytes = core::mem::take(&mut conn.ctrl_out);
        send_bytes(stream, bytes).await?;
    }
    while let Some(frame_bytes) = conn.next_output_frame() {
        send_bytes(stream, frame_bytes).await?;
    }
    Ok(())
}

// ── Frame dispatch ─────────────────────────────────────────────────

/// Process one frame. `Ok(())` = handled (the loop checks `conn.closing`
/// for graceful wind-down); `Err(code)` = connection error → GOAWAY.
async fn process_frame<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    hdr: FrameHeader,
    payload: &[u8],
) -> Result<(), u32>
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    // A header block in mid-assembly forbids interleaving: only a
    // CONTINUATION on the same stream may follow (RFC 7540 §6.2).
    if let Some(asm) = &conn.header_asm {
        if hdr.ty != ftype::CONTINUATION || hdr.stream_id != asm.stream_id {
            return Err(error::PROTOCOL_ERROR);
        }
        return continue_headers(conn, stream, handler, hdr, payload).await;
    }
    if hdr.ty == ftype::CONTINUATION {
        // CONTINUATION with no preceding HEADERS.
        return Err(error::PROTOCOL_ERROR);
    }

    match hdr.ty {
        ftype::SETTINGS => process_settings(conn, hdr, payload),
        ftype::HEADERS => process_headers(conn, stream, handler, hdr, payload).await,
        ftype::DATA => process_data(conn, stream, handler, hdr, payload).await,
        ftype::WINDOW_UPDATE => process_window_update(conn, hdr, payload),
        ftype::RST_STREAM => process_rst_stream(conn, hdr),
        ftype::PING => process_ping(conn, hdr, payload),
        ftype::PRIORITY => Ok(()), // deprecated — parse-and-ignore (RFC 9218).
        ftype::GOAWAY => {
            // Peer is winding down; finish queued work then close.
            conn.closing = true;
            Ok(())
        }
        ftype::PUSH_PROMISE => Err(error::PROTOCOL_ERROR), // clients must not push.
        _ => Ok(()), // Unknown frame types are ignored (RFC 7540 §4.1).
    }
}

fn process_settings(conn: &mut H2Conn, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
    if hdr.stream_id != 0 {
        return Err(error::PROTOCOL_ERROR);
    }
    if hdr.has_flag(flags::ACK) {
        // ACK of our SETTINGS — must be empty.
        if hdr.length != 0 {
            return Err(error::FRAME_SIZE_ERROR);
        }
        return Ok(());
    }
    let params = frame::parse_settings(payload).ok_or(error::FRAME_SIZE_ERROR)?;
    for (id, val) in params {
        apply_setting(conn, id, val)?;
    }
    frame::push_settings_ack(&mut conn.ctrl_out);
    Ok(())
}

fn apply_setting(conn: &mut H2Conn, id: u16, val: u32) -> Result<(), u32> {
    match id {
        settings_id::INITIAL_WINDOW_SIZE => {
            if val > 0x7fff_ffff {
                return Err(error::FLOW_CONTROL_ERROR);
            }
            // Retroactive adjustment of open streams' windows (RFC 7540
            // §6.9.2) is a tracked tail item (H2-6); peers send this
            // before opening streams in practice.
            conn.peer_initial_window = val as i64;
        }
        settings_id::MAX_FRAME_SIZE => {
            // Valid range 2^14..=2^24-1 (RFC 7540 §6.5.2).
            if !(16_384..=16_777_215).contains(&val) {
                return Err(error::PROTOCOL_ERROR);
            }
            conn.peer_max_frame_size = val as usize;
        }
        settings_id::ENABLE_PUSH => {
            if val > 1 {
                return Err(error::PROTOCOL_ERROR);
            }
            // We never push, so the value is informational.
        }
        // HEADER_TABLE_SIZE bounds OUR encoder's dynamic table — we use
        // none, so nothing to do. MAX_CONCURRENT_STREAMS / MAX_HEADER_
        // LIST_SIZE bound what WE send; our responses stay well under
        // any sane value. Unknown ids are ignored (RFC 7540 §6.5.2).
        _ => {}
    }
    Ok(())
}

async fn process_headers<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    hdr: FrameHeader,
    payload: &[u8],
) -> Result<(), u32>
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    if hdr.stream_id == 0 || hdr.stream_id.is_multiple_of(2) {
        // Client streams are non-zero and odd (RFC 7540 §5.1.1).
        return Err(error::PROTOCOL_ERROR);
    }
    let frag = headers_fragment(payload, hdr.flags).ok_or(error::PROTOCOL_ERROR)?;
    let end_stream = hdr.has_flag(flags::END_STREAM);
    if hdr.has_flag(flags::END_HEADERS) {
        complete_headers(conn, stream, handler, hdr.stream_id, end_stream, frag).await
    } else {
        if frag.len() > HEADER_BLOCK_CAP {
            crate::h2_drop!(header_block_too_large, "sid={}", hdr.stream_id);
            return Err(error::ENHANCE_YOUR_CALM);
        }
        conn.header_asm = Some(HeaderAsm {
            stream_id: hdr.stream_id,
            buf: frag.to_vec(),
            end_stream,
        });
        Ok(())
    }
}

async fn continue_headers<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    hdr: FrameHeader,
    payload: &[u8],
) -> Result<(), u32>
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    {
        let asm = conn.header_asm.as_mut().expect("checked by caller");
        if asm.buf.len() + payload.len() > HEADER_BLOCK_CAP {
            crate::h2_drop!(header_block_too_large, "sid={}", hdr.stream_id);
            return Err(error::ENHANCE_YOUR_CALM);
        }
        asm.buf.extend_from_slice(payload);
    }
    if hdr.has_flag(flags::END_HEADERS) {
        let asm = conn.header_asm.take().expect("present");
        complete_headers(conn, stream, handler, asm.stream_id, asm.end_stream, &asm.buf).await
    } else {
        Ok(())
    }
}

/// Decode a finished header block (HPACK), build the request, and either
/// dispatch (no body / END_STREAM) or stash it awaiting DATA. HPACK is
/// decoded for *every* block to keep the dynamic table in sync.
async fn complete_headers<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    sid: u32,
    end_stream: bool,
    block: &[u8],
) -> Result<(), u32>
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    let mut req = Request::new();
    let malformed = {
        let mut sink = RequestSink {
            req: &mut req,
            malformed: false,
        };
        match conn.hpack.decode(
            block,
            &mut conn.name_scratch[..],
            &mut conn.value_scratch[..],
            &mut sink,
        ) {
            Ok(()) => sink.malformed,
            Err(HpackError::HeaderListTooLarge) => {
                crate::h2_drop!(header_list_too_large, "sid={}", sid);
                return Err(error::ENHANCE_YOUR_CALM);
            }
            Err(_) => {
                crate::h2_drop!(hpack_error, "sid={}", sid);
                return Err(error::COMPRESSION_ERROR);
            }
        }
    };

    // Trailers on a stream already accumulating a body: the only thing
    // that matters is the END_STREAM they (must) carry.
    if let Some(pos) = conn.pending_bodies.iter().position(|s| s.id == sid) {
        if end_stream {
            let StreamReq { id, req, body } = conn.pending_bodies.remove(pos);
            dispatch_stream(conn, stream, handler, id, req, &body).await;
        }
        return Ok(());
    }

    // A new request stream — ids must strictly increase (RFC 7540 §5.1.1).
    if sid <= conn.last_stream_id {
        return Err(error::PROTOCOL_ERROR);
    }
    conn.last_stream_id = sid;

    if malformed {
        // Bad pseudo-headers → stream error, not connection error.
        frame::push_rst_stream(&mut conn.ctrl_out, sid, error::PROTOCOL_ERROR);
        return Ok(());
    }
    if conn.active_count() >= MAX_CONCURRENT_STREAMS {
        crate::h2_drop!(stream_refused, "sid={} active={}", sid, conn.active_count());
        frame::push_rst_stream(&mut conn.ctrl_out, sid, error::REFUSED_STREAM);
        return Ok(());
    }

    if end_stream {
        dispatch_stream(conn, stream, handler, sid, req, &[]).await;
    } else {
        conn.pending_bodies.push(StreamReq {
            id: sid,
            req,
            body: Vec::new(),
        });
    }
    Ok(())
}

async fn process_data<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    hdr: FrameHeader,
    payload: &[u8],
) -> Result<(), u32>
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    if hdr.stream_id == 0 {
        return Err(error::PROTOCOL_ERROR);
    }
    let data = data_payload(payload, hdr.flags).ok_or(error::PROTOCOL_ERROR)?;
    // The full frame length (incl. padding) counts against flow control
    // (RFC 7540 §6.1); replenish it so the peer can keep sending.
    let full_len = hdr.length;
    let mut stream_open = false;

    if let Some(pos) = conn.pending_bodies.iter().position(|s| s.id == hdr.stream_id) {
        let too_big = conn.pending_bodies[pos].body.len() + data.len() > MAX_BODY;
        if too_big {
            frame::push_rst_stream(&mut conn.ctrl_out, hdr.stream_id, error::ENHANCE_YOUR_CALM);
            conn.pending_bodies.remove(pos);
        } else {
            conn.pending_bodies[pos].body.extend_from_slice(data);
            if hdr.has_flag(flags::END_STREAM) {
                let StreamReq { id, req, body } = conn.pending_bodies.remove(pos);
                dispatch_stream(conn, stream, handler, id, req, &body).await;
            } else {
                stream_open = true;
            }
        }
    }
    // DATA for an unknown stream is leniently ignored (it may be one we
    // already finished / reset) — we still replenish the connection
    // window so the peer's accounting stays consistent.

    if full_len > 0 {
        frame::push_window_update(&mut conn.ctrl_out, 0, full_len);
        if stream_open {
            frame::push_window_update(&mut conn.ctrl_out, hdr.stream_id, full_len);
        }
    }
    Ok(())
}

fn process_window_update(conn: &mut H2Conn, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
    if hdr.length != 4 {
        return Err(error::FRAME_SIZE_ERROR);
    }
    let inc = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
    if inc == 0 {
        // Zero increment: connection error on stream 0, else stream error.
        if hdr.stream_id == 0 {
            return Err(error::PROTOCOL_ERROR);
        }
        frame::push_rst_stream(&mut conn.ctrl_out, hdr.stream_id, error::PROTOCOL_ERROR);
        return Ok(());
    }
    if hdr.stream_id == 0 {
        conn.conn_send_window += inc as i64;
        if conn.conn_send_window > 0x7fff_ffff {
            return Err(error::FLOW_CONTROL_ERROR);
        }
    } else if let Some(item) = conn.out_queue.iter_mut().find(|s| s.id == hdr.stream_id) {
        item.send_window += inc as i64;
        if item.send_window > 0x7fff_ffff {
            frame::push_rst_stream(&mut conn.ctrl_out, hdr.stream_id, error::FLOW_CONTROL_ERROR);
        }
    }
    // A WINDOW_UPDATE for a stream with no queued response (already
    // flushed, or not yet dispatched) is ignored.
    Ok(())
}

fn process_rst_stream(conn: &mut H2Conn, hdr: FrameHeader) -> Result<(), u32> {
    if hdr.stream_id == 0 {
        return Err(error::PROTOCOL_ERROR);
    }
    if hdr.length != 4 {
        return Err(error::FRAME_SIZE_ERROR);
    }
    conn.streams_reset += 1;
    conn.pending_bodies.retain(|s| s.id != hdr.stream_id);
    conn.out_queue.retain(|s| s.id != hdr.stream_id);
    if conn.streams_reset > RST_FLOOD_CAP {
        crate::h2_drop!(rapid_reset_abort, "resets={}", conn.streams_reset);
        return Err(error::ENHANCE_YOUR_CALM);
    }
    Ok(())
}

fn process_ping(conn: &mut H2Conn, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
    if hdr.stream_id != 0 {
        return Err(error::PROTOCOL_ERROR);
    }
    if hdr.length != 8 {
        return Err(error::FRAME_SIZE_ERROR);
    }
    if !hdr.has_flag(flags::ACK) {
        let mut op = [0u8; 8];
        op.copy_from_slice(&payload[..8]);
        frame::push_ping_ack(&mut conn.ctrl_out, &op);
    }
    Ok(())
}

/// Run the handler for a completed request stream and enqueue its
/// response frames. The request body is fully buffered in `body_bytes`,
/// so the `BodyReader` serves entirely from its prebuf and never pulls
/// the stream (matching the h3 server's buffered-body model).
async fn dispatch_stream<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    sid: u32,
    mut req: Request,
    body_bytes: &[u8],
) where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    crate::diag::COUNTERS.requests_received.bump();
    req.set_content_length(body_bytes.len());
    let resp = {
        let mut body = BodyReader::new(stream, body_bytes, body_bytes.len());
        (**handler)(&req, &mut body).await
    };
    crate::diag::COUNTERS.requests_handled.bump();

    let mut header_block = Vec::with_capacity(64);
    encode_response_headers(&resp, &mut header_block);
    let body = resp.into_body();
    let body_remaining = body.total_len();
    conn.out_queue.push_back(StreamOut {
        id: sid,
        header_block,
        headers_sent: false,
        cur: None,
        cur_off: 0,
        body,
        body_remaining,
        send_window: conn.peer_initial_window,
    });
    crate::diag::COUNTERS.responses_sent.bump();
}

// ── Header (de)framing helpers ─────────────────────────────────────

/// Sink that maps decoded HPACK fields into an `http::Request` — the H2
/// cousin of the h3 server's `RequestSink`.
struct RequestSink<'r> {
    req: &'r mut Request,
    /// Set on a malformed pseudo-header (response pseudo in a request, or
    /// an unknown `:`-prefixed name) → stream error.
    malformed: bool,
}

impl FieldSink for RequestSink<'_> {
    fn on_field(&mut self, name: &[u8], value: &[u8]) {
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
            // Surface :authority as a Host header so app code that reads
            // `Host` keeps working across H1/H2/H3.
            b":authority" => self.req.push_header(b"host", value),
            b":scheme" => {} // not used for routing — drop.
            b":status" => self.malformed = true, // response pseudo in a request.
            n if n.starts_with(b":") => self.malformed = true, // unknown pseudo.
            _ => self.req.push_header(name, value),
        }
    }
}

/// Strip optional padding / priority fields from a HEADERS payload,
/// yielding the header-block fragment. `None` on a malformed frame.
fn headers_fragment(payload: &[u8], fl: u8) -> Option<&[u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if fl & flags::PADDED != 0 {
        let (&first, rest) = p.split_first()?;
        pad = first as usize;
        p = rest;
    }
    if fl & flags::PRIORITY != 0 {
        if p.len() < 5 {
            return None;
        }
        p = &p[5..];
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// Strip optional padding from a DATA payload.
fn data_payload(payload: &[u8], fl: u8) -> Option<&[u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if fl & flags::PADDED != 0 {
        let (&first, rest) = p.split_first()?;
        pad = first as usize;
        p = rest;
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// Encode a `Response`'s header section as an HPACK header block.
fn encode_response_headers(resp: &Response, out: &mut Vec<u8>) {
    let status = status_to_3digits(resp.status);
    let mut len_buf = [0u8; 20];
    let len_off = format_usize(resp.body_len(), &mut len_buf);

    let mut list: Vec<(&[u8], &[u8])> = Vec::with_capacity(3 + http::MAX_EXTRA_HEADERS);
    list.push((b":status", &status));
    list.push((b"content-type", resp.content_type_bytes()));
    list.push((b"content-length", &len_buf[len_off..]));
    for (name, value) in resp.extra_headers() {
        list.push((name, value));
    }
    hpack::encode_header_list(&list, out);
}

/// Render an HTTP status code as 3 ASCII digits (clamped to 0..=999).
fn status_to_3digits(status: i32) -> [u8; 3] {
    let s = status.clamp(0, 999) as u32;
    [
        b'0' + (s / 100) as u8,
        b'0' + ((s / 10) % 10) as u8,
        b'0' + (s % 10) as u8,
    ]
}

/// Format `n` as ASCII decimal into `buf` from the right; returns the
/// start offset (`&buf[off..]` is the number).
fn format_usize(n: usize, buf: &mut [u8; 20]) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_fragment_strips_pad_and_priority() {
        // PADDED + PRIORITY: [padlen=2][5 priority bytes][block "ab"][2 pad]
        let payload = [2, 0, 0, 0, 0, 0, b'a', b'b', 0xff, 0xff];
        let frag = headers_fragment(&payload, flags::PADDED | flags::PRIORITY).unwrap();
        assert_eq!(frag, b"ab");
    }

    #[test]
    fn headers_fragment_plain() {
        let payload = [b'x', b'y', b'z'];
        let frag = headers_fragment(&payload, 0).unwrap();
        assert_eq!(frag, b"xyz");
    }

    #[test]
    fn data_payload_strips_padding() {
        // PADDED: [padlen=3]["body"][3 pad]
        let payload = [3, b'b', b'o', b'd', b'y', 0, 0, 0];
        let data = data_payload(&payload, flags::PADDED).unwrap();
        assert_eq!(data, b"body");
    }

    #[test]
    fn bad_padding_rejected() {
        // pad length exceeds remaining payload.
        let payload = [9, b'a'];
        assert!(data_payload(&payload, flags::PADDED).is_none());
    }

    #[test]
    fn status_digits() {
        assert_eq!(status_to_3digits(200), *b"200");
        assert_eq!(status_to_3digits(404), *b"404");
        assert_eq!(status_to_3digits(503), *b"503");
    }

    #[test]
    fn usize_format() {
        let mut b = [0u8; 20];
        let off = format_usize(0, &mut b);
        assert_eq!(&b[off..], b"0");
        let off = format_usize(12345, &mut b);
        assert_eq!(&b[off..], b"12345");
    }

    #[test]
    fn take_body_coalesces_parts() {
        let mut chain = IOBufChain::new();
        chain.push_back(IOBuf::from(b"hello".to_vec()));
        chain.push_back(IOBuf::from(b"world".to_vec()));
        let mut out = StreamOut {
            id: 1,
            header_block: Vec::new(),
            headers_sent: true,
            cur: None,
            cur_off: 0,
            body: chain,
            body_remaining: 10,
            send_window: INITIAL_WINDOW,
        };
        let first = out.take_body(7);
        assert_eq!(first, b"hellowo");
        assert_eq!(out.body_remaining, 3);
        let rest = out.take_body(100);
        assert_eq!(rest, b"rld");
        assert_eq!(out.body_remaining, 0);
    }
}
