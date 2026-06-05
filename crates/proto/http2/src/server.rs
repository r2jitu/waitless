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

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;

use http::{BodyReader, BodySource, HttpStream, IOBuf, IOBufChain, Method, Request, Response};
use waitless::runtime::{AsyncEvent, Either, select, spawn};

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

/// Backpressure cap on a streaming stream's not-yet-consumed receive
/// buffer. We credit the peer (WINDOW_UPDATE) only as the handler
/// drains, so a well-behaved peer never exceeds the window we
/// advertised; this is the defensive ceiling for a peer that ignores
/// flow control — past it we reset the stream.
const STREAM_RECV_BUF_CAP: usize = 1024 * 1024;

/// Cap on the bytes of one header block (HEADERS + CONTINUATIONs)
/// before END_HEADERS — the H2-5 CONTINUATION-flood guard.
const HEADER_BLOCK_CAP: usize = 64 * 1024;

/// Connection is torn down once this many stream resets accumulate —
/// the H2-1 Rapid-Reset (CVE-2023-44487) guard.
const RST_FLOOD_CAP: u32 = 200;

/// Steady-state cycle counter for the per-phase profiling brackets
/// (HPACK decode / encode / framing). Same rdtsc / cntvct instruction
/// the `http` + `tls` profilers use; zero on unsupported targets.
#[inline(always)]
fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) v,
            options(nomem, nostack, preserves_flags));
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

// ── Public entry point ─────────────────────────────────────────────

/// Serve one HTTP/2 connection to completion over `stream`. Mirrors
/// `http::serve_conn`'s shape and handler contract; `proto/tls` calls
/// this (instead of `http::serve_conn`) when ALPN negotiated "h2".
pub async fn serve_conn<S, H>(handler: Arc<H>, mut stream: S)
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
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
        // Arm the handler-wakeup before the bookkeeping sweeps. The
        // sweeps below run unconditionally (nothing is missed); the
        // flag only governs whether the `select` re-wakes for work a
        // handler task signals after this point.
        conn.demux_wake.reset();
        // 1. Emit receive-window credit for body bytes streaming
        //    handlers consumed, and move finished responses into the
        //    framing queue.
        conn.credit_consumed_bodies();
        conn.drain_responses();
        // 2. Flush queued control + response frames the windows allow.
        if flush(&mut conn, &mut stream).await.is_err() {
            reset_all_streams(&mut conn);
            return;
        }
        // 3. Done? (peer GOAWAY / our error, everything drained, no
        //    in-flight handlers).
        if conn.closing
            && conn.out_queue.is_empty()
            && conn.ctrl_out.is_empty()
            && conn.streams.is_empty()
        {
            return;
        }
        // 4. Wait for the next frame OR a handler task signalling work.
        //    `select` polls the read first and only drops it while
        //    pending (no chunk dequeued yet), so no inbound bytes are
        //    lost when the wakeup branch wins.
        let wake = Rc::clone(&conn.demux_wake);
        let read = read_frame(&mut conn.inbuf, &mut stream, &mut payload);
        let hdr = match select(read, wake.wait()).await {
            Either::Right(()) => continue, // handler signalled → re-sweep.
            Either::Left(ReadResult::Frame(h)) => h,
            Either::Left(ReadResult::FrameTooLarge) => {
                conn.error_goaway(error::FRAME_SIZE_ERROR);
                let _ = flush(&mut conn, &mut stream).await;
                reset_all_streams(&mut conn);
                return;
            }
            Either::Left(ReadResult::Eof) => {
                reset_all_streams(&mut conn);
                return;
            }
        };
        // 5. Process it.
        match process_frame(&mut conn, &mut stream, &handler, hdr, &payload).await {
            Ok(()) => {}
            Err(code) => {
                conn.error_goaway(code);
                let _ = flush(&mut conn, &mut stream).await;
                reset_all_streams(&mut conn);
                return;
            }
        }
    }
}

/// Tear down all in-flight streaming handlers: flag each reset and wake
/// it so its `H2BodySource` returns `None` and the task unwinds (its
/// response, if any, is dropped). Drops the demux's `StreamBody`
/// handles; the tasks keep their own clones until they finish.
fn reset_all_streams(conn: &mut H2Conn) {
    for slot in &conn.streams {
        slot.body.data.borrow_mut().reset = true;
        slot.body.event.set();
    }
    conn.streams.clear();
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
    /// Reused flush scratch: each flush frames control + response frames
    /// into it, then ships it as one IOBuf. Persisting it keeps the
    /// framing path allocation-free across requests.
    frame_buf: Vec<u8>,
    /// Responses being framed onto the wire, FIFO.
    out_queue: VecDeque<StreamOut>,
    /// Streaming request streams — one spawned handler task each, fed by
    /// a `StreamBody` the demux pushes DATA into. The body path for
    /// every request that carries one.
    streams: Vec<StreamSlot>,
    /// Responses produced by spawned handler tasks, awaiting framing.
    /// The task pushes `(stream_id, response)`; the demux drains into
    /// `out_queue`. Shared (the tasks hold a clone).
    resp_sink: Rc<RefCell<VecDeque<(u32, Response)>>>,
    /// Set by handler tasks when a response is ready or body bytes were
    /// consumed (credit to emit). The demux is the single waiter.
    demux_wake: Rc<AsyncEvent>,
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
            frame_buf: Vec::new(),
            out_queue: VecDeque::new(),
            streams: Vec::new(),
            resp_sink: Rc::new(RefCell::new(VecDeque::new())),
            demux_wake: Rc::new(AsyncEvent::new()),
            header_asm: None,
            conn_send_window: INITIAL_WINDOW,
            peer_initial_window: INITIAL_WINDOW,
            peer_max_frame_size: MAX_FRAME_SIZE,
            last_stream_id: 0,
            streams_reset: 0,
            closing: false,
        }
    }

    /// Streams that count against `MAX_CONCURRENT_STREAMS`: streaming
    /// handlers in flight plus responses still framing.
    fn active_count(&self) -> usize {
        self.streams.len() + self.out_queue.len()
    }

    /// Emit WINDOW_UPDATE credit for body bytes streaming handlers have
    /// consumed since the last sweep (receive-side flow control). Called
    /// each demux iteration; cheap when nothing was consumed.
    fn credit_consumed_bodies(&mut self) {
        for slot in &self.streams {
            let n = {
                let mut d = slot.body.data.borrow_mut();
                core::mem::take(&mut d.consumed_uncredited)
            };
            if n > 0 {
                // Stream-level credit only — the connection window is
                // replenished on arrival in `process_data`. `n` is bounded
                // by STREAM_RECV_BUF_CAP (1 MiB) « i31, so the clamp never
                // actually drops credit; the assert guards that invariant
                // if the cap is ever raised.
                debug_assert!(n <= 0x7fff_ffff, "WINDOW_UPDATE increment {n} exceeds i31");
                frame::push_window_update(&mut self.ctrl_out, slot.id, n.min(0x7fff_ffff) as u32);
            }
        }
    }

    /// Move completed handler responses into the framing queue. Drops a
    /// response whose stream was reset. Returns the stream ids that
    /// finished (so the caller can retire their slots).
    fn drain_responses(&mut self) {
        loop {
            let next = self.resp_sink.borrow_mut().pop_front();
            let Some((sid, resp)) = next else { break };
            // Locate the slot; a reset stream drops its response. No slot
            // (already reset+removed) → drop.
            let pos = self.streams.iter().position(|s| s.id == sid);
            if let Some(i) = pos {
                let was_reset = self.streams[i].body.data.borrow().reset;
                self.streams.remove(i);
                if !was_reset {
                    self.queue_response(sid, resp);
                }
            }
        }
    }

    /// Frame a finished `Response` onto `out_queue` (headers + body),
    /// honouring the per-stream initial send window.
    fn queue_response(&mut self, sid: u32, resp: Response) {
        let mut header_block = Vec::with_capacity(64);
        let __e0 = now_cycles();
        encode_response_headers(&resp, &mut header_block);
        crate::diag::COUNTERS
            .encode_cycles
            .add(now_cycles().wrapping_sub(__e0));
        let body = resp.into_body();
        let body_remaining = body.total_len();
        // Large bodies frame their DATA payloads zero-copy from the
        // body's own IOBufs; small ones copy inline into the flush
        // buffer (one contiguous send, cheaper than a chain part +
        // VecDeque for a handful of bytes).
        let zero_copy = body_remaining > INLINE_BODY_MAX;
        self.out_queue.push_back(StreamOut {
            id: sid,
            header_block,
            headers_sent: false,
            cur: None,
            cur_off: 0,
            body,
            body_remaining,
            send_window: self.peer_initial_window,
            zero_copy,
        });
        crate::diag::COUNTERS.responses_sent.bump();
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

    /// Drain every sendable frame across the out_queue into one send,
    /// honouring the connection + per-stream windows. Small frames
    /// (HEADERS, control already in `hdr_buf`, DATA frame headers, and
    /// the DATA payloads of small responses) accumulate contiguously in
    /// `hdr_buf`; a large response's DATA payloads are appended to
    /// `chain` **zero-copy** as the body's own (window-sliced) IOBufs,
    /// cutting the accumulated `hdr_buf` into the chain first so wire
    /// order holds. The caller flushes any trailing `hdr_buf` and ships
    /// `chain` in a single send. Mutates accounting and removes finished
    /// streams.
    fn drain_to_chain(&mut self, hdr_buf: &mut Vec<u8>, chain: &mut IOBufChain) {
        let peer_max = self.peer_max_frame_size as i64;
        let mut idx = 0;
        while idx < self.out_queue.len() {
            if !self.out_queue[idx].headers_sent {
                let item = &mut self.out_queue[idx];
                let end_stream = item.body_remaining == 0;
                let fl = flags::END_HEADERS | if end_stream { flags::END_STREAM } else { 0 };
                frame::push_frame(hdr_buf, ftype::HEADERS, fl, item.id, &item.header_block);
                item.headers_sent = true;
                if end_stream {
                    self.out_queue.remove(idx);
                }
                continue;
            }
            if self.out_queue[idx].body_remaining > 0 {
                let item = &self.out_queue[idx];
                let allowed = self
                    .conn_send_window
                    .min(item.send_window)
                    .min(peer_max)
                    .min(item.body_remaining as i64);
                if allowed <= 0 {
                    // Window-blocked: try the next stream.
                    idx += 1;
                    continue;
                }
                let n = allowed as usize;
                let item = &mut self.out_queue[idx];
                // END_STREAM iff this frame drains the last body byte.
                let finishes = item.body_remaining == n;
                let fl = if finishes { flags::END_STREAM } else { 0 };
                frame::push_frame_header(hdr_buf, n as u32, ftype::DATA, fl, item.id);
                if item.zero_copy {
                    // Cut the accumulated header bytes, then append the
                    // body's own IOBufs zero-copy after them.
                    if !hdr_buf.is_empty() {
                        chain.push_back(IOBuf::from_slice_with_headroom(0, &hdr_buf[..], 0));
                        hdr_buf.clear();
                    }
                    item.push_body(chain, n);
                } else {
                    item.append_body_into(hdr_buf, n);
                }
                item.send_window -= n as i64;
                self.conn_send_window -= n as i64;
                if finishes {
                    self.out_queue.remove(idx);
                }
                continue;
            }
            // Headers sent and no body left — shouldn't linger; drop it.
            self.out_queue.remove(idx);
        }
    }
}

/// DATA payloads from responses with a body at or below this size are
/// copied inline into the flush header buffer (keeping the send chain a
/// single contiguous part); larger responses frame their payloads
/// zero-copy from the body's own IOBufs. 4 KiB comfortably covers
/// small JSON / API / redirect / page responses while the bulk
/// static-asset path stays copy-free.
const INLINE_BODY_MAX: usize = 4096;

/// Shared receive-body channel for one *streaming* request stream. The
/// demux task pushes DATA payloads in arrival order; the spawned
/// handler task drains them through an [`H2BodySource`]. `event` lives
/// outside the `RefCell` so the handler can `await` it without holding
/// a borrow across the suspend point (the demux needs `borrow_mut` to
/// push).
struct StreamBody {
    data: RefCell<BodyChanData>,
    event: AsyncEvent,
}

struct BodyChanData {
    /// Queued DATA payloads, oldest first.
    chunks: VecDeque<Vec<u8>>,
    /// END_STREAM seen — no more DATA will arrive.
    eof: bool,
    /// Stream reset / connection error — the handler should stop and
    /// its response (if any) is dropped.
    reset: bool,
    /// Bytes the handler has drained but not yet credited to the peer.
    /// The demux reads + clears this and emits WINDOW_UPDATE, giving
    /// receive-side backpressure (we credit on consume, not arrival).
    consumed_uncredited: usize,
    /// Total bytes currently buffered (sum of `chunks` lengths) — the
    /// `STREAM_RECV_BUF_CAP` check reads this without walking the deque.
    buffered: usize,
}

/// Demux-side handle to a streaming request stream.
struct StreamSlot {
    id: u32,
    body: Rc<StreamBody>,
}

/// [`BodySource`] over a streaming request stream, owned by the spawned
/// handler task. Pulls DATA payloads the demux pushes into the shared
/// [`StreamBody`]; signals `demux_wake` on consume so the demux emits
/// the WINDOW_UPDATE credit.
struct H2BodySource {
    body: Rc<StreamBody>,
    demux_wake: Rc<AsyncEvent>,
}

impl BodySource for H2BodySource {
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<IOBuf>> + '_>> {
        Box::pin(async move {
            loop {
                // Arm the wakeup BEFORE checking so a push between the
                // check and the wait can't be lost.
                self.body.event.reset();
                {
                    let mut d = self.body.data.borrow_mut();
                    if let Some(chunk) = d.chunks.pop_front() {
                        d.buffered -= chunk.len();
                        d.consumed_uncredited += chunk.len();
                        drop(d);
                        // Tell the demux to credit the peer for the
                        // bytes we just took off the window.
                        self.demux_wake.set();
                        return Some(IOBuf::from(chunk));
                    }
                    if d.reset || d.eof {
                        return None;
                    }
                }
                self.body.event.wait().await;
            }
        })
    }
}

/// A response being framed onto the wire.
struct StreamOut {
    id: u32,
    header_block: Vec<u8>,
    headers_sent: bool,
    /// Current front body part being drained (inline path only —
    /// `cur`/`cur_off` non-mutating cursor; unused when `zero_copy`).
    cur: Option<IOBuf>,
    cur_off: usize,
    /// Remaining body parts.
    body: IOBufChain,
    /// Total body bytes still to send.
    body_remaining: usize,
    /// Per-stream send window (peer-granted).
    send_window: i64,
    /// Frame DATA payloads zero-copy from the body's own IOBufs (large
    /// bodies) vs copy them inline into the flush buffer (small ones).
    /// Fixed at queue time; a response uses one path throughout, so the
    /// inline cursor and the zero-copy pop/narrow never interleave.
    zero_copy: bool,
}

impl StreamOut {
    /// Append up to `n` body bytes onto `out` (advancing the cursor) for
    /// the next DATA frame's payload — coalescing across the body's parts
    /// up to `n`. Same cursor walk the old `take_body` used, but writing
    /// straight into the caller's frame buffer instead of a throwaway
    /// `Vec`. `body_remaining` is decremented by what was appended.
    fn append_body_into(&mut self, out: &mut Vec<u8>, n: usize) {
        let start = out.len();
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
        self.body_remaining -= out.len() - start;
    }

    /// Append `n` body bytes onto `chain` **zero-copy** as the body's own
    /// IOBufs — moving a whole front part, or splitting it via a
    /// refcount-shared view (`clone_shared` + `narrow`) when it overruns
    /// `n`, the tail going back on the body for the next frame. A part
    /// not yet shareable (`Owned(Heap)`, e.g. a dynamically-rendered
    /// body) is promoted with one `share()` copy first; static /
    /// already-shared bodies (the bulk-asset path) never copy. The large-
    /// body counterpart to `append_body_into`'s inline copy.
    fn push_body(&mut self, chain: &mut IOBufChain, n: usize) {
        let mut need = n;
        while need > 0 {
            let Some(mut part) = self.body.pop_front() else {
                break;
            };
            let plen = part.data().len();
            if plen <= need {
                need -= plen;
                chain.push_back(part);
            } else {
                let mut tail = match part.clone_shared() {
                    Ok(t) => t,
                    Err(_) => {
                        part = part.share();
                        part.clone_shared().expect("shareable after share()")
                    }
                };
                let _ = part.narrow(0, need);
                let _ = tail.consume(need);
                chain.push_back(part);
                self.body.push_front(tail);
                need = 0;
            }
        }
        self.body_remaining -= n - need;
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
/// to flow control — framed into one send.
///
/// Control frames go first (wire order), then every response frame the
/// connection + per-stream windows allow. Small responses' frames
/// accumulate contiguously in the reused `frame_buf`, copied once into a
/// single `IOBuf` — one part keeps the chain in its zero-alloc `Single`
/// state. A large response's DATA payloads ride the chain **zero-copy**
/// as the body's own (window-sliced) IOBufs, with the small header bytes
/// cut in as contiguous segments. `TlsStream::send` then seals the whole
/// chain into as few TLS records / TCP sends as the 16 KiB record cap
/// allows (one, for a small response). Reusing `frame_buf` keeps the
/// small-response framing path at one allocation (the send `IOBuf`).
async fn flush<S: HttpStream>(conn: &mut H2Conn, stream: &mut S) -> Result<(), ()> {
    let __f0 = now_cycles();
    let mut hdr_buf = core::mem::take(&mut conn.frame_buf);
    hdr_buf.clear();
    if !conn.ctrl_out.is_empty() {
        hdr_buf.extend_from_slice(&conn.ctrl_out);
        conn.ctrl_out.clear();
    }
    let mut chain = IOBufChain::new();
    conn.drain_to_chain(&mut hdr_buf, &mut chain);
    // Trailing accumulated header / inline-body bytes become the final
    // (and, for an all-small flush, only) contiguous chain part.
    if !hdr_buf.is_empty() {
        chain.push_back(IOBuf::from_slice_with_headroom(0, &hdr_buf[..], 0));
    }
    conn.frame_buf = hdr_buf;
    crate::diag::COUNTERS
        .frame_cycles
        .add(now_cycles().wrapping_sub(__f0));
    if chain.is_empty() {
        return Ok(());
    }
    stream.send(&mut chain).await
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
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
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
        ftype::DATA => process_data(conn, hdr, payload),
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
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
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
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
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
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
{
    let mut req = Request::new();
    let __d0 = now_cycles();
    let malformed = {
        let mut sink = RequestSink {
            req: &mut req,
            malformed: false,
        };
        let r = conn.hpack.decode(
            block,
            &mut conn.name_scratch[..],
            &mut conn.value_scratch[..],
            &mut sink,
        );
        crate::diag::COUNTERS
            .decode_cycles
            .add(now_cycles().wrapping_sub(__d0));
        match r {
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

    // Trailers on a streaming stream: a HEADERS block after DATA. The
    // HPACK was decoded above (keeps the dynamic table in sync); we
    // ignore the trailer fields but honour the END_STREAM they carry —
    // it ends the request body.
    if let Some(slot) = conn.streams.iter().find(|s| s.id == sid) {
        if end_stream {
            slot.body.data.borrow_mut().eof = true;
            slot.body.event.set();
        }
        return Ok(());
    }

    // No active slot. An id in the already-opened range (`<=
    // last_stream_id`) is a late frame on a stream we've finished and
    // dropped — most often a trailer HEADERS whose END_STREAM arrived
    // after the handler already responded (a legal request-with-trailers
    // race) — so ignore it rather than tear the whole connection down
    // with a GOAWAY. The HPACK above was decoded, so the dynamic table
    // stays in sync. Only a strictly-increasing id opens a new stream
    // (RFC 7540 §5.1.1). Charge each one to the rapid-reset flood budget:
    // legitimate late trailers are rare (≤1 per request where we respond
    // first), so a peer spamming HEADERS on old ids for unbounded
    // HPACK-decode work still trips ENHANCE_YOUR_CALM.
    if sid <= conn.last_stream_id {
        conn.streams_reset += 1;
        if conn.streams_reset > RST_FLOOD_CAP {
            crate::h2_drop!(rapid_reset_abort, "closed-stream frame flood={}", conn.streams_reset);
            return Err(error::ENHANCE_YOUR_CALM);
        }
        return Ok(());
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
        // Bodyless request (typically GET): run the handler inline —
        // it has no body to await, so it returns promptly without
        // stalling the demux, and we skip a task spawn on the hot path.
        dispatch_bodyless(conn, stream, handler, sid, req).await;
    } else {
        // A body is coming: spawn a handler task fed by a StreamBody so
        // the demux keeps reading DATA into it while the handler runs.
        // Arena exhaustion → refuse the stream (h2's overload response)
        // rather than buffer unboundedly.
        if !spawn_streaming(conn, handler, sid, req) {
            crate::h2_drop!(stream_refused, "sid={} spawn arena full", sid);
            frame::push_rst_stream(&mut conn.ctrl_out, sid, error::REFUSED_STREAM);
        }
    }
    Ok(())
}

/// Parse an ASCII `content-length` value. `None` if absent or
/// non-numeric (h2 delimits the body by END_STREAM regardless; this is
/// only used to give the handler an accurate `remaining()`).
fn parse_content_length(v: Option<&[u8]>) -> Option<usize> {
    let v = v?;
    if v.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in v {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(n)
}

/// Spawn a per-stream handler task that streams the request body from a
/// `StreamBody` and pushes its response to `resp_sink`. Returns `false`
/// if the task arena is full (caller refuses the stream). On success
/// the demux keeps a `StreamSlot` to route DATA + account for the
/// stream; the task is detached (its handle is dropped — no Drop, so it
/// runs to completion and frees its own slot).
fn spawn_streaming<H>(conn: &mut H2Conn, handler: &Arc<H>, sid: u32, req: Request) -> bool
where
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
{
    let content_length = parse_content_length(req.header(b"content-length"));
    let body = Rc::new(StreamBody {
        data: RefCell::new(BodyChanData {
            chunks: VecDeque::new(),
            eof: false,
            reset: false,
            consumed_uncredited: 0,
            buffered: 0,
        }),
        event: AsyncEvent::new(),
    });
    let handler = Arc::clone(handler);
    let body_task = Rc::clone(&body);
    let sink = Rc::clone(&conn.resp_sink);
    let demux_wake = Rc::clone(&conn.demux_wake);
    let spawned = spawn(async move {
        crate::diag::COUNTERS.requests_received.bump();
        let resp = {
            let mut src = H2BodySource {
                body: body_task,
                demux_wake: Rc::clone(&demux_wake),
            };
            let mut reader = BodyReader::new_streaming(Some(&mut src), &[], content_length);
            // Run the handler, then surrender the stream WITHOUT draining
            // any body it left unread. The old post-handler
            // `reader.discard().await` would park forever on a peer that
            // declared a Content-Length then stalled (holding the task +
            // slot until the 30s idle timeout) and forced the whole body
            // off the wire even for an early reject. Once `drain_responses`
            // drops the slot, late DATA is ignored + conn-window-credited
            // by `process_data`'s no-slot arm, and the peer stops at the
            // un-extended stream window — the h2-correct way to abandon an
            // unwanted request body.
            (*handler)(&req, &mut reader).await
        };
        crate::diag::COUNTERS.requests_handled.bump();
        sink.borrow_mut().push_back((sid, resp));
        demux_wake.set();
    });
    match spawned {
        Ok(_handle) => {
            conn.streams.push(StreamSlot { id: sid, body });
            true
        }
        Err(_) => false,
    }
}

fn process_data(conn: &mut H2Conn, hdr: FrameHeader, payload: &[u8]) -> Result<(), u32> {
    if hdr.stream_id == 0 {
        return Err(error::PROTOCOL_ERROR);
    }
    let data = data_payload(payload, hdr.flags).ok_or(error::PROTOCOL_ERROR)?;
    // The full frame length (incl. padding) counts against flow control
    // (RFC 7540 §6.1).
    let full_len = hdr.length;
    let end_stream = hdr.has_flag(flags::END_STREAM);

    match conn.streams.iter().position(|s| s.id == hdr.stream_id) {
        Some(i) => {
            // Route the payload into the streaming handler's body
            // channel. The STREAM-level window is credited on consume
            // (see `credit_consumed_bodies`) for backpressure; the
            // CONNECTION window is credited here on arrival (bounded by
            // per-stream window × MAX_CONCURRENT_STREAMS, and it keeps
            // the conn-level accounting free of per-stream credit
            // races).
            let over_cap = {
                let body = &conn.streams[i].body;
                let mut d = body.data.borrow_mut();
                if d.buffered + data.len() > STREAM_RECV_BUF_CAP {
                    true
                } else {
                    if !data.is_empty() {
                        d.chunks.push_back(data.to_vec());
                        d.buffered += data.len();
                    }
                    if end_stream {
                        d.eof = true;
                    }
                    drop(d);
                    body.event.set();
                    false
                }
            };
            if over_cap {
                // Peer ignored the stream window we advertised —
                // defensive reset.
                crate::h2_drop!(flow_control_error, "recv buffer overflow sid={}", hdr.stream_id);
                reset_stream(conn, hdr.stream_id, error::FLOW_CONTROL_ERROR);
            }
            if full_len > 0 {
                frame::push_window_update(&mut conn.ctrl_out, 0, full_len);
            }
        }
        None => {
            // DATA for an unknown stream (finished / reset / never
            // opened) is leniently ignored — we still replenish the
            // connection window so the peer's accounting stays
            // consistent.
            if full_len > 0 {
                frame::push_window_update(&mut conn.ctrl_out, 0, full_len);
            }
        }
    }
    Ok(())
}

/// Reset a streaming stream we own (e.g. it overflowed its receive
/// buffer): flag + wake its handler task so it unwinds, drop our slot,
/// and tell the peer with RST_STREAM.
fn reset_stream(conn: &mut H2Conn, sid: u32, code: u32) {
    if let Some(i) = conn.streams.iter().position(|s| s.id == sid) {
        let slot = conn.streams.remove(i);
        slot.body.data.borrow_mut().reset = true;
        slot.body.event.set();
    }
    frame::push_rst_stream(&mut conn.ctrl_out, sid, code);
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
    // Terminate a streaming handler for this stream (its response, if
    // any, is dropped on drain) and drop any queued response.
    if let Some(i) = conn.streams.iter().position(|s| s.id == hdr.stream_id) {
        let slot = conn.streams.remove(i);
        slot.body.data.borrow_mut().reset = true;
        slot.body.event.set();
    }
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

/// Run a bodyless request's handler inline and enqueue its response.
/// No DATA will arrive (END_STREAM came with the HEADERS), so the
/// `BodyReader` is empty — the `Some(stream)` source is wired for the
/// type but never pulled. Inline (vs a spawned task) keeps GETs off the
/// task arena and returns promptly without stalling the demux.
async fn dispatch_bodyless<S, H>(
    conn: &mut H2Conn,
    stream: &mut S,
    handler: &Arc<H>,
    sid: u32,
    req: Request,
) where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>) -> Response + 'static,
{
    crate::diag::COUNTERS.requests_received.bump();
    let resp = {
        let mut body = BodyReader::new(Some(stream), &[], 0);
        (**handler)(&req, &mut body).await
    };
    crate::diag::COUNTERS.requests_handled.bump();
    conn.queue_response(sid, resp);
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

    // Fixed pseudo/standard trio + the response's extra headers, built
    // on the stack — responses carry few headers, so a per-response heap
    // `Vec` here is needless allocation on the hot path.
    let mut list: [(&[u8], &[u8]); 3 + http::MAX_EXTRA_HEADERS] =
        [(&[][..], &[][..]); 3 + http::MAX_EXTRA_HEADERS];
    list[0] = (b":status", &status[..]);
    list[1] = (b"content-type", resp.content_type_bytes());
    list[2] = (b"content-length", &len_buf[len_off..]);
    let mut n = 3;
    for (name, value) in resp.extra_headers() {
        if n >= list.len() {
            break;
        }
        list[n] = (name, value);
        n += 1;
    }
    hpack::encode_header_list(&list[..n], out);
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

    fn test_stream_out(body: IOBufChain, body_remaining: usize, zero_copy: bool) -> StreamOut {
        StreamOut {
            id: 1,
            header_block: Vec::new(),
            headers_sent: true,
            cur: None,
            cur_off: 0,
            body,
            body_remaining,
            send_window: INITIAL_WINDOW,
            zero_copy,
        }
    }

    #[test]
    fn append_body_into_coalesces_parts() {
        let mut chain = IOBufChain::new();
        chain.push_back(IOBuf::from(b"hello".to_vec()));
        chain.push_back(IOBuf::from(b"world".to_vec()));
        let mut out = test_stream_out(chain, 10, false);
        // Appends into a buffer that may already hold a frame header —
        // the prefix must be preserved and the cursor split mid-part.
        let mut buf = alloc::vec![0xAA];
        out.append_body_into(&mut buf, 7);
        assert_eq!(buf, b"\xAAhellowo");
        assert_eq!(out.body_remaining, 3);
        buf.clear();
        out.append_body_into(&mut buf, 100);
        assert_eq!(buf, b"rld");
        assert_eq!(out.body_remaining, 0);
    }

    #[test]
    fn push_body_zero_copy_splits_and_coalesces() {
        // The zero-copy path coalesces whole parts and splits a part
        // mid-way (here heap parts, exercising the share()+clone_shared
        // promotion), carrying the tail for the next frame.
        let mut chain = IOBufChain::new();
        chain.push_back(IOBuf::from(b"hello".to_vec()));
        chain.push_back(IOBuf::from(b"world".to_vec()));
        let mut out = test_stream_out(chain, 10, true);
        let mut sink = IOBufChain::new();
        out.push_body(&mut sink, 7);
        assert_eq!(out.body_remaining, 3);
        let mut got = Vec::new();
        while let Some(b) = sink.pop_front() {
            got.extend_from_slice(b.data());
        }
        assert_eq!(got, b"hellowo");
        out.push_body(&mut sink, 3);
        assert_eq!(out.body_remaining, 0);
        let mut rest = Vec::new();
        while let Some(b) = sink.pop_front() {
            rest.extend_from_slice(b.data());
        }
        assert_eq!(rest, b"rld");
    }

    #[test]
    fn drain_small_inline_large_zero_copy() {
        // A small response inlines its DATA into hdr_buf (chain empty);
        // a large one frames its DATA onto the chain (zero-copy).
        let mut conn = H2Conn::new();
        let mut small = IOBufChain::new();
        small.push_back(IOBuf::from(b"hi".to_vec()));
        conn.out_queue.push_back(StreamOut {
            id: 1,
            header_block: alloc::vec![0xAB],
            headers_sent: false,
            cur: None,
            cur_off: 0,
            body: small,
            body_remaining: 2,
            send_window: INITIAL_WINDOW,
            zero_copy: false,
        });
        let mut hdr_buf = Vec::new();
        let mut chain = IOBufChain::new();
        conn.drain_to_chain(&mut hdr_buf, &mut chain);
        assert!(chain.is_empty(), "small response inlines, chain stays empty");
        assert!(!hdr_buf.is_empty());
        assert!(conn.out_queue.is_empty());

        let big = alloc::vec![7u8; INLINE_BODY_MAX + 64];
        let mut bigbody = IOBufChain::new();
        bigbody.push_back(IOBuf::from(big.clone()));
        conn.out_queue.push_back(StreamOut {
            id: 3,
            header_block: alloc::vec![0xCD],
            headers_sent: false,
            cur: None,
            cur_off: 0,
            body: bigbody,
            body_remaining: big.len(),
            send_window: INITIAL_WINDOW,
            zero_copy: true,
        });
        let mut hdr_buf2 = Vec::new();
        let mut chain2 = IOBufChain::new();
        conn.drain_to_chain(&mut hdr_buf2, &mut chain2);
        assert!(!chain2.is_empty(), "large response frames onto the chain");
        let mut got = Vec::new();
        while let Some(b) = chain2.pop_front() {
            got.extend_from_slice(b.data());
        }
        assert_eq!(&got[got.len() - big.len()..], &big[..]);
    }
}
