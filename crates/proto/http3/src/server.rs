// crates/proto/http3/src/server.rs — HTTP/3 server over //crates/proto/quic.
//
// Per QUIC connection:
//   1. Open server-side unidirectional CONTROL stream
//      (stream type byte = 0x00) and emit a SETTINGS frame
//      with no entries (defaults are fine).
//   2. For each accepted peer stream:
//      - Bidi (id & 0x3 == 0): a request stream. Read HEADERS +
//        DATA frames until FIN, build `http::Request`, hand to the
//        user handler. The response is either streamed as the
//        handler produces it (`res.write` → `H3Sink` frames HEADERS
//        + DATA under QUIC stream flow control, bounded) or, when
//        the handler buffers (`res.set`), encoded in one shot
//        (HEADERS + DATA + FIN); then close the stream.
//      - Uni (id & 0x3 == 0x2): peer's control / QPACK encoder /
//        QPACK decoder stream. We accept and discard everything
//        on these (control stream's SETTINGS frame is ignored,
//        QPACK streams stay empty since we negotiated capacity 0).
//
// Sans-allocation hot path: each request reuses the conn handler's
// `Request` and its `Scratch` buffers (recv / HEADERS / body / QPACK
// out / H3 framing prefix) instead of allocating per request.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use quic::{QuicConn, QuicListenError};

use http::{BodyReader, BodySource, IOBuf, Method, Request, RequestHead, Response, ResponseSink};

use crate::frame::{self, ftype as h3_ftype};
use crate::qpack::{self, FieldSink};

/// Stream-type byte for HTTP/3 control streams (RFC 9114 §6.2.1).
pub(crate) const STREAM_TYPE_CONTROL: u64 = 0x00;

/// The server request path's view of a QUIC connection — exactly the
/// slice of [`QuicConn`] that `handle_request` / `write_response` /
/// `H3Sink` / `H3BodySource` consume. Production monomorphises to
/// `QuicConn` (zero-cost: every method is a direct delegate); the
/// in-process loopback tests (client.rs) implement it over a raw
/// server-role `Connection` pumped against the real QUIC client, so
/// the REAL h3 server-role processing runs under `bazel test` with no
/// sockets or runtime. Wire behavior is unchanged by this seam.
pub(crate) trait ServerConn {
    async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool);
    fn queue_iobuf(&self, sid: u64, data: IOBuf);
    fn send_iobuf(&self, sid: u64, data: IOBuf);
    fn close_stream(&self, sid: u64);
    fn discard_recv(&self, sid: u64);
    fn stream_buffered(&self, sid: u64) -> usize;
    async fn stream_drain_below(&self, sid: u64, cap: usize);
    fn is_failed(&self) -> bool;
    /// S1: abort the response stream (RFC 9000 §19.4) — the
    /// mid-stream handler-error path.
    fn reset_stream(&self, sid: u64, app_error_code: u64);
}

impl ServerConn for QuicConn {
    async fn recv(&self, sid: u64, out: &mut [u8]) -> (usize, bool) {
        QuicConn::recv(self, sid, out).await
    }
    fn queue_iobuf(&self, sid: u64, data: IOBuf) {
        QuicConn::queue_iobuf(self, sid, data);
    }
    fn send_iobuf(&self, sid: u64, data: IOBuf) {
        QuicConn::send_iobuf(self, sid, data);
    }
    fn close_stream(&self, sid: u64) {
        QuicConn::close_stream(self, sid);
    }
    fn discard_recv(&self, sid: u64) {
        QuicConn::discard_recv(self, sid);
    }
    fn stream_buffered(&self, sid: u64) -> usize {
        QuicConn::stream_buffered(self, sid)
    }
    async fn stream_drain_below(&self, sid: u64, cap: usize) {
        QuicConn::stream_drain_below(self, sid, cap).await;
    }
    fn is_failed(&self) -> bool {
        QuicConn::is_failed(self)
    }
    fn reset_stream(&self, sid: u64, app_error_code: u64) {
        QuicConn::reset_stream(self, sid, app_error_code);
    }
}

#[derive(Debug)]
pub enum ListenError {
    Bind(quic::QuicListenError),
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
/// `cert_chain` (DER, leaf first then intermediates) and
/// `key_pkcs8_der` are the same blobs `http2::listen` accepts.
///
/// Returns once the server is bound; the listener stays alive for
/// the duration of the program (waitless's task system retains it).
pub fn listen<H>(
    port: u16,
    handler: H,
    cert_chain: &'static [&'static [u8]],
    key_pkcs8_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()> + Send + Sync + 'static,
{
    // Pay one-time lazy-init costs upfront so they land in the
    // HEAP_BASELINE snapshot rather than the first request's
    // alloc delta. Two contributors:
    //
    //   * `huffman::preinit` builds the QPACK static Huffman
    //     decoder tree (~4 KiB Vec) that's otherwise allocated
    //     on the first decoded request header.
    //   * `quic::preinit` (which delegates to tls)
    //     exercises the RustCrypto primitives (p256 sign +
    //     verify, ChaCha20-Poly1305 seal + open, X25519 ECDH)
    //     so any internal precomputed-table allocations on
    //     first use happen now.
    //
    // Without these the post-shutdown leak check has to tolerate
    // a fixed cushion (~12 KiB / ~10 allocs in measurements
    // before this lands); with them it can demand `delta == 0`.
    crate::huffman::preinit();
    quic::preinit();

    let handler = Arc::new(handler);
    let listener = quic::listen(port, cert_chain, key_pkcs8_der, move |conn: QuicConn| {
        let handler = Arc::clone(&handler);
        async move {
            handle_conn(conn, handler).await;
        }
    })?;
    waitless::_retain(listener);
    Ok(())
}

async fn handle_conn<H>(conn: QuicConn, handler: Arc<H>)
where
    H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()> + 'static,
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
        // Hand the Vec to the SendStream by move (zero-copy). The
        // alternative `conn.send(control_id, &buf)` would `to_vec()`
        // a duplicate inside the slice variant of `SendStream::write`.
        conn.send_owned(control_id, buf);
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
    // Browsers open exactly 3 peer uni streams per H3 conn
    // (control + QPACK encoder + QPACK decoder); 6 covers any
    // future client that opens duplicates and saves the 3 tree-
    // node allocs a `BTreeSet<u64>` would do per fresh conn.
    // Linear scan is cheaper than a tree at this cardinality.
    let mut uni_seen: [Option<u64>; 6] = [None; 6];
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
            // Drive request handling inline — so requests on one conn
            // serialize through this loop. A task per request was tried
            // (to overlap them) and reverted: every task would park on the
            // connection's shared `progress` `AsyncEvent`, which is
            // *single-waiter* — a second waiter overwrites the first's
            // waker, dropping wakeups and stalling concurrent streams (see
            // `docs/streaming-response.md`). Overlapping h3 requests needs
            // a multi-waiter conn wakeup first; until then, inline.
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
            // Inline contains+insert: scan the array for `sid`,
            // and remember the first empty slot. If `sid` is
            // not found, fill the empty slot. Past the cap, we
            // silently treat the sid as already-seen (no
            // event); the alternative — abort the conn — would
            // be hostile to non-conformant clients without a
            // real benefit.
            let mut found = false;
            let mut empty: Option<usize> = None;
            for (idx, slot) in uni_seen.iter().enumerate() {
                match slot {
                    Some(v) if *v == sid => {
                        found = true;
                        break;
                    }
                    Some(_) => {}
                    None => {
                        if empty.is_none() {
                            empty = Some(idx);
                        }
                    }
                }
            }
            if !found
                && let Some(idx) = empty
            {
                uni_seen[idx] = Some(sid);
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
/// reserved headroom/tailroom (see `write_response`); the
/// framing IOBuf's underlying storage is recycled via the
/// `FramingPool` below — also zero-alloc on the steady state.
pub(crate) struct Scratch {
    /// H3 stream-bytes accumulator — successive `recv` chunks
    /// concatenate here until enough bytes form a complete frame.
    pub(crate) recv_buf: Vec<u8>,
    /// HEADERS-frame body, copied out of `recv_buf` before the
    /// outer `drain` invalidates the borrow into it.
    pub(crate) headers_value: Vec<u8>,
    /// Pool of `Box<[u8]>` storage for response-framing IOBufs.
    /// Each `write_response` takes one from the pool, builds the
    /// HEADERS+QPACK+DATA framing IOBuf in it, and hands the
    /// IOBuf to QUIC's SendStream. When SendStream finishes
    /// draining the IOBuf's bytes onto the wire and drops it,
    /// the storage returns to this pool — capacity preserved.
    /// Steady-state alloc count: 0 framing buffers per H3
    /// request after the pool is primed.
    pub(crate) framing_pool: alloc::sync::Arc<FramingPool>,
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
            framing_pool: FramingPool::new(),
        }
    }
}

/// Per-conn pool of `Box<[u8]>` storage backing response framing
/// IOBufs. The pool is wrapped in an `Arc` and the IOBuf's drop
/// callback decrements that refcount via `Arc::from_raw` —
/// `Arc` because `IOBuf::ExternalOwned` is `Send` (an IOBuf could
/// in principle move workers before drop) and `Rc` isn't, even
/// though in practice every IOBuf this pool issues stays on
/// the worker that created it.
///
/// Per-request: pop a `Box<[u8]>` from `bufs` (or alloc fresh
/// if empty), wrap as `IOBuf::ExternalOwned` with a drop callback
/// that returns the storage to `bufs`. The Arc strong count
/// is bumped per outstanding IOBuf so the pool stays alive
/// until every framing IOBuf has dropped, even past `Scratch`'s
/// own lifetime.
pub(crate) struct FramingPool {
    bufs: core::cell::RefCell<Vec<alloc::boxed::Box<[u8]>>>,
}

/// Each framing buffer holds the H3 HEADERS frame header
/// (≤16 B) + QPACK body (typical 30-200 B, capped at 256) +
/// optional DATA frame header (≤16 B). 288 B (256 + 16 + 16)
/// covers every shape comfortably; pick a power-of-two-ish
/// size for allocator-friendliness.
const FRAMING_BUF_SIZE: usize = 288;

/// Cap on per-conn pool retention. A burst of pipelined H3
/// requests can briefly hold many framing IOBufs in flight
/// (one per outstanding response on the wire, plus any in
/// SendStream's outbound chain not yet drained); past this
/// cap the drop callback drops the storage instead of pooling.
const FRAMING_POOL_MAX: usize = 16;

impl FramingPool {
    // clippy::arc_with_non_send_sync — `Arc<FramingPool>` is
    // deliberately not `Send + Sync`: the `RefCell<Vec<...>>` inside
    // makes `FramingPool` non-`Sync`. We use `Arc` (not `Rc`) anyway
    // because `IOBuf::ExternalOwned` is `Send` in principle, and an
    // IOBuf this pool issues could be moved between workers before
    // drop. In current per-worker usage that never happens, so the
    // atomic refcount is paid for nothing — but switching to `Rc`
    // would land an unsoundness landmine for any future cross-worker
    // IOBuf hand-off. See the type-level doc above for the
    // longer-form trade-off discussion.
    #[allow(clippy::arc_with_non_send_sync)]
    fn new() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            bufs: core::cell::RefCell::new(Vec::with_capacity(FRAMING_POOL_MAX)),
        })
    }

    /// Take a framing IOBuf from the pool. The visible payload
    /// starts empty; caller writes via `extend_uninit` /
    /// `append_slice` / `prepend` and the IOBuf releases its
    /// storage back to this pool when it drops.
    fn take(self: &alloc::sync::Arc<Self>) -> http::IOBuf {
        // Pop existing storage, or allocate fresh if pool is empty.
        let storage = self
            .bufs
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| alloc::vec![0u8; FRAMING_BUF_SIZE].into_boxed_slice());
        debug_assert_eq!(storage.len(), FRAMING_BUF_SIZE);
        // Leak the Box; the drop callback reconstructs it via
        // `Box::from_raw` and either pushes back to the pool or
        // lets it drop (when the pool is full).
        let raw: *mut [u8] = alloc::boxed::Box::into_raw(storage);
        // SAFETY: `raw` is non-null (came from a valid Box) and
        // points to FRAMING_BUF_SIZE bytes.
        let base = unsafe { core::ptr::NonNull::new_unchecked((*raw).as_mut_ptr()) };
        // Bump the Arc strong count so the pool stays alive
        // until this IOBuf's drop callback fires; the callback
        // `Arc::from_raw`'s the ctx back to drop one strong ref.
        let ctx = alloc::sync::Arc::into_raw(alloc::sync::Arc::clone(self)) as *mut ();
        // SAFETY: storage was just popped from this Arc<FramingPool>'s
        // private Vec — we hold it exclusively. `base..base+
        // FRAMING_BUF_SIZE` is a valid Box<[u8]> region. The drop
        // callback `Box::from_raw`'s the same range and either
        // pushes back to the pool or drops it.
        //
        // `wrap_owned` yields an `OwnedIOBuf`; widen it to the
        // `IOBuf` the (borrow-mixing) framing chain holds. The
        // framing buffer is genuinely owned heap storage, so the
        // widening is the infallible, zero-copy `From<OwnedIOBuf>`.
        unsafe {
            http::OwnedIOBuf::wrap_owned(
                base,
                FRAMING_BUF_SIZE as u32,
                0,
                0,
                framing_pool_drop,
                ctx,
            )
        }
        .into()
    }
}

/// Drop callback fired when a framing IOBuf drops. Reconstructs
/// the underlying Box<[u8]> and the Arc<FramingPool> from the
/// raw pointers, pushes the Box back to the pool (or drops if
/// the pool is full), and lets the Arc strong count decrement.
unsafe fn framing_pool_drop(base: core::ptr::NonNull<u8>, capacity: u32, ctx: *mut ()) {
    // SAFETY: ctx came from `Arc::into_raw` in `FramingPool::take`;
    // we balance that with `Arc::from_raw` here.
    let pool: alloc::sync::Arc<FramingPool> =
        unsafe { alloc::sync::Arc::from_raw(ctx as *const FramingPool) };
    // SAFETY: base + capacity is the same range we leaked via
    // `Box::into_raw` in `FramingPool::take`; reconstruct the
    // Box so it owns the storage again.
    let storage: alloc::boxed::Box<[u8]> = unsafe {
        alloc::boxed::Box::from_raw(core::ptr::slice_from_raw_parts_mut(
            base.as_ptr(),
            capacity as usize,
        ))
    };
    let mut bufs = pool.bufs.borrow_mut();
    if bufs.len() < FRAMING_POOL_MAX {
        bufs.push(storage);
    }
    // else: storage drops at scope-end, returning bytes to allocator.
    // pool's Arc drops at scope-end too, decrementing the strong count.
}

pub(crate) async fn handle_request<C, H>(conn: &C, sid: u64, handler: &H, scratch: &mut Scratch)
where
    C: ServerConn,
    H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()>,
{
    // Read just far enough to parse the HEADERS frame, then dispatch
    // and stream the body (any later DATA frames) lazily — no
    // whole-body buffer, so uploads aren't capped at a fixed RX size.
    //
    // Cap only the pre-HEADERS accumulation: a request's HEADERS frame
    // (QPACK field section) is small, so this guards a malicious
    // oversized one without bounding the body. Any bytes left in `buf`
    // after the HEADERS frame are the start of the DATA stream — they
    // seed the body source below.
    const HEADERS_CAP: usize = 64 * 1024;
    scratch.recv_buf.clear();
    scratch.headers_value.clear();
    let buf = &mut scratch.recv_buf;
    let headers_value = &mut scratch.headers_value;
    let mut chunk = [0u8; 4096];
    let mut headers_seen = false;
    let mut eof = false;

    crate::h3_event!(requests_received, "sid={}", sid);
    while !headers_seen && !eof {
        let (n, end) = conn.recv(sid, &mut chunk).await;
        if n > 0 {
            if buf.len() + n > HEADERS_CAP {
                crate::h3_drop!(
                    recv_buffer_overflow,
                    "sid={} buf_len={} cap={}",
                    sid,
                    buf.len(),
                    HEADERS_CAP
                );
                conn.close_stream(sid);
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        if end {
            eof = true;
        }

        // Parse complete frames off the front, stopping at HEADERS.
        loop {
            let (f, used) = match frame::parse_frame(buf) {
                Ok(x) => x,
                Err(frame::FrameError::Truncated) => break,
                Err(e) => {
                    crate::h3_drop!(
                        frame_parse_error,
                        "sid={} err={:?} buf_len={}",
                        sid,
                        e,
                        buf.len()
                    );
                    conn.close_stream(sid);
                    return;
                }
            };
            if let frame::Frame::Headers(body) = f {
                // Copy into per-conn scratch BEFORE the `buf.drain`
                // invalidates the borrow.
                headers_value.clear();
                headers_value.extend_from_slice(body);
                headers_seen = true;
            }
            // Skip any control / grease frames that precede HEADERS;
            // DATA-before-HEADERS is illegal but we just consume it.
            buf.drain(..used);
            if headers_seen {
                break;
            }
        }
    }
    crate::diag::COUNTERS.read_loop_completed.bump();
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
        req: &'r mut RequestHead,
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
    let mut req = RequestHead::new();
    {
        let mut sink = RequestSink { req: &mut req };
        // 4 KiB on the stack covers ≥99th percentile
        // worst-case Huffman expansion (4× the input length)
        // for any header in normal browser traffic. A literal
        // header that exceeds this surfaces as
        // `qpack_decode_error` and the stream is closed.
        let mut name_scratch = [0u8; 4096];
        let mut value_scratch = [0u8; 4096];
        let _qd0 = crate::diag::now_cycles();
        let qd_res = qpack::decode_field_section_into(
            headers_value,
            &mut name_scratch,
            &mut value_scratch,
            &mut sink,
        );
        crate::diag::COUNTERS
            .qpack_decode_cycles
            .add(crate::diag::now_cycles().wrapping_sub(_qd0));
        if let Err(e) = qd_res {
            crate::h3_drop!(
                qpack_decode_error,
                "sid={} err={:?} header_len={}",
                sid,
                e,
                headers_value.len()
            );
            conn.close_stream(sid);
            return;
        }
    }
    // Declared body length (if any) — bounds the streamed read; absent
    // means the body is delimited only by FIN, which the source detects.
    let content_length = req.header(b"content-length").and_then(parse_content_length);
    if let Some(cl) = content_length {
        req.set_content_length(cl);
    }

    crate::diag::COUNTERS.user_handler_invoked.bump();
    // Stream the body: `H3BodySource` parses later DATA frames lazily
    // from the QUIC stream (seeded with the bytes already read after
    // HEADERS), so the handler sees the same `BodyReader` streaming
    // interface as HTTP/1.1 and large uploads aren't buffered whole.
    let mut src = H3BodySource::new(conn, sid, buf.clone(), eof);
    let mut sink = H3Sink { conn, sid };
    let mut response = Response::with_sink(&mut sink);
    let streamed;
    {
        let body = BodyReader::new_streaming(Some(&mut src), &[], content_length);
        let mut request = Request::new(&req, body);
        // A handler that streams (`res.write`) frames HEADERS + DATA
        // straight onto the QUIC stream via `H3Sink`, bounded `O(cap)` by
        // `stream_drain_below`; one that buffers (`res.set`) leaves the
        // sink unused and is framed in one shot by `write_response` below.
        let handler_result = handler(&mut request, &mut response).await;
        streamed = response.is_streamed();
        if streamed {
            if handler_result.is_err() {
                // S1: a mid-stream handler error aborts the stream with
                // RESET_STREAM(H3_INTERNAL_ERROR) — RFC 9114 §4.1.1 —
                // instead of the old silent FIN, which presented a
                // truncated body as a complete response.
                conn.reset_stream(sid, crate::errcode::H3_INTERNAL_ERROR);
            } else {
                // Head + body on the stream — FIN it.
                let _ = response.finish().await;
            }
        }
    }
    // The handler returned; abandon any unread request body WITHOUT
    // awaiting it. The old `body.discard().await` parked forever on a
    // peer that declared a Content-Length then stalled (no FIN) — and
    // because h3 dispatches request streams inline in the conn task (no
    // per-stream spawn), that stalled every *other* stream on the same
    // connection too. `discard_recv` drops the buffered bytes + credits
    // the connection window synchronously; any further DATA stays bounded
    // by the (now enforced) receive window and is reaped at conn close.
    conn.discard_recv(sid);
    crate::diag::COUNTERS.user_handler_returned.bump();
    let status = response.status;
    if !streamed {
        // Buffered response: encode HEADERS + DATA + FIN in one shot.
        // `serve_cycles` brackets the whole synchronous send-side h3 path
        // (QPACK encode + H3 framing + queue + close_stream→flush→ship);
        // it CONTAINS the nested quic `flush_tx`/`ship`/`qpack_encode`
        // brackets, so in analysis subtract those to isolate h3 framing.
        let _sv0 = crate::diag::now_cycles();
        write_response(conn, sid, response, &scratch.framing_pool);
        crate::diag::COUNTERS
            .serve_cycles
            .add(crate::diag::now_cycles().wrapping_sub(_sv0));
    }
    crate::diag::COUNTERS.write_response_completed.bump();
    crate::h3_event!(requests_handled, "sid={} status={}", sid, status);
    crate::diag::COUNTERS.responses_sent.bump();
}

/// Parse a `content-length` header value (ASCII decimal). `None` if
/// empty or non-numeric — the body is then treated as unknown-length
/// (FIN-delimited).
fn parse_content_length(v: &[u8]) -> Option<usize> {
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

/// Streams a request body off one QUIC stream: parses DATA frames out
/// of the stream bytes (seeded with whatever was read after HEADERS,
/// then pulling more via `conn.recv(sid, …)`) and yields each payload
/// as an owned `IOBuf`. A trailing HEADERS frame (trailers) or FIN ends
/// the body. This is the h3 implementation of `http::BodySource`, so a
/// streamed h3 body reaches the handler through the same `BodyReader`
/// as HTTP/1.1 — no whole-body buffering, no upload-size cap.
///
/// The DATA payload is copied out of the parse buffer (same per-frame
/// copy the old buffered path paid); true zero-copy would need the QUIC
/// recv path to surface `IOBuf`s (rx-path item L), out of scope here.
struct H3BodySource<'c, C: ServerConn> {
    conn: &'c C,
    sid: u64,
    /// Raw stream bytes not yet parsed into DATA payloads.
    buf: Vec<u8>,
    /// The QUIC stream has signalled FIN; no more bytes will arrive.
    eof: bool,
    /// Body is finished (FIN reached with the buffer drained, trailers
    /// seen, or a parse error) — further `next_chunk` calls return None.
    done: bool,
}

impl<'c, C: ServerConn> H3BodySource<'c, C> {
    fn new(conn: &'c C, sid: u64, buf: Vec<u8>, eof: bool) -> Self {
        H3BodySource {
            conn,
            sid,
            buf,
            eof,
            done: false,
        }
    }
}

impl<C: ServerConn> BodySource for H3BodySource<'_, C> {
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<IOBuf>> + '_>> {
        Box::pin(async move {
            if self.done {
                return None;
            }
            // Owned action so the immutable `parse_frame` borrow of
            // `self.buf` ends before we mutate `self.buf` / `self`.
            enum Act {
                Data(Vec<u8>),
                Skip,
                Need,
                Done,
            }
            loop {
                let (act, used) = match frame::parse_frame(&self.buf) {
                    Ok((frame::Frame::Data(payload), used)) => (Act::Data(payload.to_vec()), used),
                    // Trailing HEADERS (trailers) — end of body.
                    Ok((frame::Frame::Headers(_), used)) => (Act::Done, used),
                    // Control / grease frame interleaved in the body — skip.
                    Ok((_, used)) => (Act::Skip, used),
                    Err(frame::FrameError::Truncated) => (Act::Need, 0),
                    Err(_) => (Act::Done, 0),
                };
                match act {
                    Act::Data(payload) => {
                        self.buf.drain(..used);
                        return Some(IOBuf::from(payload));
                    }
                    Act::Skip => {
                        self.buf.drain(..used);
                        continue;
                    }
                    Act::Done => {
                        self.buf.drain(..used);
                        self.done = true;
                        return None;
                    }
                    Act::Need => {
                        if self.eof {
                            self.done = true;
                            return None;
                        }
                        let mut chunk = [0u8; 4096];
                        let (n, end) = self.conn.recv(self.sid, &mut chunk).await;
                        if n > 0 {
                            self.buf.extend_from_slice(&chunk[..n]);
                        }
                        if end {
                            self.eof = true;
                        }
                        if n == 0 && self.eof {
                            self.done = true;
                            return None;
                        }
                    }
                }
            }
        })
    }
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
/// Must equal `FRAMING_BUF_SIZE - 2 * H3_FRAME_HEADER_MAX` so
/// the pool's pre-allocated buffer matches the headroom +
/// payload + tailroom layout `write_response` expects.
const QPACK_BODY_RESERVE: usize = FRAMING_BUF_SIZE - 2 * H3_FRAME_HEADER_MAX;

fn write_response<C: ServerConn>(
    conn: &C,
    sid: u64,
    resp: Response,
    framing_pool: &alloc::sync::Arc<FramingPool>,
) {
    // Build the response framing as a single IOBuf with
    // reserved headroom for the H3 HEADERS frame header and
    // tailroom for the optional H3 DATA frame header. QPACK
    // encodes directly into the IOBuf's payload region, so:
    //
    //   * No separate `qpack_buf: Vec` scratch (was per-conn).
    //   * No `qpack_buf → framing` memcpy (was ~150-300 B/request).
    //   * The H3 frame headers prepend / append IN PLACE.
    //
    // The framing IOBuf's underlying storage comes from a per-
    // conn pool — pop a `Box<[u8]>`, wrap as `IOBuf::ExternalOwned`
    // with a drop callback that returns the storage to the
    // pool when SendStream finishes draining. Steady-state per-
    // request alloc count: 0 framing buffers (was 1).
    let status_str = status_to_bytes(resp.status);
    let body_len = resp.body_len();
    let mut len_buf = [0u8; 20];
    let len_off = format_usize_into(body_len, &mut len_buf);

    // Take a framing IOBuf from the pool. Layout:
    //   `[headroom: H3_FRAME_HEADER_MAX][qpack body region:
    //    QPACK_BODY_RESERVE][tailroom: H3_FRAME_HEADER_MAX]`.
    // Pool's IOBufs start at offset=0, len=0, with the full
    // FRAMING_BUF_SIZE as tailroom; we shift the visible
    // window to leave headroom for the HEADERS frame header
    // before encoding QPACK.
    let mut framing = framing_pool.take();
    // Reserve the headroom by extending past it via
    // `extend_uninit` then `consume(headroom_len)` — that
    // shifts offset forward without writing anything.
    let _ = framing
        .extend_uninit(H3_FRAME_HEADER_MAX)
        .expect("headroom fits in fresh framing IOBuf");
    framing
        .consume(H3_FRAME_HEADER_MAX)
        .expect("just-extended bytes are consumable");

    // Encode the QPACK field section directly into the IOBuf's
    // tailroom region (the QPACK_BODY_RESERVE-sized space
    // immediately after the headroom).
    let qpack_len = {
        let region = framing
            .extend_uninit(QPACK_BODY_RESERVE)
            .expect("qpack reserve fits in fresh IOBuf");
        let _qe0 = crate::diag::now_cycles();
        let enc = qpack::encode_field_section_into(
            &[
                (&b":status"[..], status_str.as_slice()),
                (&b"content-type"[..], resp.content_type_bytes()),
                (&b"content-length"[..], &len_buf[len_off..]),
            ],
            region,
        );
        crate::diag::COUNTERS
            .qpack_encode_cycles
            .add(crate::diag::now_cycles().wrapping_sub(_qe0));
        match enc {
            Ok(n) => n,
            Err(_) => {
                crate::h3_drop!(
                    qpack_encode_overflow,
                    "sid={} status={} qpack_reserve={}",
                    sid,
                    resp.status,
                    QPACK_BODY_RESERVE
                );
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

    // Queue the framing IOBuf (HEADERS + DATA frame header) WITHOUT
    // flushing, then queue the body, then `close_stream` — which is the
    // single flush point. The QUIC encoder coalesces all queued STREAM
    // frames that fit into one packet, so a small buffered response
    // (HEADERS + DATA + FIN) ships as ONE packet instead of three
    // (3× fewer AEAD-seal/HP passes + datagrams per request on /health;
    // a large body still spans as many packets as bandwidth needs).
    // SendStream natively holds IOBufs (no Vec conversion), so reserved
    // headroom/tailroom on body parts passes through cleanly.
    conn.queue_iobuf(sid, framing);

    // Queue each body chunk on the QUIC stream (still no flush).
    if body_len > 0 {
        for part in resp.into_body().into_parts() {
            queue_chunk(conn, sid, part);
        }
    }
    // close_stream sets FIN AND flushes: the one flush that emits the
    // whole coalesced response. The encoder stamps FIN on the last
    // queued STREAM frame.
    conn.close_stream(sid);
}

/// Push one IOBuf chunk onto stream `sid`. SendStream holds
/// IOBufs natively, so we move the chunk through without
/// converting to a Vec — preserves any reserved
/// headroom/tailroom for layers below to prepend / append.
fn queue_chunk<C: ServerConn>(conn: &C, sid: u64, b: http::IOBuf) {
    // Non-flushing: the response's frames coalesce into as few packets
    // as fit; `write_response`'s trailing `close_stream` is the flush.
    conn.queue_iobuf(sid, b);
}

/// Per-stream send-buffer cap for a *streaming* h3 response. Once a
/// `res.write` leaves more than this many bytes window-blocked on the
/// QUIC stream, the handler parks (`stream_drain_below`) until the conn
/// task flushes more onto the wire — peak send memory `O(cap)`, not
/// `O(response)`. Mirrors the h2 `STREAM_SEND_BUF_CAP`.
const H3_SEND_BUF_CAP: usize = 256 * 1024;

/// h3 [`ResponseSink`]: frames a handler's `res.write` chunks as H3
/// HEADERS + DATA frames straight onto the QUIC stream, backpressuring
/// on the stream send buffer. The QUIC conn task drains the stream
/// (peer ACK / `MAX_STREAM_DATA`) independently of this inline handler,
/// so `stream_drain_below` makes progress without a per-request spawn.
struct H3Sink<'c, C: ServerConn> {
    conn: &'c C,
    sid: u64,
}

impl<C: ServerConn> ResponseSink for H3Sink<'_, C> {
    fn send_head(
        &mut self,
        status: i32,
        content_type: &[u8],
        extra_headers: &[(&[u8], &[u8])],
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        // Streaming head: no content-length (END_STREAM/FIN delimits the
        // body), framed as an H3 HEADERS frame and shipped immediately.
        let frame = build_h3_headers_frame(status, content_type, extra_headers);
        Box::pin(async move {
            match frame {
                Some(f) => {
                    self.conn.send_iobuf(self.sid, f);
                    Ok(())
                }
                None => Err(()), // QPACK overflow
            }
        })
    }

    fn write_chunk(&mut self, buf: IOBuf) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        // Frame the body chunk WITHOUT copying its payload: emit the H3 DATA
        // frame header (type + length varint) as its own small IOBuf, then
        // move the payload IOBuf in. Two appends to the same stream
        // concatenate into one DATA frame on the QUIC byte stream — so a
        // spliced RX `IOBuf` reaches the AEAD sealer without a payload copy.
        let mut hdr = [0u8; H3_FRAME_HEADER_MAX];
        let hlen = frame::write_frame_header(h3_ftype::DATA, buf.data().len(), &mut hdr)
            .expect("data hdr fits");
        let header = IOBuf::from_slice_with_headroom(0, &hdr[..hlen], 0);
        Box::pin(async move {
            // Stop if the peer closed: `stream_drain_below` returns
            // immediately on a failed conn, so without this an app
            // streaming a large body (e.g. a 1 GiB `/stream` the client
            // abandons after a few MiB) would race ahead buffering the
            // remainder into a dead stream and exhaust the heap. The `Err`
            // breaks the handler's `res.write(..).await?` loop.
            if self.conn.is_failed() {
                return Err(());
            }
            // `send_iobuf` appends + flushes what the stream window allows
            // straight to the socket; only window-blocked bytes linger.
            self.conn.send_iobuf(self.sid, header);
            self.conn.send_iobuf(self.sid, buf);
            if self.conn.stream_buffered(self.sid) > H3_SEND_BUF_CAP {
                self.conn.stream_drain_below(self.sid, H3_SEND_BUF_CAP).await;
            }
            // Re-check after parking: the conn may have failed while we
            // waited for window.
            if self.conn.is_failed() {
                return Err(());
            }
            Ok(())
        })
    }

    fn finish(&mut self) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        Box::pin(async move {
            self.conn.close_stream(self.sid); // FIN on the last queued chunk
            Ok(())
        })
    }
}

/// Build a streaming H3 HEADERS frame (QPACK field section, **no
/// content-length**) as an owned IOBuf. `None` on QPACK overflow.
fn build_h3_headers_frame(
    status: i32,
    content_type: &[u8],
    extra: &[(&[u8], &[u8])],
) -> Option<IOBuf> {
    let status_str = status_to_bytes(status);
    let mut list: Vec<(&[u8], &[u8])> = Vec::with_capacity(2 + extra.len());
    list.push((&b":status"[..], status_str.as_slice()));
    list.push((&b"content-type"[..], content_type));
    list.extend_from_slice(extra);
    let mut qpack = alloc::vec![0u8; QPACK_BODY_RESERVE];
    let qlen = qpack::encode_field_section_into(&list, &mut qpack).ok()?;
    let mut hdr = [0u8; H3_FRAME_HEADER_MAX];
    let hlen = frame::write_frame_header(h3_ftype::HEADERS, qlen, &mut hdr).ok()?;
    let mut out = Vec::with_capacity(hlen + qlen);
    out.extend_from_slice(&hdr[..hlen]);
    out.extend_from_slice(&qpack[..qlen]);
    Some(IOBuf::from(out))
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
