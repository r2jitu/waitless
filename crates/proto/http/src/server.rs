// HTTP/1.1 listener and per-connection keep-alive loop.
//
// `listen` binds a port and fans accepts out to per-worker tasks;
// each task runs `serve_conn`, which is the shared keep-alive
// pump that plain-HTTP / HTTPS / HTTP/3 all drive (each through
// its own `HttpStream` impl).

use alloc::sync::Arc;

use iobuf::{IOBuf, IOBufChain};

use crate::body::BodyReader;
use crate::request::{ParserState, Request, parse_request_with_state};
use crate::response::{Response, write_response_into_iobuf};
use crate::stream::HttpStream;

/// Per-connection parse buffer. Sized for the request HEAD only —
/// status line + headers, terminated by `\r\n\r\n`. Bodies are
/// delivered to the handler via [`BodyReader`] which streams from
/// the transport stream (with any body bytes that happened to land
/// in this buffer as a prefix). 16 KiB covers worst-case header
/// sets we expect from bench / browser clients plus headroom for
/// the leading bytes of a POST body.
const BUF_SIZE: usize = 16 * 1024;

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

// ---- Public entry points -----------------------------------------------------

/// Listen for plain HTTP on `port`. The returned `TcpHandle`
/// owns the per-worker accept fan-out; drop it to stop accepting
/// new connections (in-flight conns drain at their idle
/// timeout).
///
/// `handler` is called for every parsed request; apps that want
/// path routing match `req.path()` inside it. Many ports can be
/// bound — call this multiple times — and each `TcpHandle` is
/// independent.
/// Listen for plain HTTP on `port`. `handler` is any async closure
/// or `async fn` taking `&Request` and producing `Response` — e.g.
/// `async fn handle(req: &Request) -> Response { ... }`. The
/// closure is shared across every accepted connection (wrapped in
/// `Arc` once internally) and the per-conn task awaits it inline,
/// so a slow handler suspends only its own connection.
pub fn listen<H>(port: u16, handler: H) -> Result<(), waitless::runtime::TcpBindError>
where
    H: for<'a, 'b> AsyncFn(
            &'a Request,
            &'a mut BodyReader<'b, waitless::runtime::TcpStream>,
        ) -> Response
        + Send
        + Sync
        + 'static,
{
    let listener = waitless::runtime::TcpListener::bind(port)?;
    let handler = Arc::new(handler);
    let h = listener.run(move |stream| {
        let handler = Arc::clone(&handler);
        async move {
            serve_conn(handler, stream).await;
        }
    });
    waitless::_retain(h);
    Ok(())
}

// ---- Unified per-connection handler ------------------------------------------

/// Per-conn keep-alive loop. Reads bytes from `stream` (plain or
/// TLS — same code path), parses pipelined requests, calls
/// `handler`, sends responses. Returns when the peer closes,
/// idle timeout fires, or the buffer overflows on a too-large
/// request.
///
/// Public so transport-specific listeners (HTTPS in `tls`,
/// HTTP/3 in `http3`) can drive their own `HttpStream` impls
/// through the same request/response machinery.
pub async fn serve_conn<S, H>(handler: Arc<H>, mut stream: S)
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    // Inline request-parse buffer in the future state. The
    // async runtime allocates the future once (as a
    // `Pin<Box<dyn Future>>` per accepted conn); folding `buf` in
    // turns the previous "future alloc + Box<[u8]> alloc" pair
    // into a single alloc per conn-accept. Sized to BODY_CAP +
    // header headroom so a full bulk-upload request fits in one
    // parse pass.
    crate::diag::COUNTERS.connections_served.bump();
    let mut buf = [0u8; BUF_SIZE];
    let mut buf_len = 0usize;
    // Per-connection scratch reused across every request on this
    // conn — `Request` carries BODY_CAP of body buffer and 256 B
    // of path. Allocating + zero-initing it per request was costing
    // ~1 GB/s of memory bandwidth per core at peak request rate.
    // `parse_request` resets length fields up front, so a stale
    // tail is invisible to the read path; only the
    // writes-then-reads-back range is observed.
    let mut req = Request::new();
    // Outbound chain is amortised across every response on this
    // connection — `send` drains it via `pop_front`, leaving
    // the chain empty but with its `VecDeque` allocation
    // preserved. Capacity 4 covers the common shapes (header +
    // 1 body part, header + 2-3 chunked body parts) without
    // forcing the deque to grow.
    let mut out_chain = IOBufChain::with_capacity(4);
    // Inline storage for the response-header IOBuf, sized for the
    // typical header set plus the worst-case transport reserve.
    // Folded into the future state so each iteration wraps it as
    // an a `Borrowed` IOBuf rather than allocating a fresh
    // `Box<[u8]>` per response. 1 KiB covers HTTP/1.1 status line
    // + Content-Type + Content-Length + Connection + a handful
    // of `with_header`-set extras (Alt-Svc, Cache-Control,
    // Set-Cookie) with room to spare.
    const HEADER_BUF_SIZE: usize = 1024;
    let mut header_storage = [0u8; HEADER_BUF_SIZE];
    // Carries the parser's progress (`scan_pos`) across calls
    // when a request arrives in multiple recv'd segments — the
    // `find_header_end` scan resumes from the last position
    // instead of restarting at byte 0. Reset to default after
    // each successfully-consumed request so the next pipelined
    // request starts a fresh scan.
    let mut parser_state = ParserState::default();
    loop {
        if buf_len == BUF_SIZE {
            // Parse buffer full and no complete request in it —
            // client sent something larger than we handle.
            crate::diag::COUNTERS.header_buffer_overflow.bump();
            return;
        }
        let recv_fut = stream.recv(&mut buf[buf_len..]);
        let got = match waitless::runtime::timeout_us(IDLE_TIMEOUT_US, recv_fut).await {
            Some(n) => n,
            None => {
                crate::diag::COUNTERS.idle_timeout.bump();
                return; // idle timeout
            }
        };
        if got == 0 {
            crate::diag::COUNTERS.peer_eof.bump();
            return; // EOF / fatal recv
        }
        buf_len += got;

        // Drain every complete request sitting in the buffer.
        while buf_len > 0 {
            let body_start = parse_request_with_state(&buf[..buf_len], &mut req, &mut parser_state);
            if body_start == 0 {
                break; // need more bytes
            }
            crate::diag::COUNTERS.requests_parsed.bump();
            let content_length = req.content_length;

            // A request the HTTP/1.1 parser flagged as malformed —
            // today only a `Transfer-Encoding: chunked` request,
            // which we don't frame yet (item E in
            // docs/rx-path-optimizations.md). Answer it with a
            // hard `400 Bad Request` and force the connection
            // closed. Falling through to the keep-alive path would
            // be a request-smuggling hole: the chunk-framed body
            // bytes still sit in `buf` and the next loop iteration
            // would misparse them as a second pipelined request.
            // So skip the handler and the `BodyReader` entirely
            // and drop into the shared send path below with
            // `want_close` forced on — that emits `Connection:
            // close` and `return`s without touching the
            // post-header bytes.
            let want_close;
            let resp;
            if req.reject {
                crate::diag::record_reject(&req);
                resp = Response::bad_request();
                want_close = true;
            } else {
                want_close = match req.header(b"Connection") {
                    Some(v) => v.eq_ignore_ascii_case(b"close"),
                    None => false,
                };

                // Construct the streaming body reader. `prebuf` is
                // the body bytes already sitting in `buf` after the
                // headers; the reader will draw stream bytes for
                // any tail that didn't fit. Restrict the prebuf to
                // body-only bytes (the slice may otherwise include
                // the start of the next pipelined request).
                let prebuf_end = (body_start + content_length).min(buf_len);
                let body_drained_ok;
                {
                    let prebuf = &buf[body_start..prebuf_end];
                    let mut body = BodyReader::new(&mut stream, prebuf, content_length);
                    resp = (*handler)(&req, &mut body).await;
                    // Drain any leftover body bytes the handler
                    // didn't consume. Keep-alive contract requires
                    // the connection to be positioned at the start
                    // of the next request before we ship the
                    // response; skipping bytes mid-body would let
                    // them be mis-parsed as the next request's
                    // bytes. If the handler asked for
                    // `Connection: close` we tear down without
                    // draining (the conn is going away anyway).
                    body_drained_ok = want_close || body.is_empty() || body.discard().await.is_ok();
                }
                if !body_drained_ok {
                    crate::diag::COUNTERS.body_drain_failed.bump();
                    return;
                }
            }

            // Wrap the per-conn `header_storage` array as an
            // a `Borrowed` IOBuf so the framing layer can build
            // headers in stack-resident memory without a heap
            // allocation per response. SAFETY contract:
            //   * `header_storage` outlives every IOBuf wrapping
            //     it (it's a future-state field, the future is
            //     pinned, and we drop the IOBuf inside this
            //     iteration before constructing the next one).
            //   * No two IOBufs ever alias the same bytes — the
            //     IOBuf is `push_back`'d into `out_chain`,
            //     drained by `send` (which drops it after
            //     committing the bytes to the wire), and only
            //     then does the next iteration construct a fresh
            //     IOBuf wrapping the same storage.
            //   * No drop callback (`drop_fn = None`) — the
            //     storage is borrowed, not owned, so the IOBuf's
            //     drop should be a no-op for the array.
            let header = unsafe {
                IOBuf::borrow(
                    core::ptr::NonNull::new_unchecked(header_storage.as_mut_ptr()),
                    HEADER_BUF_SIZE as u32,
                    0,
                    0,
                )
            };
            // SAFETY: the only IOBuf currently aliasing
            // `header_storage` is `header` itself (we just
            // constructed it). `write_response_into_iobuf` writes
            // through `header` exclusively.
            let mut header = header;
            write_response_into_iobuf(&mut header, &resp, !want_close);

            // Stage the response into the per-conn outbound chain.
            // Order: header IOBuf first, then body parts. The
            // transport (TCP / TLS) drains the chain and decides
            // the wire chunking — TCP coalesces parts into
            // MSS-bounded segments so this header-plus-body shape
            // ships in one TCP segment for tiny replies; TLS
            // encrypts each part as its own record (in-place when
            // reserves match).
            //
            // `out_chain` is empty here (`send` drains it
            // each iteration). Move the body's parts in via
            // `into_parts()`, then `push_front` the header so the
            // wire order is [header, body0, body1, ...].
            debug_assert!(out_chain.is_empty());
            for part in resp.into_body().into_parts() {
                out_chain.push_back(part);
            }
            out_chain.push_front(header);

            if stream.send(&mut out_chain).await.is_err() {
                crate::diag::COUNTERS.send_failed.bump();
                return;
            }
            crate::diag::COUNTERS.responses_sent.bump();

            if want_close {
                // Send TLS close_notify (no-op for plain TCP) before
                // the conn drops. Without this, TLS clients tear
                // down their session-resumption state on the
                // perceived unclean close — which is why every
                // post-resumption-PR fresh handshake from rustls or
                // openssl was unable to follow up with a resumed
                // one despite tickets flowing correctly on the wire.
                let _ = stream.close().await;
                return;
            }
            // Shift any post-body bytes (start of the next
            // pipelined request) to the front of `buf`. The body
            // may have extended past the parse buffer's end (in
            // which case `BodyReader` pulled the tail from the
            // transport directly); compute the end-of-body offset
            // capped at the current `buf_len`.
            let body_end_in_buf = (body_start + content_length).min(buf_len);
            let remaining = buf_len - body_end_in_buf;
            if remaining > 0 {
                buf.copy_within(body_end_in_buf..buf_len, 0);
            }
            buf_len = remaining;
            // The next pipelined request starts at byte 0 of the
            // shifted buffer, so the parser state has to forget
            // its "already scanned" cursor.
            parser_state = ParserState::default();
        }
    }
}
