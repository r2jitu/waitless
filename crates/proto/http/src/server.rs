// HTTP/1.1 listener and per-connection keep-alive loop.
//
// `listen` binds a port and fans accepts out to per-worker tasks;
// each task runs `serve_conn`, which is the shared keep-alive
// pump that plain-HTTP / HTTPS / HTTP/3 all drive (each through
// its own `HttpStream` impl).

use alloc::sync::Arc;

use iobuf::{IOBuf, IOBufChain};

use crate::body::BodyReader;
use crate::request::Request;
use crate::response::{Response, write_response_into_iobuf};
use crate::stream::HttpStream;
use crate::streaming;

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
/// `handler`, sends responses. Returns when the peer closes, the
/// idle timeout fires, or a transport error occurs.
///
/// Public so transport-specific listeners (HTTPS in `tls`,
/// HTTP/3 in `http3`) can drive their own `HttpStream` impls
/// through the same request/response machinery.
///
/// Parse path: `StreamingRequestParser` reads chunk bytes directly
/// off `recv_chunk`'s guard and writes parsed values into the
/// caller's `Request` as they arrive — no per-conn parse buffer,
/// no chunk-to-buffer memcpy. `carry: Option<IOBuf>` holds the
/// bytes that landed in the same chunk past a HEAD terminator
/// (body bytes for the current request, then start-of-next-
/// pipelined-request bytes after the body drains). `into_owned`
/// detaches the chunk from the recv borrow when carry is needed
/// past the borrow's life — zero copy on NIC-RX, one memcpy on
/// TLS, paid only when carry is non-empty.
pub async fn serve_conn<S, H>(handler: Arc<H>, mut stream: S)
where
    S: HttpStream,
    H: for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>) -> Response,
{
    crate::diag::COUNTERS.connections_served.bump();
    let mut req = Request::new();
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
    let mut parser = streaming::StreamingRequestParser::new();
    // Bytes carried over from the previous chunk. After HEAD parse:
    // contains body bytes for the current request, then start-of-
    // next-pipelined-request bytes once the body drains. Owned (via
    // `into_owned`) so it outlives the recv borrow.
    let mut carry: Option<IOBuf> = None;
    loop {
        req.clear();
        parser.reset();
        // Feed bytes until the parser signals HEAD complete. Source
        // bytes from `carry` first (left over from the previous
        // iteration), then fresh `recv_chunk` calls.
        loop {
            if let Some(buf) = carry.take() {
                match parser.feed(&mut req, buf.data()) {
                    streaming::FeedResult::Done { consumed } => {
                        carry = buf
                            .into_remainder(consumed)
                            .expect("consumed <= data().len()");
                        break;
                    }
                    streaming::FeedResult::NeedMore => {
                        drop(buf);
                    }
                }
            } else {
                let chunk_fut = stream.recv_chunk();
                match waitless::runtime::timeout_us(IDLE_TIMEOUT_US, chunk_fut).await {
                    Some(Some(guard)) => match parser.feed(&mut req, guard.data()) {
                        streaming::FeedResult::Done { consumed } => {
                            carry = guard
                                .into_remainder(consumed)
                                .expect("consumed <= data().len()");
                            break;
                        }
                        streaming::FeedResult::NeedMore => {
                            drop(guard);
                        }
                    },
                    Some(None) => {
                        crate::diag::COUNTERS.peer_eof.bump();
                        return;
                    }
                    None => {
                        crate::diag::COUNTERS.idle_timeout.bump();
                        return;
                    }
                }
            }
        }
        crate::diag::COUNTERS.requests_parsed.bump();
        let content_length = req.content_length;

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
            let body_drained_ok;
            {
                // Body prebuf comes from `carry` (the bytes that
                // landed in the same chunk as the HEAD terminator).
                // Trim to declared `Content-Length` so we don't
                // hand the body reader bytes that belong to the
                // next pipelined request.
                let prebuf: &[u8] = match carry.as_ref() {
                    Some(c) => {
                        let n = content_length.min(c.data().len());
                        &c.data()[..n]
                    }
                    None => &[],
                };
                let mut body = BodyReader::new(&mut stream, prebuf, content_length);
                resp = (*handler)(&req, &mut body).await;
                body_drained_ok = want_close
                    || body.is_empty()
                    || body.discard().await.is_ok();
            }
            if !body_drained_ok {
                crate::diag::COUNTERS.body_drain_failed.bump();
                return;
            }
        }

        // SAFETY contract for the borrowed header IOBuf:
        //   * `header_storage` outlives every IOBuf wrapping it
        //     (future-state field; future is pinned; we drop the
        //     IOBuf inside this iteration before constructing the
        //     next one).
        //   * No two IOBufs ever alias the same bytes — the IOBuf
        //     is push_back'd into out_chain, drained by send (which
        //     drops it after committing the bytes), only then does
        //     the next iteration wrap the same storage.
        //   * No drop callback (drop_fn = None) — the storage is
        //     borrowed, so the IOBuf's drop is a no-op.
        let header = unsafe {
            IOBuf::borrow(
                core::ptr::NonNull::new_unchecked(header_storage.as_mut_ptr()),
                HEADER_BUF_SIZE as u32,
                0,
                0,
            )
        };
        let mut header = header;
        write_response_into_iobuf(&mut header, &resp, !want_close);

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
            // the conn drops. Without this, TLS clients tear down
            // their session-resumption state on the perceived
            // unclean close.
            let _ = stream.close().await;
            return;
        }

        // Advance `carry` past the body bytes that were just served
        // (BodyReader handed them to the handler from `carry`'s
        // prefix; `discard` finished anything the handler skipped).
        // What's left is the start of the next pipelined request.
        if let Some(c) = carry.take() {
            let body_from_carry = content_length.min(c.data().len());
            carry = c
                .into_remainder(body_from_carry)
                .expect("body_from_carry <= data().len()");
        }
    }
}
