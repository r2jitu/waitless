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
                    streaming::FeedResult::Overflow => {
                        crate::diag::COUNTERS.header_buffer_overflow.bump();
                        return;
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
                        streaming::FeedResult::Overflow => {
                            crate::diag::COUNTERS.header_buffer_overflow.bump();
                            return;
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
        // Post-body residue captured by BodyReader when a fresh-recv
        // chunk straddled the Content-Length boundary. None in every
        // path that doesn't pull from the stream past the prebuf.
        let body_leftover: Option<IOBuf>;
        if req.reject {
            crate::diag::record_reject(&req);
            resp = Response::bad_request();
            want_close = true;
            body_leftover = None;
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
                // Pick up any residue BodyReader stashed when a
                // stream-side chunk straddled the body boundary.
                // Only meaningful when the body was fully drained;
                // a failed drain returns immediately anyway.
                body_leftover = if body_drained_ok {
                    body.into_leftover()
                } else {
                    None
                };
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
        // What's left in carry is the start of the next pipelined
        // request.
        if let Some(c) = carry.take() {
            let body_from_carry = content_length.min(c.data().len());
            carry = c
                .into_remainder(body_from_carry)
                .expect("body_from_carry <= data().len()");
        }
        // If the body extended past `carry` AND the straddling
        // fresh-recv chunk carried post-body bytes (the next
        // pipelined request's HEAD start), BodyReader stashed them
        // — promote into `carry` so the next outer iteration sees
        // them. Carry must be empty here: a body that needed the
        // stream straddled because it overran `carry`'s prefix.
        if let Some(l) = body_leftover {
            debug_assert!(
                carry.is_none(),
                "body straddled stream => carry was fully drained as body prefix",
            );
            carry = Some(l);
        }
    }
}

#[cfg(test)]
mod serve_conn_tests {
    use super::serve_conn;
    use crate::body::BodyReader;
    use crate::request::{Method, Request};
    use crate::response::Response;
    use crate::stream::HttpStream;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use iobuf::{IOBuf, IOBufChain};
    use waitless::runtime::RecvChunkGuard;

    /// Pre-canned-chunk transport. `recv_chunk` pops entries from
    /// `chunks` (`Some(bytes)` -> wrap in a guard, `None` -> signal
    /// EOF so `serve_conn` returns via the `peer_eof` arm); `send`
    /// appends every part to `sent`. Both fields are shared via
    /// `Rc<RefCell<_>>` so the test can read `sent` back after the
    /// future has consumed the stream by value.
    struct MockStream {
        chunks: Rc<RefCell<VecDeque<Option<Vec<u8>>>>>,
        sent: Rc<RefCell<Vec<u8>>>,
    }

    impl HttpStream for MockStream {
        async fn recv(&mut self, _: &mut [u8]) -> usize {
            unreachable!("serve_conn HEAD path uses recv_chunk");
        }
        async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>> {
            match self.chunks.borrow_mut().pop_front() {
                Some(Some(bytes)) => Some(RecvChunkGuard::new(IOBuf::from(bytes))),
                Some(None) | None => None,
            }
        }
        async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
            let mut sent = self.sent.borrow_mut();
            while let Some(part) = chain.pop_front() {
                sent.extend_from_slice(part.data());
            }
            Ok(())
        }
    }

    /// Single-poll driver. Every await this test exercises resolves
    /// Ready on first poll: `MockStream` methods are inline-Ready
    /// `async fn`s, and `select(fut, sleep)` inside `timeout_us`
    /// short-circuits to Ready before the sleep's waker dance fires.
    fn block_on<F: Future>(mut fut: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local that is not moved again before
        // the poll below.
        let fut = unsafe { Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future pended unexpectedly"),
        }
    }

    // Per-test recording of (method, path, body_bytes) for every
    // request the handler sees. thread_local! because the handler
    // must be a plain `async fn` (a state-capturing closure fights
    // the compiler over the HRTB
    // `for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b, S>)`).
    // Each test resets the cell before driving serve_conn.
    type ObservedReq = (Method, Vec<u8>, Vec<u8>);

    thread_local! {
        static OBSERVED: RefCell<Vec<ObservedReq>> = const { RefCell::new(Vec::new()) };
    }

    async fn observe_handler(req: &Request, body: &mut BodyReader<'_, MockStream>) -> Response {
        let mut body_bytes = Vec::new();
        while let Some(guard) = body.chunk().await {
            body_bytes.extend_from_slice(guard.data());
        }
        OBSERVED.with(|o| {
            o.borrow_mut()
                .push((req.method, req.path().to_vec(), body_bytes))
        });
        Response::ok(b"text/plain".as_slice(), b"OK".as_slice())
    }

    fn reset_observed() {
        OBSERVED.with(|o| o.borrow_mut().clear());
    }

    fn drive(chunks_vec: Vec<Option<Vec<u8>>>) -> (Vec<u8>, Vec<ObservedReq>) {
        reset_observed();
        let chunks = Rc::new(RefCell::new(VecDeque::from(chunks_vec)));
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mock = MockStream {
            chunks: Rc::clone(&chunks),
            sent: Rc::clone(&sent),
        };
        let handler = Arc::new(observe_handler);
        block_on(serve_conn(handler, mock));
        let observed = OBSERVED.with(|o| o.borrow().clone());
        let sent_bytes = Rc::try_unwrap(sent).ok().unwrap().into_inner();
        (sent_bytes, observed)
    }

    fn count_ok(bytes: &[u8]) -> usize {
        bytes
            .windows(b"HTTP/1.1 200 OK".len())
            .filter(|w| *w == b"HTTP/1.1 200 OK")
            .count()
    }

    /// Two pipelined requests packed into a SINGLE inbound chunk —
    /// the carry-stressing path. After parsing req1's HEAD,
    /// `carry` holds (body₁ ‖ HEAD₂). The handler reads body₁ from
    /// `carry`'s prefix; `into_remainder` advances past it. The
    /// next outer iteration sees `carry` non-empty and feeds it to
    /// the parser — req2's HEAD is parsed entirely from carry, no
    /// fresh recv. req2 has `Content-Length: 0`, so the body is
    /// empty; the conn returns via `peer_eof` on the next loop.
    ///
    /// Without correct carry advancement (`into_remainder` keeping
    /// the right tail) the parser would either never reach req2 or
    /// would parse a body-byte-contaminated path/method.
    #[test]
    fn carry_threads_body_then_next_pipelined_head_one_chunk() {
        let raw = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nBODYGET /b HTTP/1.1\r\nHost: x\r\n\r\n";
        let (sent, observed) = drive(alloc::vec![Some(raw.to_vec()), None]);
        assert_eq!(count_ok(&sent), 2);
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, Method::Post);
        assert_eq!(observed[0].1, b"/a");
        assert_eq!(observed[0].2, b"BODY", "body served from carry");
        assert_eq!(observed[1].0, Method::Get);
        assert_eq!(observed[1].1, b"/b", "next-pipelined HEAD parsed from carry");
        assert!(observed[1].2.is_empty());
    }

    /// Variant where the next-pipelined HEAD straddles chunk
    /// boundaries: chunk 1 = HEAD₁ + full body₁ + first half of
    /// HEAD₂; chunk 2 = rest of HEAD₂. Verifies the carry from
    /// chunk 1's leftover into chunk 2's parser feed walks the
    /// parser through `NeedMore` -> `Done` correctly across the
    /// outer loop boundary.
    #[test]
    fn carry_threads_head_across_chunks_after_body() {
        let chunk1 =
            b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nBODYGET /b HT".to_vec();
        let chunk2 = b"TP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let (sent, observed) = drive(alloc::vec![Some(chunk1), Some(chunk2), None]);
        assert_eq!(count_ok(&sent), 2, "both responses ship across chunks");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, Method::Post);
        assert_eq!(observed[0].2, b"BODY");
        assert_eq!(observed[1].0, Method::Get);
        assert_eq!(observed[1].1, b"/b");
    }

    /// **BodyReader straddle**: the body extends past `carry` into
    /// a fresh-recv chunk that also carries the next-pipelined
    /// HEAD bytes. Pre-S3, `BodyReader` capped its delivered slice
    /// at the body length and dropped the post-body residue when
    /// the underlying `RecvChunkGuard` dropped — losing req2
    /// entirely. With `BodyReader::into_leftover` plumbed through,
    /// the residue is captured and serve_conn promotes it into
    /// `carry` for the next outer iteration.
    ///
    /// Shape:
    /// * chunk 1: HEAD₁ (Content-Length: 8) + first 4 body bytes
    ///   (carry holds the 4-byte body prefix after HEAD₁ parse)
    /// * chunk 2: rest of body (4 bytes) + complete HEAD₂
    ///   (this is the straddling chunk — body needs 4 more bytes,
    ///   the rest is HEAD₂)
    /// * chunk 3: EOF.
    #[test]
    fn body_straddle_preserves_next_pipelined_head() {
        let chunk1 = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nBODY".to_vec();
        let chunk2 = b"TAILGET /b HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let (sent, observed) = drive(alloc::vec![Some(chunk1), Some(chunk2), None]);
        assert_eq!(
            count_ok(&sent),
            2,
            "both responses ship — straddle did not lose req2",
        );
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].0, Method::Post);
        assert_eq!(observed[0].1, b"/a");
        assert_eq!(observed[0].2, b"BODYTAIL", "body fully reconstructed");
        assert_eq!(observed[1].0, Method::Get);
        assert_eq!(observed[1].1, b"/b", "next-pipelined HEAD preserved");
    }
}
