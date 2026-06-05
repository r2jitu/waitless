// HTTP/1.1 listener and per-connection keep-alive loop.
//
// `listen` binds a port and fans accepts out to per-worker tasks;
// each task runs `serve_conn`, which is the shared keep-alive
// pump that plain-HTTP / HTTPS / HTTP/3 all drive (each through
// its own `HttpStream` impl).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;

use iobuf::{IOBuf, IOBufChain};

use core::cell::RefCell;

use crate::body::BodyReader;
use crate::request::{Request, RequestHead};
use crate::response::{Bytes, Response, write_response_head_parts, write_streaming_head_parts};
use crate::MAX_EXTRA_HEADERS;
use crate::stream::{BodySource, HttpStream, ResponseSink};
use crate::streaming;

/// Per-connection duplex backing for one handler call: the borrowed
/// stream wrapped in a `RefCell` so the request-body source and the
/// response sink can **both** draw on it. The handler reads the request
/// (`req.read_chunk`) and writes the response (`res.write`) over one
/// stream, used **sequentially** — each `recv`/`send` is awaited under
/// its own `borrow_mut`, and a body chunk is owned (copied off the
/// stream) before the following `write` re-borrows the cell, so the two
/// never overlap. That is the same `recv → owned → send` discipline the
/// serve loop used for the old echo splice, now exposed through
/// `req`/`res`: an echo / proxy / transform streams bounded `O(chunk)`
/// over plaintext **and** TLS with no read/write split of the transport.
/// (The per-conn task is the cell's only user, so the `borrow_mut`s held
/// across `.await` are sound — no other task touches this connection.)
type StreamCell<'s, S> = RefCell<&'s mut S>;

/// Request-body source over the shared [`StreamCell`]. `next_chunk`
/// borrows the cell only for one `recv_chunk`, then returns **owned**
/// bytes — releasing the cell before the handler's following
/// `res.write` re-borrows it. (`BodyReader` reaches this via the
/// `BodySource` seam, exactly like the non-duplex transports.)
struct CellSource<'c, 's, S: HttpStream> {
    cell: &'c StreamCell<'s, S>,
}

impl<S: HttpStream> BodySource for CellSource<'_, '_, S> {
    // `borrow_mut` is held across the `recv_chunk` await. Sound here: the
    // per-conn handler future is the cell's only borrower, and it uses the
    // source and sink sequentially (a chunk is owned and the borrow
    // released before the following `res.write`), so the borrow is never
    // re-entered. The general-case lint can't see that invariant.
    #[allow(clippy::await_holding_refcell_ref)]
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<IOBuf>> + '_>> {
        Box::pin(async move {
            let mut g = self.cell.borrow_mut();
            g.recv_chunk().await.map(|c| c.into_owned())
        })
    }
}

/// Response sink over the shared [`StreamCell`]. The head goes out
/// close-delimited (`Connection: close`) on the first chunk; each chunk
/// is its own awaited `send` (TCP/TLS backpressure → `O(chunk)` peak).
/// Takes the stream from `cell.borrow_mut()` per send, so it coexists
/// with [`CellSource`] reading the request body on the same connection.
struct CellSink<'c, 's, S: HttpStream> {
    cell: &'c StreamCell<'s, S>,
    out: IOBufChain,
}

impl<'c, 's, S: HttpStream> CellSink<'c, 's, S> {
    fn new(cell: &'c StreamCell<'s, S>) -> Self {
        CellSink {
            cell,
            out: IOBufChain::new(),
        }
    }
}

impl<S: HttpStream> ResponseSink for CellSink<'_, '_, S> {
    // `borrow_mut` held across the `send` await — sound for the same
    // reason as `CellSource::next_chunk` (single per-conn borrower, used
    // sequentially with the body source).
    #[allow(clippy::await_holding_refcell_ref)]
    fn send_head(
        &mut self,
        status: i32,
        content_type: &[u8],
        extra_headers: &[(&[u8], &[u8])],
    ) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        // Build the close-delimited head into a small heap IOBuf (one
        // alloc on the cold streaming path) and ship it.
        let mut head = crate::body_iobuf(512);
        write_streaming_head_parts(&mut head, status, content_type, extra_headers);
        Box::pin(async move {
            self.out.clear();
            self.out.push_back(head);
            let mut g = self.cell.borrow_mut();
            g.send(&mut self.out).await
        })
    }

    #[allow(clippy::await_holding_refcell_ref)]
    fn write_chunk(&mut self, buf: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        let chunk = IOBuf::from_slice_with_headroom(0, buf, 0);
        Box::pin(async move {
            self.out.clear();
            self.out.push_back(chunk);
            let mut g = self.cell.borrow_mut();
            g.send(&mut self.out).await
        })
    }

    fn finish(&mut self) -> Pin<Box<dyn Future<Output = Result<(), ()>> + '_>> {
        // Close-delimited: nothing to flush; the serve loop closes the
        // connection after a streamed response.
        Box::pin(async { Ok(()) })
    }
}

/// Idle-connection timeout. After this long without inbound data,
/// the per-conn task tears down the connection and releases its
/// backend slot. Mirrors common HTTP/1.1 keep-alive budgets.
const IDLE_TIMEOUT_US: u64 = 30_000_000;

/// Steady-state cycle counter for the per-stage `serve_conn`
/// profiling brackets (parse / handler / build). Same rdtsc / cntvct
/// instruction the `tls` profiler uses; zero on unsupported targets.
/// `http` sits above `kernel_core` via the reactor only, so we read
/// the counter directly rather than thread a dependency.
#[inline(always)]
fn now_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let v: u64;
        core::arch::asm!(
            "mrs {0}, cntvct_el0",
            out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

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
    H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()> + Send + Sync + 'static,
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
    H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()>,
{
    crate::diag::COUNTERS.connections_served.bump();
    // The reused request HEAD (parser storage). The handler sees a
    // per-dispatch `Request` facade built over a borrow of this head
    // plus the body reader.
    let mut req = RequestHead::new();
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
                let __p0 = now_cycles();
                let feed_result = parser.feed(&mut req, buf.data());
                crate::diag::COUNTERS
                    .parse_cycles
                    .add(now_cycles().wrapping_sub(__p0));
                match feed_result {
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
                    Some(Some(guard)) => {
                        let __p0 = now_cycles();
                        let feed_result = parser.feed(&mut req, guard.data());
                        crate::diag::COUNTERS
                            .parse_cycles
                            .add(now_cycles().wrapping_sub(__p0));
                        match feed_result {
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
                        }
                    }
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

        let want_close = if req.reject {
            true
        } else {
            match req.header(b"Connection") {
                Some(v) => v.eq_ignore_ascii_case(b"close"),
                None => false,
            }
        };

        // Per-connection request/response dispatch. Wrap the borrowed
        // stream in a `RefCell` and hand the handler a body reader
        // (`CellSource`) + a response sink (`CellSink`) that BOTH draw on
        // it, so a handler can read the request body and stream the
        // response over one connection — a bounded `O(chunk)` echo /
        // proxy / transform on plaintext AND TLS, no read/write split. A
        // handler that buffers (`res.set(..)`) leaves the sink unused;
        // the buffered response is sent afterward through the borrowed-
        // head path (so `/health` etc. stay zero-alloc). A malformed
        // request (`reject`) short-circuits to a buffered `400` + close.
        let streamed;
        #[allow(clippy::type_complexity)]
        let buffered: Option<(i32, Bytes, IOBufChain, [Option<(Bytes, Bytes)>; MAX_EXTRA_HEADERS])>;
        // Post-body residue captured by BodyReader when a fresh-recv
        // chunk straddled the Content-Length boundary. None on every
        // path that doesn't pull from the stream past the prebuf.
        let body_leftover: Option<IOBuf>;
        if req.reject {
            crate::diag::record_reject(&req);
            streamed = false;
            buffered = Some(Response::bad_request().into_parts());
            body_leftover = None;
        } else {
            let cell: StreamCell<'_, S> = RefCell::new(&mut stream);
            let mut source = CellSource { cell: &cell };
            let mut sink = CellSink::new(&cell);
            // Body prebuf: the bytes that rode in with the HEAD
            // terminator (`carry`), trimmed to the declared
            // Content-Length so the reader never reaches into the next
            // pipelined request. A bodyless request (CL=0) gets no
            // source — the read half stays idle.
            let prebuf: &[u8] = match carry.as_ref() {
                Some(c) => {
                    let n = content_length.min(c.data().len());
                    &c.data()[..n]
                }
                None => &[],
            };
            let body = if content_length > 0 {
                BodyReader::new(Some(&mut source), prebuf, content_length)
            } else {
                BodyReader::new(None, &[], 0)
            };
            let mut request = Request::new(&req, body);
            let mut res = Response::with_sink(&mut sink);
            let __h0 = now_cycles();
            let r = (*handler)(&mut request, &mut res).await;
            crate::diag::COUNTERS
                .handler_cycles
                .add(now_cycles().wrapping_sub(__h0));
            if r.is_err() {
                crate::diag::COUNTERS.send_failed.bump();
                return; // `cell` drops → `stream` freed → FIN
            }
            if res.is_streamed() {
                // The handler streamed: head + body already went out
                // over the sink (close-delimited). Finish the body; the
                // conn closes after — no keep-alive, no body drain (the
                // close discards anything the handler left unread).
                if res.finish().await.is_err() {
                    crate::diag::COUNTERS.send_failed.bump();
                    return;
                }
                streamed = true;
                buffered = None;
                body_leftover = None;
            } else {
                // The handler buffered: drain any request body it left
                // unread (keep-alive contract), capture any straddle
                // residue, then take the buffered parts out before the
                // cell (and its `&mut stream` borrow) drops.
                let mut body = request.into_body();
                let drained_ok =
                    want_close || body.is_empty() || body.discard().await.is_ok();
                if !drained_ok {
                    crate::diag::COUNTERS.body_drain_failed.bump();
                    return;
                }
                body_leftover = if content_length > 0 {
                    body.into_leftover()
                } else {
                    None
                };
                streamed = false;
                buffered = Some(res.into_parts());
            }
        } // `cell` / `source` / `sink` dropped → `stream` free again

        if streamed {
            crate::diag::COUNTERS.responses_sent.bump();
            let _ = stream.close().await; // streamed = close-delimited
            return;
        }

        // Buffered response: borrowed-storage head (zero-alloc) + the
        // body parts, then keep-alive or close.
        //
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
        let (status, content_type, body, extra) =
            buffered.expect("buffered set when !streamed");
        let mut header = unsafe {
            IOBuf::borrow(
                core::ptr::NonNull::new_unchecked(header_storage.as_mut_ptr()),
                HEADER_BUF_SIZE as u32,
                0,
                0,
            )
        };
        let __b0 = now_cycles();
        let mut hdrs: [(&[u8], &[u8]); MAX_EXTRA_HEADERS] =
            [(&[][..], &[][..]); MAX_EXTRA_HEADERS];
        let mut nh = 0;
        for (name, value) in extra.iter().flatten() {
            hdrs[nh] = (name.data(), value.data());
            nh += 1;
        }
        write_response_head_parts(
            &mut header,
            status,
            content_type.data(),
            &hdrs[..nh],
            body.total_len(),
            !want_close,
        );
        out_chain.clear();
        out_chain.push_back(header);
        for part in body.into_parts() {
            out_chain.push_back(part);
        }
        crate::diag::COUNTERS
            .build_cycles
            .add(now_cycles().wrapping_sub(__b0));

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

        // Advance `carry` past the body bytes that were just served.
        // GET fast path (CL=0): no bytes to advance past — `carry`
        // already points at the next pipelined request's HEAD bytes
        // (if any), so leave it untouched. Skipping the function
        // call + Option dance is the hot-path saving the bench
        // wanted back.
        if content_length > 0
            && let Some(c) = carry.take()
        {
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
    // `for<'a, 'b> AsyncFn(&'a Request, &'a mut BodyReader<'b>)`).
    // Each test resets the cell before driving serve_conn.
    type ObservedReq = (Method, Vec<u8>, Vec<u8>);

    thread_local! {
        static OBSERVED: RefCell<Vec<ObservedReq>> = const { RefCell::new(Vec::new()) };
    }

    async fn observe_handler(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
        let mut body_bytes = Vec::new();
        while let Some(guard) = req.read_chunk().await {
            body_bytes.extend_from_slice(guard.data());
        }
        OBSERVED.with(|o| {
            o.borrow_mut()
                .push((req.method(), req.path().to_vec(), body_bytes))
        });
        *res = Response::ok(b"text/plain".as_slice(), b"OK".as_slice());
        Ok(())
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

    /// **Keep-alive reuse with a body on BOTH requests.** Every other
    /// test above pairs a bodied request with a body-less GET, so none
    /// exercised a second request that actually declares a
    /// `Content-Length`. That gap hid the `Request::clear()` per-slot
    /// reset bug: the streaming parser appends header bytes
    /// (`name_len += take`) and relied on the slots starting at 0, but
    /// `clear()` only reset `header_count`. So the second POST reused
    /// request 1's stale slot lengths, corrupted its header names,
    /// `Content-Length` parsed as 0, its body was left unconsumed, and
    /// the next HEAD parse choked on the body bytes — wedging
    /// keep-alive uploads. Two separate chunks (non-pipelined, like the
    /// real upload bench): each request must be parsed fresh and its
    /// body delivered in full.
    #[test]
    fn keepalive_second_bodied_request_body_not_dropped() {
        let req = b"POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let (sent, observed) = drive(alloc::vec![Some(req.to_vec()), Some(req.to_vec()), None]);
        assert_eq!(count_ok(&sent), 2, "both keep-alive POSTs must get a 200");
        assert_eq!(observed.len(), 2, "handler must run for both requests");
        assert_eq!(observed[0].2, b"hello", "request 1 body");
        assert_eq!(
            observed[1].2, b"hello",
            "request 2 body must not be dropped (stale-slot Content-Length=0 regression)",
        );
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Drive `serve_conn` with an arbitrary handler over the pre-canned
    /// MockStream and return the bytes it sent. Same harness as `drive`,
    /// but the handler isn't pinned to `observe_handler` — so the
    /// streamed (`res.write`) paths can be exercised too.
    fn drive_handler<H>(handler: H, chunks_vec: Vec<Option<Vec<u8>>>) -> Vec<u8>
    where
        H: for<'a, 'b, 'c> AsyncFn(&'a mut Request<'b>, &'a mut Response<'c>) -> Result<(), ()>,
    {
        let chunks = Rc::new(RefCell::new(VecDeque::from(chunks_vec)));
        let sent = Rc::new(RefCell::new(Vec::new()));
        let mock = MockStream {
            chunks,
            sent: Rc::clone(&sent),
        };
        block_on(serve_conn(Arc::new(handler), mock));
        Rc::try_unwrap(sent).ok().unwrap().into_inner()
    }

    /// App-written streaming echo: read each request-body chunk and write
    /// it straight back out. On h1 `read_chunk` and `write` share the
    /// connection via the serve loop's `RefCell` duplex.
    async fn echo_handler(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
        res.content_type(b"application/octet-stream".as_slice());
        while let Some(chunk) = req.read_chunk().await {
            res.write(chunk.data()).await?;
        }
        res.finish().await
    }

    /// Generated streamed body — `res.write` with no request read.
    async fn generated_handler(_req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
        res.content_type(b"text/plain".as_slice());
        res.write(b"chunk-one;").await?;
        res.write(b"chunk-two").await?;
        res.finish().await
    }

    /// **Duplex echo, body past the prebuf.** HEAD in chunk 1 (no
    /// trailing body), body in chunk 2 — so the body read flows through
    /// `CellSource` (`recv_chunk` under a `borrow_mut` held across the
    /// await), and `res.write` flows through `CellSink`, both on the same
    /// per-conn `RefCell`. A borrow-discipline regression (e.g. a read
    /// guard that held the cell across the following write) would panic
    /// here at runtime — this is the deterministic guard the live
    /// (HVF/GCE) echo tests can't be in CI.
    #[test]
    fn duplex_echo_streams_body_back_over_cell() {
        let head = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\n".to_vec();
        let body = b"ECHOBACK".to_vec();
        let sent = drive_handler(echo_handler, alloc::vec![Some(head), Some(body), None]);
        assert!(
            sent.starts_with(b"HTTP/1.1 200"),
            "streamed head, got {:?}",
            &sent[..sent.len().min(24)],
        );
        assert!(contains(&sent, b"Connection: close"), "streamed = close-delimited");
        assert!(!contains(&sent, b"Content-Length"), "streamed head carries no Content-Length");
        assert!(sent.ends_with(b"ECHOBACK"), "echoed body follows the head");
    }

    /// **Duplex echo, body riding in the HEAD chunk.** HEAD + body in one
    /// chunk — the body read comes from the prebuf (`carry`), whose guard
    /// borrows the parse buffer, *not* the cell, so it can be held across
    /// the `res.write` that borrows the cell. Guards the guard/cell
    /// disjointness.
    #[test]
    fn duplex_echo_body_in_head_chunk() {
        let raw = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO".to_vec();
        let sent = drive_handler(echo_handler, alloc::vec![Some(raw), None]);
        assert!(sent.starts_with(b"HTTP/1.1 200"));
        assert!(contains(&sent, b"Connection: close"));
        assert!(sent.ends_with(b"HELLO"), "echoed body follows the head");
    }

    /// **Generated bodyless streaming.** A GET handler that streams two
    /// chunks via `res.write` then `finish` — exercises `CellSink`
    /// (`send_head` + `write_chunk` + `finish`) and the streamed→close
    /// branch on the bodyless path.
    #[test]
    fn generated_bodyless_streaming_close_delimited() {
        let head = b"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let sent = drive_handler(generated_handler, alloc::vec![Some(head), None]);
        assert!(sent.starts_with(b"HTTP/1.1 200"));
        assert!(contains(&sent, b"Connection: close"));
        assert!(!contains(&sent, b"Content-Length"));
        assert!(
            sent.ends_with(b"chunk-one;chunk-two"),
            "both streamed chunks land in order",
        );
    }
}
