// crates/proto/http2/src/connect.rs — the client-side TLS stream.
//
// The outbound mirror of `listen.rs`: where `listen` wraps an accepted
// `TcpStream` in a server-role `TlsStream`, `tls_client_handshake`
// wraps a *connected* stream in a client-role [`TlsClientStream`] —
// pumping the sans-io `tls::client::TlsClient` over the transport the
// same way the server-side adapter pumps `TlsServer`. Both expose
// `http::HttpStream`, so the same `http::serve_conn` machinery on the
// server and `http::client::http1_fetch` on the client run over plain
// TCP and TLS unchanged.
//
// This crate is the home for the same reason `listen.rs` lives here:
// "h2" is HTTP-over-TLS/TCP, so the TLS↔TCP↔HttpStream adapters (both
// roles) belong to this layer — `proto/tls` stays sans-io and
// `proto/http` stays TLS-unaware. The h2 *client* (client arc D) will
// build on this same stream.
//
// Unlike the server-side `TlsStream` (hardwired to the reactor's
// `TcpStream` for its TSO direct-encrypt fast path), the client stream
// is generic over any inner `HttpStream`. Client sends are small
// requests — the TSO path would buy nothing — and the generality is
// what lets the loopback test below drive the REAL client stream
// against the REAL `TlsServer` + `http::serve_conn` fully in-process
// (the deterministic-simulation arc leans on the same property).

use alloc::boxed::Box;
use alloc::vec::Vec;

use http::{HttpStream, IOBuf, IOBufChain};
use tls::client::{ClientHandshakeError, ServerAuth, TlsClient, TlsClientConfig};

use crate::listen::TLS_RECORD_LEN;

/// ALPN offer for an HTTP/1.1-only client connection. Pass as
/// `TlsClientConfig::alpn` (or offer none for protocol-less TLS).
pub const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// Why a client TLS connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsClientError {
    /// The TLS state machine rejected the server (pin mismatch, bad
    /// CertificateVerify, malformed flight, …).
    Tls(ClientHandshakeError),
    /// The transport failed (send error, or EOF mid-handshake).
    Transport,
}

/// Client-side HTTPS `HttpStream`: owns the inner byte stream + the
/// sans-io [`TlsClient`] and drives the TLS state machine — the
/// client-role mirror of `listen.rs`'s `TlsStream`. `recv_chunk`
/// surfaces decrypted plaintext records; `send` seals via
/// `seal_app_data` and ships ciphertext on the inner stream.
pub struct TlsClientStream<S: HttpStream> {
    inner: S,
    tls: Box<TlsClient>,
    /// The (small) static config `process_chunk` revalidates against.
    config: TlsClientConfig,
    /// Stack-friendly scratch for draining `pop_tx` output — same
    /// shape as the server stream's.
    tx_scratch: [u8; 2048],
    /// Lazily-allocated per-conn scratch one sealed record is built
    /// in before shipping. Owned by `&mut self` across the inner
    /// `send.await`, so the borrowed IOBuf wrapping it can't alias
    /// another task's bytes (same argument as the server stream's
    /// `record_scratch`).
    record_scratch: Option<Box<[u8]>>,
}

/// Open a client TLS 1.3 connection over an already-connected byte
/// stream: emit the ClientHello, pump the handshake to completion,
/// and return the established [`TlsClientStream`]. The caller owns
/// deadline policy (wrap in `timeout_us`, like `tcp_connect`).
///
/// `seed` is the connection's entropy, by value (32 bytes from
/// `waitless::rng::fill_bytes`, or a fixed seed in deterministic
/// simulation). `config` carries the [`ServerAuth`] mode (SPKI pin,
/// or the loudly-named `InsecureSkipVerify`), optional SNI, and the
/// ALPN offer ([`ALPN_HTTP11`] for an h1 client).
pub async fn tls_client_handshake<S: HttpStream>(
    inner: S,
    seed: [u8; 32],
    config: TlsClientConfig,
) -> Result<TlsClientStream<S>, TlsClientError> {
    let tls = TlsClient::new_box(seed, &config).map_err(TlsClientError::Tls)?;
    let mut stream = TlsClientStream {
        inner,
        tls,
        config,
        tx_scratch: [0u8; 2048],
        record_scratch: None,
    };
    loop {
        // Ship whatever the state machine queued (the ClientHello on
        // iteration 0; CCS + Finished — or a fatal alert — later).
        stream
            .drain_tx()
            .await
            .map_err(|_| TlsClientError::Transport)?;
        if stream.tls.is_established() {
            return Ok(stream);
        }
        if stream.tls.is_terminated() {
            return Err(stream
                .tls
                .error()
                .map(TlsClientError::Tls)
                .unwrap_or(TlsClientError::Transport));
        }
        let Some(guard) = stream.inner.recv_chunk().await else {
            return Err(TlsClientError::Transport);
        };
        let chunk = guard.into_owned();
        if let Err(e) = stream.tls.process_chunk(chunk, &stream.config) {
            // Best-effort: flush the fatal alert before reporting.
            let _ = stream.drain_tx().await;
            return Err(TlsClientError::Tls(e));
        }
    }
}

impl<S: HttpStream> TlsClientStream<S> {
    /// The ALPN protocol the server selected (validated against our
    /// offer during the handshake); `None` if none was negotiated.
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.tls.negotiated_alpn()
    }

    /// Drain pending TLS TX bytes (handshake flight, alerts) to the
    /// inner stream. `Err(())` is fatal.
    async fn drain_tx(&mut self) -> Result<(), ()> {
        loop {
            let n = self.tls.pop_tx(&mut self.tx_scratch);
            if n == 0 {
                return Ok(());
            }
            let mut ship = IOBufChain::new();
            let mut buf: Vec<u8> = Vec::new();
            if buf.try_reserve_exact(n).is_err() {
                return Err(());
            }
            buf.extend_from_slice(&self.tx_scratch[..n]);
            ship.push_back(IOBuf::from(buf));
            self.inner.send(&mut ship).await?;
        }
    }

    /// One sans-io RX pump cycle — the client mirror of the server
    /// stream's `pump_rx`: flush pending TX (ordering), take one
    /// inner chunk, run it through the state machine (in-place
    /// decrypt; app-data records queue as refcount-shared views),
    /// flush whatever it produced.
    async fn pump_rx(&mut self) -> Result<(), ()> {
        self.drain_tx().await?;
        {
            let Some(guard) = self.inner.recv_chunk().await else {
                return Err(());
            };
            let chunk = guard.into_owned();
            if self.tls.process_chunk(chunk, &self.config).is_err() {
                // Flush the fatal alert; the conn is dead either way.
                let _ = self.drain_tx().await;
                return Err(());
            }
        }
        self.drain_tx().await
    }

    /// Encrypt and ship one TLS 1.3 application_data record (up to
    /// 16 KiB of plaintext consumed off the front of `src`; multi-
    /// record sends loop in `send`). Seals into the lazily-allocated
    /// per-conn scratch and ships via the inner stream — the client
    /// has no TSO direct-encrypt path (requests are small; the inner
    /// stream is generic).
    async fn send_one_record(&mut self, src: &mut IOBufChain) -> Result<(), ()> {
        if src.is_empty() {
            return Ok(());
        }
        // Destructure into disjoint field borrows: scratch for the
        // seal, inner for the send.
        let Self {
            inner,
            tls,
            record_scratch,
            ..
        } = self;
        if record_scratch.is_none() {
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(TLS_RECORD_LEN).is_err() {
                return Err(());
            }
            v.resize(TLS_RECORD_LEN, 0);
            *record_scratch = Some(v.into_boxed_slice());
        }
        let scratch = record_scratch.as_mut().expect("just-ensured Some");
        let n = tls.seal_app_data(src, &mut scratch[..]).map_err(|_| ())?;
        // SAFETY: `scratch` is owned by `self` and stays alive across
        // the `inner.send.await` (we hold `&mut self` for the whole
        // call); it is per-conn private, so no other task can alias
        // these bytes. The wrapping IOBuf drops at function exit,
        // ending the raw-pointer borrow. Same contract as the server
        // stream's `send_one_record` fallback path.
        let mut ship = IOBufChain::new();
        let ptr = unsafe { core::ptr::NonNull::new_unchecked(scratch.as_mut_ptr()) };
        ship.push_back(unsafe { IOBuf::borrow(ptr, TLS_RECORD_LEN as u32, 0, n as u32) });
        inner.send(&mut ship).await
    }
}

impl<S: HttpStream> HttpStream for TlsClientStream<S> {
    /// Resolve one decrypted plaintext record as a guard (zero copy —
    /// an `Owned` view sharing the recv'd chunk's storage, or a heap
    /// copy for the rare record straddling chunks). `None` on peer
    /// close (close_notify or transport EOF) or any fatal TLS error.
    async fn recv_chunk(&mut self) -> Option<iobuf::RecvChunkGuard<'_>> {
        while !self.tls.has_plaintext() {
            // Closed/Failed with nothing queued ⇒ end of stream. The
            // check sits BEFORE the pump so a close_notify processed
            // by an earlier pump surfaces as a clean `None` instead
            // of an await on a dead transport.
            if self.tls.is_terminated() {
                return None;
            }
            if self.pump_rx().await.is_err() {
                return None;
            }
        }
        let iobuf = self.tls.pop_plaintext()?;
        Some(iobuf::RecvChunkGuard::new(iobuf))
    }

    async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
        // Preserve wire ordering: anything the state machine queued
        // (post-handshake straggler, alert) goes first.
        self.drain_tx().await?;
        while !chain.is_empty() {
            self.send_one_record(chain).await?;
        }
        Ok(())
    }

    async fn close(&mut self) -> Result<(), ()> {
        let _ = self.tls.close_notify();
        self.drain_tx().await
    }
}

// ============================================================================
// https_get — the one-shot convenience getter
// ============================================================================

/// Failure stage of [`https_get`], mirroring `http::client::GetError`
/// with the extra TLS stage.
#[derive(Debug)]
pub enum HttpsGetError {
    /// TCP connect failed.
    Connect(waitless::runtime::TcpConnectError),
    /// TLS handshake failed.
    Tls(TlsClientError),
    /// Request/response exchange failed.
    Fetch(http::client::FetchError),
    /// Body read failed.
    Body(http::client::BodyError),
}

/// One-shot HTTPS/1.1 GET: connect, TLS-handshake (auth per `auth` —
/// SPKI pin or the loud `InsecureSkipVerify`), fetch, read the body
/// into a bounded `Vec` (≤ `body_cap`), `Connection: close`.
///
/// v1 scope (matches `http::client::http_get`): no URL parsing, no
/// redirects, no connection reuse. `host` feeds the `Host` header
/// only — no SNI is offered (`TlsClientConfig::server_name` wants
/// `&'static` bytes; callers that need SNI run the layered API:
/// `tcp_connect` → [`tls_client_handshake`] with their own config →
/// `http1_fetch`). The caller owns the deadline (`timeout_us`).
pub async fn https_get(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    auth: ServerAuth,
    seed: [u8; 32],
    body_cap: usize,
) -> Result<(http::client::ResponseHead, Vec<u8>), HttpsGetError> {
    let tcp = waitless::tcp_connect(ip, port)
        .await
        .map_err(HttpsGetError::Connect)?;
    let config = TlsClientConfig {
        auth,
        server_name: None,
        alpn: ALPN_HTTP11,
    };
    let mut stream = tls_client_handshake(tcp, seed, config)
        .await
        .map_err(HttpsGetError::Tls)?;
    let mut req = http::client::FetchRequest::get(host, path);
    req.close = true;
    let (head, mut body) = http::client::http1_fetch(&mut stream, &req)
        .await
        .map_err(HttpsGetError::Fetch)?;
    let bytes = body
        .read_to_vec(body_cap)
        .await
        .map_err(HttpsGetError::Body)?;
    // Best-effort clean close (close_notify) — the server keeps its
    // resumption state happy; failure is irrelevant post-body.
    let _ = stream.close().await;
    Ok((head, bytes))
}

// ============================================================================
// Tests — THE loopback: real client stream vs real TlsServer + serve_conn
// ============================================================================

/// In-process h1-over-TLS loopback. The FULL paths on both sides:
///
///   client: `tls_client_handshake` → `TlsClientStream` →
///           `http::client::http1_fetch` → `ClientBodyReader`
///   server: `TlsServer` (the real sans-io server) pumped by a
///           pipe-backed `HttpStream` adapter (the test-local stand-in
///           for `listen.rs`'s TcpStream-bound `TlsStream`) →
///           **the real `http::serve_conn`** + a real handler.
///
/// The two sides talk through an in-memory byte-queue pipe and are
/// driven by a deterministic alternating poller. `executor::init(1)`
/// runs once so `serve_conn`'s `timeout_us` (which schedules a real
/// timer when the pipe pends) has an initialized wheel; LOOPBACK_GATE
/// serialises the tests because every test thread reads as worker 0.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::sync::Arc;
    use core::cell::RefCell;
    use core::future::Future;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use http::client::{FetchRequest, http1_fetch};
    use http::{Request, Response};
    use iobuf::RecvChunkGuard;
    use std::sync::{Mutex, OnceLock};
    use tls::client::spki_pin_from_cert_der;
    use tls::server::TlsServer;
    use tls::TlsServerConfig;

    // The dev cert the webserver + the tls crate's own loopback use.
    const CERT: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_cert.der");
    const KEY: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_key.der");

    /// One-time runtime init + per-test serialisation. All test
    /// threads read `current_worker() == 0`, so concurrent loopbacks
    /// would race on worker 0's timer wheel; the Mutex prevents it.
    fn loopback_gate() -> std::sync::MutexGuard<'static, ()> {
        static GATE: OnceLock<Mutex<()>> = OnceLock::new();
        let gate = GATE.get_or_init(|| {
            executor::init(1);
            Mutex::new(())
        });
        gate.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ---- In-memory pipe -----------------------------------------------------

    type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

    /// One direction of the duplex: `recv_chunk` pends until the peer
    /// pushed bytes; `send` flattens the chain into one queue entry.
    struct PipeStream {
        rx: Queue,
        tx: Queue,
    }

    impl HttpStream for PipeStream {
        async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>> {
            let rx = Rc::clone(&self.rx);
            let bytes = core::future::poll_fn(move |_| match rx.borrow_mut().pop_front() {
                Some(v) => Poll::Ready(v),
                None => Poll::Pending,
            })
            .await;
            Some(RecvChunkGuard::new(IOBuf::from(bytes)))
        }
        async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
            let mut flat = Vec::new();
            while let Some(part) = chain.pop_front() {
                flat.extend_from_slice(part.data());
            }
            if !flat.is_empty() {
                self.tx.borrow_mut().push_back(flat);
            }
            Ok(())
        }
    }

    fn pipe_pair() -> (PipeStream, PipeStream) {
        let c2s: Queue = Rc::new(RefCell::new(VecDeque::new()));
        let s2c: Queue = Rc::new(RefCell::new(VecDeque::new()));
        (
            PipeStream {
                rx: Rc::clone(&s2c),
                tx: Rc::clone(&c2s),
            },
            PipeStream { rx: c2s, tx: s2c },
        )
    }

    // ---- Server-side TLS adapter over the pipe ------------------------------
    //
    // The pipe-backed analogue of `listen.rs`'s `TlsStream` (which is
    // hardwired to the reactor TcpStream): same pump structure, same
    // real `TlsServer`, driven by the REAL `http::serve_conn`.

    struct ServerTlsPipe {
        pipe: PipeStream,
        tls: Box<TlsServer>,
        cfg: TlsServerConfig,
        tx_scratch: [u8; 2048],
        record_scratch: Box<[u8]>,
    }

    impl ServerTlsPipe {
        fn new(pipe: PipeStream, seed: [u8; 32]) -> Self {
            ServerTlsPipe {
                pipe,
                tls: TlsServer::new_box(seed),
                cfg: TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert"),
                tx_scratch: [0u8; 2048],
                record_scratch: alloc::vec![0u8; TLS_RECORD_LEN].into_boxed_slice(),
            }
        }

        async fn drain_tx(&mut self) -> Result<(), ()> {
            loop {
                let n = self.tls.pop_tx(&mut self.tx_scratch);
                if n == 0 {
                    return Ok(());
                }
                let mut ship = IOBufChain::new();
                ship.push_back(IOBuf::from(self.tx_scratch[..n].to_vec()));
                self.pipe.send(&mut ship).await?;
            }
        }

        async fn pump_rx(&mut self) -> Result<(), ()> {
            self.drain_tx().await?;
            {
                let Some(guard) = self.pipe.recv_chunk().await else {
                    return Err(());
                };
                let chunk = guard.into_owned();
                self.tls.process_chunk(chunk, &self.cfg).map_err(|_| ())?;
            }
            self.drain_tx().await
        }
    }

    impl HttpStream for ServerTlsPipe {
        async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>> {
            while !self.tls.has_plaintext() {
                if self.tls.is_terminated() {
                    return None;
                }
                if self.pump_rx().await.is_err() {
                    return None;
                }
            }
            let iobuf = self.tls.pop_plaintext()?;
            Some(RecvChunkGuard::new(iobuf))
        }
        async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
            self.drain_tx().await?;
            while !chain.is_empty() {
                let n = self
                    .tls
                    .seal_app_data(chain, &mut self.record_scratch[..])
                    .map_err(|_| ())?;
                let mut ship = IOBufChain::new();
                ship.push_back(IOBuf::from(self.record_scratch[..n].to_vec()));
                self.pipe.send(&mut ship).await?;
            }
            Ok(())
        }
        async fn close(&mut self) -> Result<(), ()> {
            let _ = self.tls.close_notify();
            self.drain_tx().await
        }
    }

    // ---- Deterministic alternating driver ------------------------------------

    fn noop_waker() -> Waker {
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
    }

    /// Poll the client and server futures alternately until the client
    /// completes (the server side may legitimately still be parked
    /// waiting for a next request — it is dropped then). Bounded.
    fn run_loopback<C, T, V>(client: C, server: T) -> V
    where
        C: Future<Output = V>,
        T: Future<Output = ()>,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut client = core::pin::pin!(client);
        let mut server = core::pin::pin!(server);
        let mut server_done = false;
        for _ in 0..10_000 {
            if let Poll::Ready(v) = client.as_mut().poll(&mut cx) {
                return v;
            }
            if !server_done && server.as_mut().poll(&mut cx).is_ready() {
                server_done = true;
            }
        }
        panic!("loopback made no progress within the iteration budget");
    }

    // ---- Handlers -------------------------------------------------------------

    const HELLO_BODY: &[u8] = b"hello from the real serve_conn over TLS";

    async fn handler(req: &mut Request<'_>, res: &mut Response<'_>) -> Result<(), ()> {
        match req.path() {
            b"/hello" => {
                res.set(Response::ok(b"text/plain".as_slice(), HELLO_BODY));
                Ok(())
            }
            b"/streamed" => {
                // Streamed (close-delimited) response — exercises the
                // client's ReadToEof framing end to end.
                res.content_type(b"text/plain".as_slice());
                res.write(b"part-one;").await?;
                res.write(b"part-two").await?;
                res.finish().await
            }
            _ => {
                res.set(Response::not_found());
                Ok(())
            }
        }
    }

    fn pinned_config() -> TlsClientConfig {
        TlsClientConfig {
            auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
            server_name: Some(b"localhost"),
            alpn: ALPN_HTTP11,
        }
    }

    // ---- THE loopback ----------------------------------------------------------

    /// Full h1-over-TLS exchange, in process, all-real both sides:
    /// pinned handshake → http/1.1 ALPN → GET → buffered 200 with
    /// Content-Length → byte-exact body.
    #[test]
    fn loopback_pinned_get_against_real_serve_conn() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let client = async move {
            let mut stream = tls_client_handshake(client_pipe, [0x11; 32], pinned_config())
                .await
                .expect("client handshake");
            assert_eq!(stream.negotiated_alpn(), Some(&b"http/1.1"[..]));
            let req = FetchRequest::get(b"loopback.test", b"/hello");
            let (head, mut body) = http1_fetch(&mut stream, &req).await.expect("fetch");
            assert_eq!(head.status, 200);
            assert_eq!(head.content_length(), Some(HELLO_BODY.len()));
            assert!(!head.connection_close(), "keep-alive response");
            body.read_to_vec(4096).await.expect("body")
        };
        let server = async move {
            let stream = ServerTlsPipe::new(server_pipe, [0x22; 32]);
            http::serve_conn(Arc::new(handler), stream).await;
        };

        let body = run_loopback(client, server);
        assert_eq!(body, HELLO_BODY, "byte-exact across TLS + h1 framing");
    }

    /// Streamed (close-delimited) response: serve_conn's streaming
    /// sink path → `Connection: close`, no Content-Length → the
    /// client's ReadToEof framing terminates on the server's
    /// close_notify.
    #[test]
    fn loopback_streamed_close_delimited_body() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let client = async move {
            let mut stream = tls_client_handshake(client_pipe, [0x33; 32], pinned_config())
                .await
                .expect("client handshake");
            let req = FetchRequest::get(b"loopback.test", b"/streamed");
            let (head, mut body) = http1_fetch(&mut stream, &req).await.expect("fetch");
            assert_eq!(head.status, 200);
            assert_eq!(head.content_length(), None, "streamed head has no CL");
            assert!(head.connection_close(), "streamed = close-delimited");
            body.read_to_vec(4096).await.expect("body")
        };
        let server = async move {
            let stream = ServerTlsPipe::new(server_pipe, [0x44; 32]);
            http::serve_conn(Arc::new(handler), stream).await;
        };

        let body = run_loopback(client, server);
        assert_eq!(body, b"part-one;part-two");
    }

    /// Wrong pin: the handshake must fail with the TLS stage error
    /// (and the server side simply never dispatches a request).
    #[test]
    fn loopback_wrong_pin_fails_at_tls_stage() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let client = async move {
            let cfg = TlsClientConfig {
                auth: ServerAuth::PinnedSpki([0u8; 32]),
                server_name: None,
                alpn: ALPN_HTTP11,
            };
            tls_client_handshake(client_pipe, [0x55; 32], cfg)
                .await
                .err()
                .expect("wrong pin must fail")
        };
        let server = async move {
            let stream = ServerTlsPipe::new(server_pipe, [0x66; 32]);
            http::serve_conn(Arc::new(handler), stream).await;
        };

        let err = run_loopback(client, server);
        assert_eq!(
            err,
            TlsClientError::Tls(ClientHandshakeError::PinMismatch),
            "failure surfaces at the TLS stage with the pin error",
        );
    }

    /// A keep-alive second request on the SAME TlsClientStream — the
    /// stream survives a full fetch and the server's serve_conn loops.
    #[test]
    fn loopback_two_sequential_fetches_on_one_conn() {
        let _g = loopback_gate();
        let (client_pipe, server_pipe) = pipe_pair();

        let client = async move {
            let mut stream = tls_client_handshake(client_pipe, [0x77; 32], pinned_config())
                .await
                .expect("client handshake");
            for _ in 0..2 {
                let req = FetchRequest::get(b"loopback.test", b"/hello");
                let (head, mut body) = http1_fetch(&mut stream, &req).await.expect("fetch");
                assert_eq!(head.status, 200);
                let bytes = body.read_to_vec(4096).await.expect("body");
                assert_eq!(bytes, HELLO_BODY);
            }
        };
        let server = async move {
            let stream = ServerTlsPipe::new(server_pipe, [0x88; 32]);
            http::serve_conn(Arc::new(handler), stream).await;
        };

        run_loopback(client, server);
    }
}
