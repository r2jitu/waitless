// crates/proto/https/src/client.rs — the client-side HTTPS layer.
//
// The outbound mirror of `serve`: where the facade's server half
// composes the per-transport listeners behind one call, this half owns
// what an HTTPS *client* needs — the client-role TLS stream and the
// one-shot getters ([`get`], ALPN-negotiated h2 with h1.1 fallback,
// and [`get_h1`], pinned to http/1.1).
//
// Naming convention (repo-wide, every `<crate>::client` — the crate
// path carries the protocol, the function name is the bare verb):
//   `get`     = ONE-SHOT: connect + TLS + request + bounded body read.
//   `fetch`   = one request over an ALREADY-ESTABLISHED conn/stream.
//   `connect` = establish only (here, [`handshake`] — TLS over an
//               already-connected byte stream).
//
// [`handshake`] mirrors `http2::listen`'s accept path: where `listen`
// wraps an accepted `TcpStream` in a server-role `TlsStream`,
// it wraps a *connected* stream in a client-role [`TlsClientStream`] —
// pumping the sans-io `tls::client::TlsClient` over the transport the
// same way the server-side adapter pumps `TlsServer`. Both expose
// `http::HttpStream`, so the same `http::serve_conn` machinery on the
// server and `http::client::fetch` on the client run over plain
// TCP and TLS unchanged.
//
// This crate is the home for the same reason `serve` lives here:
// "HTTPS = TLS + ALPN dispatch across HTTP versions" is composition,
// and the composition layer is this crate's job — `proto/tls` stays
// sans-io, `proto/http` stays TLS-unaware, and `proto/http2` keeps
// only the h2 protocol itself (`H2ClientConn`, which [`get`]'s h2 arm
// runs over this stream).
//
// Unlike the server-side `TlsStream` (hardwired to the reactor's
// `TcpStream` for its TSO direct-encrypt fast path), the client stream
// is generic over any inner `HttpStream`. Client sends are small
// requests — the TSO path would buy nothing — and the generality is
// what lets the loopback tests below drive the REAL client stream
// against the REAL `TlsServer` + `http::serve_conn` fully in-process
// (the deterministic-simulation arc leans on the same property).

use alloc::boxed::Box;
use alloc::vec::Vec;

use http::{HttpStream, IOBuf, IOBufChain};
use http2::{H2ClientConn, H2ClientError};
use tls::client::{ClientHandshakeError, ServerAuth, TlsClient, TlsClientConfig};
use tls::record;

/// One sealed TLS 1.3 record: 5 B header + plaintext chunk (one byte
/// under the RFC max, leaving room for the inner content-type byte) +
/// content-type byte + AEAD tag. The same record geometry as the
/// server listener's (`http2`'s `listen.rs` derives the identical
/// value from `tls::record`).
pub(crate) const TLS_RECORD_LEN: usize =
    record::HEADER_LEN + (record::MAX_INNER_PLAINTEXT - 1) + 1 + record::TAG_LEN;

/// ALPN offer for an HTTP/1.1-only client connection. Pass as
/// `TlsClientConfig::alpn` (or offer none for protocol-less TLS).
pub const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// ALPN offer for an h2-capable client connection: prefer "h2", fall
/// back to HTTP/1.1 — the client mirror of the server listener's
/// dispatch. [`get`] branches on what the server picked.
pub const ALPN_H2: &[&[u8]] = &[b"h2", b"http/1.1"];

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
/// client-role mirror of `http2::listen`'s `TlsStream`. `recv_chunk`
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
pub async fn handshake<S: HttpStream>(
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
// get_h1 — the ALPN-pinned (http/1.1) one-shot getter
// ============================================================================

/// Failure stage of [`get_h1`], mirroring `http::client::GetError`
/// with the extra TLS stage.
#[derive(Debug)]
pub enum GetH1Error {
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
/// v1 scope (matches `http::client::get`): no URL parsing, no
/// redirects, no connection reuse. `host` feeds the `Host` header
/// only — no SNI is offered (`TlsClientConfig::server_name` wants
/// `&'static` bytes; callers that need SNI run the layered API:
/// `tcp_connect` → [`handshake`] with their own config →
/// `http::client::fetch`). The caller owns the deadline (`timeout_us`).
pub async fn get_h1(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    auth: ServerAuth,
    seed: [u8; 32],
    body_cap: usize,
) -> Result<(http::client::ResponseHead, Vec<u8>), GetH1Error> {
    let tcp = waitless::tcp_connect(ip, port)
        .await
        .map_err(GetH1Error::Connect)?;
    let config = TlsClientConfig {
        auth,
        server_name: None,
        alpn: ALPN_HTTP11,
    };
    let mut stream = handshake(tcp, seed, config)
        .await
        .map_err(GetH1Error::Tls)?;
    let mut req = http::client::FetchRequest::get(host, path);
    req.close = true;
    let (head, mut body) = http::client::fetch(&mut stream, &req)
        .await
        .map_err(GetH1Error::Fetch)?;
    let bytes = body
        .read_to_vec(body_cap)
        .await
        .map_err(GetH1Error::Body)?;
    // Best-effort clean close (close_notify) — the server keeps its
    // resumption state happy; failure is irrelevant post-body.
    let _ = stream.close().await;
    Ok((head, bytes))
}

// ============================================================================
// get — ALPN-dispatching HTTPS GET (h2 with h1.1 fallback)
// ============================================================================

/// Failure stage of [`get`] — [`GetH1Error`] plus the h2 arm.
#[derive(Debug)]
pub enum GetError {
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

/// One-shot HTTPS GET offering ALPN ["h2", "http/1.1"] and dispatching
/// on what the server selected: h2 → [`H2ClientConn`]; http/1.1 (or no
/// ALPN) → the existing h1 path — the client mirror of `http2::listen`'s
/// serve dispatch. Returns `(status, body)` (the protocol-specific
/// heads differ; callers needing headers use the layered APIs —
/// [`get_h1`] pins ALPN to http/1.1 and returns the typed h1 response
/// head). Same v1 scope as [`get_h1`]: no URL parsing/redirects/SNI,
/// the caller owns the deadline.
pub async fn get(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    auth: ServerAuth,
    seed: [u8; 32],
    body_cap: usize,
) -> Result<(u16, Vec<u8>), GetError> {
    let tcp = waitless::tcp_connect(ip, port)
        .await
        .map_err(GetError::Connect)?;
    let config = TlsClientConfig {
        auth,
        server_name: None,
        alpn: ALPN_H2,
    };
    let mut stream = handshake(tcp, seed, config)
        .await
        .map_err(GetError::Tls)?;
    if stream.negotiated_alpn() == Some(&b"h2"[..]) {
        let mut conn = H2ClientConn::connect(stream)
            .await
            .map_err(GetError::H2)?;
        let req = http::client::FetchRequest::get(host, path);
        let resp = http2::client::fetch(&mut conn, &req, body_cap)
            .await
            .map_err(GetError::H2)?;
        conn.close().await;
        Ok((resp.status, resp.body))
    } else {
        let mut req = http::client::FetchRequest::get(host, path);
        req.close = true;
        let (head, mut body) = http::client::fetch(&mut stream, &req)
            .await
            .map_err(GetError::Fetch)?;
        let bytes = body
            .read_to_vec(body_cap)
            .await
            .map_err(GetError::Body)?;
        let _ = stream.close().await;
        Ok((head.status, bytes))
    }
}

// ============================================================================
// Tests — THE loopback: real client stream vs real TlsServer + serve_conn
// ============================================================================

/// In-process h1-over-TLS loopback. The FULL paths on both sides:
///
///   client: `handshake` → `TlsClientStream` →
///           `http::client::fetch` → `ClientBodyReader`
///   server: `TlsServer` (the real sans-io server) pumped by a
///           pipe-backed `HttpStream` adapter (the harness stand-in
///           for `http2::listen`'s TcpStream-bound `TlsStream`) →
///           **the real `http::serve_conn`** + a real handler.
///
/// The two sides talk through an in-memory byte-queue pipe and are
/// driven by a deterministic alternating poller. `executor::init(1)`
/// runs once so `serve_conn`'s `timeout_us` (which schedules a real
/// timer when the pipe pends) has an initialized wheel; LOOPBACK_GATE
/// serialises the tests because every test thread reads as worker 0.
///
/// The harness pieces (pipe, server-side TLS adapter, gate, configs)
/// live in [`crate::test_pipe`], shared with the h2 client's loopback
/// in `http2`'s `client.rs` — same pattern, h2 ALPN.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::task::{Context, Poll};
    use http::client::{FetchRequest, fetch};
    use http::{Request, Response};

    use crate::test_pipe::{
        ServerTlsPipe, loopback_gate, noop_waker, pinned_config_alpn, pipe_pair,
    };

    // ---- Deterministic alternating driver ------------------------------------

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
        pinned_config_alpn(ALPN_HTTP11)
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
            let mut stream = handshake(client_pipe, [0x11; 32], pinned_config())
                .await
                .expect("client handshake");
            assert_eq!(stream.negotiated_alpn(), Some(&b"http/1.1"[..]));
            let req = FetchRequest::get(b"loopback.test", b"/hello");
            let (head, mut body) = fetch(&mut stream, &req).await.expect("fetch");
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
            let mut stream = handshake(client_pipe, [0x33; 32], pinned_config())
                .await
                .expect("client handshake");
            let req = FetchRequest::get(b"loopback.test", b"/streamed");
            let (head, mut body) = fetch(&mut stream, &req).await.expect("fetch");
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
            handshake(client_pipe, [0x55; 32], cfg)
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
            let mut stream = handshake(client_pipe, [0x77; 32], pinned_config())
                .await
                .expect("client handshake");
            for _ in 0..2 {
                let req = FetchRequest::get(b"loopback.test", b"/hello");
                let (head, mut body) = fetch(&mut stream, &req).await.expect("fetch");
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
