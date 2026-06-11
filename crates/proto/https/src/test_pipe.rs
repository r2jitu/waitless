// crates/proto/https/src/test_pipe.rs — the in-memory TLS loopback
// harness, shared across crates' tests.
//
// The pieces every client-vs-server TLS loopback needs: a duplex
// byte-queue pipe, a server-side TLS adapter over it (the pipe-backed
// stand-in for `http2::listen`'s TcpStream-bound `TlsStream`), a noop
// waker for deterministic alternating polling, the one-time
// runtime-init gate, and the pinned-against-the-dev-cert client
// config. This crate's own h1 loopbacks (`client.rs`) and `http2`'s
// h2 client loopbacks drive the same harness — same pattern,
// different ALPN.
//
// `#[doc(hidden)]` + compiled only off-VM (`not(target_os = "none")`):
// cross-crate test support can't be `#[cfg(test)]` (dependents link
// the non-test rlib), so it rides the same host-only arrangement as
// `quic::sim_clock` — never part of a unikernel image, a dead no-op
// in native builds that don't call it.

extern crate std;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::task::{Poll, RawWaker, RawWakerVTable, Waker};
use std::sync::{Mutex, OnceLock};

use http::{HttpStream, IOBuf, IOBufChain};
use iobuf::RecvChunkGuard;
use tls::TlsServerConfig;
use tls::client::{ServerAuth, TlsClientConfig, spki_pin_from_cert_der};
use tls::server::TlsServer;

use crate::client::TLS_RECORD_LEN;

// The dev cert the webserver + the tls crate's own loopback use.
const CERT: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_cert.der");
const KEY: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_key.der");

/// One-time runtime init + per-test serialisation. All test
/// threads read `current_worker() == 0`, so concurrent loopbacks
/// would race on worker 0's timer wheel; the Mutex prevents it.
pub fn loopback_gate() -> std::sync::MutexGuard<'static, ()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    let gate = GATE.get_or_init(|| {
        // `executor::init` sizes the arenas/wheel but does NOT
        // publish the worker count (boot does, on real targets);
        // `executor::tick(0)` gates on it, and the h2 loopback
        // ticks the arena to drive spawned per-stream handlers.
        worker::set_num_workers(1);
        executor::init(1);
        Mutex::new(())
    });
    gate.lock().unwrap_or_else(|p| p.into_inner())
}

// ---- In-memory pipe -----------------------------------------------------

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// One direction of the duplex: `recv_chunk` pends until the peer
/// pushed bytes; `send` flattens the chain into one queue entry.
pub struct PipeStream {
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

pub fn pipe_pair() -> (PipeStream, PipeStream) {
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
// The pipe-backed analogue of `http2::listen`'s `TlsStream` (which is
// hardwired to the reactor TcpStream): same pump structure, same
// real `TlsServer`, driven by the REAL `http::serve_conn` /
// `http2::serve_conn`.

pub struct ServerTlsPipe {
    pipe: PipeStream,
    tls: Box<TlsServer>,
    cfg: TlsServerConfig,
    tx_scratch: [u8; 2048],
    record_scratch: Box<[u8]>,
}

impl ServerTlsPipe {
    pub fn new(pipe: PipeStream, seed: [u8; 32]) -> Self {
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

    /// Pump the handshake to completion and return the negotiated
    /// ALPN — the pipe analogue of `TlsStream::drive_handshake`.
    /// The h2 loopback needs it because `http2::serve_conn` WRITES
    /// first (its SETTINGS), which requires an established conn;
    /// `http::serve_conn` reads first, so the h1 loopbacks get the
    /// handshake driven implicitly by `recv_chunk`.
    pub async fn drive_handshake(&mut self) -> Result<tls::server::AlpnProtocol, ()> {
        loop {
            if self.tls.is_established() {
                return Ok(self.tls.negotiated_alpn());
            }
            if self.tls.is_terminated() {
                return Err(());
            }
            self.pump_rx().await?;
        }
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

// ---- Deterministic-poll waker ---------------------------------------------

pub fn noop_waker() -> Waker {
    fn noop(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

// ---- Client config --------------------------------------------------------

/// Pinned-against-the-dev-cert client config with the given ALPN
/// offer — the h1 loopbacks (`client.rs`) pass
/// [`crate::client::ALPN_HTTP11`], the h2 client loopbacks (`http2`'s
/// `client.rs`) pass [`crate::client::ALPN_H2`].
pub fn pinned_config_alpn(alpn: &'static [&'static [u8]]) -> TlsClientConfig {
    TlsClientConfig {
        auth: ServerAuth::PinnedSpki(spki_pin_from_cert_der(CERT).expect("pin")),
        server_name: Some(b"localhost"),
        alpn,
    }
}
