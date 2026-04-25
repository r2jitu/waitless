// uni-tls — TLS 1.3 server for HTTPS over `uni_http`.
//
// Owns the entire server-side TLS-over-TCP layer: the handshake
// state machine (`server::TlsServer` + handlers + keys + profile +
// trace) plus the `uni_http::Tls` impl that the HTTP server uses
// to terminate HTTPS connections.
//
// `//net` provides the lower-level protocol primitives that are
// shared with the future QUIC stack (`net_tls_crypto`,
// `net_tls_handshake`, `net_tls_record`, `net_tls`); this crate
// composes them into the TLS-over-stream server. Apps that don't
// import `uni_tls` link zero TLS / crypto code — the trait
// boundary in `uni_http` keeps the dependency graph clean.
//
// Public surface:
//   * `TlsServerConfig` — cert + key loaded from PKCS#8 DER.
//   * `server(cfg)` — produces a `Box<dyn uni_http::Tls>` ready
//     for `HttpServerBuilder::https`.
//   * `tls_profile_report` / `tls_profile_reset` — handshake
//     timing diagnostics.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

mod server;

pub use server::TlsServerConfig;

// ---- Public constructor for the HTTPS path -----------------------------------

/// Build the TLS provider for `uni_http::HttpServerBuilder::https`.
/// Returns a `Box<dyn uni_http::Tls>` whose `new_connection(seed)`
/// constructs a fresh handshake state machine per accepted HTTPS
/// connection, using the same `cfg` (cert + key + ALPN, etc.).
pub fn server(cfg: TlsServerConfig) -> Box<dyn uni_http::Tls> {
    Box::new(TlsImpl { cfg: Arc::new(cfg) })
}

// ---- Diagnostic helpers ------------------------------------------------------

/// Format the TLS handshake profile into `out`. Apps can serve
/// this as the body of a debug endpoint (`/tls_profile`) to
/// inspect per-stage handshake timings.
pub fn tls_profile_report(out: &mut [u8]) -> usize {
    server::profile::report(out)
}

/// Reset the TLS handshake profile accumulators. Useful between
/// benchmark runs.
pub fn tls_profile_reset() {
    server::profile::reset();
}

// ---- uni_http::Tls impl ------------------------------------------------------
//
// Thin wrappers over `server::{TlsServer, TlsServerConfig}`. The
// outer `TlsImpl` holds an `Arc<TlsServerConfig>` shared by every
// accepted connection; each per-conn `TlsConnImpl` keeps its own
// clone so `advance()` can pass the config to the state machine
// without needing a back-ref to the outer struct.

struct TlsImpl {
    cfg: Arc<TlsServerConfig>,
}

impl uni_http::Tls for TlsImpl {
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn uni_http::TlsConn> {
        Box::new(TlsConnImpl {
            tls: server::TlsServer::new(seed),
            cfg: self.cfg.clone(),
        })
    }
}

struct TlsConnImpl {
    tls: server::TlsServer,
    cfg: Arc<TlsServerConfig>,
}

impl uni_http::TlsConn for TlsConnImpl {
    fn push_rx(&mut self, bytes: &[u8]) {
        self.tls.push_rx(bytes);
    }

    fn advance(&mut self) -> Result<(), ()> {
        self.tls.advance(&self.cfg).map(|_| ()).map_err(|_| ())
    }

    fn pop_tx(&mut self, out: &mut [u8]) -> usize {
        self.tls.pop_tx(out)
    }

    fn pop_plaintext(&mut self, out: &mut [u8]) -> usize {
        self.tls.pop_plaintext(out)
    }

    fn send_app_data(&mut self, data: &[u8]) -> Result<(), ()> {
        self.tls.send_app_data(data).map_err(|_| ())
    }

    fn close_notify(&mut self) -> Result<(), ()> {
        self.tls.close_notify().map_err(|_| ())
    }
}
