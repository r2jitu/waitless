// uni-tls/src/lib.rs — TLS 1.3 carveout.
//
// Adapts the sans-io server state machine in `net_tls_server` onto
// the `uni_http::{TlsAdapter, TlsConnection}` traits so
// `uni_http::Server` can accept HTTPS connections without any
// direct dependency on TLS code. Apps that don't import `uni-tls`
// link zero bytes of TLS / crypto.
//
// Public surface is tiny: the free function `listen_tls`, the
// re-exported `TlsServerConfig`, and two diagnostic helpers.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

pub use net_tls_server::TlsServerConfig;

// ── Free-function entry point ────────────────────────────────────────────

/// Make `server` start accepting TLS connections on `port`.
///
/// Replaces the old `Server::listen_tls(port, cfg)` method. `cfg` is
/// wrapped in an adapter and handed to the server via its
/// `listen_tls` entry, which is TLS-agnostic. Clone-friendly —
/// multiple ports can share the same config cheaply.
pub fn listen_tls(server: &mut uni_http::Server, port: u16, cfg: TlsServerConfig) {
    server.listen_tls(port, Box::new(TlsAdapterImpl { cfg: Arc::new(cfg) }));
}

// ── Diagnostic helpers (moved from `uni::http`) ──────────────────────────

/// Format the TLS handshake profile into `out`. Apps can serve this
/// as the body of a debug endpoint (`/tls_profile`) to inspect
/// per-stage handshake timings.
pub fn tls_profile_report(out: &mut [u8]) -> usize {
    net_tls_server::profile::report(out)
}

/// Reset the TLS handshake profile accumulators. Useful between
/// benchmark runs.
pub fn tls_profile_reset() {
    net_tls_server::profile::reset();
}

// ── TlsAdapter / TlsConnection impls ─────────────────────────────────────
//
// Thin wrappers over `net_tls_server::{TlsServer, TlsServerConfig}`.
// The adapter holds an `Arc<TlsServerConfig>` shared by every
// accepted connection; each `TlsConnection` keeps its own clone of
// the `Arc` so `advance()` can pass the config to the state machine
// without needing a back-ref to the adapter.

struct TlsAdapterImpl {
    cfg: Arc<TlsServerConfig>,
}

impl uni_http::TlsAdapter for TlsAdapterImpl {
    fn new_connection(&self, seed: [u8; 32]) -> Box<dyn uni_http::TlsConnection> {
        Box::new(TlsConnImpl {
            tls: net_tls_server::TlsServer::new(seed),
            cfg: self.cfg.clone(),
        })
    }
}

struct TlsConnImpl {
    tls: net_tls_server::TlsServer,
    cfg: Arc<TlsServerConfig>,
}

impl uni_http::TlsConnection for TlsConnImpl {
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
