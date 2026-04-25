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
//   * `acceptor(cert, key)` — parses cert + key, returns the
//     `Arc<dyn uni_http::Tls>` that `uni_http::listen_https`
//     consumes.
//   * `TlsServerConfig` — typed cert + key bundle, exposed for
//     advanced uses (custom ALPN, future per-connection cert
//     selection).
//   * `tls_profile_report` / `tls_profile_reset` — handshake
//     timing diagnostics.
//   * `TlsError` — failure to parse cert / key DER.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

mod server;

pub use server::TlsServerConfig;

/// Cert / key parse failure. Apps treat this as "TLS not
/// available" and fall back to plain HTTP.
#[derive(Debug)]
pub enum TlsError {
    CertOrKey,
}

// ---- Public constructor for the HTTPS path -----------------------------------

/// Build a TLS acceptor from a self-signed dev certificate
/// (X.509 DER) + PKCS#8 ECDSA P-256 private key (DER). Both
/// blobs are typically `include_bytes!`'d at compile time; see
/// `apps/webserver/dev_certs/regen.sh` for the openssl
/// invocation that generates them.
///
/// The returned `Arc<dyn uni_http::Tls>` is what `uni_http::
/// listen_https` consumes. For multi-port HTTPS reusing one
/// cert, clone the Arc per port: `tls.clone()`.
pub fn acceptor(
    cert_der: &'static [u8],
    key_pkcs8_der: &[u8],
) -> Result<Arc<dyn uni_http::Tls>, TlsError> {
    let cfg = TlsServerConfig::from_dev_cert(cert_der, key_pkcs8_der)
        .ok_or(TlsError::CertOrKey)?;
    Ok(Arc::new(TlsImpl { cfg: Arc::new(cfg) }))
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
