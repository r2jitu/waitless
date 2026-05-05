// uni-tls — TLS 1.3 for HTTPS-over-TCP and TLS-over-QUIC.
//
// Top-level layout under `src/`:
//
//   tcp/   TLS 1.3 server state machine for the HTTPS-over-TCP
//          path. The `TlsServer` connection state, the handshake
//          handlers, the per-stage profiler, the session-ticket
//          envelope, and the diagnostic trace module live here.
//          A future `tcp/client.rs` would slot in alongside.
//   quic/  TLS-over-QUIC stack: `QuicTls` handshake driver
//          (CRYPTO-frame I/O), the `Connection` state machine,
//          the per-conn `ConnInbox` async queue, and the UDP
//          listener (`quic_listen` + `QuicListener`). A future
//          `quic/client.rs` slots in alongside.
//
// The two transports share the lower-level protocol primitives
// from `//net` (`tls`, `tls_handshake`, `tls_record`, `tls_crypto`,
// `quic_wire`, `quic_crypto`, `quic_frame`); this crate composes
// them into transport-specific server stacks. Apps that don't
// import `uni_tls` link zero TLS / crypto code — the trait
// boundary in `uni_http` keeps the dependency graph clean.
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

// Stays no_std in production. Under `bazel test`, the
// `tests_need_std` flag flips this crate's `std` feature on so
// libtest's panic=unwind harness can link past the RustCrypto
// deps' no_std requirement.
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

mod tcp;
pub mod quic;

pub use tcp::TlsServerConfig;

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

/// Error from [`listen`]: either the cert / key pair didn't parse,
/// or the underlying TCP bind failed.
#[derive(Debug)]
pub enum ListenError {
    /// `acceptor` rejected the cert / key bytes.
    Cert,
    /// `TcpListener::bind` failed (port in use, registry full, …).
    Bind(uni::runtime::TcpBindError),
}

/// One-call HTTPS listener. Builds a TLS acceptor from `cert_der`
/// / `key_der` and starts the HTTPS server on `port` with `handler`
/// dispatching every parsed `Request`.
///
/// Equivalent to:
/// ```ignore
/// let tls = uni_tls::acceptor(cert_der, key_der)?;
/// uni_http::listen_https(port, handler, tls)?;
/// ```
/// — but without the intermediate `acceptor` variable. Use
/// [`acceptor`] + [`uni_http::listen_https`] directly if you want
/// to share one TLS context across multiple ports.
pub fn listen<H>(
    port: u16,
    handler: H,
    cert_der: &'static [u8],
    key_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: AsyncFn(&uni_http::Request) -> uni_http::Response + Send + Sync + 'static,
{
    let tls = acceptor(cert_der, key_der).map_err(|_| ListenError::Cert)?;
    uni_http::listen_https(port, handler, tls).map_err(ListenError::Bind)
}

// ---- Diagnostic helpers ------------------------------------------------------

/// Format the TLS handshake profile into `out`. Apps can serve
/// this as the body of a debug endpoint (`/tls_profile`) to
/// inspect per-stage handshake timings.
pub fn tls_profile_report(out: &mut [u8]) -> usize {
    tcp::profile::report(out)
}

/// Reset the TLS handshake profile accumulators. Useful between
/// benchmark runs.
pub fn tls_profile_reset() {
    tcp::profile::reset();
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
            tls: tcp::TlsServer::new(seed),
            cfg: self.cfg.clone(),
        })
    }
}

struct TlsConnImpl {
    tls: tcp::TlsServer,
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
