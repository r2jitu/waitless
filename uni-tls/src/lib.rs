// uni-tls — TLS 1.3 protocol stack for HTTPS-over-TCP.
//
// Owns the full TLS 1.3 implementation: sans-io primitives that
// were previously split across `//net/tls{,_crypto,_handshake,_record}`,
// plus the TCP-specific record-layer driver and the per-connection
// server state machine. After the //net→//uni-tls merger this is
// one cohesive crate; `//uni-quic` reuses the sans-io modules
// (`schedule`, `aead`, `handshake`) but skips `record` (which is
// TCP-specific) and substitutes its own CRYPTO-frame I/O.
//
// Module layout (flat under `src/`):
//
//   lib.rs       public API + acceptor wiring + uni_http::Tls impl
//   schedule.rs  TLS 1.3 key schedule, transcript, X25519, HKDF math
//   aead.rs      ChaCha20-Poly1305 wrapper (the only AEAD TLS-over-
//                  TCP needs; AES-128-GCM lives in //uni-quic for
//                  Initial-packet protection)
//   handshake.rs ClientHello parser, server-flight builders,
//                  signature-content shaper, finished helpers
//   record.rs    TLS record framing (TCP-specific)
//   server.rs    TlsServer connection state machine + state enum
//   handlers.rs  do_client_hello / do_client_finished / do_app_data
//   keys.rs      finished_key derivation + ct_eq_32 + HMAC helpers
//                  (small protocol math used by handlers + ticket)
//   profile.rs   per-stage handshake timing diagnostics
//   ticket.rs    session-resumption ticket envelope
//   trace.rs     diagnostic tracing (cfg(tls_debug))
//
// Public surface (re-exported through this module's root):
//   * `acceptor(cert, key)` — TLS acceptor for `uni_http::listen_https`.
//   * `listen(port, handler, cert, key)` — one-call HTTPS server.
//   * `TlsServerConfig` — typed cert + key bundle.
//   * `tls_profile_report` / `tls_profile_reset` — diagnostics.
//   * `TlsError`, `ListenError` — failure modes.
//
// Sans-io modules (`schedule`, `aead`, `handshake`) are also `pub`
// so `//uni-quic` can reach into them without going through the
// TCP-server wrappers. Apps consuming `uni-tls` for HTTPS only
// don't import them directly — the public API hides them behind
// `acceptor` / `listen`.

// Stays no_std in production. Under `bazel test`, the
// `tests_need_std` flag flips this crate's `std` feature on so
// libtest's panic=unwind harness can link past the RustCrypto
// deps' no_std requirement.
#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

// Sans-io TLS primitives (formerly //net:tls{,_crypto,_handshake,_record}).
// Pub because //uni-quic reaches into `schedule`, `aead`, `handshake`
// for the TLS-handshake-over-CRYPTO-frames driver. `record` stays
// pub for symmetry; it's TCP-only but the wider audience doesn't
// pay any cost — LTO drops it from QUIC binaries.
pub mod aead;
pub mod handshake;
pub mod record;
pub mod schedule;

// TLS-over-TCP server state machine. (`//uni-quic` lives in its
// own crate now and depends on this one for the sans-io TLS bits.)
pub mod server;

// Submodules of the server stack. `pub` so `//uni-quic` can reuse
// `keys::{ct_eq_32, derive_finished_key, hmac_sha256}` (RFC 8446
// §4.4.4 finished-key + helpers) and `profile` for the shared
// per-stage timing accumulator.
pub mod handlers;
pub mod keys;
pub mod profile;
pub mod ticket;
pub mod trace;

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
pub fn listen<H>(
    port: u16,
    handler: H,
    cert_der: &'static [u8],
    key_der: &'static [u8],
) -> Result<(), ListenError>
where
    H: AsyncFn(&uni_http::Request) -> uni_http::Response + Send + Sync + 'static,
{
    listen_advertising_h3(port, handler, cert_der, key_der, false)
}

/// Like [`listen`] but every HTTPS response includes
/// `Alt-Svc: h3=":<port>"; ma=86400` when `advertise_h3` is true.
/// The `<port>` is taken from each request's `Host` header so the
/// advertisement matches whatever port the client actually used —
/// the bazel-run default maps host `:8443` → guest `:443`, and a
/// static `:443` would silently disable HTTP/3 upgrade. The app
/// passes `true` only after `uni_http3::listen` has reported
/// success, otherwise the browser's alt-svc cache gets poisoned
/// with a non-functional advertisement for up to 24 h.
pub fn listen_advertising_h3<H>(
    port: u16,
    handler: H,
    cert_der: &'static [u8],
    key_der: &'static [u8],
    advertise_h3: bool,
) -> Result<(), ListenError>
where
    H: AsyncFn(&uni_http::Request) -> uni_http::Response + Send + Sync + 'static,
{
    let tls = acceptor(cert_der, key_der).map_err(|_| ListenError::Cert)?;
    uni_http::listen_https_advertising_h3(port, handler, tls, advertise_h3)
        .map_err(ListenError::Bind)
}

// ---- Diagnostic helpers ------------------------------------------------------

/// Format the TLS handshake profile into `out`. Apps can serve
/// this as the body of a debug endpoint (`/tls_profile`) to
/// inspect per-stage handshake timings.
pub fn tls_profile_report(out: &mut [u8]) -> usize {
    profile::report(out)
}

/// Reset the TLS handshake profile accumulators. Useful between
/// benchmark runs.
pub fn tls_profile_reset() {
    profile::reset();
}

// ---- uni_http::Tls impl ------------------------------------------------------

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
