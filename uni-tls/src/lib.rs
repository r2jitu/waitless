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
pub mod replay;
pub mod ticket;
pub mod trace;

pub use server::TlsServerConfig;

/// Cert / key parse failure. Apps treat this as "TLS not
/// available" and fall back to plain HTTP.
#[derive(Debug)]
pub enum TlsError {
    CertOrKey,
}

/// Force-exercise every TLS primitive that lazily allocates inside
/// its RustCrypto crate so the heap allocations land in
/// `HEAP_BASELINE` at boot rather than being charged to the first
/// request as a per-conn delta. Idempotent.
///
/// `listen` / `acceptor` call this once on entry. Apps that build
/// their own `TlsServerConfig` directly should call it once at
/// boot too. Cost is one ECDSA sign + verify, one ChaCha20-Poly1305
/// seal + open, one X25519 keypair + ECDH — single-digit
/// microseconds total on Apple silicon, dwarfed by `getrandom`'s
/// own boot-time work.
///
/// Without this, the first HTTPS / HTTP/3 connection's handshake
/// allocates whichever precomputed scalar / Poly1305 / Curve25519
/// tables those crates lazy-init on first use, and the post-
/// shutdown leak check picks them up as a +N alloc delta. With it,
/// the leak check can demand `delta == 0`.
pub fn preinit() {
    // ECDSA P-256 sign + verify exercise. Uses an arbitrary 32-byte
    // private scalar so we don't depend on the dev cert at preinit
    // time; the math hits the same precomputed scalar tables the
    // real CertVerify path will use. All-ones is a valid scalar
    // (it's < the group order).
    {
        use p256::ecdsa::{
            signature::{Signer, Verifier},
            Signature, SigningKey, VerifyingKey,
        };
        let scalar = [0xFFu8; 32];
        if let Ok(sk) = SigningKey::from_slice(&scalar) {
            let sig: Signature = sk.sign(b"uni-tls preinit");
            let vk = VerifyingKey::from(&sk);
            let _ = vk.verify(b"uni-tls preinit", &sig);
        }
    }

    // ChaCha20-Poly1305 seal + open exercise. Hits the Poly1305
    // initialization path on first use.
    {
        let key = [0u8; aead::KEY_LEN];
        let nonce = [0u8; aead::NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = aead::chacha20poly1305_seal(&key, &nonce, b"", &mut buf);
        let _ = aead::chacha20poly1305_open(&key, &nonce, b"", &mut buf, &tag);
    }

    // X25519 ECDH exercise. The schedule path uses
    // `x25519_dalek::StaticSecret::from(seed).diffie_hellman(...)`
    // — both operations may populate Curve25519 lazy state.
    {
        use x25519_dalek::{PublicKey, StaticSecret};
        let a = StaticSecret::from([1u8; 32]);
        let b = StaticSecret::from([2u8; 32]);
        let _shared = a.diffie_hellman(&PublicKey::from(&b));
    }
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
/// Apps that want to advertise an HTTP/3 endpoint via `Alt-Svc`
/// emit it themselves per-response — read `req.host_port()` and
/// add the header via `Response::with_header(b"Alt-Svc", ...)`.
/// The framework no longer hardcodes this (it used to take an
/// `advertise_h3` flag and the host-header reparse fired on
/// every response); apps that don't care don't pay.
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

    fn send_app_data_iobuf(&mut self, buf: &mut uni_iobuf::IOBuf) -> Result<(), ()> {
        self.tls.send_app_data_iobuf(buf).map_err(|_| ())
    }

    fn send_app_data_chain_to(
        &mut self,
        src_chain: &uni_iobuf::IOBufChain,
        dst: &mut uni_iobuf::IOBuf,
    ) -> Result<(), ()> {
        self.tls.send_app_data_chain_to(src_chain, dst).map_err(|_| ())
    }

    fn close_notify(&mut self) -> Result<(), ()> {
        self.tls.close_notify().map_err(|_| ())
    }
}
