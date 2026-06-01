// crates/proto/tls — TLS 1.3 protocol stack (sans-io).
//
// Owns the full TLS 1.3 implementation: sans-io primitives that
// were previously split across `//net/tls{,_crypto,_handshake,_record}`,
// plus the TCP-specific record-layer driver and the per-connection
// server state machine. This crate is **transport- and HTTP-agnostic**:
// it has no `http` / `http2` dependency. The HTTPS *listener* — the
// `HttpStream` adapter over TCP and the ALPN dispatch to the HTTP serve
// loops — lives one layer up in `//crates/proto/https`, mirroring how
// `//crates/proto/http3` is its own listener over `//crates/proto/quic`.
// `//crates/proto/quic` reuses the sans-io modules (`schedule`, `aead`,
// `handshake`) but skips `record` (TCP-specific) and substitutes its own
// CRYPTO-frame I/O.
//
// Module layout (flat under `src/`):
//
//   lib.rs       public API: `preinit`, `TlsError`, the profile
//                  diagnostics, and the `TlsServerConfig` /
//                  `AlpnProtocol` re-exports.
//   schedule.rs  TLS 1.3 key schedule, transcript, X25519, HKDF math
//   aead.rs      AES-128-GCM wrapper — the single AEAD shared by
//                  TLS-over-TCP record protection here AND //crates/proto/quic
//                  packet protection (see RFC 9001 §5.3)
//   handshake.rs ClientHello parser, server-flight builders,
//                  signature-content shaper, finished helpers
//   record.rs    TLS record framing (TCP-specific)
//   server.rs    TlsServer connection state machine + state enum +
//                  ALPN result
//   handlers.rs  do_client_hello / do_client_finished / do_app_data
//   keys.rs      finished_key derivation + ct_eq_32 + HMAC helpers
//                  (small protocol math used by handlers + ticket)
//   profile.rs   per-stage handshake timing diagnostics
//   ticket.rs    session-resumption ticket envelope
//   trace.rs     diagnostic tracing (cfg(tls_debug))
//
// Public surface (re-exported through this module's root):
//   * `TlsServerConfig` — typed cert + key bundle (used by the
//     `https` listener and the QUIC handshake driver).
//   * `AlpnProtocol` — the negotiated ALPN, read by the `https`
//     dispatch.
//   * `preinit` — one-shot crypto-primitive warmup.
//   * `tls_profile_report` / `tls_profile_reset` — diagnostics.
//   * `TlsError` — cert/key parse failure.
//
// Sans-io modules (`schedule`, `aead`, `handshake`) are also `pub`
// so `//crates/proto/quic` and `//crates/proto/https` can reach into
// them without going through a higher-level wrapper.

// Stays no_std in production; flips to std only under `--test`
// so the libtest harness has the std it needs.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

// Sans-io TLS primitives (formerly //crates/net:tls{,_crypto,_handshake,_record}).
// Pub because //crates/proto/quic reaches into `schedule`, `aead`, `handshake`
// for the TLS-handshake-over-CRYPTO-frames driver, and //crates/proto/https
// reaches into `record` (record sizes) + `server` (the state machine).
// `record` stays pub for symmetry; it's TCP-only but the wider audience
// doesn't pay any cost — LTO drops it from QUIC binaries.
pub mod aead;
pub mod diag;
pub mod handshake;
pub mod record;
pub mod schedule;

// TLS-over-TCP server state machine. (`//crates/proto/quic` lives in its
// own crate now and depends on this one for the sans-io TLS bits;
// `//crates/proto/https` drives this state machine over a TcpStream.)
pub mod server;

// Submodules of the server stack. `pub` so `//crates/proto/quic` can reuse
// `keys::{ct_eq_32, derive_finished_key, hmac_sha256}` (RFC 8446
// §4.4.4 finished-key + helpers) and `profile` for the shared
// per-stage timing accumulator.
pub mod handlers;
pub mod keys;
pub mod profile;
pub mod replay;
pub mod ticket;
pub mod trace;

pub use server::{AlpnProtocol, TlsServerConfig};

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
/// The `https` listener and apps that build their own `TlsServerConfig`
/// should call this once at boot. Cost is one ECDSA sign + verify, one
/// AES-128-GCM seal + open, one X25519 keypair + ECDH — single-digit
/// microseconds total on Apple silicon, dwarfed by `getrandom`'s own
/// boot-time work.
///
/// Without this, the first HTTPS / HTTP/3 connection's handshake
/// allocates whichever precomputed scalar / GHASH / Curve25519
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
            Signature, SigningKey, VerifyingKey,
            signature::{Signer, Verifier},
        };
        let scalar = [0xFFu8; 32];
        if let Ok(sk) = SigningKey::from_slice(&scalar) {
            let sig: Signature = sk.sign(b"waitless-tls preinit");
            let vk = VerifyingKey::from(&sk);
            let _ = vk.verify(b"waitless-tls preinit", &sig);
        }
    }

    // AES-128-GCM seal + open exercise. Hits the AES round-key
    // expansion + GHASH H-table init the crate lazily allocates
    // on the first cipher constructor.
    {
        let key = [0u8; aead::KEY_LEN];
        let nonce = [0u8; aead::NONCE_LEN];
        let mut buf = [0u8; 16];
        let tag = aead::seal(&key, &nonce, b"", &mut buf);
        let _ = aead::open(&key, &nonce, b"", &mut buf, &tag);
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
