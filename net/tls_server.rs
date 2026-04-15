// net/tls_server.rs — TLS 1.3 server handshake state machine.
//
// Pure state machine + byte-buffer I/O — the caller is responsible for
// feeding it bytes from a `TcpStream` and flushing bytes back out.
// Never blocks, never allocates on the hot path, never touches a
// lock. One `TlsServer` is intended to live inline in a per-core
// connection pool alongside TCP state.
//
// Scope (v1 of hand-rolled TLS):
//   - TLS 1.3 only (no fallback)
//   - TLS_CHACHA20_POLY1305_SHA256 only
//   - X25519 key exchange only
//   - ECDSA P-256 + SHA-256 server certificate only
//   - No client authentication
//   - No session resumption / tickets
//   - No 0-RTT
//   - No key update
//   - No ALPN (for now)
//
// References:
//   RFC 8446 §2      overall handshake flow
//   RFC 8446 §4.1.3  ServerHello
//   RFC 8446 §4.3.1  EncryptedExtensions
//   RFC 8446 §4.4.2  Certificate
//   RFC 8446 §4.4.3  CertificateVerify
//   RFC 8446 §4.4.4  Finished
//   RFC 8446 §5      Record protocol
//   RFC 8446 §7.1    Key schedule

#![no_std]

extern crate hmac;
extern crate kernel;
extern crate net_tls as tls;
extern crate net_tls_crypto as tls_crypto;
extern crate net_tls_handshake as handshake;
extern crate net_tls_record as record;
extern crate p256;
extern crate sha2;

use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, Signature as EcdsaSignature, SigningKey};
use sha2::Sha256;

use handshake::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_server_hello, encode_handshake, msg_type, parse_finished, parse_handshake,
    sign_content_server_cert_verify, ClientHello, ParseError,
};
use record::{content_type, open as record_open, seal as record_seal, RecordError, HEADER_LEN};
use tls::{KeySchedule, TrafficKey, Transcript, X25519ServerKey, HASH_LEN};

// ============================================================================
// Tunables
// ============================================================================
//
// Buffer sizes chosen so `Box::new(TlsServer::new(...))` doesn't
// overflow a 64 KB kernel stack during construction. Rust's Box::new
// constructs the value on the stack before moving it to the heap,
// and a debug build doesn't always elide that — so keep the combined
// buffer footprint well under half the stack.

/// Max raw TLS bytes we buffer from the peer before advancing the
/// state machine. Sized to hold a typical ClientHello (~500 bytes)
/// or an HTTP/1.1 request under TLS record overhead. TLS 1.3 lets
/// peers send up to 16 KB records but clients rarely do; anything
/// bigger than this will close the connection.
pub const RX_BUF_LEN: usize = 4 * 1024;

/// Max raw TLS bytes we emit during the server flight
/// (ServerHello + CCS + encrypted {EncExt, Certificate, CertVerify,
/// Finished}). A typical self-signed ECDSA P-256 dev cert is ~550 bytes
/// so the flight fits in ~1.5 KB; 4 KB is generous room.
pub const TX_BUF_LEN: usize = 4 * 1024;

/// Max decrypted plaintext we buffer for the app (one HTTP request).
pub const PT_BUF_LEN: usize = 4 * 1024;

// ============================================================================
// Configuration
// ============================================================================

/// Static server configuration shared across all TLS connections.
/// Must outlive every `TlsServer` that references it.
pub struct TlsServerConfig {
    /// DER-encoded X.509 certificate. We include it opaque — we don't
    /// parse it, because the client's job is to verify it (or not,
    /// in the `curl -k` case).
    pub cert_der: &'static [u8],
    /// The ECDSA P-256 private scalar that corresponds to the cert's
    /// public key. 32-byte raw scalar (NOT a PKCS#8 blob — the caller
    /// extracts the bytes from the `dev_key.der` file via
    /// `extract_p256_d_from_pkcs8`).
    pub signing_seed: [u8; 32],
}

impl TlsServerConfig {
    /// Load from our checked-in dev cert. The dev key DER from
    /// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`
    /// is a PKCS#8 `PrivateKeyInfo` wrapping an RFC 5915 `ECPrivateKey`
    /// SEQUENCE, which contains the 32-byte private scalar.
    ///
    /// Returns `None` if the PKCS#8 blob isn't the expected shape.
    pub fn from_dev_cert(cert_der: &'static [u8], pkcs8_key: &[u8]) -> Option<Self> {
        let seed = extract_p256_d_from_pkcs8(pkcs8_key)?;
        Some(TlsServerConfig {
            cert_der,
            signing_seed: seed,
        })
    }
}

/// Extract the 32-byte private scalar `d` from a PKCS#8 `PrivateKeyInfo`
/// DER encoding of an ECDSA P-256 key (as produced by `openssl genpkey
/// -algorithm EC -pkeyopt ec_paramgen_curve:P-256`).
///
/// The layout is:
/// ```text
///   SEQUENCE
///     INTEGER 0                              (PKCS#8 version)
///     SEQUENCE                               (AlgorithmIdentifier)
///       OID 1.2.840.10045.2.1                (id-ecPublicKey)
///       OID 1.2.840.10045.3.1.7              (prime256v1 = secp256r1)
///     OCTET STRING containing
///       SEQUENCE                             (ECPrivateKey, RFC 5915)
///         INTEGER 1                          (version)
///         OCTET STRING <d>                   (32-byte private scalar)
///         [0] explicit parameters (optional)
///         [1] explicit publicKey  (optional)
/// ```
///
/// We check that the prime256v1 OID appears in the blob, then scan for
/// `02 01 01 04 20` — the ECPrivateKey `version = 1` INTEGER followed
/// by the `OCTET STRING length = 32` header. The 32 bytes right after
/// that header are the private scalar. Deliberately narrow-minded: we
/// only parse our own checked-in dev key, not arbitrary PKCS#8.
fn extract_p256_d_from_pkcs8(blob: &[u8]) -> Option<[u8; 32]> {
    // Sanity-check the prime256v1 OID appears somewhere in the header.
    // Bytes: 06 08 2a 86 48 ce 3d 03 01 07
    //        ^  ^-- length
    //        OID tag
    const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    if blob.len() < P256_OID.len() + 5 + 32 {
        return None;
    }
    let mut found_oid = false;
    for start in 0..=blob.len() - P256_OID.len() {
        if &blob[start..start + P256_OID.len()] == P256_OID {
            found_oid = true;
            break;
        }
    }
    if !found_oid {
        return None;
    }

    // Scan for `02 01 01 04 20` (ECPrivateKey version=1 +
    // 32-byte OCTET STRING header) and take the 32 bytes after.
    const D_HEADER: &[u8] = &[0x02, 0x01, 0x01, 0x04, 0x20];
    for start in 0..=blob.len() - D_HEADER.len() - 32 {
        if &blob[start..start + D_HEADER.len()] == D_HEADER {
            let d_offset = start + D_HEADER.len();
            let mut d = [0u8; 32];
            d.copy_from_slice(&blob[d_offset..d_offset + 32]);
            return Some(d);
        }
    }
    None
}

// ============================================================================
// Error type
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    ParseError(ParseError),
    RecordError(RecordError),
    /// Client's ClientHello didn't meet our requirements
    /// (missing TLS 1.3 / X25519 / ChaCha20-Poly1305).
    UnsupportedClient,
    /// AEAD tag mismatch on an incoming record.
    AeadFailed,
    /// Output buffer too small to hold the server flight.
    TxBufTooSmall,
    /// Client's Finished didn't match the expected HMAC.
    BadClientFinished,
    /// We received a record in a state that doesn't expect it.
    UnexpectedRecord,
    /// Internal bug: a buffer was too small (shouldn't happen with our
    /// fixed limits, but we return it instead of panicking so fuzzing
    /// input can't crash the server).
    Internal,
}

impl From<ParseError> for TlsError {
    fn from(e: ParseError) -> Self {
        TlsError::ParseError(e)
    }
}

impl From<RecordError> for TlsError {
    fn from(e: RecordError) -> Self {
        TlsError::RecordError(e)
    }
}

// ============================================================================
// State
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Before any bytes have arrived.
    WaitClientHello,
    /// Server flight has been written to tx_buf. Transitions to
    /// `WaitClientFinished` once the caller drains it.
    /// (We don't actually distinguish — we move to WaitClientFinished
    /// as soon as the flight is generated.)
    WaitClientFinished,
    /// Handshake done; application data can flow.
    Established,
    /// Peer cleanly closed or we sent close_notify.
    Closed,
    /// Fatal error. `error` field in `TlsServer` holds the cause.
    Failed,
}

// ============================================================================
// TlsServer
// ============================================================================

/// TLS 1.3 server connection state.
///
/// The caller owns the TCP socket; this struct owns the TLS state.
/// Typical event-loop glue per connection:
///
/// ```ignore
/// // On each tick:
/// let bytes_read = tcp.recv(&mut tmp);
/// tls.push_rx(&tmp[..bytes_read]);
/// loop {
///     let n_tx = tls.pop_tx(&mut tx_tmp);
///     if n_tx > 0 { tcp.send(&tx_tmp[..n_tx]); continue; }
///     let n_pt = tls.pop_plaintext(&mut pt_tmp);
///     if n_pt > 0 { app.handle(&pt_tmp[..n_pt]); continue; }
///     match tls.advance(config) { ... }
///     break;
/// }
/// ```
pub struct TlsServer {
    // State
    state: State,
    error: Option<TlsError>,

    // Raw TLS bytes received from peer (may contain partial or
    // multiple records).
    rx_buf: [u8; RX_BUF_LEN],
    rx_len: usize,

    // Raw TLS bytes waiting to be sent to peer.
    tx_buf: [u8; TX_BUF_LEN],
    tx_len: usize,
    tx_pos: usize, // how many bytes we've handed out via pop_tx()

    // Decrypted application data waiting to be consumed by the app.
    pt_buf: [u8; PT_BUF_LEN],
    pt_len: usize,
    pt_pos: usize,

    // Key schedule + transcript
    transcript: Transcript,
    schedule: KeySchedule,
    ephemeral: Option<X25519ServerKey>,

    // Traffic keys at each stage. `Option` so we can derive lazily.
    client_hs_tk: Option<TrafficKey>,
    server_hs_tk: Option<TrafficKey>,
    client_ap_tk: Option<TrafficKey>,
    server_ap_tk: Option<TrafficKey>,

    // Server-side handshake traffic secret — needed separately to
    // compute server Finished and then derive the master secret.
    server_hs_secret: Option<[u8; HASH_LEN]>,
    client_hs_secret: Option<[u8; HASH_LEN]>,
}

// ============================================================================
// Compile-time-gated handshake tracing
// ============================================================================
//
// Enable with `--cfg=tls_debug` in rustc_flags on //net:tls_server when
// you need to diagnose a broken handshake. When disabled (the default),
// every function in `trace` is a no-op stub with no arguments read —
// the compiler optimizes them to nothing, so there's zero runtime cost
// and zero code-size overhead in the release binary.
//
// The corresponding debug fields in `handshake::ClientHello` (e.g.
// `observed_key_shares`) are populated unconditionally by the parser —
// they're tiny (<200 bytes of stack data per ClientHello) and the cost
// is negligible given the parser only runs once per connection, so
// it's not worth the conditional-compilation complexity to gate them.
mod trace {
    #![allow(unused_variables, dead_code)]

    use super::{handshake, State, TlsError};
    #[cfg(tls_debug)]
    use kernel::serial;

    #[cfg(tls_debug)]
    pub fn client_hello(ch: &handshake::ClientHello<'_>) {
        serial::puts(b"[tls-debug] ClientHello key_shares: ");
        if ch.observed_key_share_count == 0 {
            serial::puts(b"(none)");
        } else {
            for i in 0..ch.observed_key_share_count as usize {
                let (group, key_len) = ch.observed_key_shares[i];
                if i > 0 {
                    serial::puts(b", ");
                }
                serial::puts(b"group=0x");
                put_u16_hex(group);
                serial::puts(b"(");
                put_group_name(group);
                serial::puts(b") len=");
                put_u16_dec(key_len);
            }
        }
        serial::puts(b"\n[tls-debug] ClientHello supported_groups: ");
        if ch.observed_supported_group_count == 0 {
            serial::puts(b"(none)");
        } else {
            for i in 0..ch.observed_supported_group_count as usize {
                let g = ch.observed_supported_groups[i];
                if i > 0 {
                    serial::puts(b", ");
                }
                serial::puts(b"0x");
                put_u16_hex(g);
                serial::puts(b"(");
                put_group_name(g);
                serial::puts(b")");
            }
        }
        serial::puts(b"\n[tls-debug] ClientHello signature_algorithms: ");
        if ch.observed_sig_alg_count == 0 {
            serial::puts(b"(none)");
        } else {
            let mut offers_p256 = false;
            for i in 0..ch.observed_sig_alg_count as usize {
                let a = ch.observed_sig_algs[i];
                if a == 0x0403 {
                    offers_p256 = true;
                }
                if i > 0 {
                    serial::puts(b", ");
                }
                serial::puts(b"0x");
                put_u16_hex(a);
                serial::puts(b"(");
                put_sig_alg_name(a);
                serial::puts(b")");
            }
            serial::puts(b"\n[tls-debug] offers_ecdsa_p256=");
            serial::puts(if offers_p256 { b"true" } else { b"false" });
        }
        serial::puts(b"\n[tls-debug] has_x25519_share=");
        serial::puts(if ch.x25519_client_pub.is_some() {
            b"true"
        } else {
            b"false"
        });
        serial::puts(b" offers_x25519=");
        serial::puts(if ch.offers_x25519 { b"true" } else { b"false" });
        serial::puts(b"\n");
    }
    #[cfg(not(tls_debug))]
    pub fn client_hello(_ch: &handshake::ClientHello<'_>) {}

    #[cfg(tls_debug)]
    pub fn step(msg: &[u8]) {
        serial::puts(msg);
    }
    #[cfg(not(tls_debug))]
    pub fn step(_msg: &[u8]) {}

    #[cfg(tls_debug)]
    pub fn do_client_finished_entry(rx_len: usize, first_byte: Option<u8>) {
        serial::puts(b"[tls] do_client_finished entered, rx_len=");
        put_u16_dec(rx_len as u16);
        serial::puts(b"\n");
        if let Some(b) = first_byte {
            serial::puts(b"[tls]   first byte (content_type) = 0x");
            put_u16_hex(b as u16);
            serial::puts(b"\n");
        }
    }
    #[cfg(not(tls_debug))]
    pub fn do_client_finished_entry(_rx_len: usize, _first_byte: Option<u8>) {}

    #[cfg(tls_debug)]
    pub fn waiting_for_bytes(have: usize, need: usize) {
        serial::puts(b"[tls]   waiting for more bytes (have ");
        put_u16_dec(have as u16);
        serial::puts(b", need ");
        put_u16_dec(need as u16);
        serial::puts(b")\n");
    }
    #[cfg(not(tls_debug))]
    pub fn waiting_for_bytes(_have: usize, _need: usize) {}

    #[cfg(tls_debug)]
    pub fn record_header(content_type: u8, total_len: usize) {
        serial::puts(b"[tls]   full record arrived, content_type=0x");
        put_u16_hex(content_type as u16);
        serial::puts(b" len=");
        put_u16_dec(total_len as u16);
        serial::puts(b"\n");
    }
    #[cfg(not(tls_debug))]
    pub fn record_header(_content_type: u8, _total_len: usize) {}

    #[cfg(tls_debug)]
    pub fn decrypted_record(inner_type: u8, pt_len: usize) {
        serial::puts(b"[tls]   decrypted, inner_type=0x");
        put_u16_hex(inner_type as u16);
        serial::puts(b" pt_len=");
        put_u16_dec(pt_len as u16);
        serial::puts(b"\n");
    }
    #[cfg(not(tls_debug))]
    pub fn decrypted_record(_inner_type: u8, _pt_len: usize) {}

    #[cfg(tls_debug)]
    pub fn alert_received(level: u8, desc: u8) {
        serial::puts(b"[tls]   client sent ALERT level=");
        put_u16_dec(level as u16);
        serial::puts(b" desc=");
        put_u16_dec(desc as u16);
        serial::puts(b" (");
        serial::puts(alert_name(desc));
        serial::puts(b")\n");
    }
    #[cfg(not(tls_debug))]
    pub fn alert_received(_level: u8, _desc: u8) {}

    #[cfg(tls_debug)]
    pub fn error(state: State, err: &TlsError) {
        serial::puts(b"[tls] ERROR in state=");
        serial::puts(state_name(state));
        serial::puts(b" err=");
        serial::puts(err_name(err));
        serial::puts(b"\n");
    }
    #[cfg(not(tls_debug))]
    pub fn error(_state: State, _err: &TlsError) {}

    // ── Internal formatting helpers (compiled only with tls_debug) ──────
    #[cfg(tls_debug)]
    fn put_u16_hex(v: u16) {
        let hex = b"0123456789abcdef";
        let buf = [
            hex[((v >> 12) & 0xf) as usize],
            hex[((v >> 8) & 0xf) as usize],
            hex[((v >> 4) & 0xf) as usize],
            hex[(v & 0xf) as usize],
        ];
        serial::puts(&buf);
    }

    #[cfg(tls_debug)]
    fn put_u16_dec(mut v: u16) {
        if v == 0 {
            serial::puts(b"0");
            return;
        }
        let mut buf = [0u8; 6];
        let mut n = 0;
        while v > 0 {
            buf[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        let mut out = [0u8; 6];
        for i in 0..n {
            out[i] = buf[n - 1 - i];
        }
        serial::puts(&out[..n]);
    }

    #[cfg(tls_debug)]
    fn put_group_name(g: u16) {
        let name: &[u8] = match g {
            0x0017 => b"secp256r1",
            0x0018 => b"secp384r1",
            0x0019 => b"secp521r1",
            0x001d => b"x25519",
            0x001e => b"x448",
            0x0100 => b"ffdhe2048",
            0x0101 => b"ffdhe3072",
            0x11ec => b"x25519mlkem768",
            0x6399 => b"x25519kyber768draft00",
            _ => b"?",
        };
        serial::puts(name);
    }

    #[cfg(tls_debug)]
    fn put_sig_alg_name(a: u16) {
        let name: &[u8] = match a {
            0x0201 => b"rsa_pkcs1_sha1",
            0x0203 => b"ecdsa_sha1",
            0x0401 => b"rsa_pkcs1_sha256",
            0x0403 => b"ecdsa_secp256r1_sha256",
            0x0501 => b"rsa_pkcs1_sha384",
            0x0503 => b"ecdsa_secp384r1_sha384",
            0x0601 => b"rsa_pkcs1_sha512",
            0x0603 => b"ecdsa_secp521r1_sha512",
            0x0804 => b"rsa_pss_rsae_sha256",
            0x0805 => b"rsa_pss_rsae_sha384",
            0x0806 => b"rsa_pss_rsae_sha512",
            0x0807 => b"ed25519",
            0x0808 => b"ed448",
            0x0809 => b"rsa_pss_pss_sha256",
            0x080a => b"rsa_pss_pss_sha384",
            0x080b => b"rsa_pss_pss_sha512",
            _ => b"?",
        };
        serial::puts(name);
    }

    #[cfg(tls_debug)]
    fn state_name(s: State) -> &'static [u8] {
        match s {
            State::WaitClientHello => b"WaitClientHello",
            State::WaitClientFinished => b"WaitClientFinished",
            State::Established => b"Established",
            State::Closed => b"Closed",
            State::Failed => b"Failed",
        }
    }

    #[cfg(tls_debug)]
    fn err_name(e: &TlsError) -> &'static [u8] {
        match e {
            TlsError::ParseError(_) => b"ParseError",
            TlsError::RecordError(_) => b"RecordError",
            TlsError::UnsupportedClient => b"UnsupportedClient",
            TlsError::AeadFailed => b"AeadFailed",
            TlsError::TxBufTooSmall => b"TxBufTooSmall",
            TlsError::BadClientFinished => b"BadClientFinished",
            TlsError::UnexpectedRecord => b"UnexpectedRecord",
            TlsError::Internal => b"Internal",
        }
    }

    #[cfg(tls_debug)]
    fn alert_name(desc: u8) -> &'static [u8] {
        match desc {
            0 => b"close_notify",
            10 => b"unexpected_message",
            20 => b"bad_record_mac",
            22 => b"record_overflow",
            40 => b"handshake_failure",
            42 => b"bad_certificate",
            43 => b"unsupported_certificate",
            44 => b"certificate_revoked",
            45 => b"certificate_expired",
            46 => b"certificate_unknown",
            47 => b"illegal_parameter",
            48 => b"unknown_ca",
            49 => b"access_denied",
            50 => b"decode_error",
            51 => b"decrypt_error",
            70 => b"protocol_version",
            71 => b"insufficient_security",
            80 => b"internal_error",
            86 => b"inappropriate_fallback",
            90 => b"user_canceled",
            109 => b"missing_extension",
            110 => b"unsupported_extension",
            112 => b"unrecognized_name",
            113 => b"bad_certificate_status_response",
            115 => b"unknown_psk_identity",
            116 => b"certificate_required",
            120 => b"no_application_protocol",
            _ => b"?",
        }
    }
}

impl TlsServer {
    /// Create a fresh TlsServer with a random X25519 keypair.
    /// `seed` is 32 bytes of entropy for the ephemeral key — caller
    /// supplies from `kernel::rng::fill_bytes()`.
    pub fn new(x25519_seed: [u8; 32]) -> Self {
        TlsServer {
            state: State::WaitClientHello,
            error: None,
            rx_buf: [0; RX_BUF_LEN],
            rx_len: 0,
            tx_buf: [0; TX_BUF_LEN],
            tx_len: 0,
            tx_pos: 0,
            pt_buf: [0; PT_BUF_LEN],
            pt_len: 0,
            pt_pos: 0,
            transcript: Transcript::new(),
            schedule: KeySchedule::new_without_psk(),
            ephemeral: Some(X25519ServerKey::from_seed(x25519_seed)),
            client_hs_tk: None,
            server_hs_tk: None,
            client_ap_tk: None,
            server_ap_tk: None,
            server_hs_secret: None,
            client_hs_secret: None,
        }
    }

    // ── Outward API (caller-driven) ─────────────────────────────────

    /// Push raw TLS bytes from the peer into the RX buffer. Returns
    /// the number of bytes accepted (may be less than `data.len()` if
    /// our buffer is temporarily full).
    pub fn push_rx(&mut self, data: &[u8]) -> usize {
        let space = RX_BUF_LEN - self.rx_len;
        let n = core::cmp::min(space, data.len());
        self.rx_buf[self.rx_len..self.rx_len + n].copy_from_slice(&data[..n]);
        self.rx_len += n;
        n
    }

    /// Drain buffered outgoing TLS bytes into `out`. Returns bytes copied.
    pub fn pop_tx(&mut self, out: &mut [u8]) -> usize {
        let available = self.tx_len - self.tx_pos;
        let n = core::cmp::min(available, out.len());
        out[..n].copy_from_slice(&self.tx_buf[self.tx_pos..self.tx_pos + n]);
        self.tx_pos += n;
        if self.tx_pos == self.tx_len {
            self.tx_len = 0;
            self.tx_pos = 0;
        }
        n
    }

    /// Drain decrypted application data into `out`.
    pub fn pop_plaintext(&mut self, out: &mut [u8]) -> usize {
        let available = self.pt_len - self.pt_pos;
        let n = core::cmp::min(available, out.len());
        out[..n].copy_from_slice(&self.pt_buf[self.pt_pos..self.pt_pos + n]);
        self.pt_pos += n;
        if self.pt_pos == self.pt_len {
            self.pt_len = 0;
            self.pt_pos = 0;
        }
        n
    }

    /// Emit a TLS 1.3 `close_notify` alert record (RFC 8446 §6.1)
    /// into the TX buffer and move the connection to `State::Closed`.
    ///
    /// The alert is `[level=warning(1), description=close_notify(0)]`
    /// — 2 bytes of plaintext wrapped in an `alert`-type record and
    /// encrypted under the current server application traffic key.
    /// After this call, the caller is expected to drain `tx_buf` onto
    /// the wire and then close the underlying TCP connection. No
    /// further `send_app_data` / `advance` calls should be made.
    ///
    /// Silently no-ops if the connection is not in `Established` (we
    /// don't send alerts during a half-complete handshake because
    /// the traffic keys may not exist yet — closing the TCP without
    /// an alert is the conservative thing in that case).
    pub fn close_notify(&mut self) -> Result<(), TlsError> {
        if self.state != State::Established {
            // No traffic keys, nothing we can cleanly encrypt.
            // Caller should just close TCP.
            self.state = State::Closed;
            return Ok(());
        }
        let tk = self
            .server_ap_tk
            .as_mut()
            .ok_or(TlsError::Internal)?;
        let alert_body: [u8; 2] = [1, 0]; // warning(1), close_notify(0)
        let needed = record::HEADER_LEN + alert_body.len() + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
            // No space for the alert; give up cleanly rather than
            // wedging. Caller will close TCP; peer will see an
            // unexpected eof but at least nothing crashes.
            self.state = State::Closed;
            return Ok(());
        }
        let n = record_seal(
            tk,
            content_type::ALERT,
            &alert_body,
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += n;
        self.state = State::Closed;
        Ok(())
    }

    /// Encrypt `plaintext` into a TLSCiphertext application_data record
    /// and append it to the TX buffer. Only valid in `Established` state.
    pub fn send_app_data(&mut self, plaintext: &[u8]) -> Result<(), TlsError> {
        if self.state != State::Established {
            return Err(TlsError::UnexpectedRecord);
        }
        let tk = self
            .server_ap_tk
            .as_mut()
            .ok_or(TlsError::Internal)?;

        // Split plaintext into chunks that fit in one record (max
        // ~16 KB inner plaintext).
        const CHUNK: usize = 15 * 1024;
        let mut offset = 0;
        while offset < plaintext.len() {
            let end = core::cmp::min(offset + CHUNK, plaintext.len());
            let space = TX_BUF_LEN - self.tx_len;
            let needed = record::HEADER_LEN + (end - offset) + 1 + record::TAG_LEN;
            if space < needed {
                return Err(TlsError::TxBufTooSmall);
            }
            let n = record_seal(
                tk,
                content_type::APPLICATION_DATA,
                &plaintext[offset..end],
                &mut self.tx_buf[self.tx_len..],
            )?;
            self.tx_len += n;
            offset = end;
        }
        Ok(())
    }

    /// Advance the state machine as far as possible with what's in
    /// `rx_buf`. Returns the current state.
    ///
    /// Loops until no further progress is possible: each state handler
    /// processes at most one record, but a single caller push may have
    /// delivered multiple records across state-transition boundaries
    /// (e.g. ClientChangeCipherSpec + ClientFinished + first
    /// application_data record all arrive in one TCP segment). Without
    /// the loop, the handler that transitions WaitClientFinished →
    /// Established would consume Finished and return, leaving the app
    /// data record stranded in `rx_buf` until the next caller push —
    /// which for a short HTTPS request never comes, wedging the conn.
    pub fn advance(&mut self, config: &TlsServerConfig) -> Result<State, TlsError> {
        loop {
            let before_state = self.state;
            let before_rx = self.rx_len;
            let before_pt = self.pt_len;
            let before_tx = self.tx_len;
            let step_result: Result<(), TlsError> = match self.state {
                State::WaitClientHello => self.do_client_hello(config),
                State::WaitClientFinished => self.do_client_finished(),
                State::Established => self.do_app_data(),
                State::Closed | State::Failed => return Ok(self.state),
            };
            if let Err(e) = step_result {
                trace::error(before_state, &e);
                return Err(e);
            }
            let progressed = self.state != before_state
                || self.rx_len != before_rx
                || self.pt_len != before_pt
                || self.tx_len != before_tx;
            if !progressed {
                return Ok(self.state);
            }
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn error(&self) -> Option<TlsError> {
        self.error
    }

    pub fn has_tx(&self) -> bool {
        self.tx_len > self.tx_pos
    }

    pub fn has_plaintext(&self) -> bool {
        self.pt_len > self.pt_pos
    }

    // ── Inward: handshake handlers ──────────────────────────────────

    /// Handle the WaitClientHello state. Looks for one plaintext record
    /// of content_type::handshake containing ClientHello. If found,
    /// emits the full server flight into tx_buf and transitions to
    /// WaitClientFinished.
    fn do_client_hello(&mut self, config: &TlsServerConfig) -> Result<(), TlsError> {
        // Need at least a record header.
        if self.rx_len < record::HEADER_LEN {
            return Ok(());
        }
        // Peek at the plaintext record. `Truncated` means the record
        // is fragmented across TCP segments and we need to wait for
        // more bytes — NOT a fatal error.
        let (ct, body, consumed) = match record::parse_plaintext(&self.rx_buf[..self.rx_len]) {
            Ok(tuple) => tuple,
            Err(RecordError::Truncated) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if ct != content_type::HANDSHAKE {
            return Err(TlsError::UnexpectedRecord);
        }
        // Check handshake type. A partial handshake message inside a
        // complete record is theoretically possible (fragmentation) but
        // ClientHello always fits in one record in practice, so treat
        // a parse failure as Truncated → wait for more data.
        let (hs_type, hs_body) = match parse_handshake(body) {
            Ok(tuple) => tuple,
            Err(ParseError::Truncated) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if hs_type != msg_type::CLIENT_HELLO {
            return Err(TlsError::UnexpectedRecord);
        }

        // Parse ClientHello for the fields we need (client random,
        // session_id, X25519 share). We copy the few fields we care
        // about into owned locals immediately so we can drop the
        // borrow into `self.rx_buf` and continue.
        let (client_x25519_pub, session_id_echo, sid_len) = {
            let ch = ClientHello::parse(hs_body).map_err(|_| TlsError::UnsupportedClient)?;
            trace::client_hello(&ch);
            let mut sid = [0u8; 32];
            let sid_len = ch.legacy_session_id.len();
            sid[..sid_len].copy_from_slice(ch.legacy_session_id);
            let pub_key = ch.x25519_client_pub.ok_or(TlsError::UnsupportedClient)?;
            (pub_key, sid, sid_len)
        };
        trace::step(b"[tls] ClientHello parsed\n");

        // Update transcript with the full handshake message (body is
        // still borrowed into self.rx_buf; that's fine — transcript
        // reads it and releases).
        self.transcript.update(body);

        // Consume the ClientHello record from rx_buf. After this the
        // `body`/`hs_body` borrows are invalid; we've already extracted
        // everything we need into owned locals.
        self.drain_rx(consumed);

        // ── Generate and emit ServerHello ──────────────────────────
        // Server random: 32 bytes of entropy.
        let mut server_random = [0u8; 32];
        kernel::rng::fill_bytes(&mut server_random);
        // Our ephemeral X25519 public key:
        let ephemeral = self.ephemeral.take().ok_or(TlsError::Internal)?;
        let server_pub = ephemeral.public_bytes();

        // Build ServerHello body + handshake wrapper + plaintext record.
        let mut sh_body = [0u8; 256];
        let sh_len = build_server_hello(
            &server_random,
            &session_id_echo[..sid_len],
            &server_pub,
            &mut sh_body,
        )
        .ok_or(TlsError::Internal)?;
        let mut sh_msg = [0u8; 280];
        let sh_msg_len = encode_handshake(msg_type::SERVER_HELLO, &sh_body[..sh_len], &mut sh_msg)
            .ok_or(TlsError::Internal)?;

        // Emit as plaintext record.
        let sh_rec_len = record::build_plaintext(
            content_type::HANDSHAKE,
            &sh_msg[..sh_msg_len],
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += sh_rec_len;
        trace::step(b"[tls] ServerHello emitted\n");

        // Update transcript with ServerHello.
        self.transcript.update(&sh_msg[..sh_msg_len]);

        // ── Compute shared secret + derive handshake traffic keys ──
        let shared = ephemeral.shared_secret(&client_x25519_pub);
        let transcript_h1 = self.transcript.snapshot();
        let hs_secrets = self.schedule.enter_handshake(&shared, &transcript_h1);
        self.client_hs_secret = Some(hs_secrets.client_hs);
        self.server_hs_secret = Some(hs_secrets.server_hs);
        self.client_hs_tk = Some(TrafficKey::from_secret(&hs_secrets.client_hs));
        let mut server_hs_tk = TrafficKey::from_secret(&hs_secrets.server_hs);

        // ── Middlebox-compat: emit a plaintext ChangeCipherSpec ────
        // RFC 8446 §D.4: a TLS 1.3 server that wants to interop with
        // middleboxes sends a dummy ChangeCipherSpec (0x14 0x03 0x03
        // 0x00 0x01 0x01) immediately after ServerHello. Clients that
        // also sent a session_id expect it. We always send it; it's
        // harmless.
        let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        if TX_BUF_LEN - self.tx_len < ccs.len() {
            return Err(TlsError::TxBufTooSmall);
        }
        self.tx_buf[self.tx_len..self.tx_len + ccs.len()].copy_from_slice(&ccs);
        self.tx_len += ccs.len();

        // ── Emit encrypted handshake flight ────────────────────────
        // Each message: EncryptedExtensions / Certificate /
        // CertificateVerify / Finished. Each becomes its own handshake
        // message inside a TLSCiphertext record, though in principle
        // they could share records — separate records is simpler.

        // EncryptedExtensions
        let mut ee_body = [0u8; 16];
        let ee_body_len =
            build_encrypted_extensions(&mut ee_body).ok_or(TlsError::Internal)?;
        let mut ee_msg = [0u8; 32];
        let ee_msg_len = encode_handshake(
            msg_type::ENCRYPTED_EXTENSIONS,
            &ee_body[..ee_body_len],
            &mut ee_msg,
        )
        .ok_or(TlsError::Internal)?;
        self.transcript.update(&ee_msg[..ee_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &ee_msg[..ee_msg_len])?;
        trace::step(b"[tls] EncryptedExtensions sealed\n");

        // Certificate
        // Build into a stack buffer; 2 KB handles our 500-ish-byte dev cert.
        let mut cert_body = [0u8; 2048];
        let cert_body_len =
            build_certificate(config.cert_der, &mut cert_body).ok_or(TlsError::Internal)?;
        let mut cert_msg = [0u8; 2100];
        let cert_msg_len = encode_handshake(
            msg_type::CERTIFICATE,
            &cert_body[..cert_body_len],
            &mut cert_msg,
        )
        .ok_or(TlsError::Internal)?;
        self.transcript.update(&cert_msg[..cert_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &cert_msg[..cert_msg_len])?;
        trace::step(b"[tls] Certificate sealed\n");

        // CertificateVerify: sign the transcript hash through Certificate.
        // ECDSA P-256 + SHA-256 per TLS 1.3 sig_scheme::ECDSA_SECP256R1_SHA256.
        // `SigningKey::sign` pre-hashes the message with SHA-256 (the
        // signature::Signer impl for p256::ecdsa::SigningKey) and uses
        // RFC 6979 deterministic `k` so we don't need an RNG here.
        // The returned Signature is then DER-encoded into the
        // `SEQUENCE { INTEGER r, INTEGER s }` shape TLS 1.3 requires
        // on the wire.
        let transcript_hash = self.transcript.snapshot();
        let mut sign_content = [0u8; 130];
        sign_content_server_cert_verify(&transcript_hash, &mut sign_content);
        let signing_key = SigningKey::from_slice(&config.signing_seed)
            .map_err(|_| TlsError::Internal)?;
        let signature: EcdsaSignature = signing_key.sign(&sign_content);
        let der_sig = signature.to_der();
        let signature_bytes: &[u8] = der_sig.as_bytes();

        let mut cv_body = [0u8; 128];
        let cv_body_len =
            build_certificate_verify(signature_bytes, &mut cv_body).ok_or(TlsError::Internal)?;
        let mut cv_msg = [0u8; 150];
        let cv_msg_len = encode_handshake(
            msg_type::CERTIFICATE_VERIFY,
            &cv_body[..cv_body_len],
            &mut cv_msg,
        )
        .ok_or(TlsError::Internal)?;
        self.transcript.update(&cv_msg[..cv_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &cv_msg[..cv_msg_len])?;
        trace::step(b"[tls] CertificateVerify sealed\n");

        // Server Finished
        // verify_data = HMAC(finished_key, Transcript-Hash(CH ... CertVerify))
        let server_finished_key = derive_finished_key(&hs_secrets.server_hs);
        let transcript_for_sfin = self.transcript.snapshot();
        let sf_verify = hmac_sha256(&server_finished_key, &transcript_for_sfin);
        let mut sf_body = [0u8; HASH_LEN];
        let sf_body_len =
            build_finished(&sf_verify, &mut sf_body).ok_or(TlsError::Internal)?;
        let mut sf_msg = [0u8; 48];
        let sf_msg_len = encode_handshake(
            msg_type::FINISHED,
            &sf_body[..sf_body_len],
            &mut sf_msg,
        )
        .ok_or(TlsError::Internal)?;
        self.transcript.update(&sf_msg[..sf_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &sf_msg[..sf_msg_len])?;
        trace::step(b"[tls] ServerFinished sealed, entering WaitClientFinished\n");

        // Store the updated server handshake traffic key (its seq
        // counter has advanced across the 4 sealed records).
        self.server_hs_tk = Some(server_hs_tk);

        // ── Derive application traffic secrets ─────────────────────
        // Transcript hash is now through ServerFinished.
        let transcript_h2 = self.transcript.snapshot();
        let app_secrets = self.schedule.enter_application(&transcript_h2);
        self.client_ap_tk = Some(TrafficKey::from_secret(&app_secrets.client_ap));
        self.server_ap_tk = Some(TrafficKey::from_secret(&app_secrets.server_ap));

        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn seal_handshake_record(
        &mut self,
        tk: &mut TrafficKey,
        body: &[u8],
    ) -> Result<(), TlsError> {
        let needed = HEADER_LEN + body.len() + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
            return Err(TlsError::TxBufTooSmall);
        }
        let n = record_seal(tk, content_type::HANDSHAKE, body, &mut self.tx_buf[self.tx_len..])?;
        self.tx_len += n;
        Ok(())
    }

    /// Handle the WaitClientFinished state. Parses one incoming
    /// encrypted record under the client handshake traffic key and
    /// expects it to contain a Finished message.
    fn do_client_finished(&mut self) -> Result<(), TlsError> {
        trace::do_client_finished_entry(
            self.rx_len,
            if self.rx_len >= 1 { Some(self.rx_buf[0]) } else { None },
        );
        // Skip any middlebox-compat ChangeCipherSpec the client sends
        // (plaintext record with content_type 20, 1-byte body = 0x01).
        loop {
            if self.rx_len < record::HEADER_LEN {
                return Ok(());
            }
            if self.rx_buf[0] != content_type::CHANGE_CIPHER_SPEC {
                break;
            }
            // Parse the plaintext CCS record and drop it. Treat
            // Truncated as wait-for-more-data.
            let (_ct, _body, consumed) =
                match record::parse_plaintext(&self.rx_buf[..self.rx_len]) {
                    Ok(tuple) => tuple,
                    Err(RecordError::Truncated) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
            self.drain_rx(consumed);
            trace::step(b"[tls]   skipped ChangeCipherSpec\n");
        }

        // Need a full encrypted record.
        if self.rx_len < record::HEADER_LEN {
            return Ok(());
        }
        let record_len_field = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]) as usize;
        let total = record::HEADER_LEN + record_len_field;
        if self.rx_len < total {
            trace::waiting_for_bytes(self.rx_len, total);
            return Ok(());
        }
        trace::record_header(self.rx_buf[0], total);

        // Decrypt in place under the client handshake traffic key.
        let tk = self
            .client_hs_tk
            .as_mut()
            .ok_or(TlsError::Internal)?;
        let (inner_type, pt, consumed) = record_open(tk, &mut self.rx_buf[..total])?;
        trace::decrypted_record(inner_type, pt.len());
        if inner_type == content_type::ALERT && pt.len() >= 2 {
            trace::alert_received(pt[0], pt[1]);
        }
        if inner_type != content_type::HANDSHAKE {
            return Err(TlsError::UnexpectedRecord);
        }
        // Parse the handshake message out of the decrypted body.
        // `pt` borrows from self.rx_buf; copy it out so we can drain.
        let mut msg_copy = [0u8; 256];
        if pt.len() > msg_copy.len() {
            return Err(TlsError::Internal);
        }
        let pt_len = pt.len();
        msg_copy[..pt_len].copy_from_slice(pt);
        // Drop the pt borrow.
        let _ = pt;
        let (hs_type, hs_body) = parse_handshake(&msg_copy[..pt_len])?;
        if hs_type != msg_type::FINISHED {
            return Err(TlsError::UnexpectedRecord);
        }
        let client_verify = parse_finished(hs_body)?;

        // Expected verify_data = HMAC(client_finished_key, transcript)
        // where transcript covers CH .. Server Finished (NOT including
        // the client Finished itself).
        let client_hs_secret = self
            .client_hs_secret
            .as_ref()
            .ok_or(TlsError::Internal)?;
        let client_finished_key = derive_finished_key(client_hs_secret);
        let expected_verify = hmac_sha256(&client_finished_key, &self.transcript.snapshot());

        if !ct_eq_32(client_verify, &expected_verify) {
            trace::step(b"[tls]   BadClientFinished: verify_data mismatch\n");
            return Err(TlsError::BadClientFinished);
        }

        // Now we can update the transcript with Client Finished.
        self.transcript.update(&msg_copy[..pt_len]);
        // Consume the record.
        self.drain_rx(consumed);

        self.state = State::Established;
        trace::step(b"[tls] Client Finished verified -> Established\n");
        Ok(())
    }

    /// Once established, decrypt incoming application-data records
    /// and buffer the plaintext.
    fn do_app_data(&mut self) -> Result<(), TlsError> {
        loop {
            if self.rx_len < record::HEADER_LEN {
                return Ok(());
            }
            let record_len_field = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]) as usize;
            let total = record::HEADER_LEN + record_len_field;
            if self.rx_len < total {
                return Ok(());
            }
            let tk = self
                .client_ap_tk
                .as_mut()
                .ok_or(TlsError::Internal)?;
            let (inner_type, pt, consumed) = record_open(tk, &mut self.rx_buf[..total])?;
            match inner_type {
                content_type::APPLICATION_DATA => {
                    // Append to plaintext buffer.
                    let pt_len = pt.len();
                    if self.pt_len + pt_len > self.pt_buf.len() {
                        // Plaintext ring is full — pause until the
                        // app drains it. Don't consume the record.
                        return Ok(());
                    }
                    self.pt_buf[self.pt_len..self.pt_len + pt_len].copy_from_slice(pt);
                    self.pt_len += pt_len;
                    // Drop borrow and consume record.
                    let _ = pt;
                    self.drain_rx(consumed);
                }
                content_type::ALERT => {
                    // Peer close_notify or fatal alert. Either way we
                    // move to Closed.
                    let _ = pt;
                    self.drain_rx(consumed);
                    self.state = State::Closed;
                    return Ok(());
                }
                _ => {
                    return Err(TlsError::UnexpectedRecord);
                }
            }
        }
    }

    fn drain_rx(&mut self, n: usize) {
        debug_assert!(n <= self.rx_len);
        self.rx_buf.copy_within(n..self.rx_len, 0);
        self.rx_len -= n;
    }
}

// ============================================================================
// Helpers: HKDF-Expand-Label("finished") + HMAC-SHA256 + constant-time eq
// ============================================================================

/// Derive the TLS 1.3 `finished_key` from a traffic secret:
///     finished_key = HKDF-Expand-Label(secret, "finished", "", HashLen)
fn derive_finished_key(secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    tls::hkdf_expand_label(secret, b"finished", &[], &mut out);
    out
}

/// HMAC-SHA256 over `data` with `key`.
fn hmac_sha256(key: &[u8; HASH_LEN], data: &[u8]) -> [u8; HASH_LEN] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any slice");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; HASH_LEN];
    result.copy_from_slice(&out);
    result
}

/// Constant-time equality for two 32-byte slices. `a` is a slice so
/// the caller can pass a byte slice from a parsed message; we check
/// the length up front.
fn ct_eq_32(a: &[u8], b: &[u8; HASH_LEN]) -> bool {
    if a.len() != HASH_LEN {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..HASH_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// Basic host tests (primitives only)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_32_basics() {
        let a = [0x55u8; 32];
        let b = [0x55u8; 32];
        assert!(ct_eq_32(&a, &b));
        let mut c = b;
        c[0] ^= 1;
        assert!(!ct_eq_32(&a, &c));
        // Wrong length.
        assert!(!ct_eq_32(&[0u8; 16], &[0u8; 32]));
    }

    #[test]
    fn extract_p256_d_matches_known_shape() {
        // Hand-assembled PKCS#8 matching the openssl genpkey -algorithm EC
        // -pkeyopt ec_paramgen_curve:P-256 -outform DER output, stripped
        // down to just the parts our extractor checks for:
        //   * the prime256v1 OID (06 08 2a 86 48 ce 3d 03 01 07) somewhere
        //     in the AlgorithmIdentifier
        //   * the ECPrivateKey `version=1` INTEGER followed by a 32-byte
        //     OCTET STRING containing the private scalar (02 01 01 04 20
        //     <32 bytes>)
        let mut blob = [0u8; 64];
        // id-ecPublicKey + prime256v1 OIDs (just the prime256v1 OID is
        // required by our extractor; id-ecPublicKey is a real-blob detail).
        blob[0..10].copy_from_slice(&[
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        ]);
        // ECPrivateKey version=1 + OCTET STRING length=32 header.
        blob[10..15].copy_from_slice(&[0x02, 0x01, 0x01, 0x04, 0x20]);
        // Scalar: 32 bytes of 0, 1, 2, ... 31.
        for (i, slot) in blob[15..47].iter_mut().enumerate() {
            *slot = i as u8;
        }
        let d = extract_p256_d_from_pkcs8(&blob).expect("parse");
        let mut expected = [0u8; 32];
        for (i, slot) in expected.iter_mut().enumerate() {
            *slot = i as u8;
        }
        assert_eq!(d, expected);
    }
}
