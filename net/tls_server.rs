// TLS 1.3 server handshake state machine. Sans-io: caller feeds bytes
// via `push_rx` / `pop_tx`, drives state with `advance`.
//
// Supports exactly:
//   - TLS 1.3, TLS_CHACHA20_POLY1305_SHA256, X25519
//   - ECDSA P-256 + SHA-256 server cert
// No client auth, no resumption, no 0-RTT, no key update, no ALPN.
//
// References: RFC 8446 §2 (flow), §4.1.3 (ServerHello),
// §4.3.1 (EncryptedExtensions), §4.4.2-4 (Certificate chain),
// §5 (Record protocol), §7.1 (Key schedule).

#![no_std]

extern crate alloc;

extern crate getrandom;
extern crate hmac;
extern crate net_tls as tls;
extern crate net_tls_crypto as tls_crypto;
extern crate net_tls_handshake as handshake;
extern crate net_tls_record as record;
extern crate p256;
extern crate sha2;

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::boxed::Box;

// `//kernel` is only linked in on bare-metal builds (see
// net/BUILD.bazel's select()). The native host build uses the
// same tls_server sources but skips the kernel dep entirely,
// which lets `//uni:uni` use the full hand-rolled TLS stack on
// both the unikernel and POSIX paths. The only consumer of
// kernel functionality left in this crate is the optional
// `#[cfg(tls_debug)]` serial tracer, which falls back to
// `libc::write(2, ...)` on hosted targets.
#[cfg(all(tls_debug, target_os = "none"))]
extern crate kernel;

use p256::ecdsa::SigningKey;

use handshake::ParseError;
use record::{content_type, seal as record_seal, RecordError};
use tls::{KeySchedule, TrafficKey, Transcript, X25519ServerKey, HASH_LEN};

// Submodules. Paths are explicit so the flat net/ directory layout
// keeps `tls_server_*` prefixes instead of colliding with unrelated
// `profile.rs` / `handlers.rs` files.
#[path = "tls_server_keys.rs"]
mod keys;
#[path = "tls_server_trace.rs"]
mod trace;
#[path = "tls_server_profile.rs"]
pub mod profile;
#[path = "tls_server_handlers.rs"]
mod handlers;

// ============================================================================
// Tunables
// ============================================================================
//
// rx/tx/pt buffers are heap-allocated via `zeroed_boxed_slice` in
// `TlsServer::new` (see below), so these sizes don't impact the
// boot stack. Sized to fit a typical ClientHello / server flight /
// HTTP/1.1 request respectively; 4 KB is generous for all three.

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
    /// Pre-constructed ECDSA P-256 signing key. Built once at config
    /// creation so the handshake hot path doesn't re-derive it on
    /// every connection.
    ///
    /// Why this matters: `SigningKey::from_slice(seed)` internally
    /// runs `PublicKey::from_secret_scalar(&secret_scalar)` to
    /// populate the `verifying_key` field of the returned key (the
    /// `verifying` feature is on by default). That's a full P-256
    /// scalar multiplication (`d*G`) that we'd otherwise pay on
    /// every handshake even though we never look at the verifying
    /// key. Caching the constructed `SigningKey` eliminates that
    /// redundant scalar mult from the critical path — profiling
    /// showed it was ~half of the 346µs the raw `sign()` call took.
    pub signing_key: SigningKey,
}

impl TlsServerConfig {
    /// Load from our checked-in dev cert. The dev key DER from
    /// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`
    /// is a PKCS#8 `PrivateKeyInfo` wrapping an RFC 5915 `ECPrivateKey`
    /// SEQUENCE, which contains the 32-byte private scalar.
    ///
    /// Returns `None` if the PKCS#8 blob isn't the expected shape or
    /// the extracted scalar isn't a valid P-256 private key.
    pub fn from_dev_cert(cert_der: &'static [u8], pkcs8_key: &[u8]) -> Option<Self> {
        let seed = extract_p256_d_from_pkcs8(pkcs8_key)?;
        let signing_key = SigningKey::from_slice(&seed).ok()?;
        Some(TlsServerConfig {
            cert_der,
            signing_key,
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
    /// Server flight has been generated; the client's Finished record
    /// is expected next. (There's no separate "flushing" state — we
    /// transition as soon as the flight is written to `tx_buf`.)
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
    pub(crate) state: State,
    pub(crate) error: Option<TlsError>,

    // Raw TLS bytes received from peer (may contain partial or
    // multiple records). Heap-allocated so the 4 KB footprint lands
    // on the heap at connection-accept time instead of reserving
    // the bytes inline for every pre-allocated `TlsServer` slot.
    pub(crate) rx_buf: Box<[u8]>,
    pub(crate) rx_len: usize,

    // Raw TLS bytes waiting to be sent to peer.
    pub(crate) tx_buf: Box<[u8]>,
    pub(crate) tx_len: usize,
    pub(crate) tx_pos: usize, // how many bytes we've handed out via pop_tx()

    // Decrypted application data waiting to be consumed by the app.
    pub(crate) pt_buf: Box<[u8]>,
    pub(crate) pt_len: usize,
    pub(crate) pt_pos: usize,

    // Key schedule + transcript
    pub(crate) transcript: Transcript,
    pub(crate) schedule: KeySchedule,
    pub(crate) ephemeral: Option<X25519ServerKey>,

    // Traffic keys at each stage. `Option` so we can derive lazily.
    pub(crate) client_hs_tk: Option<TrafficKey>,
    pub(crate) server_hs_tk: Option<TrafficKey>,
    pub(crate) client_ap_tk: Option<TrafficKey>,
    pub(crate) server_ap_tk: Option<TrafficKey>,

    // Server-side handshake traffic secret — needed separately to
    // compute server Finished and then derive the master secret.
    pub(crate) server_hs_secret: Option<[u8; HASH_LEN]>,
    pub(crate) client_hs_secret: Option<[u8; HASH_LEN]>,
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        // TrafficKey / KeySchedule have their own Drop impls that
        // wipe `key` / `iv` / `secret`. The raw handshake-secret
        // arrays in this struct are separately held, so scrub them
        // here before the backing memory is released back to the
        // global allocator. (rx/tx/pt Box<[u8]> drops are safe to
        // leave as-is — they hold ciphertext and decrypted request
        // plaintext, which isn't secret key material.)
        if let Some(mut s) = self.server_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
        if let Some(mut s) = self.client_hs_secret.take() {
            tls::secure_zero(&mut s);
        }
    }
}

/// Allocate a zero-filled `Box<[u8]>` directly on the heap via
/// `alloc_zeroed`, bypassing any `[0u8; N]` stack temporary.
/// Critical for this module because a stack-constructed then
/// moved-to-heap `[0u8; 4096]` array could blow the boot stack
/// before optimisation — `alloc_zeroed` writes straight to the
/// new allocation.
///
/// OOM aborts (`handle_alloc_error`); TlsServer::new is called
/// from connection-accept, and refusing an HTTPS conn at the
/// kernel-OOM level would cascade into aborting the connection
/// anyway, so we let the global allocator's OOM handler run.
fn zeroed_boxed_slice(len: usize) -> Box<[u8]> {
    let layout = Layout::from_size_align(len, 1).expect("valid layout");
    // SAFETY: non-zero size (RX/TX/PT_BUF_LEN are all 4 KB > 0);
    // u8 has no invalid bit patterns so zero-initialised memory is
    // a valid `[u8]`; Box::from_raw takes ownership of the
    // freshly-allocated slice pointer.
    unsafe {
        let raw = alloc_zeroed(layout);
        if raw.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        let slice = core::slice::from_raw_parts_mut(raw, len);
        Box::from_raw(slice)
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
            rx_buf: zeroed_boxed_slice(RX_BUF_LEN),
            rx_len: 0,
            tx_buf: zeroed_boxed_slice(TX_BUF_LEN),
            tx_len: 0,
            tx_pos: 0,
            pt_buf: zeroed_boxed_slice(PT_BUF_LEN),
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
}

// ============================================================================
// Basic host tests (primitives only)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
