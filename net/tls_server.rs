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
//   - Ed25519 server certificate only
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

extern crate ed25519_dalek;
extern crate hmac;
extern crate kernel;
extern crate net_tls as tls;
extern crate net_tls_crypto as tls_crypto;
extern crate net_tls_handshake as handshake;
extern crate net_tls_record as record;
extern crate sha2;

use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
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
/// Finished}). A typical self-signed Ed25519 dev cert is ~500 bytes
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
    /// The Ed25519 private key that corresponds to the cert's public
    /// key. 32-byte raw seed (NOT a PKCS#8 blob — the caller extracts
    /// the seed bytes from the `dev_key.der` file).
    pub signing_seed: [u8; 32],
}

impl TlsServerConfig {
    /// Load from our checked-in dev cert. The dev key DER from
    /// `openssl genpkey -algorithm ED25519 -outform DER` is a PKCS#8
    /// wrapper of the 32-byte raw seed. The exact PKCS#8 layout for
    /// Ed25519 is well-defined (RFC 8410) and the seed lives at a
    /// fixed offset; we extract it here.
    ///
    /// Returns `None` if the PKCS#8 blob isn't the expected shape.
    pub fn from_dev_cert(cert_der: &'static [u8], pkcs8_key: &[u8]) -> Option<Self> {
        let seed = extract_ed25519_seed_from_pkcs8(pkcs8_key)?;
        Some(TlsServerConfig {
            cert_der,
            signing_seed: seed,
        })
    }
}

/// Extract the 32-byte Ed25519 private seed from a minimal PKCS#8
/// `PrivateKeyInfo` DER blob produced by `openssl genpkey -algorithm
/// ED25519`. We look for the octet-string inside the octet-string
/// that wraps the raw key.
///
/// The format (RFC 5958 / RFC 8410) is:
/// ```text
///   30 2e         SEQUENCE (46 bytes)
///     02 01 00    INTEGER 0  (version)
///     30 05       SEQUENCE (5 bytes)
///       06 03 2b 65 70    OID 1.3.101.112 (Ed25519)
///     04 22       OCTET STRING (34 bytes)
///       04 20     OCTET STRING (32 bytes)
///         <seed>  -- 32 bytes
/// ```
///
/// The nested OCTET STRING structure is because the PKCS#8 wrapper
/// wraps the algorithm-specific encoding, which for Ed25519 is itself
/// an OCTET STRING around the seed (RFC 8410 §7).
fn extract_ed25519_seed_from_pkcs8(blob: &[u8]) -> Option<[u8; 32]> {
    // Minimum plausible size.
    if blob.len() < 48 {
        return None;
    }
    // We just scan for the trailing `04 20 <32 bytes>` and check
    // the preceding bytes look like Ed25519. This is fragile for
    // arbitrary inputs but robust for a fixed, generated-once file.
    if blob.len() < 34 {
        return None;
    }
    let seed_tag = &blob[blob.len() - 34..blob.len() - 32];
    if seed_tag != [0x04, 0x20] {
        return None;
    }
    // Check the Ed25519 OID appears somewhere in the prefix.
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    let mut found_oid = false;
    if blob.len() >= ED25519_OID.len() + 34 {
        for start in 0..=blob.len() - ED25519_OID.len() - 34 {
            if &blob[start..start + ED25519_OID.len()] == ED25519_OID {
                found_oid = true;
                break;
            }
        }
    }
    if !found_oid {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&blob[blob.len() - 32..]);
    Some(seed)
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
            match self.state {
                State::WaitClientHello => self.do_client_hello(config)?,
                State::WaitClientFinished => self.do_client_finished()?,
                State::Established => self.do_app_data()?,
                State::Closed | State::Failed => return Ok(self.state),
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
            let mut sid = [0u8; 32];
            let sid_len = ch.legacy_session_id.len();
            sid[..sid_len].copy_from_slice(ch.legacy_session_id);
            (ch.x25519_client_pub, sid, sid_len)
        };

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

        // CertificateVerify: sign the transcript hash through Certificate.
        let transcript_hash = self.transcript.snapshot();
        let mut sign_content = [0u8; 130];
        sign_content_server_cert_verify(&transcript_hash, &mut sign_content);
        let signing_key = SigningKey::from_bytes(&config.signing_seed);
        let signature = signing_key.sign(&sign_content);
        let signature_bytes = signature.to_bytes();

        let mut cv_body = [0u8; 128];
        let cv_body_len =
            build_certificate_verify(&signature_bytes, &mut cv_body).ok_or(TlsError::Internal)?;
        let mut cv_msg = [0u8; 150];
        let cv_msg_len = encode_handshake(
            msg_type::CERTIFICATE_VERIFY,
            &cv_body[..cv_body_len],
            &mut cv_msg,
        )
        .ok_or(TlsError::Internal)?;
        self.transcript.update(&cv_msg[..cv_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &cv_msg[..cv_msg_len])?;

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
        }

        // Need a full encrypted record.
        if self.rx_len < record::HEADER_LEN {
            return Ok(());
        }
        let record_len_field = u16::from_be_bytes([self.rx_buf[3], self.rx_buf[4]]) as usize;
        let total = record::HEADER_LEN + record_len_field;
        if self.rx_len < total {
            return Ok(());
        }

        // Decrypt in place under the client handshake traffic key.
        let tk = self
            .client_hs_tk
            .as_mut()
            .ok_or(TlsError::Internal)?;
        let (inner_type, pt, consumed) = record_open(tk, &mut self.rx_buf[..total])?;
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
            return Err(TlsError::BadClientFinished);
        }

        // Now we can update the transcript with Client Finished.
        self.transcript.update(&msg_copy[..pt_len]);
        // Consume the record.
        self.drain_rx(consumed);

        self.state = State::Established;
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
    fn extract_ed25519_seed_matches_known_shape() {
        // Hand-assembled PKCS#8 matching the openssl genpkey -algorithm
        // ED25519 -outform DER output:
        //   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
        let mut blob = [0u8; 48];
        blob[0..14].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
        ]);
        blob[14] = 0x04;
        blob[15] = 0x20;
        for (i, slot) in blob[16..48].iter_mut().enumerate() {
            *slot = i as u8;
        }
        let seed = extract_ed25519_seed_from_pkcs8(&blob).expect("parse");
        let mut expected = [0u8; 32];
        for (i, slot) in expected.iter_mut().enumerate() {
            *slot = i as u8;
        }
        assert_eq!(seed, expected);
    }
}
