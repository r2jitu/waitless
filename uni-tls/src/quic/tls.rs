// uni-tls/src/server/quic.rs — TLS 1.3 handshake driver for QUIC.
//
// QUIC carries TLS handshake messages in CRYPTO frames at three
// distinct packet number spaces (Initial / Handshake / 1-RTT)
// rather than over the TLS record layer. RFC 9001 §4 specifies
// the integration: same handshake state machine, same key
// schedule, same cipher suite — only the I/O wrapping differs.
//
// `QuicTls` reuses every primitive in `//net:tls` (Transcript,
// KeySchedule, X25519ServerKey) and `//net:tls_handshake`
// (ClientHello parser, ServerHello / Certificate / etc. builders,
// signed-content shaping for CertificateVerify) — the only thing
// that changes vs the existing record-layer driver is:
//
//   * inputs come from `push_handshake(level, bytes)` rather than
//     a TLSPlaintext / TLSCiphertext record reader, and
//   * outputs go to per-level tx queues rather than sealed records.
//
// The connection state machine sits on top: it carves these
// per-level buffers into CRYPTO frames, packs them into Initial /
// Handshake / 1-RTT packets, and applies QUIC packet protection
// using the traffic secrets this module surfaces at each
// transition.
//
// Out of scope here:
//   * 0-RTT (early_data extension, second key schedule arm)
//   * Session ticket emission (resumption is on the post-MVP list)
//   * HelloRetryRequest (we accept any client that sends a usable
//     X25519 share; HRR is for negotiating a different group)
//   * Key update (1-RTT key rotation; RFC 9001 §6)

// The connection state machine is the consumer of this module.
// Until that crate lands, the public API surface here looks
// dead-code from the workspace's perspective — silence the
// `#![deny(warnings)]` on the items the connection state machine
// will wire into.
#![allow(dead_code)]

use alloc::vec::Vec;

use p256::ecdsa::{signature::Signer, Signature as EcdsaSignature};

use net_tls::{ApplicationSecrets, HandshakeSecrets, KeySchedule, Transcript, X25519ServerKey, HASH_LEN};
use net_tls_handshake::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_server_hello, encode_handshake, msg_type, parse_finished, parse_handshake,
    sign_content_server_cert_verify, ClientHello, ParseError,
};

use crate::server::keys::{ct_eq_32, derive_finished_key, hmac_sha256};
use crate::server::TlsServerConfig;

// ============================================================================
// Public types
// ============================================================================

/// QUIC packet number space for CRYPTO frames. Each level uses a
/// separate set of packet protection keys derived from a different
/// stage of the TLS key schedule.
/// `OneRtt` is part of the public level taxonomy — the connection
/// state machine routes 1-RTT-protected CRYPTO frames through it
/// — even though the QuicTls module doesn't itself emit anything
/// at that level today (no NewSessionTicket / NewToken yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CryptoLevel {
    /// Initial space: ClientHello / ServerHello. Keys from
    /// `quic_crypto::derive_initial_keys`, NOT from the TLS schedule.
    Initial = 0,
    /// Handshake space: EncryptedExtensions through (server, client)
    /// Finished. Keys derived from `HandshakeSecrets::{client,server}_hs`.
    Handshake = 1,
    /// 1-RTT (Application) space: post-handshake messages,
    /// `NewSessionTicket`, `HANDSHAKE_DONE`, app data via STREAM.
    /// Keys derived from `ApplicationSecrets::{client,server}_ap`.
    OneRtt = 2,
}

/// State of the QUIC TLS handshake. Three states cover the full
/// server-side flow; `Failed` is the absorbing terminal on any
/// fatal protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicTlsState {
    WaitClientHello,
    WaitClientFinished,
    Established,
    Failed,
}

/// Failure modes surfaced from `advance`. Caller maps these to
/// QUIC CONNECTION_CLOSE error codes (RFC 9000 §20.2 transport
/// errors — typically `CRYPTO_ERROR + tls_alert_code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicTlsError {
    ParseError(ParseError),
    /// ClientHello didn't meet our requirements (no TLS 1.3, no
    /// X25519 share, no ChaCha20-Poly1305 cipher offered).
    UnsupportedClient,
    /// Client Finished verify_data didn't match expected HMAC.
    BadClientFinished,
    /// We received a handshake message that doesn't make sense
    /// for the current state (e.g. ClientHello when we're already
    /// in WaitClientFinished).
    UnexpectedMessage,
    /// Output-buffer-too-small / alloc failure / RNG failure.
    Internal,
}

impl From<ParseError> for QuicTlsError {
    fn from(e: ParseError) -> Self {
        Self::ParseError(e)
    }
}

// ============================================================================
// QuicTls — handshake driver
// ============================================================================

/// TLS 1.3 server handshake driven by QUIC CRYPTO frames.
///
/// Lifecycle:
/// 1. `QuicTls::new(rng_seed)` — fresh handshake state.
/// 2. Caller reassembles inbound CRYPTO frame payloads in offset
///    order per level and feeds them via `push_handshake(level, bytes)`.
/// 3. Caller invokes `advance(&config)` after each push. The
///    state machine consumes complete handshake messages from the
///    rx queues and appends outgoing handshake messages to the
///    matching tx queues. After each `advance` the caller drains
///    `pop_handshake(level, out)` to get bytes for outbound CRYPTO
///    frames at that level.
/// 4. After `WaitClientHello → WaitClientFinished`,
///    `handshake_secrets()` is `Some` — caller derives Handshake-
///    space packet protection keys from these. Similarly,
///    `application_secrets()` becomes `Some` immediately after
///    that transition (RFC 9001 §5.1: server can derive 1-RTT keys
///    as soon as it sends ServerFinished).
/// 5. After `WaitClientFinished → Established`, the handshake is
///    complete. Caller emits `HANDSHAKE_DONE` (RFC 9000 §19.20)
///    in 1-RTT to tell the client it can drop the Handshake-space
///    keys.
///
/// **In-order-CRYPTO assumption:** RFC 9000 §19.6 allows CRYPTO
/// frames to arrive out of order at the connection layer. This
/// module's input side (`push_handshake`) does NOT reassemble —
/// the caller must deliver bytes in offset order per level. The
/// QUIC connection state machine has the offset visibility to do
/// the reassembly cheaply (small offset map per level); pushing
/// that responsibility down here would duplicate it.
pub struct QuicTls {
    state: QuicTlsState,
    transcript: Transcript,
    schedule: KeySchedule,
    /// Server's ephemeral X25519 keypair. Consumed by the
    /// `WaitClientHello → WaitClientFinished` transition; the
    /// `Option` lets `take()` move it out without `unsafe`.
    ephemeral: Option<X25519ServerKey>,

    /// Inbound handshake bytes per level, in offset order. The
    /// `advance` loop parses prefixes off the front; remaining
    /// bytes wait for the next push.
    rx_initial: Vec<u8>,
    rx_handshake: Vec<u8>,

    /// Outbound handshake bytes per level. The connection layer
    /// drains these into CRYPTO frames and clears the queue.
    tx_initial: Vec<u8>,
    tx_handshake: Vec<u8>,

    /// Stage-3 traffic secrets, exposed read-only to the caller
    /// once the relevant transition fires. `None` before then.
    handshake_secrets: Option<HandshakeSecrets>,
    application_secrets: Option<ApplicationSecrets>,
}

impl QuicTls {
    /// Construct a fresh QUIC TLS handshake driver. `seed` is 32
    /// bytes of randomness for the X25519 ephemeral keypair —
    /// caller pulls from kernel RNG.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            state: QuicTlsState::WaitClientHello,
            transcript: Transcript::new(),
            schedule: KeySchedule::new_without_psk(),
            ephemeral: Some(X25519ServerKey::from_seed(seed)),
            rx_initial: Vec::new(),
            rx_handshake: Vec::new(),
            tx_initial: Vec::new(),
            tx_handshake: Vec::new(),
            handshake_secrets: None,
            application_secrets: None,
        }
    }

    /// Current state — caller checks for `Established` to know
    /// the handshake is done.
    pub fn state(&self) -> QuicTlsState {
        self.state
    }

    /// Handshake-stage traffic secrets (`client_hs`, `server_hs`).
    /// `Some` after the WaitClientHello → WaitClientFinished
    /// transition; the caller derives Handshake-space packet
    /// protection keys from these via `quic_crypto::derive_chacha_keys`
    /// or equivalent.
    pub fn handshake_secrets(&self) -> Option<&HandshakeSecrets> {
        self.handshake_secrets.as_ref()
    }

    /// Application-stage traffic secrets (`client_ap`, `server_ap`,
    /// `exporter`). Same transition as `handshake_secrets`: the
    /// server derives 1-RTT keys as soon as it has sent its
    /// Finished (RFC 9001 §5.1), so caller can begin 1-RTT TX
    /// even before client Finished arrives.
    pub fn application_secrets(&self) -> Option<&ApplicationSecrets> {
        self.application_secrets.as_ref()
    }

    /// Append handshake bytes received from a CRYPTO frame at
    /// `level`. Caller must deliver bytes in offset order per
    /// level (no reassembly here). 1-RTT level is accepted but
    /// ignored — server doesn't expect post-handshake handshake
    /// messages from the client today.
    pub fn push_handshake(&mut self, level: CryptoLevel, bytes: &[u8]) {
        match level {
            CryptoLevel::Initial => self.rx_initial.extend_from_slice(bytes),
            CryptoLevel::Handshake => self.rx_handshake.extend_from_slice(bytes),
            CryptoLevel::OneRtt => {
                // No client-originated handshake messages in 1-RTT
                // for our v1 server (no key update, no client cert).
            }
        }
    }

    /// Drain queued outgoing handshake bytes for `level` into
    /// `out`. Returns bytes copied; caller wraps into one or
    /// more CRYPTO frames at the matching packet number space.
    pub fn pop_handshake(&mut self, level: CryptoLevel, out: &mut [u8]) -> usize {
        let buf = match level {
            CryptoLevel::Initial => &mut self.tx_initial,
            CryptoLevel::Handshake => &mut self.tx_handshake,
            CryptoLevel::OneRtt => return 0,
        };
        let n = out.len().min(buf.len());
        out[..n].copy_from_slice(&buf[..n]);
        buf.drain(..n);
        n
    }

    /// Advance the state machine over the bytes currently buffered.
    /// Returns the (possibly unchanged) state. Idempotent on
    /// truncated input — re-call after the next `push_handshake`.
    pub fn advance(&mut self, config: &TlsServerConfig) -> Result<QuicTlsState, QuicTlsError> {
        loop {
            let before = self.state;
            match self.state {
                QuicTlsState::WaitClientHello => self.do_client_hello(config)?,
                QuicTlsState::WaitClientFinished => self.do_client_finished()?,
                QuicTlsState::Established | QuicTlsState::Failed => return Ok(self.state),
            }
            if self.state == before {
                return Ok(self.state);
            }
        }
    }

    // ── Internal: WaitClientHello → WaitClientFinished ──────────

    fn do_client_hello(&mut self, config: &TlsServerConfig) -> Result<(), QuicTlsError> {
        // Need at least the 4-byte handshake header.
        if self.rx_initial.len() < 4 {
            return Ok(());
        }
        // Peek the announced length BEFORE handing off to
        // `parse_handshake`. The TLS-over-TCP parser treats
        // "announced length > buffer" as `BadLength` (it expects
        // exactly one message per record), but in QUIC mode the
        // remaining bytes are simply still in flight as more
        // CRYPTO frames — wait for them. We cap the announced
        // length at 64 KiB as a sanity bound; anything larger is
        // a malformed message (the largest legitimate handshake
        // message in our suite is the Certificate, ~2 KiB).
        const MAX_HS_MSG: usize = 64 * 1024;
        let announced = ((self.rx_initial[1] as usize) << 16)
            | ((self.rx_initial[2] as usize) << 8)
            | (self.rx_initial[3] as usize);
        if announced > MAX_HS_MSG {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::ParseError(ParseError::BadLength));
        }
        if 4 + announced > self.rx_initial.len() {
            return Ok(());
        }
        let (mt, body) = match parse_handshake(&self.rx_initial) {
            Ok(t) => t,
            Err(ParseError::Truncated) => return Ok(()),
            Err(e) => {
                self.state = QuicTlsState::Failed;
                return Err(e.into());
            }
        };
        if mt != msg_type::CLIENT_HELLO {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::UnexpectedMessage);
        }
        let total_len = 4 + body.len();

        // Parse ClientHello fields we need; copy into owned
        // locals so we can drop the borrow into rx_initial.
        let (client_x25519_pub, sid_echo, sid_len) = {
            let ch = ClientHello::parse(body).map_err(|_| QuicTlsError::UnsupportedClient)?;
            let mut sid = [0u8; 32];
            let n = ch.legacy_session_id.len();
            sid[..n].copy_from_slice(ch.legacy_session_id);
            let pk = ch.x25519_client_pub.ok_or(QuicTlsError::UnsupportedClient)?;
            (pk, sid, n)
        };

        // Update transcript with the full ClientHello message,
        // then drain consumed bytes.
        self.transcript.update(&self.rx_initial[..total_len]);
        self.rx_initial.drain(..total_len);

        // ── Generate ServerHello (Initial-level CRYPTO output) ──
        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).map_err(|_| QuicTlsError::Internal)?;
        let ephemeral = self.ephemeral.take().ok_or(QuicTlsError::Internal)?;
        let server_pub = ephemeral.public_bytes();

        let mut sh_body = [0u8; 256];
        let sh_len = build_server_hello(
            &server_random,
            &sid_echo[..sid_len],
            &server_pub,
            None, // no PSK resumption in QUIC v1 server
            &mut sh_body,
        )
        .ok_or(QuicTlsError::Internal)?;
        let mut sh_msg = [0u8; 280];
        let sh_msg_len =
            encode_handshake(msg_type::SERVER_HELLO, &sh_body[..sh_len], &mut sh_msg)
                .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&sh_msg[..sh_msg_len]);
        self.tx_initial.extend_from_slice(&sh_msg[..sh_msg_len]);

        // Compute (EC)DHE shared secret + handshake traffic secrets.
        let shared = ephemeral.shared_secret(&client_x25519_pub);
        let transcript_h1 = self.transcript.snapshot();
        let hs_secrets = self.schedule.enter_handshake(&shared, &transcript_h1);
        // Note: server_hs and client_hs both retained — caller
        // needs both to derive its own send key + the client's
        // recv key.
        self.handshake_secrets = Some(hs_secrets);

        // ── EncryptedExtensions (Handshake-level CRYPTO output) ─
        let mut ee_body = [0u8; 16];
        let ee_body_len =
            build_encrypted_extensions(&mut ee_body).ok_or(QuicTlsError::Internal)?;
        let mut ee_msg = [0u8; 32];
        let ee_msg_len = encode_handshake(
            msg_type::ENCRYPTED_EXTENSIONS,
            &ee_body[..ee_body_len],
            &mut ee_msg,
        )
        .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&ee_msg[..ee_msg_len]);
        self.tx_handshake.extend_from_slice(&ee_msg[..ee_msg_len]);

        // ── Certificate (Handshake-level) ───────────────────────
        // Heap-allocate scratch buffers since cert can be ~2KB.
        let mut cert_body = alloc::vec![0u8; 2048];
        let cert_body_len =
            build_certificate(config.cert_der, &mut cert_body).ok_or(QuicTlsError::Internal)?;
        let mut cert_msg = alloc::vec![0u8; 2100];
        let cert_msg_len = encode_handshake(
            msg_type::CERTIFICATE,
            &cert_body[..cert_body_len],
            &mut cert_msg,
        )
        .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&cert_msg[..cert_msg_len]);
        self.tx_handshake
            .extend_from_slice(&cert_msg[..cert_msg_len]);

        // ── CertificateVerify ───────────────────────────────────
        let transcript_hash = self.transcript.snapshot();
        let mut sign_content = [0u8; 130];
        sign_content_server_cert_verify(&transcript_hash, &mut sign_content);
        let signature: EcdsaSignature = config.signing_key.sign(&sign_content);
        let der_sig = signature.to_der();
        let signature_bytes: &[u8] = der_sig.as_bytes();

        let mut cv_body = [0u8; 128];
        let cv_body_len = build_certificate_verify(signature_bytes, &mut cv_body)
            .ok_or(QuicTlsError::Internal)?;
        let mut cv_msg = [0u8; 150];
        let cv_msg_len = encode_handshake(
            msg_type::CERTIFICATE_VERIFY,
            &cv_body[..cv_body_len],
            &mut cv_msg,
        )
        .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&cv_msg[..cv_msg_len]);
        self.tx_handshake.extend_from_slice(&cv_msg[..cv_msg_len]);

        // ── Server Finished ─────────────────────────────────────
        let server_hs = &self
            .handshake_secrets
            .as_ref()
            .ok_or(QuicTlsError::Internal)?
            .server_hs;
        let server_finished_key = derive_finished_key(server_hs);
        let transcript_for_sfin = self.transcript.snapshot();
        let sf_verify = hmac_sha256(&server_finished_key, &transcript_for_sfin);
        let mut sf_body = [0u8; HASH_LEN];
        let sf_body_len = build_finished(&sf_verify, &mut sf_body)
            .ok_or(QuicTlsError::Internal)?;
        let mut sf_msg = [0u8; 48];
        let sf_msg_len = encode_handshake(
            msg_type::FINISHED,
            &sf_body[..sf_body_len],
            &mut sf_msg,
        )
        .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&sf_msg[..sf_msg_len]);
        self.tx_handshake.extend_from_slice(&sf_msg[..sf_msg_len]);

        // ── Derive 1-RTT (application) traffic secrets ─────────
        // RFC 9001 §5.1: server can derive 1-RTT keys immediately
        // after sending ServerFinished (NOT only after receiving
        // ClientFinished — this lets the server send 1-RTT data
        // before the client's ack of the server flight).
        let transcript_h2 = self.transcript.snapshot();
        let app_secrets = self.schedule.enter_application(&transcript_h2);
        self.application_secrets = Some(app_secrets);

        self.state = QuicTlsState::WaitClientFinished;
        Ok(())
    }

    // ── Internal: WaitClientFinished → Established ──────────────

    fn do_client_finished(&mut self) -> Result<(), QuicTlsError> {
        if self.rx_handshake.len() < 4 {
            return Ok(());
        }
        const MAX_HS_MSG: usize = 64 * 1024;
        let announced = ((self.rx_handshake[1] as usize) << 16)
            | ((self.rx_handshake[2] as usize) << 8)
            | (self.rx_handshake[3] as usize);
        if announced > MAX_HS_MSG {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::ParseError(ParseError::BadLength));
        }
        if 4 + announced > self.rx_handshake.len() {
            return Ok(());
        }
        let (mt, body) = match parse_handshake(&self.rx_handshake) {
            Ok(t) => t,
            Err(ParseError::Truncated) => return Ok(()),
            Err(e) => {
                self.state = QuicTlsState::Failed;
                return Err(e.into());
            }
        };
        if mt != msg_type::FINISHED {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::UnexpectedMessage);
        }
        let total_len = 4 + body.len();
        let client_verify = parse_finished(body)?;

        let hs_secrets = self
            .handshake_secrets
            .as_ref()
            .ok_or(QuicTlsError::Internal)?;
        let client_finished_key = derive_finished_key(&hs_secrets.client_hs);
        let expected_verify =
            hmac_sha256(&client_finished_key, &self.transcript.snapshot());
        if !ct_eq_32(client_verify, &expected_verify) {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::BadClientFinished);
        }

        // Update transcript with client Finished, then drain.
        self.transcript.update(&self.rx_handshake[..total_len]);
        self.rx_handshake.drain(..total_len);

        self.state = QuicTlsState::Established;
        Ok(())
    }
}

// `Box<QuicTls>` is the conventional shape for the connection
// state machine to hold one without paying its full size on the
// per-conn stack frame; the public type stays `QuicTls` so
// callers that prefer inline storage aren't forced into a heap
// allocation.

// ============================================================================
// Tests — feed a synthetic ClientHello, verify state transitions
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use net_tls_handshake::{cipher_suite, ext_type, named_group, LEGACY_VERSION_TLS12};

    /// Hand-rolled minimal TLS 1.3 ClientHello body — same shape
    /// the existing `parse_synthetic_client_hello` test in
    /// `net/tls_handshake.rs` exercises against the parser.
    /// Returns the FULL handshake message (including the 4-byte
    /// header) since QuicTls expects message-framed bytes.
    fn synthetic_client_hello_message(client_pub: [u8; 32]) -> Vec<u8> {
        // Extensions: supported_versions, supported_groups, key_share, sig_algs.
        let mut ext = Vec::<u8>::new();
        let write_ext = |buf: &mut Vec<u8>, ty: u16, body: &[u8]| {
            buf.extend_from_slice(&ty.to_be_bytes());
            buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
            buf.extend_from_slice(body);
        };
        write_ext(&mut ext, ext_type::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
        write_ext(&mut ext, ext_type::SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d]);
        let mut ks = Vec::<u8>::new();
        ks.extend_from_slice(&36u16.to_be_bytes());
        ks.extend_from_slice(&named_group::X25519.to_be_bytes());
        ks.extend_from_slice(&32u16.to_be_bytes());
        ks.extend_from_slice(&client_pub);
        write_ext(&mut ext, ext_type::KEY_SHARE, &ks);
        // Tiny signature_algorithms list including ECDSA P-256.
        write_ext(
            &mut ext,
            ext_type::SIGNATURE_ALGORITHMS,
            &[0x00, 0x02, 0x04, 0x03],
        );

        let mut body = Vec::<u8>::new();
        body.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
        body.extend_from_slice(&[0x11u8; 32]); // random
        body.push(0); // session_id length = 0
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&cipher_suite::TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
        body.push(1); // compression_methods length
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        // Wrap with handshake header.
        let mut msg = Vec::<u8>::new();
        msg.push(msg_type::CLIENT_HELLO);
        let len = body.len() as u32;
        msg.push(((len >> 16) & 0xff) as u8);
        msg.push(((len >> 8) & 0xff) as u8);
        msg.push((len & 0xff) as u8);
        msg.extend_from_slice(&body);
        msg
    }

    fn dev_config() -> TlsServerConfig {
        // Bundled dev cert + key. Same files the webserver uses.
        const CERT: &[u8] =
            include_bytes!("../../../apps/webserver/dev_certs/dev_cert.der");
        const KEY: &[u8] =
            include_bytes!("../../../apps/webserver/dev_certs/dev_key.der");
        TlsServerConfig::from_dev_cert(CERT, KEY).expect("dev cert load")
    }

    #[test]
    fn fresh_handshake_walks_state_machine() {
        let cfg = dev_config();
        let mut q = QuicTls::new([0x42u8; 32]);
        assert_eq!(q.state(), QuicTlsState::WaitClientHello);
        assert!(q.handshake_secrets().is_none());

        // Push a ClientHello in the Initial space.
        let client_pub = [0x77u8; 32];
        let ch = synthetic_client_hello_message(client_pub);
        q.push_handshake(CryptoLevel::Initial, &ch);

        let s = q.advance(&cfg).expect("advance after CH");
        assert_eq!(s, QuicTlsState::WaitClientFinished);
        assert!(q.handshake_secrets().is_some(), "hs secrets after SH");
        assert!(q.application_secrets().is_some(), "ap secrets after server flight");

        // Initial-level output should contain a ServerHello message.
        let mut buf = [0u8; 512];
        let n = q.pop_handshake(CryptoLevel::Initial, &mut buf);
        assert!(n > 0, "ServerHello bytes available");
        assert_eq!(buf[0], msg_type::SERVER_HELLO);
        assert_eq!(q.pop_handshake(CryptoLevel::Initial, &mut buf), 0,
                   "initial buffer drained");

        // Handshake-level output should contain EE + Cert + CV + Finished.
        // The exact bytes depend on the dev cert + ECDSA RNG; just
        // check there's a sizeable amount and the first message
        // type is EncryptedExtensions.
        let mut buf = [0u8; 4096];
        let n = q.pop_handshake(CryptoLevel::Handshake, &mut buf);
        assert!(n > 100, "server flight bytes available, got {n}");
        assert_eq!(buf[0], msg_type::ENCRYPTED_EXTENSIONS);
    }

    #[test]
    fn truncated_client_hello_holds_state() {
        let cfg = dev_config();
        let mut q = QuicTls::new([0x33u8; 32]);
        let ch = synthetic_client_hello_message([0x55u8; 32]);

        // Push only the first 10 bytes — clearly not a complete CH.
        q.push_handshake(CryptoLevel::Initial, &ch[..10]);
        let s = q.advance(&cfg).expect("advance on partial CH");
        assert_eq!(s, QuicTlsState::WaitClientHello,
                   "must remain WaitClientHello on truncated CH");

        // Push the rest, advance, transition fires.
        q.push_handshake(CryptoLevel::Initial, &ch[10..]);
        let s = q.advance(&cfg).expect("advance after full CH");
        assert_eq!(s, QuicTlsState::WaitClientFinished);
    }

    #[test]
    fn unexpected_message_fails() {
        let cfg = dev_config();
        let mut q = QuicTls::new([0x55u8; 32]);
        // Push a Finished message in Initial space — wrong type for
        // WaitClientHello state.
        let mut bogus = Vec::<u8>::new();
        bogus.push(msg_type::FINISHED);
        bogus.extend_from_slice(&[0, 0, 32]);
        bogus.extend_from_slice(&[0u8; 32]);
        q.push_handshake(CryptoLevel::Initial, &bogus);
        let r = q.advance(&cfg);
        assert!(matches!(r, Err(QuicTlsError::UnexpectedMessage)));
        assert_eq!(q.state(), QuicTlsState::Failed);
    }
}

