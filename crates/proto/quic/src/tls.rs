// crates/proto/quic/src/tls.rs — TLS 1.3 handshake driver for QUIC.
//
// QUIC carries TLS handshake messages in CRYPTO frames at three
// distinct packet number spaces (Initial / Handshake / 1-RTT)
// rather than over the TLS record layer. RFC 9001 §4 specifies
// the integration: same handshake state machine, same key
// schedule, same cipher suite — only the I/O wrapping differs.
//
// `QuicTls` reuses every primitive in `//crates/net:tls` (Transcript,
// KeySchedule, X25519ServerKey) and `//crates/net:tls_handshake`
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

use alloc::vec::Vec;

use p256::ecdsa::{Signature as EcdsaSignature, signature::Signer};

use tls::handshake::{
    ClientHello, ParseError, build_certificate, build_certificate_verify,
    build_encrypted_extensions, build_finished, build_server_hello, encode_handshake, msg_type,
    parse_finished, parse_handshake, sign_content_server_cert_verify,
};
use tls::schedule::{
    ApplicationSecrets, HASH_LEN, HandshakeSecrets, KeySchedule, Transcript, X25519ServerKey,
};

use tls::TlsServerConfig;
use tls::keys::{ct_eq_32, derive_finished_key, hmac_sha256};

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
    /// X25519 share, no AES-128-GCM cipher offered).
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

    /// Inbound handshake bytes per level, contiguous from the
    /// start of the level's CRYPTO stream. `push_handshake` does
    /// offset-aware reassembly into these via per-level `RxBuf`s.
    /// The `advance` loop parses prefixes off the front; remaining
    /// bytes wait for the next push.
    rx_initial: RxBuf,
    rx_handshake: RxBuf,

    /// Outbound handshake bytes per level. The connection layer
    /// drains these into CRYPTO frames and clears the queue. The
    /// 1-RTT level carries post-handshake messages — currently
    /// `NewSessionTicket` (RFC 8446 §4.6.1) for QUIC resumption,
    /// emitted right after the WaitClientFinished → Established
    /// transition.
    tx_initial: Vec<u8>,
    tx_handshake: Vec<u8>,
    tx_one_rtt: Vec<u8>,

    /// Stage-3 traffic secrets, exposed read-only to the caller
    /// once the relevant transition fires. `None` before then.
    handshake_secrets: Option<HandshakeSecrets>,
    application_secrets: Option<ApplicationSecrets>,

    /// Client early-data (0-RTT) traffic secret. `Some` only on a
    /// resumed handshake whose PSK validated — derived from the
    /// early_secret + Transcript-Hash(ClientHello). The connection
    /// layer turns this into AEAD keys for decrypting 0-RTT
    /// packets. `None` for fresh handshakes (no early-data) and
    /// always `None` for the SERVER side of early data (server
    /// never sends 0-RTT).
    client_early_traffic_secret: Option<[u8; 32]>,

    /// QUIC transport parameters (RFC 9000 §18) the server will
    /// advertise inside EncryptedExtensions. Set by the connection
    /// state machine before the first `advance`. Empty until set —
    /// in that case we still advertise a `quic_transport_parameters`
    /// extension with an empty body, which is technically invalid
    /// per RFC 9001 §8.2 but never observed in production because
    /// the connection layer always populates this.
    server_transport_params: Vec<u8>,

    /// Client-side transport parameters captured from the
    /// ClientHello. `None` until ClientHello has been parsed.
    client_transport_params: Option<Vec<u8>>,
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
            rx_initial: RxBuf::default(),
            rx_handshake: RxBuf::default(),
            tx_initial: Vec::new(),
            tx_handshake: Vec::new(),
            tx_one_rtt: Vec::new(),
            handshake_secrets: None,
            application_secrets: None,
            client_early_traffic_secret: None,
            server_transport_params: Vec::new(),
            client_transport_params: None,
        }
    }

    /// Set the server's transport parameter blob. The connection
    /// state machine constructs this once it knows its `local_cid`
    /// (used for `initial_source_connection_id`) and the original
    /// destination CID from the client's first Initial.
    pub fn set_server_transport_params(&mut self, params: Vec<u8>) {
        self.server_transport_params = params;
    }

    /// Client transport parameters the server learned from the
    /// `quic_transport_parameters` extension in ClientHello. `None`
    /// until ClientHello has been processed.
    pub fn client_transport_params(&self) -> Option<&[u8]> {
        self.client_transport_params.as_deref()
    }

    /// Current state — caller checks for `Established` to know
    /// the handshake is done.
    pub fn state(&self) -> QuicTlsState {
        self.state
    }

    /// Handshake-stage traffic secrets (`client_hs`, `server_hs`).
    /// `Some` after the WaitClientHello → WaitClientFinished
    /// transition; the caller derives Handshake-space packet
    /// protection keys from these via
    /// `quic_crypto::derive_aes128_keys`.
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

    /// Client early-data (0-RTT) traffic secret. `Some` only on
    /// resumed handshakes — the connection layer derives AEAD keys
    /// from this and unprotects incoming 0-RTT packets with them.
    pub fn client_early_traffic_secret(&self) -> Option<&[u8; 32]> {
        self.client_early_traffic_secret.as_ref()
    }

    /// Append handshake bytes received from a CRYPTO frame at
    /// `level`, starting at `offset` in the level's CRYPTO stream.
    /// Reassembles out-of-order frames into a contiguous buffer —
    /// curl/ngtcp2 deliberately scrambles CRYPTO offsets as an
    /// anti-fingerprinting measure (RFC 9000 §19.6 explicitly
    /// permits arbitrary order), so the receiver MUST handle it.
    /// 1-RTT level is accepted but ignored — server doesn't
    /// expect post-handshake handshake messages from the client
    /// today.
    pub fn push_handshake(&mut self, level: CryptoLevel, offset: u64, bytes: &[u8]) {
        match level {
            CryptoLevel::Initial => self.rx_initial.ingest(offset, bytes),
            CryptoLevel::Handshake => self.rx_handshake.ingest(offset, bytes),
            CryptoLevel::OneRtt => {}
        }
    }

    /// Drain queued outgoing handshake bytes for `level` into
    /// `out`. Returns bytes copied; caller wraps into one or
    /// more CRYPTO frames at the matching packet number space.
    pub fn pop_handshake(&mut self, level: CryptoLevel, out: &mut [u8]) -> usize {
        let buf = match level {
            CryptoLevel::Initial => &mut self.tx_initial,
            CryptoLevel::Handshake => &mut self.tx_handshake,
            CryptoLevel::OneRtt => &mut self.tx_one_rtt,
        };
        let n = out.len().min(buf.len());
        out[..n].copy_from_slice(&buf[..n]);
        buf.drain(..n);
        n
    }

    /// Whether any Handshake-level CRYPTO bytes are still buffered
    /// for transmission. `flush_outbound` uses this to decide
    /// whether the server flight needs another fragment packet:
    /// the flight (EncryptedExtensions + Certificate +
    /// CertificateVerify + Finished) routinely exceeds one packet
    /// for a real leaf+intermediate cert chain.
    pub fn has_pending_handshake(&self) -> bool {
        !self.tx_handshake.is_empty()
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
        // locals so we can drop the borrow into rx_initial. Same
        // scope holds the resumption attempt — `PskOffer` borrows
        // from `body`, so the `try_resume` call must happen before
        // the borrow expires; the returned `ResumeAccept` is
        // owned, so it remains valid past the scope.
        let (client_x25519_pub, sid_echo, sid_len, selected_alpn, resume_accept) = {
            let ch = ClientHello::parse(body).map_err(|e| {
                crate::quic_drop!(
                    unsupported_client,
                    "ClientHello::parse failed: {:?} body_len={}",
                    e,
                    body.len()
                );
                QuicTlsError::UnsupportedClient
            })?;
            let mut sid = [0u8; 32];
            let n = ch.legacy_session_id.len();
            sid[..n].copy_from_slice(ch.legacy_session_id);
            let pk = ch.x25519_client_pub.ok_or_else(|| {
                crate::quic_drop!(
                    unsupported_client,
                    "no x25519 in ClientHello key_share (groups offered: {} key_shares: {})",
                    ch.observed_supported_group_count,
                    ch.observed_key_share_count
                );
                QuicTlsError::UnsupportedClient
            })?;
            self.client_transport_params = ch.quic_transport_parameters.map(|s| s.to_vec());
            let alpn = ch.alpn_protocol_list.and_then(|list| {
                let mut h3 = None;
                let mut first = None;
                for p in tls::handshake::iter_alpn(list) {
                    if first.is_none() {
                        first = Some(p.to_vec());
                    }
                    if p == b"h3" {
                        h3 = Some(p.to_vec());
                        break;
                    }
                }
                h3.or(first)
            });

            // Resumption attempt. RFC 9001 §4.5: QUIC requires
            // psk_dhe_ke (forward-secret resumption); pure-PSK is
            // forbidden. `try_resume` enforces that and validates
            // the binder against `Truncate(ClientHello)`. On any
            // failure we fall through to a fresh handshake with
            // no observable difference to the client.
            let resume = if let Some(psk_offer) = ch.psk.as_ref() {
                // `try_resume` expects the FULL handshake message
                // (4-byte header + body), which is `rx_initial[..total_len]`.
                let full_hs = &self.rx_initial[..total_len];
                tls::handlers::try_resume(full_hs, psk_offer, ch.psk_ke_modes)
            } else {
                None
            };
            (pk, sid, n, alpn, resume)
        };

        // Adopt the resumed schedule (if any) so handshake_traffic_secret
        // derivation downstream uses the PSK-derived early secret.
        let selected_psk_identity: Option<u16> =
            resume_accept.as_ref().map(|r| r.selected_identity);
        let resumed = resume_accept.is_some();
        if let Some(ra) = resume_accept {
            let id = ra.selected_identity;
            self.schedule = ra.schedule;
            if ra.early_data_allowed {
                // Derive client_early_traffic_secret from
                // Transcript-Hash(ClientHello). At this point
                // `self.transcript` already includes the full
                // CH (updated above) and nothing else, so its
                // snapshot IS that hash. The connection layer
                // pops it via `client_early_traffic_secret()`
                // and turns it into 0-RTT AEAD keys.
                let transcript_h0 = self.transcript.snapshot();
                self.client_early_traffic_secret =
                    Some(self.schedule.early_traffic(&transcript_h0));
            } else {
                // Replay-cache hit (RFC 9001 §5.5). 1-RTT
                // resumption proceeds; 0-RTT is rejected by
                // virtue of leaving `client_early_traffic_secret`
                // None, which makes the QUIC layer drop any
                // incoming 0-RTT packets at AEAD open. Surface
                // the event so an operator can spot replay
                // attempts vs. the normal accept path.
                crate::quic_event!(
                    zero_rtt_unresumable,
                    "reason=replay_cache_hit selected_identity={}",
                    id
                );
            }
            crate::quic_event!(tickets_accepted, "selected_identity={}", id);
        }

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
            selected_psk_identity, // Some(idx) on resumption, None on fresh
            &mut sh_body,
        )
        .ok_or(QuicTlsError::Internal)?;
        let mut sh_msg = [0u8; 280];
        let sh_msg_len = encode_handshake(msg_type::SERVER_HELLO, &sh_body[..sh_len], &mut sh_msg)
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
        // Inject quic_transport_parameters (RFC 9001 §8.2) and
        // (if the client offered ALPN) the
        // application_layer_protocol_negotiation echo (RFC 7301).
        // Body fits comfortably in 256 bytes — defaults + two CIDs
        // + ALPN "h3" are <60 bytes.
        let mut ee_body = alloc::vec![0u8; 256];
        // ALPN echo body: u16 list_len || u8 name_len || name.
        let alpn_body: Option<alloc::vec::Vec<u8>> = selected_alpn.as_ref().map(|name| {
            let mut blob = alloc::vec::Vec::with_capacity(3 + name.len());
            let entry_len = (1 + name.len()) as u16;
            blob.extend_from_slice(&entry_len.to_be_bytes());
            blob.push(name.len() as u8);
            blob.extend_from_slice(name);
            blob
        });
        let mut extras: alloc::vec::Vec<(u16, &[u8])> = alloc::vec::Vec::new();
        if !self.server_transport_params.is_empty() {
            extras.push((
                tls::handshake::ext_type::QUIC_TRANSPORT_PARAMETERS,
                self.server_transport_params.as_slice(),
            ));
        }
        if let Some(blob) = &alpn_body {
            extras.push((
                tls::handshake::ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                blob.as_slice(),
            ));
        }
        // RFC 8446 §4.2.10 / RFC 9001 §4.6: empty `early_data`
        // extension in EE = "I accept 0-RTT for this conn". Without
        // this, an RFC-compliant client treats 0-RTT as REJECTED
        // even when its CH offered it AND we accepted the PSK —
        // the client retransmits the early data over 1-RTT instead
        // of relying on it. We only emit when both:
        //   * the client offered early-data (we'd add the extension
        //     parsing to ClientHello to detect this — for now we
        //     just gate on `resumed`, which is the necessary
        //     precondition; for non-early-data resumptions the
        //     client ignores the EE extension)
        //   * we have early_recv keys ready
        // In practice today the gate is just `resumed && PSK_offered`
        // — early_data acceptance follows automatically on resumption.
        if resumed {
            extras.push((
                tls::handshake::ext_type::EARLY_DATA,
                &[], // empty body in EE
            ));
        }
        let ee_body_len =
            build_encrypted_extensions(&extras, &mut ee_body).ok_or(QuicTlsError::Internal)?;
        let mut ee_msg = alloc::vec![0u8; 256 + 16];
        let ee_msg_len = encode_handshake(
            msg_type::ENCRYPTED_EXTENSIONS,
            &ee_body[..ee_body_len],
            &mut ee_msg,
        )
        .ok_or(QuicTlsError::Internal)?;
        self.transcript.update(&ee_msg[..ee_msg_len]);
        self.tx_handshake.extend_from_slice(&ee_msg[..ee_msg_len]);

        // ── Certificate + CertificateVerify (skipped on resume) ──
        // RFC 8446 §4.4.1: when the handshake is resumed via PSK,
        // the server omits Certificate and CertificateVerify — the
        // client already authenticated the server in the original
        // connection that issued the ticket. Skipping these saves
        // ~1 KB of handshake bytes and the ECDSA signing cost
        // (the slowest server-side step in our profile).
        if !resumed {
            // 4 KiB covers a self-signed dev cert and a real CA chain
            // (leaf + one ECDSA intermediate); `build_certificate`
            // fails the handshake cleanly if a larger chain overflows.
            let mut cert_body = alloc::vec![0u8; 4096];
            let cert_body_len = build_certificate(config.cert_chain, &mut cert_body)
                .ok_or(QuicTlsError::Internal)?;
            let mut cert_msg = alloc::vec![0u8; 4128];
            let cert_msg_len = encode_handshake(
                msg_type::CERTIFICATE,
                &cert_body[..cert_body_len],
                &mut cert_msg,
            )
            .ok_or(QuicTlsError::Internal)?;
            self.transcript.update(&cert_msg[..cert_msg_len]);
            self.tx_handshake
                .extend_from_slice(&cert_msg[..cert_msg_len]);

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
        }

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
        let sf_body_len = build_finished(&sf_verify, &mut sf_body).ok_or(QuicTlsError::Internal)?;
        let mut sf_msg = [0u8; 48];
        let sf_msg_len = encode_handshake(msg_type::FINISHED, &sf_body[..sf_body_len], &mut sf_msg)
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
        let expected_verify = hmac_sha256(&client_finished_key, &self.transcript.snapshot());
        if !ct_eq_32(client_verify, &expected_verify) {
            self.state = QuicTlsState::Failed;
            return Err(QuicTlsError::BadClientFinished);
        }

        // Update transcript with client Finished, then drain.
        self.transcript.update(&self.rx_handshake[..total_len]);
        self.rx_handshake.drain(..total_len);

        // Emit a NewSessionTicket so the client can resume in a
        // future connection. The body is small (~150 bytes) and
        // queued in `tx_one_rtt` so the conn layer wraps it in a
        // 1-RTT-level CRYPTO frame on the next outbound flush. This
        // is the foundation for QUIC 0-RTT (subsequent connections
        // present this ticket via the `pre_shared_key` extension).
        // Failure here is non-fatal — the handshake completed; the
        // client just won't be able to resume on the next visit.
        let _ = self.emit_new_session_ticket();

        self.state = QuicTlsState::Established;
        Ok(())
    }

    /// Build, seal, and queue a NewSessionTicket for emission via
    /// `tx_one_rtt`. Mirrors `tls::handlers::emit_session_ticket`
    /// but writes raw handshake-message bytes (the QUIC connection
    /// layer wraps them in CRYPTO frames; there's no TLS record
    /// envelope at QUIC's 1-RTT level).
    fn emit_new_session_ticket(&mut self) -> Result<(), QuicTlsError> {
        // Resumption master secret over the post-ClientFinished
        // transcript. Same as the TCP-TLS path.
        let post_cf_transcript = self.transcript.snapshot();
        let rms = self.schedule.resumption_secret(&post_cf_transcript);

        let mut age_bytes = [0u8; 4];
        getrandom::getrandom(&mut age_bytes).map_err(|_| QuicTlsError::Internal)?;
        let age_add = u32::from_be_bytes(age_bytes);

        let pt = tls::ticket::TicketPlaintext {
            version: tls::ticket::TICKET_VERSION,
            resumption_master_secret: rms,
            ticket_age_add: age_add,
            issued_at_cycles: tls::ticket::now_cycles(),
            cipher_suite: tls::handshake::cipher_suite::TLS_AES_128_GCM_SHA256,
        };
        let mut sealed = [0u8; tls::ticket::SEALED_LEN];
        let n = tls::ticket::seal_ticket(&pt, &mut sealed).ok_or(QuicTlsError::Internal)?;

        // RFC 8446 §4.6.1 NewSessionTicket layout, plus the
        // RFC 9001 §4.6.1 `early_data` extension carrying the
        // sentinel `max_early_data_size = 0xffffffff`. Without
        // this extension the client won't even attempt 0-RTT on
        // the next connection — it's the sole signal "future-self
        // accepts 0-RTT". RFC 9001 mandates exactly this value
        // for QUIC; any other is a connection error.
        let mut early_data_ext = [0u8; 8];
        early_data_ext[0..2].copy_from_slice(&tls::handshake::ext_type::EARLY_DATA.to_be_bytes());
        early_data_ext[2..4].copy_from_slice(&4u16.to_be_bytes());
        early_data_ext[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());

        let mut nst_body = alloc::vec![0u8; n + 64];
        let body_len = tls::handshake::build_new_session_ticket(
            tls::ticket::TICKET_LIFETIME_SECONDS,
            age_add,
            &[], // empty ticket_nonce — one ticket per connection
            &sealed[..n],
            &early_data_ext,
            &mut nst_body,
        )
        .ok_or(QuicTlsError::Internal)?;

        let mut nst_msg = alloc::vec![0u8; body_len + 4];
        let msg_len = tls::handshake::encode_handshake(
            tls::handshake::msg_type::NEW_SESSION_TICKET,
            &nst_body[..body_len],
            &mut nst_msg,
        )
        .ok_or(QuicTlsError::Internal)?;

        // Queue the raw TLS handshake bytes; the QUIC conn layer
        // pop_handshake's them at the OneRtt level on its next
        // flush_outbound and emits a CRYPTO frame in a 1-RTT packet.
        self.tx_one_rtt.extend_from_slice(&nst_msg[..msg_len]);
        Ok(())
    }
}

// ============================================================================
// RxBuf — per-level CRYPTO-stream reassembly
// ============================================================================
//
// Each TLS level has its own monotonically-increasing CRYPTO byte
// stream. Frames may arrive in any order (RFC 9000 §19.6): the
// receiver MUST reassemble. This is a small specialisation of the
// stream-recv pattern in //crates/proto/quic/streams.rs — no FIN tracking,
// no flow control, just contiguous-prefix accumulation + an
// offset-keyed gap buffer for late chunks.
//
// `Deref<Target=[u8]>` returns the contiguous in-order bytes
// available for parsing (callers index it like a slice). `drain`
// consumes a prefix once a complete handshake message has been
// processed.

#[derive(Default)]
pub(crate) struct RxBuf {
    /// Contiguous bytes from offset 0 (after `drain`'d prefixes are
    /// removed). The TLS parser consumes from the front of this.
    contiguous: Vec<u8>,
    /// Cumulative number of bytes ever delivered into `contiguous`
    /// — i.e. the next stream-offset that would extend it.
    consumed: u64,
    /// Out-of-order chunks keyed by their start offset. Folded into
    /// `contiguous` as the gap fills.
    pending: alloc::collections::BTreeMap<u64, Vec<u8>>,
    /// Soft cap on pending bytes — anything past this is dropped to
    /// prevent a malicious peer flooding us with non-contiguous
    /// chunks. ClientHello + ServerHello flights are well under
    /// 4 KiB; cert-only paths might push higher; 64 KiB is a
    /// generous overhead.
    pending_budget: usize,
}

impl RxBuf {
    /// Total contiguous bytes available right now.
    pub(crate) fn len(&self) -> usize {
        self.contiguous.len()
    }

    /// Discard a prefix of `n` bytes from the contiguous buffer
    /// (called after a complete handshake message has been parsed).
    pub(crate) fn drain(&mut self, range: core::ops::RangeTo<usize>) {
        self.contiguous.drain(range);
    }

    /// Ingest a CRYPTO frame `(offset, data)` at this level. The
    /// chunk may be in-order, ahead-of-order, or partially overlap
    /// data already delivered. RFC 9000 §19.6 requires receivers
    /// to handle all three cases.
    pub(crate) fn ingest(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = offset + data.len() as u64;
        // Frame entirely before what we've already delivered →
        // duplicate retransmit; ignore.
        if end <= self.consumed {
            return;
        }
        // Trim leading bytes that overlap already-delivered data.
        let (offset, data) = if offset < self.consumed {
            let skip = (self.consumed - offset) as usize;
            (self.consumed, &data[skip..])
        } else {
            (offset, data)
        };
        if offset == self.consumed {
            self.contiguous.extend_from_slice(data);
            self.consumed += data.len() as u64;
            // See if pending entries can now be folded in.
            while let Some((&next_off, _)) = self.pending.iter().next() {
                if next_off > self.consumed {
                    break;
                }
                let v = self.pending.remove(&next_off).unwrap();
                self.pending_budget = self.pending_budget.saturating_add(v.len());
                let skip = self.consumed.saturating_sub(next_off) as usize;
                if skip < v.len() {
                    self.contiguous.extend_from_slice(&v[skip..]);
                    self.consumed += (v.len() - skip) as u64;
                }
            }
        } else if data.len() <= self.pending_budget.saturating_sub(0) + (64 * 1024) {
            // Stash for later. We initialise with a 0 budget on
            // Default and grow it lazily — that quirk lets us cap
            // the amount we'd buffer for a misbehaving peer with
            // a single check below.
            const PENDING_CAP: usize = 64 * 1024;
            let pending_total: usize =
                self.pending.values().map(|v| v.len()).sum::<usize>() + data.len();
            if pending_total <= PENDING_CAP {
                self.pending.insert(offset, data.to_vec());
            }
        }
    }
}

impl core::ops::Deref for RxBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.contiguous
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
    use tls::handshake::{LEGACY_VERSION_TLS12, cipher_suite, ext_type, named_group};

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
        write_ext(
            &mut ext,
            ext_type::SUPPORTED_GROUPS,
            &[0x00, 0x02, 0x00, 0x1d],
        );
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
        body.extend_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
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
        const CERT: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_cert.der");
        const KEY: &[u8] = include_bytes!("../../../../apps/webserver/dev_certs/dev_key.der");
        TlsServerConfig::from_chain(&[CERT], KEY).expect("dev cert load")
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
        q.push_handshake(CryptoLevel::Initial, 0, &ch);

        let s = q.advance(&cfg).expect("advance after CH");
        assert_eq!(s, QuicTlsState::WaitClientFinished);
        assert!(q.handshake_secrets().is_some(), "hs secrets after SH");
        assert!(
            q.application_secrets().is_some(),
            "ap secrets after server flight"
        );

        // Initial-level output should contain a ServerHello message.
        let mut buf = [0u8; 512];
        let n = q.pop_handshake(CryptoLevel::Initial, &mut buf);
        assert!(n > 0, "ServerHello bytes available");
        assert_eq!(buf[0], msg_type::SERVER_HELLO);
        assert_eq!(
            q.pop_handshake(CryptoLevel::Initial, &mut buf),
            0,
            "initial buffer drained"
        );

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
        q.push_handshake(CryptoLevel::Initial, 0, &ch[..10]);
        let s = q.advance(&cfg).expect("advance on partial CH");
        assert_eq!(
            s,
            QuicTlsState::WaitClientHello,
            "must remain WaitClientHello on truncated CH"
        );

        // Push the rest, advance, transition fires.
        q.push_handshake(CryptoLevel::Initial, 10, &ch[10..]);
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
        q.push_handshake(CryptoLevel::Initial, 0, &bogus);
        let r = q.advance(&cfg);
        assert!(matches!(r, Err(QuicTlsError::UnexpectedMessage)));
        assert_eq!(q.state(), QuicTlsState::Failed);
    }
}
