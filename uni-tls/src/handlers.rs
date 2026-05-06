// net/tls_server_handlers.rs — TLS 1.3 handshake state handlers.
//
// Implements the three non-terminal transitions of the server state
// machine as `impl super::TlsServer` methods. The crate-root
// `advance()` loops over these until no further progress is
// possible:
//
//     WaitClientHello    -> do_client_hello    -> WaitClientFinished
//     WaitClientFinished -> do_client_finished -> Established
//     Established        -> do_app_data        -> Established | Closed
//
// The handlers are free to consume one record at a time from
// `rx_buf`, buffer plaintext into `pt_buf`, and emit sealed records
// into `tx_buf`; they never perform I/O directly.

use p256::ecdsa::{signature::Signer, Signature as EcdsaSignature};

use crate::handshake::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_new_session_ticket, build_server_hello, cipher_suite, encode_handshake, msg_type,
    parse_finished, parse_handshake, psk_ke_mode, sign_content_server_cert_verify, ClientHello,
    ParseError, PskOffer,
};
use crate::record::{self, content_type, open as record_open, seal as record_seal, RecordError, HEADER_LEN};
use crate::schedule::{
    derive_secret, empty_transcript_hash, hkdf_expand_label, secure_zero, KeySchedule,
    TrafficKey, HASH_LEN,
};

use sha2::{Digest as _, Sha256};

use crate::keys::{ct_eq_32, derive_finished_key, hmac_sha256};
use crate::profile;
use crate::ticket::{
    open_ticket, seal_ticket, TicketPlaintext, SEALED_LEN, TICKET_LIFETIME_SECONDS,
    TICKET_VERSION,
};
use crate::trace;
use crate::server::{State, HandshakeError, TlsServer, TlsServerConfig, TX_BUF_LEN};

/// Monotonic value the server stamps into freshly-issued tickets and
/// against which `open_ticket` measures age.
///
/// Bare-metal: arch cycle counter (CNTVCT_EL0 / TSC), already
/// calibrated for use by the existing boot-phase timing.
/// Native: 0 — the freshness window is effectively disabled until
/// the runtime grows a unified monotonic clock; tickets still seal
/// and open correctly, they just can't expire.
/// Re-export so the rest of `handlers.rs` keeps working without
/// the cfg-dance — the canonical definition lives in `ticket.rs`
/// so the QUIC handshake driver shares one helper.
use crate::ticket::now_cycles as ticket_now_cycles;

/// Hard cap on how old a ticket can be before `open_ticket` rejects
/// it. Bare-metal: 7 days converted via `cycles_per_us`. Native:
/// `u64::MAX` (effectively no expiry — see comment on
/// `ticket_now_cycles`).
#[cfg(target_os = "none")]
fn ticket_max_age_cycles() -> u64 {
    let cyc_per_us = uni_kernel::time::cycles_per_us();
    // 7 days * 24h * 3600s * 1e6 us/s, then × cyc_per_us. Saturating
    // multiplication so a wildly fast cycle counter can't wrap.
    (7u64 * 24 * 3600 * 1_000_000).saturating_mul(cyc_per_us)
}
#[cfg(not(target_os = "none"))]
fn ticket_max_age_cycles() -> u64 {
    u64::MAX
}

/// Outcome of attempting to resume a session from a `pre_shared_key`
/// extension. Public so the QUIC handshake driver can drive the same
/// path — both transports share `try_resume` and the resulting
/// `KeySchedule` initialised from the recovered RMS.
pub struct ResumeAccept {
    /// Fresh `KeySchedule` initialised via `new_with_psk` from the
    /// recovered resumption_master_secret. Replaces the default
    /// `new_without_psk` schedule on the connection.
    pub schedule: KeySchedule,
    /// Index into the client's PskIdentity list — echoes back as
    /// `selected_identity` in the ServerHello pre_shared_key extension.
    pub selected_identity: u16,
    /// `false` when the ticket nonce was already seen by the
    /// 0-RTT replay cache (RFC 9001 §5.5). The 1-RTT resumption
    /// proceeds normally; the QUIC layer skips deriving the
    /// early-data secret and any 0-RTT packets are dropped at
    /// AEAD open. `true` for first-use tickets.
    pub early_data_allowed: bool,
}

/// Try every PskIdentity in the order the client sent them; first
/// one whose ticket opens AND whose binder verifies wins.
///
/// Per RFC 8446 §4.2.11: a server that finds no acceptable PSK MAY
/// fall back to a fresh handshake — so this returns `None` for any
/// rejection (decrypt fail, expired, suite mismatch, binder mismatch)
/// and lets the caller continue down the fresh path with no observable
/// difference to the client.
///
/// `full_handshake_message` is the bytes of the entire ClientHello
/// handshake message INCLUDING the 4-byte `(type, uint24 length)`
/// header. RFC 8446 §4.2.11.2 specifies the binder transcript as
/// `Truncate(ClientHello)` — everything up to but not including the
/// binders list — and Truncate is computed over the full handshake
/// message, so we hash from byte 0 to `4 + binders_offset`.
pub fn try_resume(
    full_handshake_message: &[u8],
    psk_offer: &PskOffer<'_>,
    psk_modes: u8,
) -> Option<ResumeAccept> {
    // Forward secrecy is non-negotiable — only psk_dhe_ke is accepted.
    if psk_modes & psk_ke_mode::FLAG_PSK_DHE_KE == 0 {
        return None;
    }
    let truncate_len = 4 + psk_offer.binders_offset;
    if truncate_len > full_handshake_message.len() {
        return None;
    }

    // Pre-compute the partial transcript hash once; the binder check
    // for each candidate identity HMACs the same digest.
    let mut hasher = Sha256::new();
    hasher.update(&full_handshake_message[..truncate_len]);
    let partial_transcript: [u8; HASH_LEN] = hasher.finalize().into();

    let now = ticket_now_cycles();
    let max_age = ticket_max_age_cycles();

    let n = psk_offer.identity_count.min(psk_offer.binder_count) as usize;
    for i in 0..n {
        let identity_bytes = psk_offer.identities[i].0;
        let binder = psk_offer.binders[i];

        let opened = match open_ticket(identity_bytes, now, max_age) {
            Some(t) => t,
            None => continue,
        };
        // We only ever issue tickets for one cipher suite; reject on
        // any other so a future suite addition can't cause silent
        // misderivation.
        if opened.cipher_suite != cipher_suite::TLS_CHACHA20_POLY1305_SHA256 {
            continue;
        }

        // PSK = HKDF-Expand-Label(rms, "resumption", ticket_nonce, Hash.length)
        // We seal tickets with empty ticket_nonce (one ticket per
        // connection — the distinguisher serves no purpose).
        let mut psk = [0u8; HASH_LEN];
        hkdf_expand_label(
            &opened.resumption_master_secret,
            b"resumption",
            &[],
            &mut psk,
        );

        let candidate = KeySchedule::new_with_psk(&psk);
        secure_zero(&mut psk);

        // binder_key = Derive-Secret(early_secret, "res binder", "")
        // finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
        // expected = HMAC(finished_key, partial_transcript)
        let binder_key =
            derive_secret(candidate.secret(), b"res binder", &empty_transcript_hash());
        let finished_key = derive_finished_key(&binder_key);
        let expected = hmac_sha256(&finished_key, &partial_transcript);

        if ct_eq_32(binder, &expected) {
            // RFC 9001 §5.5: check the 0-RTT replay cache before
            // letting the caller derive the early-data secret.
            // Sealed-ticket layout (see ticket.rs::seal_under_key):
            //   [name(16) | nonce(12) | ciphertext | tag]
            // We use the per-ticket AEAD nonce as the replay
            // identifier — it's already a fresh 96-bit random
            // generated at seal time, so each ticket has a unique
            // value even when the underlying RMS is shared.
            let early_data_allowed = if identity_bytes.len() >= 28 {
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&identity_bytes[16..28]);
                crate::replay::check_and_record(&nonce)
            } else {
                // Truncated ticket — paranoid: refuse 0-RTT
                // rather than fail-open. The 1-RTT resumption
                // proceeds.
                false
            };
            return Some(ResumeAccept {
                schedule: candidate,
                selected_identity: i as u16,
                early_data_allowed,
            });
        }
        // Wrong binder: drop this candidate's schedule and keep trying.
        // (KeySchedule::Drop wipes the secret on the way out.)
    }
    None
}

impl TlsServer {
    /// Handle the WaitClientHello state. Looks for one plaintext record
    /// of content_type::handshake containing ClientHello. If found,
    /// emits the full server flight into tx_buf and transitions to
    /// WaitClientFinished.
    pub(super) fn do_client_hello(&mut self, config: &TlsServerConfig) -> Result<(), HandshakeError> {
        // Need at least a record header.
        if self.rx_len < record::HEADER_LEN {
            return Ok(());
        }
        // Begin per-stage cycle profile. `t` threads through each
        // stage boundary via `profile::mark()` until the handshake is
        // complete.
        let t = profile::start();
        // Peek at the plaintext record. `Truncated` means the record
        // is fragmented across TCP segments and we need to wait for
        // more bytes — NOT a fatal error.
        let (ct, body, consumed) = match record::parse_plaintext(&self.rx_buf[..self.rx_len]) {
            Ok(tuple) => tuple,
            Err(RecordError::Truncated) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if ct != content_type::HANDSHAKE {
            return Err(HandshakeError::UnexpectedRecord);
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
            return Err(HandshakeError::UnexpectedRecord);
        }

        // Parse ClientHello for the fields we need (client random,
        // session_id, X25519 share). We copy the few fields we care
        // about into owned locals immediately so we can drop the
        // borrow into `self.rx_buf` and continue. The resumption
        // attempt is bracketed inside the same scope so PskOffer's
        // slices into hs_body are still live; the returned
        // `ResumeAccept` is owned (no borrows) and stays valid past
        // the subsequent `drain_rx`.
        let (client_x25519_pub, session_id_echo, sid_len, resume_accept) = {
            let ch = ClientHello::parse(hs_body).map_err(|_| HandshakeError::UnsupportedClient)?;
            trace::client_hello(&ch);
            let mut sid = [0u8; 32];
            let sid_len = ch.legacy_session_id.len();
            sid[..sid_len].copy_from_slice(ch.legacy_session_id);
            let pub_key = ch.x25519_client_pub.ok_or(HandshakeError::UnsupportedClient)?;

            let resume_accept = if let Some(psk_offer) = ch.psk.as_ref() {
                let pre = profile::start();
                let r = try_resume(body, psk_offer, ch.psk_ke_modes);
                if r.is_some() {
                    profile::mark(profile::Stage::PskBinder, pre);
                }
                r
            } else {
                None
            };

            (pub_key, sid, sid_len, resume_accept)
        };
        if resume_accept.is_some() {
            trace::step(b"[tls] ClientHello parsed (resumed)\n");
        } else {
            trace::step(b"[tls] ClientHello parsed\n");
        }

        // Update transcript with the full handshake message (body is
        // still borrowed into self.rx_buf; that's fine — transcript
        // reads it and releases).
        self.transcript.update(body);

        // Consume the ClientHello record from rx_buf. After this the
        // `body`/`hs_body` borrows are invalid; we've already extracted
        // everything we need into owned locals.
        self.drain_rx(consumed);
        let t = profile::mark(profile::Stage::Parse, t);

        // ── Generate and emit ServerHello ──────────────────────────
        // Server random: 32 bytes of entropy.
        //
        // `getrandom` bridges both worlds: on the unikernel build
        // it's routed to `uni_kernel::rng` via
        // `register_custom_getrandom!` (see kernel/rng.rs); on native
        // builds it falls through to the host OS entropy source
        // (`/dev/urandom`, `getentropy(2)`, etc.). Either way the
        // call can't fail in practice, and we treat a failure as a
        // fatal Internal error because it means we can't finish the
        // handshake.
        let mut server_random = [0u8; 32];
        getrandom::getrandom(&mut server_random).map_err(|_| HandshakeError::Internal)?;
        // Our ephemeral X25519 public key:
        let ephemeral = self.ephemeral.take().ok_or(HandshakeError::Internal)?;
        let server_pub = ephemeral.public_bytes();

        // Build ServerHello body + handshake wrapper + plaintext record.
        // On resumption we additionally emit a `pre_shared_key` extension
        // carrying the matching identity index, and we'll skip the
        // Certificate + CertificateVerify flight further down.
        let selected_psk_identity = resume_accept.as_ref().map(|r| r.selected_identity);
        let mut sh_body = [0u8; 256];
        let sh_len = build_server_hello(
            &server_random,
            &session_id_echo[..sid_len],
            &server_pub,
            selected_psk_identity,
            &mut sh_body,
        )
        .ok_or(HandshakeError::Internal)?;
        let mut sh_msg = [0u8; 280];
        let sh_msg_len = encode_handshake(msg_type::SERVER_HELLO, &sh_body[..sh_len], &mut sh_msg)
            .ok_or(HandshakeError::Internal)?;

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
        let t = profile::mark(profile::Stage::ServerHello, t);

        // ── Compute shared secret + derive handshake traffic keys ──
        let shared = ephemeral.shared_secret(&client_x25519_pub);
        let t = profile::mark(profile::Stage::Ecdhe, t);
        // If we're resuming, swap in the PSK-seeded schedule before
        // entering the handshake stage. `enter_handshake` reads
        // `self.schedule.secret` (the early secret) as one of its
        // inputs to the HKDF cascade, so this MUST happen before that
        // call. The dropped default schedule wipes its zeros via
        // `Drop for KeySchedule`.
        let resumed = if let Some(ra) = resume_accept {
            self.schedule = ra.schedule;
            true
        } else {
            false
        };
        let transcript_h1 = self.transcript.snapshot();
        let hs_secrets = self.schedule.enter_handshake(&shared, &transcript_h1);
        self.client_hs_secret = Some(hs_secrets.client_hs);
        self.server_hs_secret = Some(hs_secrets.server_hs);
        self.client_hs_tk = Some(TrafficKey::from_secret(&hs_secrets.client_hs));
        let mut server_hs_tk = TrafficKey::from_secret(&hs_secrets.server_hs);
        let t = profile::mark(profile::Stage::HkdfHs, t);

        // ── Middlebox-compat: emit a plaintext ChangeCipherSpec ────
        // RFC 8446 §D.4: a TLS 1.3 server that wants to interop with
        // middleboxes sends a dummy ChangeCipherSpec (0x14 0x03 0x03
        // 0x00 0x01 0x01) immediately after ServerHello. Clients that
        // also sent a session_id expect it. We always send it; it's
        // harmless.
        let ccs: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        if TX_BUF_LEN - self.tx_len < ccs.len() {
            return Err(HandshakeError::TxBufTooSmall);
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
            build_encrypted_extensions(&[], &mut ee_body).ok_or(HandshakeError::Internal)?;
        let mut ee_msg = [0u8; 32];
        let ee_msg_len = encode_handshake(
            msg_type::ENCRYPTED_EXTENSIONS,
            &ee_body[..ee_body_len],
            &mut ee_msg,
        )
        .ok_or(HandshakeError::Internal)?;
        self.transcript.update(&ee_msg[..ee_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &ee_msg[..ee_msg_len])?;
        trace::step(b"[tls] EncryptedExtensions sealed\n");
        let t = profile::mark(profile::Stage::EncExt, t);

        // Certificate + CertificateVerify — fresh handshakes only.
        // RFC 8446 §2.2: a successfully resumed PSK handshake
        // authenticates via the binder + the resumed key material;
        // the server flight skips both the Certificate and
        // CertificateVerify messages. Saving roughly half the
        // handshake's wall-time on the resumed path is the whole
        // point of resumption.
        let t = if !resumed {
            // Certificate
            // Build into a stack buffer; 2 KB handles our 500-ish-byte dev cert.
            let mut cert_body = [0u8; 2048];
            let cert_body_len = build_certificate(config.cert_der, &mut cert_body)
                .ok_or(HandshakeError::Internal)?;
            let mut cert_msg = [0u8; 2100];
            let cert_msg_len = encode_handshake(
                msg_type::CERTIFICATE,
                &cert_body[..cert_body_len],
                &mut cert_msg,
            )
            .ok_or(HandshakeError::Internal)?;
            self.transcript.update(&cert_msg[..cert_msg_len]);
            self.seal_handshake_record(&mut server_hs_tk, &cert_msg[..cert_msg_len])?;
            trace::step(b"[tls] Certificate sealed\n");
            let t = profile::mark(profile::Stage::Cert, t);

            // CertificateVerify: sign the transcript hash through Certificate.
            // ECDSA P-256 + SHA-256 per TLS 1.3 sig_scheme::ECDSA_SECP256R1_SHA256.
            // `SigningKey::sign` pre-hashes the message with SHA-256 (the
            // signature::Signer impl for p256::ecdsa::SigningKey) and uses
            // RFC 6979 deterministic `k` so we don't need an RNG here.
            // The returned Signature is then DER-encoded into the
            // `SEQUENCE { INTEGER r, INTEGER s }` shape TLS 1.3 requires
            // on the wire. The SigningKey itself is pre-constructed in
            // the shared TlsServerConfig so we don't pay a redundant
            // `d*G` scalar multiplication per handshake just to populate
            // the unused `verifying_key` field.
            let transcript_hash = self.transcript.snapshot();
            let mut sign_content = [0u8; 130];
            sign_content_server_cert_verify(&transcript_hash, &mut sign_content);
            let signature: EcdsaSignature = config.signing_key.sign(&sign_content);
            let der_sig = signature.to_der();
            let signature_bytes: &[u8] = der_sig.as_bytes();
            let t = profile::mark(profile::Stage::CvSign, t);

            let mut cv_body = [0u8; 128];
            let cv_body_len = build_certificate_verify(signature_bytes, &mut cv_body)
                .ok_or(HandshakeError::Internal)?;
            let mut cv_msg = [0u8; 150];
            let cv_msg_len = encode_handshake(
                msg_type::CERTIFICATE_VERIFY,
                &cv_body[..cv_body_len],
                &mut cv_msg,
            )
            .ok_or(HandshakeError::Internal)?;
            self.transcript.update(&cv_msg[..cv_msg_len]);
            self.seal_handshake_record(&mut server_hs_tk, &cv_msg[..cv_msg_len])?;
            trace::step(b"[tls] CertificateVerify sealed\n");
            profile::mark(profile::Stage::CvSeal, t)
        } else {
            t
        };

        // Server Finished
        // verify_data = HMAC(finished_key, Transcript-Hash(CH ... CertVerify))
        let server_finished_key = derive_finished_key(&hs_secrets.server_hs);
        let transcript_for_sfin = self.transcript.snapshot();
        let sf_verify = hmac_sha256(&server_finished_key, &transcript_for_sfin);
        let mut sf_body = [0u8; HASH_LEN];
        let sf_body_len =
            build_finished(&sf_verify, &mut sf_body).ok_or(HandshakeError::Internal)?;
        let mut sf_msg = [0u8; 48];
        let sf_msg_len = encode_handshake(
            msg_type::FINISHED,
            &sf_body[..sf_body_len],
            &mut sf_msg,
        )
        .ok_or(HandshakeError::Internal)?;
        self.transcript.update(&sf_msg[..sf_msg_len]);
        self.seal_handshake_record(&mut server_hs_tk, &sf_msg[..sf_msg_len])?;
        trace::step(b"[tls] ServerFinished sealed, entering WaitClientFinished\n");
        let t = profile::mark(profile::Stage::Finished, t);

        // Store the updated server handshake traffic key (its seq
        // counter has advanced across the 4 sealed records).
        self.server_hs_tk = Some(server_hs_tk);

        // ── Derive application traffic secrets ─────────────────────
        // Transcript hash is now through ServerFinished.
        let transcript_h2 = self.transcript.snapshot();
        let app_secrets = self.schedule.enter_application(&transcript_h2);
        self.client_ap_tk = Some(TrafficKey::from_secret(&app_secrets.client_ap));
        self.server_ap_tk = Some(TrafficKey::from_secret(&app_secrets.server_ap));
        profile::mark(profile::Stage::HkdfAp, t);
        profile::bump_count();

        self.state = State::WaitClientFinished;
        Ok(())
    }

    fn seal_handshake_record(
        &mut self,
        tk: &mut TrafficKey,
        body: &[u8],
    ) -> Result<(), HandshakeError> {
        let needed = HEADER_LEN + body.len() + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
            return Err(HandshakeError::TxBufTooSmall);
        }
        let n = record_seal(tk, content_type::HANDSHAKE, body, &mut self.tx_buf[self.tx_len..])?;
        self.tx_len += n;
        Ok(())
    }

    /// Handle the WaitClientFinished state. Parses one incoming
    /// encrypted record under the client handshake traffic key and
    /// expects it to contain a Finished message.
    pub(super) fn do_client_finished(&mut self) -> Result<(), HandshakeError> {
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
            .ok_or(HandshakeError::Internal)?;
        let (inner_type, pt, consumed) = record_open(tk, &mut self.rx_buf[..total])?;
        trace::decrypted_record(inner_type, pt.len());
        if inner_type == content_type::ALERT && pt.len() >= 2 {
            trace::alert_received(pt[0], pt[1]);
        }
        if inner_type != content_type::HANDSHAKE {
            return Err(HandshakeError::UnexpectedRecord);
        }
        // Parse the handshake message out of the decrypted body.
        // `pt` borrows from self.rx_buf; copy it out so we can drain.
        let mut msg_copy = [0u8; 256];
        if pt.len() > msg_copy.len() {
            return Err(HandshakeError::Internal);
        }
        let pt_len = pt.len();
        msg_copy[..pt_len].copy_from_slice(pt);
        // Drop the pt borrow.
        let _ = pt;
        let (hs_type, hs_body) = parse_handshake(&msg_copy[..pt_len])?;
        if hs_type != msg_type::FINISHED {
            return Err(HandshakeError::UnexpectedRecord);
        }
        let client_verify = parse_finished(hs_body)?;

        // Expected verify_data = HMAC(client_finished_key, transcript)
        // where transcript covers CH .. Server Finished (NOT including
        // the client Finished itself).
        let client_hs_secret = self
            .client_hs_secret
            .as_ref()
            .ok_or(HandshakeError::Internal)?;
        let client_finished_key = derive_finished_key(client_hs_secret);
        let expected_verify = hmac_sha256(&client_finished_key, &self.transcript.snapshot());

        if !ct_eq_32(client_verify, &expected_verify) {
            trace::step(b"[tls]   BadClientFinished: verify_data mismatch\n");
            return Err(HandshakeError::BadClientFinished);
        }

        // Now we can update the transcript with Client Finished.
        self.transcript.update(&msg_copy[..pt_len]);
        // Consume the record.
        self.drain_rx(consumed);

        // Issue exactly one resumption ticket. The handshake state
        // machine has already advanced `self.schedule.secret` to
        // master_secret (via `enter_application` in do_client_hello),
        // and the transcript above has just been updated with
        // ClientFinished — both preconditions for `resumption_secret`
        // (RFC 8446 §7.1). Failure here is treated as soft: a logged
        // trace + drop the ticket. The handshake itself is already
        // complete; clients that wanted resumption simply won't get it.
        if let Err(e) = self.emit_session_ticket() {
            trace::error(self.state, &e);
        }

        self.state = State::Established;
        trace::step(b"[tls] Client Finished verified -> Established\n");
        Ok(())
    }

    /// Build, seal, and emit one NewSessionTicket post-handshake
    /// message. Called from `do_client_finished` immediately before
    /// the Established transition. The TX buffer must have room for
    /// the (currently small) sealed record; if it doesn't, we surface
    /// `TxBufTooSmall` so the caller can decide whether the conn is
    /// still usable (it is — the handshake completed).
    fn emit_session_ticket(&mut self) -> Result<(), HandshakeError> {
        // Derive resumption_master_secret over the transcript that
        // now ends with ClientFinished.
        let post_cf_transcript = self.transcript.snapshot();
        let rms = self.schedule.resumption_secret(&post_cf_transcript);

        // RNG: ticket_age_add is a u32 that obscures absolute ticket
        // age (RFC 8446 §4.2.11.1). Failure to draw RNG is fatal for
        // the ticket but not for the handshake.
        let mut age_bytes = [0u8; 4];
        if getrandom::getrandom(&mut age_bytes).is_err() {
            return Err(HandshakeError::Internal);
        }
        let age_add = u32::from_be_bytes(age_bytes);

        // Seal the ticket plaintext. Wipe the rms after we've handed
        // ownership to the (drop-impl-zeroizing) TicketPlaintext.
        let pt = TicketPlaintext {
            version: TICKET_VERSION,
            resumption_master_secret: rms,
            ticket_age_add: age_add,
            issued_at_cycles: ticket_now_cycles(),
            cipher_suite: cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
        };
        let mut sealed = [0u8; SEALED_LEN];
        let n = seal_ticket(&pt, &mut sealed).ok_or(HandshakeError::Internal)?;
        debug_assert_eq!(n, SEALED_LEN);

        // Wrap the sealed blob in a NewSessionTicket body, then in a
        // handshake header, then in an encrypted record under
        // server_ap_tk. The body is small (~100 bytes), so a stack
        // buffer is fine.
        let mut nst_body = [0u8; SEALED_LEN + 32];
        // ticket_nonce = "" — we issue exactly one ticket per
        // connection, so the nonce-distinguisher RFC 8446 mentions
        // serves no purpose here.
        // TCP TLS resumption path doesn't yet advertise 0-RTT
        // (Phase E in the QUIC roadmap). Empty extensions list.
        let body_len = build_new_session_ticket(
            TICKET_LIFETIME_SECONDS,
            age_add,
            &[],
            &sealed[..n],
            &[], // no extensions (no early_data)
            &mut nst_body,
        )
        .ok_or(HandshakeError::Internal)?;

        let mut nst_msg = [0u8; SEALED_LEN + 64];
        let msg_len = encode_handshake(
            msg_type::NEW_SESSION_TICKET,
            &nst_body[..body_len],
            &mut nst_msg,
        )
        .ok_or(HandshakeError::Internal)?;

        let tk = self
            .server_ap_tk
            .as_mut()
            .ok_or(HandshakeError::Internal)?;
        let needed = HEADER_LEN + msg_len + 1 + record::TAG_LEN;
        if TX_BUF_LEN - self.tx_len < needed {
            return Err(HandshakeError::TxBufTooSmall);
        }
        let written = record_seal(
            tk,
            content_type::HANDSHAKE,
            &nst_msg[..msg_len],
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += written;
        trace::step(b"[tls] NewSessionTicket sealed\n");
        Ok(())
    }

    /// Once established, decrypt incoming application-data records
    /// and buffer the plaintext.
    pub(super) fn do_app_data(&mut self) -> Result<(), HandshakeError> {
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
                .ok_or(HandshakeError::Internal)?;
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
                    return Err(HandshakeError::UnexpectedRecord);
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
