// net/tls_server_handlers.rs — TLS 1.3 handshake state handlers.
//
// Implements the three non-terminal transitions of the server state
// machine as `impl super::TlsServer` methods. The crate-root
// `process_chunk` orchestrator frames one record at a time off the
// inbound TCP chunk and dispatches to:
//
//     WaitClientHello    -> do_client_hello    -> WaitClientFinished
//     WaitClientFinished -> do_client_finished -> Established
//     Established        -> do_app_data        -> Established | Closed
//
// Handlers take a `record: &mut [u8]` of the exact bytes of one
// complete TLS record (header + body — encrypted or plaintext per
// state), AEAD-decrypt them in place when needed, push any
// decrypted application plaintext to `pending_plaintext` as an
// owned Heap IOBuf, and emit sealed handshake records into
// `tx_buf`. No direct I/O.

use p256::ecdsa::{Signature as EcdsaSignature, signature::Signer};

use crate::handshake::{
    ClientHello, ParseError, PskOffer, build_certificate, build_certificate_verify,
    build_encrypted_extensions, build_finished, build_new_session_ticket, build_server_hello,
    cipher_suite, encode_handshake, ext_type, iter_alpn, msg_type, parse_finished, parse_handshake,
    psk_ke_mode, sign_content_server_cert_verify,
};
use crate::record::{
    self, HEADER_LEN, RecordError, content_type, open as record_open, seal as record_seal,
};
use crate::schedule::{
    HASH_LEN, KeySchedule, TrafficKey, derive_secret, empty_transcript_hash, hkdf_expand_label,
    secure_zero,
};

use sha2::{Digest as _, Sha256};

use crate::keys::{ct_eq_32, derive_finished_key, hmac_sha256};
use crate::profile;
use crate::server::{HandshakeError, State, TX_BUF_LEN, TlsServer, TlsServerConfig};
use crate::ticket::{
    SEALED_LEN, TICKET_LIFETIME_SECONDS, TICKET_VERSION, TicketPlaintext, open_ticket, seal_ticket,
};
use crate::trace;

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
    let cyc_per_us = kernel_bare::time::cycles_per_us();
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
        if opened.cipher_suite != cipher_suite::TLS_AES_128_GCM_SHA256 {
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
        let binder_key = derive_secret(candidate.secret(), b"res binder", &empty_transcript_hash());
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
    /// Handle the WaitClientHello state. `record` is one complete
    /// plaintext TLS record framed by the chunk orchestrator —
    /// expected to carry a ClientHello (`content_type::handshake`).
    /// On success the full server flight is emitted into tx_buf and
    /// state advances to WaitClientFinished.
    pub(super) fn do_client_hello(
        &mut self,
        record: &mut [u8],
        config: &TlsServerConfig,
    ) -> Result<(), HandshakeError> {
        // Begin per-stage cycle profile. `t` threads through each
        // stage boundary via `profile::mark()` until the handshake is
        // complete.
        let t = profile::start();
        // The orchestrator already framed exactly one complete
        // plaintext record. Parse the header and content.
        let (ct, body, _consumed) = record::parse_plaintext(record).map_err(|e| {
            // Truncation here would mean the orchestrator framed a
            // shorter record than the header advertised — which is
            // impossible given the framing pass — but map to
            // RecordError just in case to keep the trace token
            // stable.
            HandshakeError::from(if matches!(e, RecordError::Truncated) {
                RecordError::RecordTooLarge
            } else {
                e
            })
        })?;
        if ct != content_type::HANDSHAKE {
            return Err(HandshakeError::UnexpectedRecord);
        }
        // Parse handshake type. ClientHello always fits in one
        // record in practice; a `Truncated` parse here would mean
        // the inner handshake-length field exceeds the framed
        // record body — a malformed client.
        let (hs_type, hs_body) = match parse_handshake(body) {
            Ok(tuple) => tuple,
            Err(ParseError::Truncated) => return Err(HandshakeError::UnsupportedClient),
            Err(e) => return Err(e.into()),
        };
        if hs_type != msg_type::CLIENT_HELLO {
            return Err(HandshakeError::UnexpectedRecord);
        }

        // Parse ClientHello for the fields we need (client random,
        // session_id, X25519 share). We copy the few fields we care
        // about into owned locals immediately so we can drop the
        // borrow into `record` and continue. The resumption attempt
        // is bracketed inside the same scope so PskOffer's slices
        // into hs_body are still live; the returned `ResumeAccept`
        // is owned (no borrows) and stays valid past return.
        // Buffer for the selected ALPN protocol name. We pull it out
        // of `ch.alpn_protocol_list` while ch is still in scope (the
        // list borrows into `hs_body` which dies with `body`), then
        // copy the chosen name into a small stack array so we can
        // use it later in EncryptedExtensions. `selected_alpn_len`
        // == 0 means "client didn't offer ALPN" — we skip the
        // extension entirely in that case.
        let mut selected_alpn = [0u8; 8]; // longest currently-supported is "http/1.1" (8)
        let mut selected_alpn_len: usize = 0;

        let (client_x25519_pub, session_id_echo, sid_len, resume_accept) = {
            let ch = ClientHello::parse(hs_body).map_err(|_| HandshakeError::UnsupportedClient)?;
            trace::client_hello(&ch);
            let mut sid = [0u8; 32];
            let sid_len = ch.legacy_session_id.len();
            sid[..sid_len].copy_from_slice(ch.legacy_session_id);
            let pub_key = ch
                .x25519_client_pub
                .ok_or(HandshakeError::UnsupportedClient)?;

            // RFC 7301 §3.2: if the client offered ALPN and we
            // support a name in their list, we MUST echo the
            // selected name in EncryptedExtensions. Modern Chrome
            // refuses to fall back on a missing-ALPN ServerHello
            // when it offered `h2,http/1.1` — surfaces as
            // ERR_SSL_PROTOCOL_ERROR. We don't speak HTTP/2, so
            // `http/1.1` is the only protocol we select on the
            // TCP/TLS path. (HTTP/3 is selected separately by
            // `quic`'s own EncryptedExtensions builder.)
            if let Some(alpn_list) = ch.alpn_protocol_list {
                for name in iter_alpn(alpn_list) {
                    if name == b"http/1.1" {
                        selected_alpn[..name.len()].copy_from_slice(name);
                        selected_alpn_len = name.len();
                        break;
                    }
                }
            }

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

        // Update transcript with the full handshake message. `body`
        // borrows from `record` (the chunk slice); transcript copies
        // through SHA-256 update, the borrow ends here.
        self.transcript.update(body);
        let t = profile::mark(profile::Stage::Parse, t);

        // ── Generate and emit ServerHello ──────────────────────────
        // Server random: 32 bytes of entropy.
        //
        // `getrandom` bridges both worlds: on the unikernel build
        // it's routed to `kernel_bare::rng` via
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

        // EncryptedExtensions. If the client offered ALPN and we
        // selected a protocol above, echo it back per RFC 7301 §3.2.
        // Wire body for ALPN: u16 list_len || u8 name_len || name.
        // For our 8-byte max name ("http/1.1"), the body fits in 12
        // bytes — fully stack-allocated.
        let mut alpn_body_buf = [0u8; 12];
        let alpn_body_len = if selected_alpn_len > 0 {
            let list_len = (1 + selected_alpn_len) as u16;
            alpn_body_buf[0..2].copy_from_slice(&list_len.to_be_bytes());
            alpn_body_buf[2] = selected_alpn_len as u8;
            alpn_body_buf[3..3 + selected_alpn_len]
                .copy_from_slice(&selected_alpn[..selected_alpn_len]);
            3 + selected_alpn_len
        } else {
            0
        };
        let extras_storage: [(u16, &[u8]); 1] = [(
            ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            &alpn_body_buf[..alpn_body_len],
        )];
        let extras: &[(u16, &[u8])] = if alpn_body_len > 0 {
            &extras_storage[..]
        } else {
            &[]
        };
        // 32 bytes covers: 2 (body_len) + 4 (ext envelope) + 12
        // (ALPN body) = 18; rounded up.
        let mut ee_body = [0u8; 32];
        let ee_body_len =
            build_encrypted_extensions(extras, &mut ee_body).ok_or(HandshakeError::Internal)?;
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
            // Build into a stack buffer. 4 KiB covers a self-signed
            // dev cert and a real CA chain (leaf + one ECDSA
            // intermediate ≈ 1.6 KiB body); `build_certificate`
            // returns `None` — failing the handshake cleanly — if a
            // larger chain ever overflows it.
            let mut cert_body = [0u8; 4096];
            let cert_body_len = build_certificate(config.cert_chain, &mut cert_body)
                .ok_or(HandshakeError::Internal)?;
            let mut cert_msg = [0u8; 4128];
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
        let sf_msg_len = encode_handshake(msg_type::FINISHED, &sf_body[..sf_body_len], &mut sf_msg)
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
        let n = record_seal(
            tk,
            content_type::HANDSHAKE,
            body,
            &mut self.tx_buf[self.tx_len..],
        )?;
        self.tx_len += n;
        Ok(())
    }

    /// Handle the WaitClientFinished state. `record` is one
    /// complete TLS record framed by the chunk orchestrator —
    /// either a middlebox-compat ChangeCipherSpec (which we skip)
    /// or the client's encrypted Finished message.
    pub(super) fn do_client_finished(
        &mut self,
        record: &mut [u8],
    ) -> Result<(), HandshakeError> {
        trace::do_client_finished_entry(record.len(), record.first().copied());

        // Middlebox-compat: a plaintext CCS (0x14) record can land
        // here per RFC 8446 §D.4. Just drop it — state stays
        // WaitClientFinished and the next record will be the real
        // encrypted Finished.
        if record[0] == content_type::CHANGE_CIPHER_SPEC {
            // Validate the framing is at least syntactically a
            // record (5-byte header + body).
            let _ = record::parse_plaintext(record)?;
            trace::step(b"[tls]   skipped ChangeCipherSpec\n");
            return Ok(());
        }

        let total = record.len();
        trace::record_header(record[0], total);

        // Decrypt in place under the client handshake traffic key.
        let tk = self.client_hs_tk.as_mut().ok_or(HandshakeError::Internal)?;
        let (inner_type, pt, _consumed) = record_open(tk, record)?;
        trace::decrypted_record(inner_type, pt.len());
        if inner_type == content_type::ALERT && pt.len() >= 2 {
            trace::alert_received(pt[0], pt[1]);
        }
        if inner_type != content_type::HANDSHAKE {
            return Err(HandshakeError::UnexpectedRecord);
        }
        // Parse the handshake message out of the decrypted body.
        // `pt` borrows from `record`; copy it out so the transcript
        // update can take a separate `&mut self.transcript` borrow
        // without aliasing.
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
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
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

        let tk = self.server_ap_tk.as_mut().ok_or(HandshakeError::Internal)?;
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

    /// Once established, decrypt one incoming application_data
    /// record and enqueue its plaintext for the app. The chunk
    /// orchestrator frames the record; this handler only AEAD-opens
    /// it and pushes a fresh Heap `IOBuf` carrying the plaintext to
    /// `pending_plaintext`.
    pub(super) fn do_app_data(&mut self, record: &mut [u8]) -> Result<(), HandshakeError> {
        let tk = self.client_ap_tk.as_mut().ok_or(HandshakeError::Internal)?;
        let (inner_type, pt, _consumed) = record_open(tk, record)?;
        match inner_type {
            content_type::APPLICATION_DATA => {
                // Lift the plaintext slice (borrow into `record`) to
                // an owned Heap IOBuf so the chunk's storage can be
                // released back to the NIC pool the moment
                // process_chunk returns. Empty records are legal
                // (RFC 8446 §5.4 anti-traffic-analysis padding may
                // produce zero-length content) but uninteresting to
                // surface as a "chunk" — the consumer's reader would
                // see them as a false zero-byte EOF. Drop silently.
                if pt.is_empty() {
                    return Ok(());
                }
                let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                if v.try_reserve_exact(pt.len()).is_err() {
                    return Err(HandshakeError::Internal);
                }
                v.extend_from_slice(pt);
                // Drop the pt borrow into `record` before mutating
                // self below (push_back may grow the deque).
                let _ = pt;
                if self.pending_plaintext.try_reserve(1).is_err() {
                    return Err(HandshakeError::Internal);
                }
                self.pending_plaintext.push_back(v);
                Ok(())
            }
            content_type::ALERT => {
                // Peer close_notify or fatal alert. Either way we
                // move to Closed.
                let _ = pt;
                self.state = State::Closed;
                Ok(())
            }
            _ => Err(HandshakeError::UnexpectedRecord),
        }
    }
}
