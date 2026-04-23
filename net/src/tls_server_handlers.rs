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

use super::handshake::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_server_hello, encode_handshake, msg_type, parse_finished, parse_handshake,
    sign_content_server_cert_verify, ClientHello, ParseError,
};
use super::record::{self, content_type, open as record_open, seal as record_seal, RecordError, HEADER_LEN};
use super::tls::{TrafficKey, HASH_LEN};

use super::keys::{ct_eq_32, derive_finished_key, hmac_sha256};
use super::profile;
use super::trace;
use super::{State, TlsError, TlsServer, TlsServerConfig, TX_BUF_LEN};

impl TlsServer {
    /// Handle the WaitClientHello state. Looks for one plaintext record
    /// of content_type::handshake containing ClientHello. If found,
    /// emits the full server flight into tx_buf and transitions to
    /// WaitClientFinished.
    pub(super) fn do_client_hello(&mut self, config: &TlsServerConfig) -> Result<(), TlsError> {
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
        getrandom::getrandom(&mut server_random).map_err(|_| TlsError::Internal)?;
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
        let t = profile::mark(profile::Stage::ServerHello, t);

        // ── Compute shared secret + derive handshake traffic keys ──
        let shared = ephemeral.shared_secret(&client_x25519_pub);
        let t = profile::mark(profile::Stage::Ecdhe, t);
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
        let t = profile::mark(profile::Stage::EncExt, t);

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
        let t = profile::mark(profile::Stage::CvSeal, t);

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
    pub(super) fn do_client_finished(&mut self) -> Result<(), TlsError> {
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
    pub(super) fn do_app_data(&mut self) -> Result<(), TlsError> {
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
