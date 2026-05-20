// Builders + parsers for the post-ServerHello handshake messages
// the server sends/consumes:
//
//   EncryptedExtensions      RFC 8446 §4.3.1
//   Certificate              RFC 8446 §4.4.2
//   CertificateVerify        RFC 8446 §4.4.3
//   Finished (build + parse) RFC 8446 §4.4.4
//   NewSessionTicket         RFC 8446 §4.6.1
//
// All are sans-io byte-slice helpers — the caller wraps each body with
// `encode_handshake(...)` before handing it to the record layer.

use super::{HASH_LEN, ParseError, sig_scheme};

// ============================================================================
// EncryptedExtensions builder (RFC 8446 §4.3.1)
// ============================================================================

/// Build an EncryptedExtensions message body.
///
/// `extras` lets the caller append zero-or-more extensions. The
/// TLS-over-TCP path passes `&[]` (no negotiated extensions); the
/// QUIC path passes the `quic_transport_parameters` blob (RFC 9001
/// §8.2) plus, for HTTP/3, the `application_layer_protocol_
/// negotiation` echo (RFC 7301).
///
/// Wire layout: `u16 extensions_length || (extension_envelope ...)`.
/// Each extension envelope is `u16 ext_type || u16 ext_len || bytes`.
///
/// Returns bytes written, or `None` if `out` is too small or the
/// total extensions length exceeds `0xffff`.
pub fn build_encrypted_extensions(extras: &[(u16, &[u8])], out: &mut [u8]) -> Option<usize> {
    let body_len: usize = extras.iter().map(|(_, d)| 4 + d.len()).sum();
    if body_len > 0xffff || out.len() < 2 + body_len {
        return None;
    }
    out[0] = ((body_len >> 8) & 0xff) as u8;
    out[1] = (body_len & 0xff) as u8;
    let mut p = 2usize;
    for (ty, data) in extras {
        out[p..p + 2].copy_from_slice(&ty.to_be_bytes());
        let len = data.len() as u16;
        out[p + 2..p + 4].copy_from_slice(&len.to_be_bytes());
        out[p + 4..p + 4 + data.len()].copy_from_slice(data);
        p += 4 + data.len();
    }
    Some(2 + body_len)
}

// ============================================================================
// Certificate builder (RFC 8446 §4.4.2)
// ============================================================================

/// Build a TLS 1.3 `Certificate` message body with a single cert entry.
///
/// Wire format:
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///     opaque cert_data<1..2^24-1>;   /* X.509 DER */
///     Extension extensions<0..2^16-1>; /* empty for us */
/// } CertificateEntry;
/// ```
///
/// `cert_der` is the single X.509 DER cert we're sending. We don't support
/// cert chains in this first cut — if the client needs intermediates they
/// must already trust the leaf directly (self-signed dev cert case).
///
/// Returns the number of bytes written. The layout is deterministic so
/// the caller can predict the total size as:
///   1 (ctx len=0) + 3 (list len) + 3 (cert len) + cert_der.len() + 2 (ext len=0)
pub fn build_certificate(cert_der: &[u8], out: &mut [u8]) -> Option<usize> {
    let entry_len = 3 + cert_der.len() + 2; // cert_len(3) + cert_der + ext_len(2)
    let total = 1 + 3 + entry_len; // ctx_len(1) + list_len(3) + entry
    if out.len() < total || cert_der.len() > 0xff_ffff {
        return None;
    }

    let mut p = 0;
    // certificate_request_context: 0 bytes
    out[p] = 0;
    p += 1;
    // certificate_list length (uint24, big-endian)
    out[p] = ((entry_len >> 16) & 0xff) as u8;
    out[p + 1] = ((entry_len >> 8) & 0xff) as u8;
    out[p + 2] = (entry_len & 0xff) as u8;
    p += 3;
    // CertificateEntry: cert_data length (uint24)
    out[p] = ((cert_der.len() >> 16) & 0xff) as u8;
    out[p + 1] = ((cert_der.len() >> 8) & 0xff) as u8;
    out[p + 2] = (cert_der.len() & 0xff) as u8;
    p += 3;
    // cert_data
    out[p..p + cert_der.len()].copy_from_slice(cert_der);
    p += cert_der.len();
    // extensions (u16 length = 0)
    out[p] = 0;
    out[p + 1] = 0;
    p += 2;

    debug_assert_eq!(p, total);
    Some(p)
}

// ============================================================================
// CertificateVerify builder (RFC 8446 §4.4.3)
// ============================================================================

/// The "content to sign" for the server's CertificateVerify message.
/// RFC 8446 §4.4.3 specifies:
///
///     64 bytes of 0x20 | "TLS 1.3, server CertificateVerify" | 0x00 | transcript_hash
///
/// Returns the exact bytes that must be fed into the signature function.
/// Output length = 64 + 33 + 1 + HASH_LEN = 130.
pub fn sign_content_server_cert_verify(transcript_hash: &[u8; HASH_LEN], out: &mut [u8; 130]) {
    // 64 bytes of 0x20 padding
    out[0..64].fill(0x20);
    // Context string — exactly as quoted in the RFC.
    let ctx = b"TLS 1.3, server CertificateVerify";
    out[64..64 + ctx.len()].copy_from_slice(ctx);
    debug_assert_eq!(ctx.len(), 33);
    // Separator byte 0x00
    out[64 + 33] = 0x00;
    // Transcript hash
    out[64 + 33 + 1..].copy_from_slice(transcript_hash);
}

/// Build a CertificateVerify message body from a pre-computed ECDSA
/// signature over `sign_content_server_cert_verify(...)`. The signature
/// must be in ASN.1 DER form — `SEQUENCE { INTEGER r, INTEGER s }` —
/// which is what TLS 1.3 (RFC 8446 §4.2.3) mandates for ECDSA. Length
/// is variable (~70–72 bytes) because r and s get sign-extended by DER.
///
/// Wire format:
/// ```text
/// struct {
///     SignatureScheme algorithm;      /* u16 = 0x0403 for P-256 */
///     opaque signature<0..2^16-1>;    /* DER-encoded r,s INTEGER pair */
/// } CertificateVerify;
/// ```
///
/// Caller is responsible for actually computing the signature (we don't
/// want this module to depend on `p256`; that's `//crates/proto/tls`'s job).
pub fn build_certificate_verify(signature: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 2 + 2 + signature.len();
    if out.len() < total || signature.len() > 0xffff {
        return None;
    }
    out[0..2].copy_from_slice(&sig_scheme::ECDSA_SECP256R1_SHA256.to_be_bytes());
    out[2..4].copy_from_slice(&(signature.len() as u16).to_be_bytes());
    out[4..4 + signature.len()].copy_from_slice(signature);
    Some(total)
}

// ============================================================================
// NewSessionTicket builder (RFC 8446 §4.6.1)
// ============================================================================

/// Build a `NewSessionTicket` body (the bytes that go AFTER the
/// `encode_handshake(NEW_SESSION_TICKET, ...)` header).
///
/// Wire format:
/// ```text
/// struct {
///     uint32 ticket_lifetime;        /* seconds; max 7 days per spec */
///     uint32 ticket_age_add;         /* random per-ticket value */
///     opaque ticket_nonce<0..255>;   /* distinguishes multi-ticket emits */
///     opaque ticket<1..2^16-1>;      /* the opaque resumption blob */
///     Extension extensions<0..2^16-2>;  /* empty for our use */
/// } NewSessionTicket;
/// ```
///
/// The `ticket` argument is the already-sealed ticket bytes (commit 2
/// produces these via `seal_ticket`); this function only frames them.
/// `extensions` is a pre-encoded extensions blob (each entry being
/// `ext_type:u16 || ext_len:u16 || ext_data`). Pass `&[]` for the
/// 1-RTT-only case (TCP TLS resumption); QUIC 0-RTT callers pass the
/// `early_data` extension envelope (RFC 9001 §4.6.1) here.
///
/// Returns the number of bytes written, or `None` if `out` is too
/// small or any field exceeds its wire-encoded bound.
pub fn build_new_session_ticket(
    lifetime_seconds: u32,
    age_add: u32,
    ticket_nonce: &[u8],
    ticket: &[u8],
    extensions: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if ticket_nonce.len() > 255 {
        return None;
    }
    if ticket.is_empty() || ticket.len() > 0xffff {
        return None;
    }
    if extensions.len() > 0xfffe {
        return None;
    }
    let total = 4 + 4 + 1 + ticket_nonce.len() + 2 + ticket.len() + 2 + extensions.len();
    if out.len() < total {
        return None;
    }

    let mut p = 0usize;
    out[p..p + 4].copy_from_slice(&lifetime_seconds.to_be_bytes());
    p += 4;
    out[p..p + 4].copy_from_slice(&age_add.to_be_bytes());
    p += 4;
    out[p] = ticket_nonce.len() as u8;
    p += 1;
    out[p..p + ticket_nonce.len()].copy_from_slice(ticket_nonce);
    p += ticket_nonce.len();
    out[p..p + 2].copy_from_slice(&(ticket.len() as u16).to_be_bytes());
    p += 2;
    out[p..p + ticket.len()].copy_from_slice(ticket);
    p += ticket.len();
    // Extensions list: u16 length prefix + bytes.
    out[p..p + 2].copy_from_slice(&(extensions.len() as u16).to_be_bytes());
    p += 2;
    out[p..p + extensions.len()].copy_from_slice(extensions);
    p += extensions.len();

    debug_assert_eq!(p, total);
    Some(p)
}

// ============================================================================
// Finished builder + parser (RFC 8446 §4.4.4)
// ============================================================================

/// Build a Finished message body. The body IS the verify_data — there's
/// no extra framing inside a Finished message.
///
/// Caller computes `verify_data = HMAC(finished_key, transcript_hash)`
/// and passes it here. For `TLS_AES_128_GCM_SHA256` (our only suite)
/// the output is 32 bytes (SHA-256 HMAC).
pub fn build_finished(verify_data: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = verify_data.len();
    if out.len() < n {
        return None;
    }
    out[..n].copy_from_slice(verify_data);
    Some(n)
}

/// Parse a Finished message body. Simply exposes the verify_data bytes
/// so the caller can constant-time-compare them against the expected
/// HMAC.
pub fn parse_finished(body: &[u8]) -> Result<&[u8], ParseError> {
    // TLS 1.3 Finished has no inner framing — the whole body is
    // verify_data. Length must equal the HMAC output (HASH_LEN for
    // SHA-256 suites).
    if body.len() != HASH_LEN {
        return Err(ParseError::BadLength);
    }
    Ok(body)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::ext_type;
    use super::*;

    #[test]
    fn encrypted_extensions_is_empty_extension_list() {
        let mut out = [0u8; 8];
        let n = build_encrypted_extensions(&[], &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&out[..n], &[0x00, 0x00]);
    }

    #[test]
    fn encrypted_extensions_with_quic_transport_parameters() {
        // Two-byte body, ext_type = 0x0039.
        let blob = [0xab, 0xcd];
        let extras: &[(u16, &[u8])] = &[(ext_type::QUIC_TRANSPORT_PARAMETERS, &blob)];
        let mut out = [0u8; 16];
        let n = build_encrypted_extensions(extras, &mut out).unwrap();
        // body = ext_type(2) + ext_len(2) + blob(2) = 6 → total = 2 + 6.
        assert_eq!(n, 8);
        assert_eq!(&out[..2], &[0x00, 0x06]);
        assert_eq!(&out[2..4], &[0x00, 0x39]);
        assert_eq!(&out[4..6], &[0x00, 0x02]);
        assert_eq!(&out[6..8], &blob);
    }

    #[test]
    fn encrypted_extensions_with_two_extensions() {
        let qtp = [0x10u8, 0x20];
        // ALPN echo body: u16 list_len || u8 name_len || name.
        let alpn_body = [0u8, 3, 2, b'h', b'3'];
        let extras: &[(u16, &[u8])] = &[
            (ext_type::QUIC_TRANSPORT_PARAMETERS, &qtp),
            (ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &alpn_body),
        ];
        let mut out = [0u8; 32];
        let n = build_encrypted_extensions(extras, &mut out).unwrap();
        // body = (4 + 2) + (4 + 5) = 15. Total = 17.
        assert_eq!(n, 17);
        assert_eq!(&out[..2], &[0x00, 0x0f]);
    }

    #[test]
    fn certificate_single_entry_layout() {
        // 10-byte fake cert DER.
        let cert_der = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x01];
        let mut out = [0u8; 64];
        let n = build_certificate(&cert_der, &mut out).unwrap();

        // Expected: ctx_len(1) + list_len(3) + cert_len(3) + cert(10) + ext_len(2) = 19
        assert_eq!(n, 19);
        // certificate_request_context length = 0
        assert_eq!(out[0], 0);
        // certificate_list length = 15 (3 cert_len + 10 cert + 2 ext)
        assert_eq!(&out[1..4], &[0, 0, 15]);
        // cert_data length = 10
        assert_eq!(&out[4..7], &[0, 0, 10]);
        // cert_data
        assert_eq!(&out[7..17], &cert_der[..]);
        // extensions length = 0
        assert_eq!(&out[17..19], &[0, 0]);
    }

    #[test]
    fn certificate_verify_layout_for_ecdsa_p256() {
        // Fake 71-byte DER ECDSA signature (realistic typical length
        // for P-256: 2 + 2*(1+1+32) ≈ 70-72 bytes).
        let sig = [0x22u8; 71];
        let mut out = [0u8; 128];
        let n = build_certificate_verify(&sig, &mut out).unwrap();

        // algorithm(2) + sig_len(2) + sig(71) = 75
        assert_eq!(n, 75);
        // algorithm = ecdsa_secp256r1_sha256 = 0x0403
        assert_eq!(&out[0..2], &[0x04, 0x03]);
        // signature length = 71
        assert_eq!(&out[2..4], &[0x00, 0x47]);
        // signature bytes
        assert_eq!(&out[4..75], &sig[..]);
    }

    #[test]
    fn cert_verify_sign_content_matches_rfc8446() {
        // RFC 8446 §4.4.3: the content to sign is
        //   64 * 0x20 | "TLS 1.3, server CertificateVerify" | 0x00 | transcript_hash
        let transcript = [0x42u8; HASH_LEN];
        let mut content = [0u8; 130];
        sign_content_server_cert_verify(&transcript, &mut content);

        // First 64 bytes are all 0x20.
        assert!(content[..64].iter().all(|&b| b == 0x20));
        // Next 33 bytes are the context string.
        assert_eq!(&content[64..97], b"TLS 1.3, server CertificateVerify");
        // Separator byte.
        assert_eq!(content[97], 0x00);
        // Transcript hash.
        assert_eq!(&content[98..130], &transcript[..]);
    }

    #[test]
    fn finished_build_and_parse_roundtrip() {
        let verify_data = [0x55u8; HASH_LEN];
        let mut out = [0u8; 64];
        let n = build_finished(&verify_data, &mut out).unwrap();
        assert_eq!(n, HASH_LEN);
        assert_eq!(&out[..n], &verify_data[..]);

        let parsed = parse_finished(&out[..n]).unwrap();
        assert_eq!(parsed, &verify_data[..]);
    }

    #[test]
    fn finished_parse_rejects_wrong_length() {
        // Short
        assert!(parse_finished(&[0u8; 16]).is_err());
        // Long
        assert!(parse_finished(&[0u8; 64]).is_err());
    }

    #[test]
    fn new_session_ticket_layout() {
        // Spec wire example: lifetime=600, age_add=0xdeadbeef,
        // nonce=[0x01,0x02], ticket=10 bytes, ext_len=0.
        let nonce = [0x01u8, 0x02];
        let ticket = [0x99u8; 10];
        let mut out = [0u8; 64];
        let n = build_new_session_ticket(600, 0xdead_beef, &nonce, &ticket, &[], &mut out).unwrap();

        // Layout: 4 + 4 + 1 + 2 + 2 + 10 + 2 = 25
        assert_eq!(n, 25);
        // lifetime
        assert_eq!(&out[0..4], &600u32.to_be_bytes());
        // age_add
        assert_eq!(&out[4..8], &0xdead_beefu32.to_be_bytes());
        // nonce_len
        assert_eq!(out[8], 2);
        assert_eq!(&out[9..11], &nonce[..]);
        // ticket length (u16)
        assert_eq!(&out[11..13], &10u16.to_be_bytes());
        // ticket bytes
        assert_eq!(&out[13..23], &ticket[..]);
        // empty extensions
        assert_eq!(&out[23..25], &[0, 0]);
    }

    #[test]
    fn new_session_ticket_rejects_oversize_nonce() {
        let big_nonce = [0u8; 256];
        let mut out = [0u8; 1024];
        assert!(build_new_session_ticket(60, 0, &big_nonce, &[1, 2, 3], &[], &mut out).is_none());
    }

    #[test]
    fn new_session_ticket_rejects_empty_ticket() {
        let mut out = [0u8; 64];
        assert!(build_new_session_ticket(60, 0, &[], &[], &[], &mut out).is_none());
    }
}
