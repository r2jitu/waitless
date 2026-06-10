// Builders + parsers for the post-ServerHello handshake messages
// the server sends/consumes:
//
//   EncryptedExtensions      RFC 8446 §4.3.1
//   Certificate              RFC 8446 §4.4.2
//   CertificateVerify        RFC 8446 §4.4.3
//   Finished (build + parse) RFC 8446 §4.4.4
//   NewSessionTicket         RFC 8446 §4.6.1
//
// …plus the mirror PARSERS the client role (`client.rs`) needs to
// consume the same flight: `parse_encrypted_extensions`,
// `parse_certificate_leaf`, `parse_certificate_verify`.
//
// All are sans-io byte-slice helpers — the caller wraps each body with
// `encode_handshake(...)` before handing it to the record layer.

use super::reader::Reader;
use super::{HASH_LEN, ParseError, ext_type, sig_scheme};

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
// EncryptedExtensions parser (client role's mirror half)
// ============================================================================

/// Parsed view of an EncryptedExtensions body — just the two
/// extensions the client role cares about. Unknown extensions are
/// tolerated/skipped.
#[derive(Clone, Copy)]
pub struct EncryptedExtensionsView<'a> {
    /// The single ALPN protocol name the server selected (RFC 7301
    /// §3.2), if it echoed one. The caller checks it against its
    /// offered list.
    pub alpn_protocol: Option<&'a [u8]>,
    /// Raw `quic_transport_parameters` blob (RFC 9001 §8.2), for the
    /// future QUIC client driver. `None` over TCP.
    pub quic_transport_parameters: Option<&'a [u8]>,
}

/// Parse an EncryptedExtensions body: `u16 extensions_len || (u16
/// ext_type || u16 ext_len || data)*`. Bounds-checked throughout; no
/// input can panic.
pub fn parse_encrypted_extensions(body: &[u8]) -> Result<EncryptedExtensionsView<'_>, ParseError> {
    let mut r = Reader::new(body);
    let ext_bytes = r.read_vector_u16()?;
    if !r.is_empty() {
        return Err(ParseError::BadLength);
    }
    let mut er = Reader::new(ext_bytes);
    let mut alpn_protocol = None;
    let mut quic_transport_parameters = None;
    while !er.is_empty() {
        let ext_type_v = er.read_u16()?;
        let ext_data = er.read_vector_u16()?;
        match ext_type_v {
            ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                // RFC 7301 §3.2: the server's echo carries EXACTLY one
                // protocol name: u16 list_len || u8 name_len || name.
                let mut ar = Reader::new(ext_data);
                let names = ar.read_vector_u16()?;
                if !ar.is_empty() {
                    return Err(ParseError::BadExtension);
                }
                let mut nr = Reader::new(names);
                let name = nr.read_vector_u8()?;
                if name.is_empty() || !nr.is_empty() {
                    return Err(ParseError::BadExtension);
                }
                alpn_protocol = Some(name);
            }
            ext_type::QUIC_TRANSPORT_PARAMETERS => {
                quic_transport_parameters = Some(ext_data);
            }
            _ => { /* tolerate/skip unknown extensions */ }
        }
    }
    Ok(EncryptedExtensionsView {
        alpn_protocol,
        quic_transport_parameters,
    })
}

// ============================================================================
// Certificate builder (RFC 8446 §4.4.2)
// ============================================================================

/// Build a TLS 1.3 `Certificate` message body from a certificate
/// chain — leaf first, then any intermediate CA certificates.
///
/// Wire format:
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///     opaque cert_data<1..2^24-1>;     /* X.509 DER */
///     Extension extensions<0..2^16-1>; /* empty for us */
/// } CertificateEntry;
/// ```
///
/// `chain[0]` is the end-entity (leaf) certificate; `chain[1..]` are
/// the intermediates a client needs to build a path to a trusted
/// root. A self-signed dev cert is a one-element chain. A real CA
/// (Let's Encrypt) leaf needs its issuing intermediate appended, or
/// clients reject the connection with `unknown_ca`.
///
/// Returns the number of bytes written, or `None` if `out` is too
/// small, the chain is empty, or the encoding overflows a 2^24 cap.
pub fn build_certificate(chain: &[&[u8]], out: &mut [u8]) -> Option<usize> {
    if chain.is_empty() {
        return None;
    }
    // certificate_list is the concatenation of one CertificateEntry
    // per cert: cert_len(3) + cert_data + ext_len(2).
    let mut list_len = 0usize;
    for cert in chain {
        if cert.len() > 0xff_ffff {
            return None;
        }
        list_len += 3 + cert.len() + 2;
    }
    let total = 1 + 3 + list_len; // ctx_len(1) + list_len(3) + entries
    if out.len() < total || list_len > 0xff_ffff {
        return None;
    }

    let mut p = 0;
    // certificate_request_context: 0 bytes
    out[p] = 0;
    p += 1;
    // certificate_list length (uint24, big-endian)
    out[p] = ((list_len >> 16) & 0xff) as u8;
    out[p + 1] = ((list_len >> 8) & 0xff) as u8;
    out[p + 2] = (list_len & 0xff) as u8;
    p += 3;
    for cert in chain {
        // CertificateEntry: cert_data length (uint24)
        out[p] = ((cert.len() >> 16) & 0xff) as u8;
        out[p + 1] = ((cert.len() >> 8) & 0xff) as u8;
        out[p + 2] = (cert.len() & 0xff) as u8;
        p += 3;
        // cert_data
        out[p..p + cert.len()].copy_from_slice(cert);
        p += cert.len();
        // extensions (u16 length = 0)
        out[p] = 0;
        out[p + 1] = 0;
        p += 2;
    }

    debug_assert_eq!(p, total);
    Some(p)
}

/// Parse a Certificate body and return the LEAF certificate's DER
/// bytes (the first `CertificateEntry`'s `cert_data`).
///
/// The client role authenticates by SPKI pin on the leaf, so the rest
/// of the chain is irrelevant — its entries are not even walked (the
/// list length is bounds-checked; trailing entries stay opaque).
/// Full chain / web-PKI validation is a documented non-goal.
pub fn parse_certificate_leaf(body: &[u8]) -> Result<&[u8], ParseError> {
    let mut r = Reader::new(body);
    // certificate_request_context<0..2^8-1> — empty for server auth;
    // skipped either way.
    let _ctx = r.read_vector_u8()?;
    // certificate_list<0..2^24-1>
    let list = r.read_vector_u24()?;
    if !r.is_empty() {
        return Err(ParseError::BadLength);
    }
    let mut lr = Reader::new(list);
    // First CertificateEntry: cert_data<1..2^24-1> + extensions.
    let leaf = lr.read_vector_u24()?;
    if leaf.is_empty() {
        return Err(ParseError::BadLength);
    }
    let _leaf_extensions = lr.read_vector_u16()?;
    Ok(leaf)
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

/// Parse a CertificateVerify body: `(SignatureScheme, signature)`.
/// The caller checks the scheme and verifies the DER-encoded ECDSA
/// signature against the §4.4.3 signed content.
pub fn parse_certificate_verify(body: &[u8]) -> Result<(u16, &[u8]), ParseError> {
    let mut r = Reader::new(body);
    let algorithm = r.read_u16()?;
    let signature = r.read_vector_u16()?;
    if !r.is_empty() {
        return Err(ParseError::BadLength);
    }
    Ok((algorithm, signature))
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
        // 10-byte fake cert DER — a one-element chain (the dev cert).
        let cert_der: [u8; 10] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x01];
        let mut out = [0u8; 64];
        let n = build_certificate(&[&cert_der], &mut out).unwrap();

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
    fn certificate_two_entry_chain_layout() {
        // A leaf + one intermediate — the shape of a real CA chain.
        let leaf: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let intermediate: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut out = [0u8; 64];
        let n = build_certificate(&[&leaf, &intermediate], &mut out).unwrap();

        // ctx(1) + list_len(3) + [cert_len(3)+leaf(4)+ext(2)]
        //                      + [cert_len(3)+intermediate(6)+ext(2)] = 24
        assert_eq!(n, 24);
        assert_eq!(out[0], 0, "request context is empty");
        // certificate_list length = 9 + 11 = 20
        assert_eq!(&out[1..4], &[0, 0, 20]);
        // first entry: the leaf, leaf-first ordering
        assert_eq!(&out[4..7], &[0, 0, 4], "first entry length = leaf");
        assert_eq!(&out[7..11], &leaf[..]);
        assert_eq!(&out[11..13], &[0, 0], "first entry extensions empty");
        // second entry: the intermediate
        assert_eq!(&out[13..16], &[0, 0, 6], "second entry length = intermediate");
        assert_eq!(&out[16..22], &intermediate[..]);
        assert_eq!(&out[22..24], &[0, 0], "second entry extensions empty");
    }

    #[test]
    fn certificate_rejects_an_empty_chain() {
        let mut out = [0u8; 64];
        assert!(
            build_certificate(&[], &mut out).is_none(),
            "an empty chain has no leaf to send",
        );
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

    // ── Client-role mirror parsers ──────────────────────────────────

    #[test]
    fn parse_encrypted_extensions_round_trips_builder() {
        // Empty EE (the fresh TCP path).
        let mut out = [0u8; 64];
        let n = build_encrypted_extensions(&[], &mut out).unwrap();
        let ee = parse_encrypted_extensions(&out[..n]).unwrap();
        assert!(ee.alpn_protocol.is_none());
        assert!(ee.quic_transport_parameters.is_none());

        // ALPN echo + a QUIC transport-params blob.
        let alpn_body = [0u8, 3, 2, b'h', b'2'];
        let qtp = [0xab, 0xcd];
        let extras: &[(u16, &[u8])] = &[
            (ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &alpn_body),
            (ext_type::QUIC_TRANSPORT_PARAMETERS, &qtp),
        ];
        let n = build_encrypted_extensions(extras, &mut out).unwrap();
        let ee = parse_encrypted_extensions(&out[..n]).unwrap();
        assert_eq!(ee.alpn_protocol, Some(&b"h2"[..]));
        assert_eq!(ee.quic_transport_parameters, Some(&qtp[..]));
    }

    #[test]
    fn parse_encrypted_extensions_rejects_malformed() {
        // Trailing junk after the extensions vector.
        assert_eq!(
            parse_encrypted_extensions(&[0x00, 0x00, 0xff]).err(),
            Some(ParseError::BadLength)
        );
        // ALPN echo with TWO names is not a valid server selection.
        let alpn_two = [0u8, 6, 2, b'h', b'2', 2, b'h', b'3'];
        let extras: &[(u16, &[u8])] = &[(
            ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            &alpn_two,
        )];
        let mut out = [0u8; 64];
        let n = build_encrypted_extensions(extras, &mut out).unwrap();
        assert_eq!(
            parse_encrypted_extensions(&out[..n]).err(),
            Some(ParseError::BadExtension)
        );
        // Truncated never panics.
        for end in 0..n {
            let _ = parse_encrypted_extensions(&out[..end]);
        }
    }

    #[test]
    fn parse_certificate_leaf_round_trips_builder() {
        let leaf: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
        let intermediate: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut out = [0u8; 64];
        let n = build_certificate(&[&leaf, &intermediate], &mut out).unwrap();
        let parsed = parse_certificate_leaf(&out[..n]).unwrap();
        assert_eq!(parsed, &leaf[..]);
        // Truncations never panic.
        for end in 0..n {
            let _ = parse_certificate_leaf(&out[..end]);
        }
    }

    #[test]
    fn parse_certificate_verify_round_trips_builder() {
        let sig = [0x22u8; 71];
        let mut out = [0u8; 128];
        let n = build_certificate_verify(&sig, &mut out).unwrap();
        let (alg, parsed_sig) = parse_certificate_verify(&out[..n]).unwrap();
        assert_eq!(alg, sig_scheme::ECDSA_SECP256R1_SHA256);
        assert_eq!(parsed_sig, &sig[..]);
        // Trailing junk is rejected; truncations never panic.
        let mut long = out[..n].to_vec();
        long.push(0);
        assert!(parse_certificate_verify(&long).is_err());
        for end in 0..n {
            let _ = parse_certificate_verify(&out[..end]);
        }
    }
}
