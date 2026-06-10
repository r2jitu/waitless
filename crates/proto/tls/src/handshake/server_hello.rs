// ServerHello + ServerHello pre_shared_key extension builders, and the
// mirror ServerHello PARSER used by the client role (`client.rs`).
//
// We only ever issue ServerHellos for one shape:
//   cipher_suite = TLS_AES_128_GCM_SHA256
//   key_share    = X25519
// Other suites / groups are unsupported by this crate, so the builder
// is concrete rather than parameterised on suite — and the parser is
// equally strict (anything else fails with `Unsupported`).

use super::reader::Reader;
use super::{LEGACY_VERSION_TLS12, ParseError, VERSION_TLS13, cipher_suite, ext_type, named_group};

/// Build a ServerHello body for TLS 1.3 with
/// cipher_suite = TLS_AES_128_GCM_SHA256 and key_share = X25519.
///
/// `selected_psk_identity` is `Some(idx)` when the server is accepting
/// a resumption offer — `idx` indexes into the client's PskIdentity
/// list and goes out as the body of the ServerHello `pre_shared_key`
/// extension (RFC 8446 §4.2.11). `None` for fresh handshakes.
///
/// Writes into `out` and returns the body length. The caller should
/// wrap the result with `encode_handshake(SERVER_HELLO, body, ...)`.
pub fn build_server_hello(
    server_random: &[u8; 32],
    legacy_session_id_echo: &[u8],
    server_x25519_pub: &[u8; 32],
    selected_psk_identity: Option<u16>,
    out: &mut [u8],
) -> Option<usize> {
    // Layout (fresh handshake — without `selected_psk_identity`):
    //   u16  legacy_version = 0x0303
    //   32   random
    //   u8   session_id_len  + bytes
    //   u16  cipher_suite = 0x1303
    //   u8   legacy_compression = 0
    //   u16  extensions_len
    //     u16  ext_type = supported_versions
    //     u16  ext_len = 2
    //     u16  selected_version = 0x0304
    //     u16  ext_type = key_share
    //     u16  ext_len = 4 + 32
    //     u16  group = x25519
    //     u16  key_exchange_len = 32
    //     32   key_exchange
    //
    // Resumption: append a `pre_shared_key` extension carrying the
    // u16 selected_identity (RFC 8446 §4.2.11). +6 bytes to `ext_total`.
    if legacy_session_id_echo.len() > 32 {
        return None;
    }

    // Extensions total (written first so we know the length):
    //   supported_versions: 2 + 2 + 2 = 6
    //   key_share:          2 + 2 + 2 + 2 + 32 = 40
    //   pre_shared_key:     2 + 2 + 2 = 6 (resumption only)
    let psk_ext_len: u16 = if selected_psk_identity.is_some() {
        6
    } else {
        0
    };
    let ext_total: u16 = 6 + 40 + psk_ext_len;
    let sid_len = legacy_session_id_echo.len();
    let total = 2 + 32 + 1 + sid_len + 2 + 1 + 2 + ext_total as usize;
    if out.len() < total {
        return None;
    }

    let mut p = 0usize;
    // legacy_version
    out[p..p + 2].copy_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
    p += 2;
    // random
    out[p..p + 32].copy_from_slice(server_random);
    p += 32;
    // legacy_session_id_echo
    out[p] = sid_len as u8;
    p += 1;
    out[p..p + sid_len].copy_from_slice(legacy_session_id_echo);
    p += sid_len;
    // cipher_suite
    out[p..p + 2].copy_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
    p += 2;
    // legacy_compression_method = null
    out[p] = 0;
    p += 1;
    // extensions length
    out[p..p + 2].copy_from_slice(&ext_total.to_be_bytes());
    p += 2;

    // supported_versions extension
    out[p..p + 2].copy_from_slice(&ext_type::SUPPORTED_VERSIONS.to_be_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&2u16.to_be_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&VERSION_TLS13.to_be_bytes());
    p += 2;

    // key_share extension
    out[p..p + 2].copy_from_slice(&ext_type::KEY_SHARE.to_be_bytes());
    p += 2;
    // ext body = group(2) + key_exchange_len(2) + key_exchange(32) = 36
    out[p..p + 2].copy_from_slice(&36u16.to_be_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&named_group::X25519.to_be_bytes());
    p += 2;
    out[p..p + 2].copy_from_slice(&32u16.to_be_bytes());
    p += 2;
    out[p..p + 32].copy_from_slice(server_x25519_pub);
    p += 32;

    // Optional pre_shared_key extension (resumption).
    if let Some(idx) = selected_psk_identity {
        let psk_written = build_server_pre_shared_key_ext(idx, &mut out[p..])?;
        p += psk_written;
    }

    debug_assert_eq!(p, total);
    Some(p)
}

/// Build the `pre_shared_key` extension a server emits inside its
/// ServerHello when accepting a resumed handshake. The body is just
/// a u16 `selected_identity` indexing into the client's offered
/// identities list — the server picks which ticket it accepted.
///
/// Output is the full extension envelope: `ext_type(2) || ext_len(2) ||
/// selected_identity(2)` = 6 bytes.
///
/// `out` must have at least 6 bytes; returns `Some(6)` on success,
/// `None` if the buffer is too small.
pub fn build_server_pre_shared_key_ext(selected_identity: u16, out: &mut [u8]) -> Option<usize> {
    if out.len() < 6 {
        return None;
    }
    out[0..2].copy_from_slice(&ext_type::PRE_SHARED_KEY.to_be_bytes());
    out[2..4].copy_from_slice(&2u16.to_be_bytes());
    out[4..6].copy_from_slice(&selected_identity.to_be_bytes());
    Some(6)
}

// ============================================================================
// ServerHello parser (RFC 8446 §4.1.3) — the client role's mirror half
// ============================================================================

/// RFC 8446 §4.1.3: a ServerHello whose `random` equals this value is
/// a HelloRetryRequest in disguise. (The constant is SHA-256 of
/// "HelloRetryRequest" — pinned by a test below.)
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8,
    0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8,
    0x33, 0x9C,
];

/// Parsed view of a ServerHello body. Byte slices point into the
/// input buffer — a view, not owned data.
#[derive(Clone, Copy)]
pub struct ServerHelloView<'a> {
    /// Server random (32 bytes).
    pub random: &'a [u8; 32],
    /// The echoed legacy_session_id — the client checks it equals
    /// what it sent (RFC 8446 §4.1.3). Empty for an HRR view.
    pub legacy_session_id_echo: &'a [u8],
    /// `true` when `random` is the HelloRetryRequest sentinel. The
    /// rest of the view is NOT populated in that case — HRR re-uses
    /// the ServerHello frame but changes the key_share format, and
    /// HRR support is a documented non-goal (we always offer x25519,
    /// so a compliant server never needs to retry us).
    pub is_hello_retry_request: bool,
    /// The server's X25519 public key from its key_share extension.
    /// Always `Some` on the non-HRR path (the parser fails with
    /// `Unsupported` otherwise).
    pub x25519_server_pub: Option<[u8; 32]>,
    /// `true` when the server echoed a `pre_shared_key` extension
    /// (it accepted a resumption offer). The v1 client never offers
    /// a PSK, so it treats this as a protocol violation.
    pub has_pre_shared_key: bool,
}

/// Parse a ServerHello body (the bytes AFTER the handshake header).
///
/// Strict mirror of our builder: the cipher suite must be
/// `TLS_AES_128_GCM_SHA256`, `supported_versions` must select 0x0304,
/// and a 32-byte X25519 key_share must be present — anything else is
/// `Unsupported`. Unknown extensions are skipped (tolerated). A
/// HelloRetryRequest-shaped hello short-circuits: the view comes back
/// with `is_hello_retry_request = true` and no further validation, so
/// the caller can surface its own distinct error.
///
/// Attacker-facing parser discipline: all reads go through the
/// bounds-checked `Reader`; no input can panic (fuzz-smoke below).
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHelloView<'_>, ParseError> {
    let mut r = Reader::new(body);

    // legacy_version — fixed 0x0303 on the wire; ignored (the real
    // version is in supported_versions, exactly like the CH parser).
    let _legacy_version = r.read_u16()?;

    let random_slice = r.read_bytes(32)?;
    let random: &[u8; 32] = random_slice.try_into().map_err(|_| ParseError::BadLength)?;
    if *random == HELLO_RETRY_REQUEST_RANDOM {
        // HRR re-purposes the ServerHello frame with a different
        // key_share payload — don't validate further, just flag it.
        return Ok(ServerHelloView {
            random,
            legacy_session_id_echo: &[],
            is_hello_retry_request: true,
            x25519_server_pub: None,
            has_pre_shared_key: false,
        });
    }

    let legacy_session_id_echo = r.read_vector_u8()?;
    if legacy_session_id_echo.len() > 32 {
        return Err(ParseError::BadLength);
    }

    let suite = r.read_u16()?;
    if suite != cipher_suite::TLS_AES_128_GCM_SHA256 {
        return Err(ParseError::Unsupported);
    }

    let compression = r.read_bytes(1)?;
    if compression[0] != 0 {
        // TLS 1.3 ServerHello MUST carry null compression.
        return Err(ParseError::Unsupported);
    }

    let ext_bytes = r.read_vector_u16()?;
    if !r.is_empty() {
        return Err(ParseError::BadLength);
    }

    let mut er = Reader::new(ext_bytes);
    let mut selected_tls13 = false;
    let mut x25519_server_pub: Option<[u8; 32]> = None;
    let mut has_pre_shared_key = false;
    while !er.is_empty() {
        let ext_type_v = er.read_u16()?;
        let ext_data = er.read_vector_u16()?;
        match ext_type_v {
            ext_type::SUPPORTED_VERSIONS => {
                // ServerHello form: exactly one u16 selected_version.
                if ext_data.len() != 2 {
                    return Err(ParseError::BadExtension);
                }
                let v = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                if v != VERSION_TLS13 {
                    return Err(ParseError::Unsupported);
                }
                selected_tls13 = true;
            }
            ext_type::KEY_SHARE => {
                // ServerHello form: a single KeyShareEntry (no list
                // prefix): group(u16) || key_exchange<1..2^16-1>.
                let mut kr = Reader::new(ext_data);
                let group = kr.read_u16()?;
                let key_exchange = kr.read_vector_u16()?;
                if !kr.is_empty() {
                    return Err(ParseError::BadExtension);
                }
                if group != named_group::X25519 || key_exchange.len() != 32 {
                    return Err(ParseError::Unsupported);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(key_exchange);
                x25519_server_pub = Some(pk);
            }
            ext_type::PRE_SHARED_KEY => {
                // Body is a u16 selected_identity.
                if ext_data.len() != 2 {
                    return Err(ParseError::BadExtension);
                }
                has_pre_shared_key = true;
            }
            _ => { /* tolerate/skip unknown extensions */ }
        }
    }

    if !selected_tls13 {
        // RFC 8446 §4.1.3: supported_versions is mandatory in a
        // TLS 1.3 ServerHello. Its absence means the peer negotiated
        // TLS 1.2-or-below — unsupported.
        return Err(ParseError::Unsupported);
    }
    if x25519_server_pub.is_none() {
        return Err(ParseError::Unsupported);
    }

    Ok(ServerHelloView {
        random,
        legacy_session_id_echo,
        is_hello_retry_request: false,
        x25519_server_pub,
        has_pre_shared_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_hello_layout() {
        let random = [0xaau8; 32];
        let sid_echo = [];
        let server_pub = [0xccu8; 32];
        let mut out = [0u8; 256];
        let n = build_server_hello(&random, &sid_echo, &server_pub, None, &mut out).unwrap();

        // Parse back the first few fields to sanity-check.
        assert_eq!(&out[0..2], &[0x03, 0x03]); // legacy_version
        assert_eq!(&out[2..34], &random[..]);
        assert_eq!(out[34], 0); // session_id length
        assert_eq!(&out[35..37], &[0x13, 0x01]); // cipher_suite (TLS_AES_128_GCM_SHA256)
        assert_eq!(out[37], 0); // legacy_compression
        // extensions_len = 46
        assert_eq!(u16::from_be_bytes([out[38], out[39]]), 46);
        // supported_versions
        assert_eq!(&out[40..42], &[0x00, 0x2b]); // ext_type
        assert_eq!(u16::from_be_bytes([out[42], out[43]]), 2);
        assert_eq!(&out[44..46], &[0x03, 0x04]); // 0x0304
        // key_share
        assert_eq!(&out[46..48], &[0x00, 0x33]); // ext_type
        assert_eq!(u16::from_be_bytes([out[48], out[49]]), 36);
        assert_eq!(&out[50..52], &[0x00, 0x1d]); // x25519
        assert_eq!(u16::from_be_bytes([out[52], out[53]]), 32);
        assert_eq!(&out[54..86], &server_pub[..]);
        assert_eq!(n, 86);
    }

    #[test]
    fn server_hello_with_psk_appends_extension() {
        let random = [0xbbu8; 32];
        let sid = [];
        let server_pub = [0xccu8; 32];
        let mut out = [0u8; 256];
        let n = build_server_hello(&random, &sid, &server_pub, Some(0x1234), &mut out).unwrap();
        // Without PSK: 86 bytes (server_hello_layout test).
        // With PSK: +6 bytes for the pre_shared_key extension envelope.
        assert_eq!(n, 92);
        // extensions_len = 46 (fresh) + 6 (psk) = 52
        assert_eq!(u16::from_be_bytes([out[38], out[39]]), 52);
        // The PSK extension sits at the very end: type 0x0029, len 2, body 0x1234.
        assert_eq!(&out[86..88], &[0x00, 0x29]);
        assert_eq!(&out[88..90], &[0x00, 0x02]);
        assert_eq!(&out[90..92], &[0x12, 0x34]);
    }

    #[test]
    fn server_pre_shared_key_ext_layout() {
        let mut out = [0u8; 16];
        let n = build_server_pre_shared_key_ext(0x0001, &mut out).unwrap();
        assert_eq!(n, 6);
        // ext_type = 0x0029 (41)
        assert_eq!(&out[0..2], &[0x00, 0x29]);
        // ext_len = 2
        assert_eq!(&out[2..4], &[0x00, 0x02]);
        // selected_identity = 1
        assert_eq!(&out[4..6], &[0x00, 0x01]);
    }

    #[test]
    fn server_pre_shared_key_ext_too_small_buffer() {
        let mut out = [0u8; 5];
        assert!(build_server_pre_shared_key_ext(0, &mut out).is_none());
    }

    // ── ServerHello parser (client role) ────────────────────────────

    /// The HRR sentinel is, per RFC 8446 §4.1.3, SHA-256 of the ASCII
    /// string "HelloRetryRequest" — pin the constant against the math.
    #[test]
    fn hrr_random_is_sha256_of_label() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"HelloRetryRequest");
        let digest: [u8; 32] = h.finalize().into();
        assert_eq!(digest, HELLO_RETRY_REQUEST_RANDOM);
    }

    /// Builder → parser round-trip: every field the builder emits is
    /// recovered, for both the fresh and resumption shapes.
    #[test]
    fn parse_server_hello_round_trips_builder() {
        let random = [0x5au8; 32];
        let sid = [0x66u8; 32];
        let server_pub = [0x99u8; 32];
        let mut out = [0u8; 256];

        let n = build_server_hello(&random, &sid, &server_pub, None, &mut out).unwrap();
        let sh = parse_server_hello(&out[..n]).expect("parse fresh");
        assert!(!sh.is_hello_retry_request);
        assert_eq!(sh.random, &random);
        assert_eq!(sh.legacy_session_id_echo, &sid[..]);
        assert_eq!(sh.x25519_server_pub, Some(server_pub));
        assert!(!sh.has_pre_shared_key);

        let n = build_server_hello(&random, &sid, &server_pub, Some(0), &mut out).unwrap();
        let sh = parse_server_hello(&out[..n]).expect("parse resumed");
        assert!(sh.has_pre_shared_key);
    }

    /// An HRR-shaped hello is flagged, not parsed strictly.
    #[test]
    fn parse_server_hello_detects_hrr() {
        let sid: [u8; 0] = [];
        let server_pub = [0x11u8; 32];
        let mut out = [0u8; 256];
        let n =
            build_server_hello(&HELLO_RETRY_REQUEST_RANDOM, &sid, &server_pub, None, &mut out)
                .unwrap();
        let sh = parse_server_hello(&out[..n]).expect("HRR view");
        assert!(sh.is_hello_retry_request);
        assert!(sh.x25519_server_pub.is_none());
    }

    /// Strictness: wrong cipher suite / missing supported_versions
    /// fail with `Unsupported` rather than mis-negotiating.
    #[test]
    fn parse_server_hello_rejects_wrong_suite() {
        let random = [0x42u8; 32];
        let sid: [u8; 0] = [];
        let server_pub = [0x11u8; 32];
        let mut out = [0u8; 256];
        let n = build_server_hello(&random, &sid, &server_pub, None, &mut out).unwrap();
        // With an empty session id the cipher suite sits at [35..37]
        // (see `server_hello_layout`). Corrupt it.
        out[36] = 0x02; // TLS_AES_256_GCM_SHA384
        assert_eq!(
            parse_server_hello(&out[..n]).err(),
            Some(ParseError::Unsupported)
        );
    }

    /// Fuzz-smoke (same discipline as `ClientHello::parse`): random
    /// buffers, single-byte mutations of a valid hello, and every
    /// truncation must return — never panic.
    #[test]
    fn parse_server_hello_fuzz_smoke_never_panics() {
        let random = [0x21u8; 32];
        let sid = [0x33u8; 32];
        let server_pub = [0x44u8; 32];
        let mut out = [0u8; 256];
        let n = build_server_hello(&random, &sid, &server_pub, Some(1), &mut out).unwrap();
        let valid = &out[..n];
        assert!(parse_server_hello(valid).is_ok(), "fixture must parse");

        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // (a) Raw random buffers, varied lengths incl. empty.
        for _ in 0..20_000 {
            let len = (rnd() % 256) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let _ = parse_server_hello(&buf);
        }
        // (b) Single-byte mutations at every position.
        for pos in 0..valid.len() {
            for _ in 0..32 {
                let mut m = valid.to_vec();
                m[pos] = rnd() as u8;
                let _ = parse_server_hello(&m);
            }
        }
        // (c) Truncations at every length.
        for end in 0..valid.len() {
            let _ = parse_server_hello(&valid[..end]);
        }
    }
}
