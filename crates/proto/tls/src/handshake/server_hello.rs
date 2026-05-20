// ServerHello + ServerHello pre_shared_key extension builders.
//
// We only ever issue ServerHellos for one shape:
//   cipher_suite = TLS_AES_128_GCM_SHA256
//   key_share    = X25519
// Other suites / groups are unsupported by this crate, so the builder
// is concrete rather than parameterised on suite.

use super::{LEGACY_VERSION_TLS12, VERSION_TLS13, cipher_suite, ext_type, named_group};

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
}
