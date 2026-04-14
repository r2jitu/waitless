// net/tls_handshake.rs — TLS 1.3 handshake message framing + parser.
//
// Reads and writes the `Handshake` message format from RFC 8446 §4:
//
//   struct {
//       HandshakeType msg_type;     // 1 byte
//       uint24 length;              // 3 bytes, big-endian
//       select (Handshake.msg_type) {
//           case client_hello:    ClientHello;
//           case server_hello:    ServerHello;
//           ...
//       } body;
//   } Handshake;
//
// This module is sans-io: it takes/returns byte slices. The caller is
// responsible for record layer framing (TLSPlaintext / TLSCiphertext)
// and for piping bytes into and out of the TCP stream.
//
// Scope of this first cut:
// - Handshake message header encode/decode
// - `ClientHello` parser: legacy fields + the three TLS 1.3 extensions
//   we actually need (supported_versions, key_share, supported_groups).
// - `ServerHello` builder for TLS_CHACHA20_POLY1305_SHA256 + X25519.
//
// Explicitly out of scope (future work):
// - EncryptedExtensions / Certificate / CertificateVerify / Finished
// - signature_algorithms extension parsing
// - Pre-shared key / 0-RTT extensions
// - Session tickets / resumption
// - Alert record format

#![no_std]

// ============================================================================
// Constants
// ============================================================================

/// HandshakeType values from RFC 8446 §4.
pub mod msg_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const END_OF_EARLY_DATA: u8 = 5;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
}

/// ExtensionType values from the IANA registry.
pub mod ext_type {
    pub const SERVER_NAME: u16 = 0;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const KEY_SHARE: u16 = 51;
}

/// NamedGroup values (we only implement x25519).
pub mod named_group {
    pub const X25519: u16 = 0x001d;
}

/// CipherSuite values (we only implement one).
pub mod cipher_suite {
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
}

/// TLS 1.2 legacy_version value used in the outer ClientHello /
/// ServerHello header for middlebox compatibility.
pub const LEGACY_VERSION_TLS12: u16 = 0x0303;

/// The real version, as advertised in `supported_versions`.
pub const VERSION_TLS13: u16 = 0x0304;

// ============================================================================
// Handshake framing
// ============================================================================

/// Errors that can occur while parsing handshake messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input buffer too short to contain the next structure.
    Truncated,
    /// A declared length field exceeds the buffer.
    BadLength,
    /// The handshake type byte didn't match what the caller expected.
    WrongType,
    /// A required extension (e.g. supported_versions) was missing.
    MissingExtension,
    /// An extension's body wasn't formatted as the spec requires.
    BadExtension,
    /// The advertised ClientHello didn't include TLS 1.3 in
    /// `supported_versions`, or didn't offer X25519, or didn't send
    /// an X25519 key_share.
    Unsupported,
}

/// Parse a single handshake message header (4 bytes) and return
/// `(msg_type, body)`. The body is a slice pointing into `data`.
pub fn parse_handshake(data: &[u8]) -> Result<(u8, &[u8]), ParseError> {
    if data.len() < 4 {
        return Err(ParseError::Truncated);
    }
    let msg_type = data[0];
    let len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | (data[3] as usize);
    if 4 + len > data.len() {
        return Err(ParseError::BadLength);
    }
    Ok((msg_type, &data[4..4 + len]))
}

/// Write a handshake header (type + 3-byte length) followed by the
/// caller-provided body, returning the total number of bytes written.
pub fn encode_handshake(msg_type: u8, body: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 4 + body.len();
    if out.len() < total || body.len() > 0xff_ffff {
        return None;
    }
    out[0] = msg_type;
    out[1] = ((body.len() >> 16) & 0xff) as u8;
    out[2] = ((body.len() >> 8) & 0xff) as u8;
    out[3] = (body.len() & 0xff) as u8;
    out[4..total].copy_from_slice(body);
    Some(total)
}

// ============================================================================
// ClientHello parser (subset: only what TLS 1.3 + X25519 needs)
// ============================================================================

/// Parsed subset of a ClientHello. Byte slices point into the input
/// buffer — the struct is a view, not owned data.
#[derive(Clone, Copy)]
pub struct ClientHello<'a> {
    /// Echoed back in ServerHello for middlebox compat. May be empty.
    pub legacy_session_id: &'a [u8],
    /// Client random (32 bytes, used as ClientHello.random).
    pub random: &'a [u8; 32],
    /// The client's X25519 public key, from its key_share extension.
    pub x25519_client_pub: [u8; 32],
    /// Did the client offer TLS 1.3 in supported_versions?
    pub offers_tls13: bool,
    /// Did the client list X25519 in supported_groups?
    pub offers_x25519: bool,
}

impl<'a> ClientHello<'a> {
    /// Parse a ClientHello body (i.e. the bytes AFTER the handshake
    /// header). Returns the extracted view or `Err(ParseError)`.
    ///
    /// The parser is strict: if TLS 1.3 isn't advertised or the client
    /// didn't send an X25519 key_share, we fail with `Unsupported`
    /// rather than silently falling back. The caller is expected to
    /// abort the handshake in that case.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut r = Reader::new(body);

        // legacy_version (u16) — ignored for the TLS 1.3 check; the real
        // version lives in `supported_versions`.
        let _legacy_version = r.read_u16()?;

        // random (32 bytes)
        let random_slice = r.read_bytes(32)?;
        // SAFETY: read_bytes returned exactly 32 bytes, so the cast is valid.
        let random: &[u8; 32] = random_slice.try_into().map_err(|_| ParseError::BadLength)?;

        // legacy_session_id: opaque<0..32>
        let legacy_session_id = r.read_vector_u8()?;
        if legacy_session_id.len() > 32 {
            return Err(ParseError::BadLength);
        }

        // cipher_suites: opaque<2..2^16-2>
        // We don't currently enforce which cipher suite the server picks
        // from the client list — we just check for the one we support.
        let suites = r.read_vector_u16()?;
        if suites.len() % 2 != 0 {
            return Err(ParseError::BadLength);
        }
        let mut offers_chacha = false;
        let mut i = 0;
        while i < suites.len() {
            let s = u16::from_be_bytes([suites[i], suites[i + 1]]);
            if s == cipher_suite::TLS_CHACHA20_POLY1305_SHA256 {
                offers_chacha = true;
            }
            i += 2;
        }
        if !offers_chacha {
            return Err(ParseError::Unsupported);
        }

        // legacy_compression_methods: opaque<1..2^8-1>
        let _compression = r.read_vector_u8()?;

        // extensions: Extension<0..2^16-1>
        let ext_bytes = r.read_vector_u16()?;
        let mut er = Reader::new(ext_bytes);

        let mut offers_tls13 = false;
        let mut offers_x25519 = false;
        let mut x25519_client_pub: Option<[u8; 32]> = None;

        while !er.is_empty() {
            let ext_type = er.read_u16()?;
            let ext_data = er.read_vector_u16()?;
            match ext_type {
                ext_type::SUPPORTED_VERSIONS => {
                    // ClientHello form: opaque<2..254> list of u16 versions.
                    let mut vr = Reader::new(ext_data);
                    let versions = vr.read_vector_u8()?;
                    if versions.len() % 2 != 0 {
                        return Err(ParseError::BadExtension);
                    }
                    let mut j = 0;
                    while j < versions.len() {
                        let v = u16::from_be_bytes([versions[j], versions[j + 1]]);
                        if v == VERSION_TLS13 {
                            offers_tls13 = true;
                        }
                        j += 2;
                    }
                }
                ext_type::SUPPORTED_GROUPS => {
                    let mut gr = Reader::new(ext_data);
                    let groups = gr.read_vector_u16()?;
                    if groups.len() % 2 != 0 {
                        return Err(ParseError::BadExtension);
                    }
                    let mut j = 0;
                    while j < groups.len() {
                        let g = u16::from_be_bytes([groups[j], groups[j + 1]]);
                        if g == named_group::X25519 {
                            offers_x25519 = true;
                        }
                        j += 2;
                    }
                }
                ext_type::KEY_SHARE => {
                    // ClientHello key_share: KeyShareEntry client_shares<0..2^16-1>;
                    // KeyShareEntry = { group: u16, key_exchange: opaque<1..2^16-1> }
                    let mut kr = Reader::new(ext_data);
                    let entries = kr.read_vector_u16()?;
                    let mut kr2 = Reader::new(entries);
                    while !kr2.is_empty() {
                        let group = kr2.read_u16()?;
                        let key_exchange = kr2.read_vector_u16()?;
                        if group == named_group::X25519 && key_exchange.len() == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(key_exchange);
                            x25519_client_pub = Some(pk);
                        }
                    }
                }
                _ => { /* ignore extensions we don't care about */ }
            }
        }

        if !offers_tls13 {
            return Err(ParseError::Unsupported);
        }
        let x25519_client_pub = x25519_client_pub.ok_or(ParseError::Unsupported)?;
        // `offers_x25519` is advisory; if the client sent a key_share we
        // accept it regardless of whether they listed it in supported_groups.

        Ok(ClientHello {
            legacy_session_id,
            random,
            x25519_client_pub,
            offers_tls13,
            offers_x25519,
        })
    }
}

// ============================================================================
// ServerHello builder
// ============================================================================

/// Build a ServerHello body for TLS 1.3 with
/// cipher_suite = TLS_CHACHA20_POLY1305_SHA256 and key_share = X25519.
///
/// Writes into `out` and returns the body length. The caller should
/// wrap the result with `encode_handshake(SERVER_HELLO, body, ...)`.
pub fn build_server_hello(
    server_random: &[u8; 32],
    legacy_session_id_echo: &[u8],
    server_x25519_pub: &[u8; 32],
    out: &mut [u8],
) -> Option<usize> {
    // Layout:
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
    if legacy_session_id_echo.len() > 32 {
        return None;
    }

    // Extensions total (written first so we know the length):
    //   supported_versions: 2 + 2 + 2 = 6
    //   key_share:          2 + 2 + 2 + 2 + 32 = 40
    let ext_total: u16 = 6 + 40;
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
    out[p..p + 2].copy_from_slice(&cipher_suite::TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
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

    debug_assert_eq!(p, total);
    Some(p)
}

// ============================================================================
// Small byte reader helper
// ============================================================================

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.remaining() < n {
            return Err(ParseError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn read_u16(&mut self) -> Result<u16, ParseError> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a length-prefixed vector where the length is a u8.
    fn read_vector_u8(&mut self) -> Result<&'a [u8], ParseError> {
        if self.remaining() < 1 {
            return Err(ParseError::Truncated);
        }
        let len = self.buf[self.pos] as usize;
        self.pos += 1;
        self.read_bytes(len)
    }

    /// Read a length-prefixed vector where the length is a big-endian u16.
    fn read_vector_u16(&mut self) -> Result<&'a [u8], ParseError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_header_roundtrip() {
        let body = [0xaa, 0xbb, 0xcc];
        let mut out = [0u8; 8];
        let n = encode_handshake(msg_type::CLIENT_HELLO, &body, &mut out).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&out[..n], &[1, 0, 0, 3, 0xaa, 0xbb, 0xcc]);

        let (ty, parsed) = parse_handshake(&out[..n]).unwrap();
        assert_eq!(ty, msg_type::CLIENT_HELLO);
        assert_eq!(parsed, &body[..]);
    }

    #[test]
    fn handshake_reject_truncated_length() {
        // Claims body length 5, but only 2 bytes of body follow.
        let buf = [msg_type::CLIENT_HELLO, 0, 0, 5, 0xde, 0xad];
        assert_eq!(parse_handshake(&buf), Err(ParseError::BadLength));
    }

    #[test]
    fn server_hello_layout() {
        let random = [0xaau8; 32];
        let sid_echo = [];
        let server_pub = [0xccu8; 32];
        let mut out = [0u8; 256];
        let n = build_server_hello(&random, &sid_echo, &server_pub, &mut out).unwrap();

        // Parse back the first few fields to sanity-check.
        assert_eq!(&out[0..2], &[0x03, 0x03]); // legacy_version
        assert_eq!(&out[2..34], &random[..]);
        assert_eq!(out[34], 0); // session_id length
        assert_eq!(&out[35..37], &[0x13, 0x03]); // cipher_suite
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

    /// Build a synthetic TLS 1.3 ClientHello with the minimum
    /// extensions we care about: supported_versions + supported_groups
    /// + key_share(x25519). Parse it and verify every field round-trips.
    #[test]
    fn parse_synthetic_client_hello() {
        let client_pub = [0x77u8; 32];

        // Helper: write ext header + body, returning new cursor.
        fn write_ext(buf: &mut [u8], mut p: usize, ty: u16, body: &[u8]) -> usize {
            buf[p..p + 2].copy_from_slice(&ty.to_be_bytes());
            p += 2;
            buf[p..p + 2].copy_from_slice(&(body.len() as u16).to_be_bytes());
            p += 2;
            buf[p..p + body.len()].copy_from_slice(body);
            p + body.len()
        }

        let mut ext = [0u8; 256];
        let mut p = 0usize;

        // supported_versions body: u8 vector of u16 versions.
        //   [0x02, 0x03, 0x04]
        let sv_body = [0x02u8, 0x03, 0x04];
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_VERSIONS, &sv_body);

        // supported_groups body: u16 vector of u16 groups.
        //   [0x00, 0x02, 0x00, 0x1d]
        let sg_body = [0x00u8, 0x02, 0x00, 0x1d];
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_GROUPS, &sg_body);

        // key_share body:
        //   u16 client_shares_len = 36
        //   KeyShareEntry { group: x25519, key_exchange: 32 bytes }
        let mut ks_body = [0u8; 38];
        ks_body[0..2].copy_from_slice(&36u16.to_be_bytes());
        ks_body[2..4].copy_from_slice(&named_group::X25519.to_be_bytes());
        ks_body[4..6].copy_from_slice(&32u16.to_be_bytes());
        ks_body[6..38].copy_from_slice(&client_pub);
        p = write_ext(&mut ext, p, ext_type::KEY_SHARE, &ks_body);

        // Now build the full ClientHello body:
        //   u16 legacy_version | 32 random | u8 session_id_len=0 |
        //   u16 cipher_suites_len=2 | u16 TLS_CHACHA20_POLY1305_SHA256 |
        //   u8 legacy_compression_len=1 | u8 null |
        //   u16 extensions_len | ext_bytes
        let mut ch = [0u8; 512];
        let mut q = 0usize;
        ch[q..q + 2].copy_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
        q += 2;
        // random — use 0x11..
        ch[q..q + 32].copy_from_slice(&[0x11u8; 32]);
        q += 32;
        ch[q] = 0; // session_id length
        q += 1;
        ch[q..q + 2].copy_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        q += 2;
        ch[q..q + 2].copy_from_slice(&cipher_suite::TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
        q += 2;
        ch[q] = 1; // compression_methods_len
        q += 1;
        ch[q] = 0; // null compression
        q += 1;
        let ext_len = p;
        ch[q..q + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        q += 2;
        ch[q..q + ext_len].copy_from_slice(&ext[..ext_len]);
        q += ext_len;

        let parsed = ClientHello::parse(&ch[..q]).expect("parse failed");
        assert!(parsed.offers_tls13);
        assert!(parsed.offers_x25519);
        assert_eq!(parsed.x25519_client_pub, client_pub);
        assert_eq!(parsed.legacy_session_id.len(), 0);
        assert_eq!(parsed.random, &[0x11u8; 32]);
    }

    #[test]
    fn parse_client_hello_rejects_truncated() {
        let buf = [0x03, 0x03, 0xaa]; // 3 bytes, nowhere near enough
        assert!(ClientHello::parse(&buf).is_err());
    }
}
