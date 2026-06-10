// TLS 1.3 handshake message framing + parser.
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
// Scope:
// - Handshake message header encode/decode (this file)
// - `ClientHello` parser: legacy fields + the TLS 1.3 extensions we
//   need (supported_versions, key_share, supported_groups, PSK, ALPN,
//   QUIC transport params). See `client_hello.rs`.
// - `ServerHello` builder for TLS_AES_128_GCM_SHA256 + X25519. See
//   `server_hello.rs`.
// - `EncryptedExtensions`, `Certificate`, `CertificateVerify`,
//   `Finished`, `NewSessionTicket` builders covering the server side
//   of the TLS 1.3 handshake. See `messages.rs`.
// - `Finished` parser for the client's response (`messages.rs`).
// - Client-role mirror halves: `ClientHello` BUILDER
//   (`client_hello.rs`), `ServerHello` PARSER incl. HelloRetryRequest
//   detection (`server_hello.rs`), and parsers for
//   EncryptedExtensions / Certificate-leaf / CertificateVerify
//   (`messages.rs`). Driven by the `TlsClient` state machine in
//   `crate::client`.
//
// Explicitly out of scope (future work):
// - signature_algorithms extension parsing / enforcement (we
//   unconditionally pick ECDSA P-256 + SHA-256 since that's what our
//   dev cert uses)
// - 0-RTT / early_data extensions (beyond carrying them in
//   NewSessionTicket / EncryptedExtensions for QUIC)
// - Alert record format
// - X.509 DER parsing beyond "treat the cert as an opaque byte blob
//   to include in Certificate.certificate_list"
//
// Session-resumption wire primitives:
// - `pre_shared_key` (ext 41) and `psk_key_exchange_modes` (ext 45)
//   parsing in `ClientHello`, including `binders_offset` for the
//   RFC 8446 §4.2.11.2 partial-transcript hash.
// - `build_new_session_ticket` (RFC 8446 §4.6.1) — the post-handshake
//   message a server emits to issue a resumption ticket.
// - `build_server_pre_shared_key_ext` — the ServerHello extension
//   echoing the `selected_identity` index. Higher layers do the
//   actual ticket sealing/opening + binder verification.

mod client_hello;
mod messages;
mod reader;
mod server_hello;

// Public re-exports preserve the pre-split `tls::handshake::*` API.
// The client-role mirror halves (`build_client_hello`,
// `parse_server_hello`, the EE / Certificate / CertificateVerify
// parsers) export alongside their server-role counterparts.
pub use client_hello::{
    AlpnIter, ClientHello, ClientHelloParams, PskOffer, build_client_hello, iter_alpn,
};
pub use messages::{
    EncryptedExtensionsView, build_certificate, build_certificate_verify,
    build_encrypted_extensions, build_finished, build_new_session_ticket,
    parse_certificate_leaf, parse_certificate_verify, parse_encrypted_extensions, parse_finished,
    sign_content_server_cert_verify,
};
pub use server_hello::{
    HELLO_RETRY_REQUEST_RANDOM, ServerHelloView, build_server_hello,
    build_server_pre_shared_key_ext, parse_server_hello,
};

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
    /// PskKeyExchangeModes — RFC 8446 §4.2.9. Required when offering
    /// `pre_shared_key`; servers MUST abort if it's missing alongside
    /// a PSK offer.
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const KEY_SHARE: u16 = 51;
    /// `quic_transport_parameters` (RFC 9001 §8.2). Carries the
    /// peer's `transport_parameters` TLV blob inside ClientHello /
    /// EncryptedExtensions when TLS is layered under QUIC.
    pub const QUIC_TRANSPORT_PARAMETERS: u16 = 0x39;
    /// `early_data` extension (RFC 8446 §4.2.10). Empty body in
    /// EncryptedExtensions ("server accepts 0-RTT for this conn");
    /// 4-byte `max_early_data_size` body in NewSessionTicket
    /// (which RFC 9001 §4.6.1 mandates equal `0xffffffff` for
    /// QUIC, signaling future-self will accept 0-RTT).
    pub const EARLY_DATA: u16 = 42;
}

/// PskKeyExchangeMode wire values (RFC 8446 §4.2.9), plus convenience
/// bitmask flags used inside `ClientHello::psk_ke_modes`.
pub mod psk_ke_mode {
    /// Wire value: PSK-only key establishment.
    pub const PSK_KE: u8 = 0;
    /// Wire value: PSK + (EC)DHE — the only mode we support for
    /// resumption (forward secrecy is non-negotiable).
    pub const PSK_DHE_KE: u8 = 1;

    /// Set in `ClientHello::psk_ke_modes` when the client advertised `psk_ke`.
    pub const FLAG_PSK_KE: u8 = 1 << 0;
    /// Set in `ClientHello::psk_ke_modes` when the client advertised `psk_dhe_ke`.
    pub const FLAG_PSK_DHE_KE: u8 = 1 << 1;
}

/// NamedGroup values (we only implement x25519).
pub mod named_group {
    pub const X25519: u16 = 0x001d;
}

/// CipherSuite values (we only implement one). TLS 1.3 lists three
/// MTI suites in RFC 8446 §9.1; we ship `TLS_AES_128_GCM_SHA256`
/// because it's the **mandatory-to-implement** one (the other two
/// are SHOULD-implement) and because AES-NI / FEAT_AES is on every
/// CPU we deploy to, giving us hardware-accelerated record
/// encryption on both x86_64 (Intel + AMD) and aarch64 (Apple
/// Silicon, modern ARM servers). Migrated from
/// `TLS_CHACHA20_POLY1305_SHA256` (0x1303) — see commit log for
/// the rationale (broken chacha20 SIMD path on
/// `x86_64-unknown-none` + universal browser preference for
/// AES-128-GCM when the client sees AES-NI).
pub mod cipher_suite {
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
}

/// SignatureScheme values from RFC 8446 §4.2.3. We only implement one.
pub mod sig_scheme {
    /// ECDSA over secp256r1 (NIST P-256) with SHA-256 hash.
    /// Used by our dev cert in CertificateVerify. This is also the
    /// first scheme in every modern client's preference list (Chrome,
    /// Firefox, Safari, curl, ...), so interop is essentially free.
    /// We picked it over ed25519 (0x0807) because Chromium-family
    /// browsers don't advertise ed25519 for server-auth signatures
    /// and reject an Ed25519-signed CertVerify with illegal_parameter.
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
}

/// TLS 1.2 legacy_version value used in the outer ClientHello /
/// ServerHello header for middlebox compatibility.
pub const LEGACY_VERSION_TLS12: u16 = 0x0303;

/// The real version, as advertised in `supported_versions`.
pub const VERSION_TLS13: u16 = 0x0304;

/// TLS 1.3 uses SHA-256 as its transcript hash for every cipher suite
/// we support (`TLS_AES_128_GCM_SHA256`). All code that needs a
/// transcript digest should assume 32-byte outputs.
pub const HASH_LEN: usize = 32;

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
// Tests for the framing helpers (per-message tests live with each builder).
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
}
