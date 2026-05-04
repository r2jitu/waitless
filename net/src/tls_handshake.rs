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
// Scope:
// - Handshake message header encode/decode
// - `ClientHello` parser: legacy fields + the TLS 1.3 extensions we need
//   (supported_versions, key_share, supported_groups).
// - `ServerHello` builder for TLS_CHACHA20_POLY1305_SHA256 + X25519.
// - `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`
//   builders covering the server side of the TLS 1.3 handshake.
// - `Finished` parser for client's response.
//
// Explicitly out of scope (future work):
// - signature_algorithms extension parsing / enforcement (we unconditionally
//   pick ECDSA P-256 + SHA-256 since that's what our dev cert uses)
// - 0-RTT / early_data extensions
// - Alert record format
// - X.509 DER parsing beyond "treat the cert as an opaque byte blob to
//   include in Certificate.certificate_list"
//
// Session-resumption wire primitives (commit 1 of the resumption work):
// - `pre_shared_key` (ext 41) and `psk_key_exchange_modes` (ext 45)
//   parsing in `ClientHello`, including `binders_offset` for the
//   RFC 8446 §4.2.11.2 partial-transcript hash.
// - `build_new_session_ticket` (RFC 8446 §4.6.1) — the post-handshake
//   message a server emits to issue a resumption ticket.
// - `build_server_pre_shared_key_ext` — the ServerHello extension
//   echoing the `selected_identity` index. Higher layers do the
//   actual ticket sealing/opening + binder verification.

// See .bazelrc for why this is `cfg_attr(not(test), no_std)` and not bare `#![no_std]`.
#![cfg_attr(not(test), no_std)]

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

/// CipherSuite values (we only implement one).
pub mod cipher_suite {
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
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
/// we support (`TLS_CHACHA20_POLY1305_SHA256`). All code that needs a
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
// ClientHello parser (subset: only what TLS 1.3 + X25519 needs)
// ============================================================================

/// Parsed view of a `pre_shared_key` extension (RFC 8446 §4.2.11).
/// Lives inside `ClientHello.psk` when the client offered resumption.
///
/// `binders_offset` is the load-bearing field: per RFC 8446 §4.2.11.2
/// the binder is HMAC over `Transcript-Hash(Truncate(ClientHello))`,
/// where `Truncate` removes the binders list. Concretely, the
/// transcript-hash input is the 4-byte handshake header followed by
/// `body[..binders_offset]` — i.e. everything up through the
/// identities list, ending right before the u16 binders-length prefix.
/// We capture this offset during parse so commit 4 can reconstruct
/// the partial transcript without re-parsing.
#[derive(Clone, Copy)]
pub struct PskOffer<'a> {
    /// Up to 4 `(identity_bytes, obfuscated_ticket_age)` pairs in the
    /// order the client sent them. Most clients send exactly one;
    /// we cap at 4 for fixed-size storage and the count below tracks
    /// how many we actually saw on the wire.
    pub identities: [(&'a [u8], u32); 4],
    /// Number of identities seen, capped to `identities.len()`.
    pub identity_count: u8,
    /// Up to 4 `PskBinderEntry` byte slices, parallel to `identities`.
    /// Each is 32–255 bytes (`opaque PskBinderEntry<32..255>`).
    pub binders: [&'a [u8]; 4],
    pub binder_count: u8,
    /// Byte offset within the ClientHello body where the binders
    /// list's u16 length prefix begins. See struct doc.
    pub binders_offset: usize,
}

/// Parsed subset of a ClientHello. Byte slices point into the input
/// buffer — the struct is a view, not owned data.
#[derive(Clone, Copy)]
pub struct ClientHello<'a> {
    /// Echoed back in ServerHello for middlebox compat. May be empty.
    pub legacy_session_id: &'a [u8],
    /// Client random (32 bytes, used as ClientHello.random).
    pub random: &'a [u8; 32],
    /// The client's X25519 public key, from its key_share extension.
    /// `None` if the client didn't send an X25519 key_share — e.g.
    /// a PQ-enabled Chromium that sent only an x25519mlkem768 share.
    /// Callers can still use the rest of the parsed ClientHello for
    /// diagnostics or (once supported) to issue HelloRetryRequest.
    pub x25519_client_pub: Option<[u8; 32]>,
    /// Did the client offer TLS 1.3 in supported_versions?
    pub offers_tls13: bool,
    /// Did the client list X25519 in supported_groups?
    pub offers_x25519: bool,
    /// DEBUG: every (group_id, key_len) tuple observed in the key_share
    /// extension, in the order sent by the client. Populated by the
    /// parser so upper layers can log what the client offered — useful
    /// for diagnosing rejected handshakes from PQ-enabled browsers that
    /// send only `x25519mlkem768` (group 0x11ec) without a plain
    /// `x25519` (group 0x001d) share. Up to 8 entries are recorded;
    /// anything past that is silently dropped (ClientHellos with >8
    /// key_shares are vanishingly rare).
    pub observed_key_shares: [(u16, u16); 8],
    pub observed_key_share_count: u8,
    /// DEBUG: the first 16 group IDs the client listed in
    /// `supported_groups`. Lets us tell "client knows X25519 but didn't
    /// precompute a key for it" (HelloRetryRequest case) from "client
    /// genuinely doesn't know X25519" (hopeless case).
    pub observed_supported_groups: [u16; 16],
    pub observed_supported_group_count: u8,
    /// DEBUG: every signature scheme the client listed in its
    /// `signature_algorithms` extension. BoringSSL (Chrome/Arc) rejects
    /// a server CertVerify whose algorithm isn't in this list with
    /// `illegal_parameter(47)` — and Chrome's default list has
    /// historically omitted ed25519 for server auth, which breaks our
    /// hand-rolled ed25519-signing server.
    pub observed_sig_algs: [u16; 32],
    pub observed_sig_alg_count: u8,
    /// Parsed `pre_shared_key` extension if the client offered
    /// resumption; `None` otherwise. See `PskOffer` for binder
    /// transcript semantics.
    pub psk: Option<PskOffer<'a>>,
    /// Bitmask of `psk_key_exchange_modes` (RFC 8446 §4.2.9):
    /// `psk_ke_mode::FLAG_PSK_KE` and/or `FLAG_PSK_DHE_KE`. Zero
    /// when the extension is absent. We only accept resumption when
    /// `FLAG_PSK_DHE_KE` is set (forward secrecy required).
    pub psk_ke_modes: u8,
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
        //
        // Track the absolute offset (within `body`) where the
        // extensions vector starts so we can compute `binders_offset`
        // when we encounter `pre_shared_key`. `r.pos` here points at
        // the u16 extensions-length prefix; the extensions blob
        // itself starts 2 bytes later.
        let ext_bytes_offset_in_body = r.pos + 2;
        let ext_bytes = r.read_vector_u16()?;
        let mut er = Reader::new(ext_bytes);

        let mut offers_tls13 = false;
        let mut offers_x25519 = false;
        let mut x25519_client_pub: Option<[u8; 32]> = None;
        let mut observed_key_shares = [(0u16, 0u16); 8];
        let mut observed_key_share_count: u8 = 0;
        let mut observed_supported_groups = [0u16; 16];
        let mut observed_supported_group_count: u8 = 0;
        let mut observed_sig_algs = [0u16; 32];
        let mut observed_sig_alg_count: u8 = 0;
        let mut psk: Option<PskOffer<'a>> = None;
        let mut psk_ke_modes: u8 = 0;

        while !er.is_empty() {
            // Snapshot the position of *this* extension's type byte
            // within the outer body so we can derive `binders_offset`
            // for `pre_shared_key`.
            let this_ext_offset_in_body = ext_bytes_offset_in_body + er.pos;
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
                        if (observed_supported_group_count as usize)
                            < observed_supported_groups.len()
                        {
                            observed_supported_groups
                                [observed_supported_group_count as usize] = g;
                            observed_supported_group_count += 1;
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
                        if (observed_key_share_count as usize)
                            < observed_key_shares.len()
                        {
                            observed_key_shares
                                [observed_key_share_count as usize] =
                                (group, key_exchange.len() as u16);
                            observed_key_share_count += 1;
                        }
                        if group == named_group::X25519 && key_exchange.len() == 32 {
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(key_exchange);
                            x25519_client_pub = Some(pk);
                        }
                    }
                }
                ext_type::SIGNATURE_ALGORITHMS => {
                    // signature_algorithms extension body: opaque<2..2^16-2>
                    // of u16 SignatureScheme values.
                    let mut sr = Reader::new(ext_data);
                    let algs = sr.read_vector_u16()?;
                    if algs.len() % 2 != 0 {
                        return Err(ParseError::BadExtension);
                    }
                    let mut j = 0;
                    while j < algs.len() {
                        let a = u16::from_be_bytes([algs[j], algs[j + 1]]);
                        if (observed_sig_alg_count as usize) < observed_sig_algs.len() {
                            observed_sig_algs[observed_sig_alg_count as usize] = a;
                            observed_sig_alg_count += 1;
                        }
                        j += 2;
                    }
                }
                ext_type::PSK_KEY_EXCHANGE_MODES => {
                    // PskKeyExchangeModes: u8-prefixed list of u8 modes.
                    // RFC 8446 §4.2.9 — list MUST be non-empty.
                    let mut mr = Reader::new(ext_data);
                    let modes = mr.read_vector_u8()?;
                    if modes.is_empty() || !mr.is_empty() {
                        return Err(ParseError::BadExtension);
                    }
                    for &m in modes {
                        match m {
                            psk_ke_mode::PSK_KE => psk_ke_modes |= psk_ke_mode::FLAG_PSK_KE,
                            psk_ke_mode::PSK_DHE_KE => {
                                psk_ke_modes |= psk_ke_mode::FLAG_PSK_DHE_KE
                            }
                            // Unknown modes: ignore for forward-compat.
                            _ => {}
                        }
                    }
                }
                ext_type::PRE_SHARED_KEY => {
                    // OfferedPsks layout (RFC 8446 §4.2.11):
                    //   u16 identities_length
                    //   PskIdentity identities[..]   { opaque identity<1..2^16-1>; uint32 obfuscated_ticket_age; }
                    //   u16 binders_length
                    //   PskBinderEntry binders[..]   { opaque binder<32..255>; }
                    let mut psk_r = Reader::new(ext_data);
                    let identities_bytes = psk_r.read_vector_u16()?;

                    // ext_data starts at this_ext_offset_in_body + 4
                    // (ext_type:2 + ext_len:2). Within ext_data, the
                    // binders length prefix sits at offset
                    //   2 (identities len prefix) + identities_bytes.len().
                    let binders_offset_in_body =
                        this_ext_offset_in_body + 4 + 2 + identities_bytes.len();

                    let empty: &[u8] = &[];
                    let mut identities = [(empty, 0u32); 4];
                    let mut identity_count: u16 = 0;
                    let mut id_r = Reader::new(identities_bytes);
                    while !id_r.is_empty() {
                        let identity = id_r.read_vector_u16()?;
                        if identity.is_empty() {
                            return Err(ParseError::BadExtension);
                        }
                        let age = id_r.read_u32()?;
                        if (identity_count as usize) < identities.len() {
                            identities[identity_count as usize] = (identity, age);
                        }
                        identity_count = identity_count.saturating_add(1);
                    }

                    let binders_bytes = psk_r.read_vector_u16()?;
                    let mut binders = [empty; 4];
                    let mut binder_count: u16 = 0;
                    let mut bind_r = Reader::new(binders_bytes);
                    while !bind_r.is_empty() {
                        let binder = bind_r.read_vector_u8()?;
                        // PskBinderEntry<32..255>
                        if binder.len() < 32 || binder.len() > 255 {
                            return Err(ParseError::BadExtension);
                        }
                        if (binder_count as usize) < binders.len() {
                            binders[binder_count as usize] = binder;
                        }
                        binder_count = binder_count.saturating_add(1);
                    }

                    // Identities and binders lists are exactly parallel.
                    if identity_count != binder_count || identity_count == 0 {
                        return Err(ParseError::BadExtension);
                    }
                    if !psk_r.is_empty() {
                        return Err(ParseError::BadExtension);
                    }

                    psk = Some(PskOffer {
                        identities,
                        identity_count: (identity_count.min(4)) as u8,
                        binders,
                        binder_count: (binder_count.min(4)) as u8,
                        binders_offset: binders_offset_in_body,
                    });

                    // RFC 8446 §4.2.11: pre_shared_key MUST be the last
                    // extension. Servers MUST abort with illegal_parameter
                    // if it isn't. We surface that as BadExtension.
                    if !er.is_empty() {
                        return Err(ParseError::BadExtension);
                    }
                }
                _ => { /* ignore extensions we don't care about */ }
            }
        }

        if !offers_tls13 {
            return Err(ParseError::Unsupported);
        }
        // `offers_x25519` is advisory; if the client sent a key_share we
        // accept it regardless of whether they listed it in supported_groups.
        // The lack of an X25519 key_share is NOT an error here — callers
        // inspect `x25519_client_pub.is_none()` and can either drop the
        // handshake or (someday) issue HelloRetryRequest.

        Ok(ClientHello {
            legacy_session_id,
            random,
            x25519_client_pub,
            offers_tls13,
            offers_x25519,
            observed_key_shares,
            observed_key_share_count,
            observed_supported_groups,
            observed_supported_group_count,
            observed_sig_algs,
            observed_sig_alg_count,
            psk,
            psk_ke_modes,
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
// EncryptedExtensions builder (RFC 8446 §4.3.1)
// ============================================================================

/// Build an EncryptedExtensions message body. For our use case the
/// extensions list is empty — we don't negotiate ALPN, SNI, early data,
/// supported_groups_in_eerror, or any of the other things that go here.
/// An empty body is just `[0x00, 0x00]` (u16 extensions_length = 0).
///
/// Returns the number of bytes written. `out` must have at least 2 bytes.
pub fn build_encrypted_extensions(out: &mut [u8]) -> Option<usize> {
    if out.len() < 2 {
        return None;
    }
    // Extensions length = 0.
    out[0] = 0;
    out[1] = 0;
    Some(2)
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
pub fn sign_content_server_cert_verify(
    transcript_hash: &[u8; HASH_LEN],
    out: &mut [u8; 130],
) {
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
/// want this module to depend on `p256`; that's `//uni-tls`'s job).
pub fn build_certificate_verify(
    signature: &[u8],
    out: &mut [u8],
) -> Option<usize> {
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
/// We always emit an empty extensions list — `early_data` (the only
/// realistic ticket-extension) is out of scope for now.
///
/// Returns the number of bytes written, or `None` if `out` is too
/// small or any field exceeds its wire-encoded bound.
pub fn build_new_session_ticket(
    lifetime_seconds: u32,
    age_add: u32,
    ticket_nonce: &[u8],
    ticket: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if ticket_nonce.len() > 255 {
        return None;
    }
    if ticket.is_empty() || ticket.len() > 0xffff {
        return None;
    }
    let total = 4 + 4 + 1 + ticket_nonce.len() + 2 + ticket.len() + 2;
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
    // Empty extensions list.
    out[p] = 0;
    out[p + 1] = 0;
    p += 2;

    debug_assert_eq!(p, total);
    Some(p)
}

// ============================================================================
// ServerHello pre_shared_key extension builder (RFC 8446 §4.2.11)
// ============================================================================

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
pub fn build_server_pre_shared_key_ext(
    selected_identity: u16,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < 6 {
        return None;
    }
    out[0..2].copy_from_slice(&ext_type::PRE_SHARED_KEY.to_be_bytes());
    out[2..4].copy_from_slice(&2u16.to_be_bytes());
    out[4..6].copy_from_slice(&selected_identity.to_be_bytes());
    Some(6)
}

// ============================================================================
// Finished builder + parser (RFC 8446 §4.4.4)
// ============================================================================

/// Build a Finished message body. The body IS the verify_data — there's
/// no extra framing inside a Finished message.
///
/// Caller computes `verify_data = HMAC(finished_key, transcript_hash)`
/// and passes it here. For `TLS_CHACHA20_POLY1305_SHA256` (our only suite)
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

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
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
        assert_eq!(parsed.x25519_client_pub, Some(client_pub));
        assert_eq!(parsed.legacy_session_id.len(), 0);
        assert_eq!(parsed.random, &[0x11u8; 32]);
    }

    #[test]
    fn parse_client_hello_rejects_truncated() {
        let buf = [0x03, 0x03, 0xaa]; // 3 bytes, nowhere near enough
        assert!(ClientHello::parse(&buf).is_err());
    }

    #[test]
    fn encrypted_extensions_is_empty_extension_list() {
        let mut out = [0u8; 8];
        let n = build_encrypted_extensions(&mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&out[..n], &[0x00, 0x00]);
    }

    #[test]
    fn certificate_single_entry_layout() {
        // 10-byte fake cert DER.
        let cert_der = [
            0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0x00, 0x01,
        ];
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

    // ── PSK / session-resumption parsing & builders ────────────────────────

    /// Helper used by the resumption tests: writes one extension
    /// (type + u16-length + body) into `buf` at `p`, returning the
    /// new cursor.
    fn write_ext(buf: &mut [u8], mut p: usize, ty: u16, body: &[u8]) -> usize {
        buf[p..p + 2].copy_from_slice(&ty.to_be_bytes());
        p += 2;
        buf[p..p + 2].copy_from_slice(&(body.len() as u16).to_be_bytes());
        p += 2;
        buf[p..p + body.len()].copy_from_slice(body);
        p + body.len()
    }

    /// Build a synthetic ClientHello with arbitrary trailing
    /// extension bytes after the always-required ones. Returns
    /// `(ch_body_bytes, trailing_offset)`. `trailing_offset` is the
    /// offset within the ClientHello body where `trailing_ext_bytes`
    /// was placed — i.e. directly past the required extensions.
    fn build_synthetic_ch_with_trailing_ext_bytes(
        random: [u8; 32],
        client_pub: [u8; 32],
        trailing_ext_bytes: &[u8],
    ) -> (Vec<u8>, usize) {
        // Required extensions: supported_versions, supported_groups, key_share.
        let mut ext = [0u8; 256];
        let mut p = 0usize;
        let sv_body = [0x02u8, 0x03, 0x04];
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_VERSIONS, &sv_body);
        let sg_body = [0x00u8, 0x02, 0x00, 0x1d];
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_GROUPS, &sg_body);
        let mut ks_body = [0u8; 38];
        ks_body[0..2].copy_from_slice(&36u16.to_be_bytes());
        ks_body[2..4].copy_from_slice(&named_group::X25519.to_be_bytes());
        ks_body[4..6].copy_from_slice(&32u16.to_be_bytes());
        ks_body[6..38].copy_from_slice(&client_pub);
        p = write_ext(&mut ext, p, ext_type::KEY_SHARE, &ks_body);

        let required_ext_len = p;
        let total_ext_len = required_ext_len + trailing_ext_bytes.len();

        let mut ch = vec![0u8; 0];
        // legacy_version
        ch.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
        // random
        ch.extend_from_slice(&random);
        // session_id
        ch.push(0);
        // cipher_suites (only one)
        ch.extend_from_slice(&2u16.to_be_bytes());
        ch.extend_from_slice(&cipher_suite::TLS_CHACHA20_POLY1305_SHA256.to_be_bytes());
        // legacy compression
        ch.push(1);
        ch.push(0);
        // extensions length
        ch.extend_from_slice(&(total_ext_len as u16).to_be_bytes());
        ch.extend_from_slice(&ext[..required_ext_len]);
        let trailing_offset = ch.len();
        ch.extend_from_slice(trailing_ext_bytes);

        (ch, trailing_offset)
    }

    /// Encode an OfferedPsks body (the contents of the
    /// `pre_shared_key` extension): `(identities..., binders...)`.
    /// Each identity is `(opaque_bytes, obfuscated_age)`. Each
    /// binder is its raw HMAC bytes (32–255).
    fn encode_offered_psks(
        identities: &[(&[u8], u32)],
        binders: &[&[u8]],
    ) -> Vec<u8> {
        let mut idents_body = vec![];
        for (identity, age) in identities {
            idents_body.extend_from_slice(&(identity.len() as u16).to_be_bytes());
            idents_body.extend_from_slice(identity);
            idents_body.extend_from_slice(&age.to_be_bytes());
        }
        let mut binders_body = vec![];
        for binder in binders {
            binders_body.push(binder.len() as u8);
            binders_body.extend_from_slice(binder);
        }
        let mut out = vec![];
        out.extend_from_slice(&(idents_body.len() as u16).to_be_bytes());
        out.extend_from_slice(&idents_body);
        out.extend_from_slice(&(binders_body.len() as u16).to_be_bytes());
        out.extend_from_slice(&binders_body);
        out
    }

    #[test]
    fn parse_psk_extensions_and_capture_binders_offset() {
        let identity_bytes = b"ticket-blob-12345";
        let binder_bytes = [0x55u8; 32];
        let psk_body = encode_offered_psks(
            &[(identity_bytes, 0xdead_beef)],
            &[&binder_bytes[..]],
        );

        // psk_key_exchange_modes: u8 length=1, modes=[1 (psk_dhe_ke)]
        let kem_body = [0x01u8, 0x01];
        let mut trailing = vec![];
        // Order: psk_key_exchange_modes first, pre_shared_key LAST.
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);
        trailing.extend_from_slice(&tmp[..q]);

        let (ch, trailing_offset) =
            build_synthetic_ch_with_trailing_ext_bytes([0xa1; 32], [0x77; 32], &trailing);
        let parsed = ClientHello::parse(&ch).expect("parse failed");

        // PSK extension fully captured.
        let psk = parsed.psk.expect("psk should be present");
        assert_eq!(psk.identity_count, 1);
        assert_eq!(psk.binder_count, 1);
        assert_eq!(psk.identities[0].0, identity_bytes);
        assert_eq!(psk.identities[0].1, 0xdead_beef);
        assert_eq!(psk.binders[0], &binder_bytes[..]);

        // psk_key_exchange_modes captured (psk_dhe_ke set, psk_ke not).
        assert_eq!(parsed.psk_ke_modes & psk_ke_mode::FLAG_PSK_DHE_KE,
                   psk_ke_mode::FLAG_PSK_DHE_KE);
        assert_eq!(parsed.psk_ke_modes & psk_ke_mode::FLAG_PSK_KE, 0);

        // binders_offset must point at the u16 binders-length prefix.
        // Layout within `trailing`:
        //   [0..6]   psk_key_exchange_modes envelope (4 hdr + 2 body)
        //   [6..10]  pre_shared_key envelope header (type+len)
        //   [10..]   pre_shared_key body = OfferedPsks
        //     [10..12]    u16 identities_length
        //     [12..12+L]  identities (L = 2 + 17 + 4 = 23)
        //     [12+L..]    u16 binders_length  ← binders_offset points here
        let kem_envelope_len = 4 + kem_body.len(); // 4 hdr + 2 body = 6
        let psk_body_offset_in_trailing = kem_envelope_len + 4; // +4 psk hdr
        let idents_body_len = 2 + identity_bytes.len() + 4; // u16 len + identity + u32 age
        let expected = trailing_offset
            + psk_body_offset_in_trailing
            + 2
            + idents_body_len;
        assert_eq!(psk.binders_offset, expected, "binders_offset mismatch");

        // Confirm body[..binders_offset] ends at the byte BEFORE the
        // u16 binders-length prefix (which is 0x00 0x21 = 33 = 1+32).
        assert_eq!(ch[psk.binders_offset], 0x00);
        assert_eq!(ch[psk.binders_offset + 1], 0x21);
    }

    #[test]
    fn parse_psk_rejects_non_last() {
        // pre_shared_key followed by another extension is illegal.
        let psk_body = encode_offered_psks(
            &[(b"x", 0)],
            &[&[0x11u8; 32][..]],
        );
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        // Wrong order: psk first, then psk_key_exchange_modes.
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xb2; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(ClientHello::parse(&ch), Err(ParseError::BadExtension)));
    }

    #[test]
    fn parse_psk_rejects_count_mismatch() {
        // Two identities but only one binder.
        let psk_body = encode_offered_psks(
            &[(b"id1", 1), (b"id2", 2)],
            &[&[0x33u8; 32][..]],
        );
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xc3; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(ClientHello::parse(&ch), Err(ParseError::BadExtension)));
    }

    #[test]
    fn parse_psk_rejects_short_binder() {
        // Binder must be 32–255 bytes; 16 is too short.
        let psk_body = encode_offered_psks(
            &[(b"id", 0)],
            &[&[0x44u8; 16][..]],
        );
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xd4; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(ClientHello::parse(&ch), Err(ParseError::BadExtension)));
    }

    #[test]
    fn parse_psk_modes_both_flags() {
        // psk_key_exchange_modes with both modes; no pre_shared_key.
        let kem_body = [0x02u8, 0x00, 0x01]; // [psk_ke, psk_dhe_ke]
        let mut tmp = [0u8; 64];
        let q = write_ext(&mut tmp, 0, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xe5; 32], [0x77; 32], &tmp[..q]);
        let parsed = ClientHello::parse(&ch).unwrap();
        assert_eq!(
            parsed.psk_ke_modes,
            psk_ke_mode::FLAG_PSK_KE | psk_ke_mode::FLAG_PSK_DHE_KE
        );
        assert!(parsed.psk.is_none());
    }

    #[test]
    fn parse_psk_modes_rejects_empty_list() {
        // ke_modes<1..255> — empty body is illegal.
        let kem_body = [0x00u8]; // length=0
        let mut tmp = [0u8; 64];
        let q = write_ext(&mut tmp, 0, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xe6; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(ClientHello::parse(&ch), Err(ParseError::BadExtension)));
    }

    #[test]
    fn parse_no_psk_means_psk_none() {
        // Existing-shape ClientHello (no PSK extensions) still parses
        // and reports no PSK offer.
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes(
            [0xf7; 32], [0x77; 32], &[]);
        let parsed = ClientHello::parse(&ch).unwrap();
        assert!(parsed.psk.is_none());
        assert_eq!(parsed.psk_ke_modes, 0);
    }

    #[test]
    fn new_session_ticket_layout() {
        // Spec wire example: lifetime=600, age_add=0xdeadbeef,
        // nonce=[0x01,0x02], ticket=10 bytes, ext_len=0.
        let nonce = [0x01u8, 0x02];
        let ticket = [0x99u8; 10];
        let mut out = [0u8; 64];
        let n = build_new_session_ticket(600, 0xdead_beef, &nonce, &ticket, &mut out)
            .unwrap();

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
        assert!(build_new_session_ticket(60, 0, &big_nonce, &[1, 2, 3], &mut out)
            .is_none());
    }

    #[test]
    fn new_session_ticket_rejects_empty_ticket() {
        let mut out = [0u8; 64];
        assert!(build_new_session_ticket(60, 0, &[], &[], &mut out).is_none());
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
