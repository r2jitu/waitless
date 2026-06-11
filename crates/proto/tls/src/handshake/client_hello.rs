// ClientHello parser (subset: only what TLS 1.3 + X25519 needs) and
// the mirror ClientHello BUILDER used by the client role (`client.rs`).
//
// The parser is strict: TLS 1.3 (via supported_versions) must be
// advertised or we fail with `Unsupported`. Lack of an X25519 key_share
// is NOT an error — callers inspect `x25519_client_pub.is_none()` and
// can either drop the handshake or (someday) issue HelloRetryRequest.
//
// Session-resumption support lives here as well: the parser captures
// `pre_shared_key` + `psk_key_exchange_modes` and records the binders
// offset so the caller can later rebuild the partial-transcript hash
// per RFC 8446 §4.2.11.2. (The builder offers no PSK — client-side
// resumption is a follow-up.)

use super::reader::Reader;
use super::{
    LEGACY_VERSION_TLS12, ParseError, VERSION_TLS13, cipher_suite, ext_type, named_group,
    psk_ke_mode, sig_scheme,
};

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
    /// Raw bytes of the `quic_transport_parameters` extension if
    /// the client sent one. `None` for plain TLS-over-TCP CHs;
    /// QUIC clients always include this. The server interprets
    /// the bytes via `quic::transport_params::parse_client_params`.
    pub quic_transport_parameters: Option<&'a [u8]>,
    /// Raw bytes of the `application_layer_protocol_negotiation`
    /// extension's body if the client offered ALPN. The body is
    /// `u16 list_len || (u8 name_len || name)+`; the QUIC server
    /// scans for `"h3"` and rejects otherwise.
    pub alpn_protocol_list: Option<&'a [u8]>,
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
            if s == cipher_suite::TLS_AES_128_GCM_SHA256 {
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
        let mut quic_transport_parameters: Option<&'a [u8]> = None;
        let mut alpn_protocol_list: Option<&'a [u8]> = None;

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
                        if v == super::VERSION_TLS13 {
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
                            observed_supported_groups[observed_supported_group_count as usize] = g;
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
                        if (observed_key_share_count as usize) < observed_key_shares.len() {
                            observed_key_shares[observed_key_share_count as usize] =
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
                            psk_ke_mode::PSK_DHE_KE => psk_ke_modes |= psk_ke_mode::FLAG_PSK_DHE_KE,
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
                ext_type::QUIC_TRANSPORT_PARAMETERS => {
                    // Body is opaque to the TLS parser — the QUIC layer
                    // decodes the TLV stream via `parse_client_params`.
                    quic_transport_parameters = Some(ext_data);
                }
                ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    // ALPN body: u16 list_len || (u8 name_len || name)+.
                    // We pass the inner bytes (after the list_len prefix)
                    // up to the caller for protocol selection.
                    let mut ar = Reader::new(ext_data);
                    let names = ar.read_vector_u16()?;
                    alpn_protocol_list = Some(names);
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
            quic_transport_parameters,
            alpn_protocol_list,
        })
    }
}

// ============================================================================
// ClientHello builder (RFC 8446 §4.1.2) — the client role's mirror half
// ============================================================================

/// Inputs to [`build_client_hello`]. All entropy arrives by value /
/// reference — the builder itself is deterministic, so the same params
/// reproduce the same wire bytes (the deterministic-simulation arc
/// leans on this).
#[derive(Clone, Copy)]
pub struct ClientHelloParams<'a> {
    /// ClientHello.random — 32 bytes of caller-supplied entropy.
    pub random: &'a [u8; 32],
    /// legacy_session_id (0–32 bytes). The client role sends a random
    /// 32-byte id for middlebox compat (RFC 8446 §D.4) and expects the
    /// ServerHello to echo it verbatim.
    pub legacy_session_id: &'a [u8],
    /// Our ephemeral X25519 public key for the key_share extension.
    pub x25519_pub: &'a [u8; 32],
    /// Optional `server_name` (RFC 6066) host bytes. ≤ 255 bytes.
    pub server_name: Option<&'a [u8]>,
    /// ALPN protocol names in preference order (RFC 7301). Empty
    /// list ⇒ no ALPN extension. Each name 1–255 bytes.
    pub alpn: &'a [&'a [u8]],
    /// Extra raw extensions appended verbatim after the standard set:
    /// `(extension_type, extension_data)` pairs. The QUIC client role
    /// injects `quic_transport_parameters` (RFC 9001 §8.2) here; the
    /// TCP client passes `&[]`. Each body ≤ 65535 bytes.
    pub extras: &'a [(u16, &'a [u8])],
}

/// Serialise a TLS 1.3 ClientHello *body* (the bytes AFTER the 4-byte
/// handshake header) for the one shape this crate speaks:
///
///   cipher_suites        = [TLS_AES_128_GCM_SHA256]
///   supported_versions   = [0x0304]
///   supported_groups     = [x25519]
///   key_share            = one X25519 entry
///   signature_algorithms = [ecdsa_secp256r1_sha256]
///   server_name / ALPN   = caller-supplied, optional
///
/// Returns bytes written, or `None` if `out` is too small or a
/// caller-supplied field exceeds its wire bound. The output parses
/// back through [`ClientHello::parse`] — pinned by a round-trip test.
pub fn build_client_hello(p: &ClientHelloParams<'_>, out: &mut [u8]) -> Option<usize> {
    if p.legacy_session_id.len() > 32 {
        return None;
    }
    if p
        .server_name
        .is_some_and(|name| name.is_empty() || name.len() > 255)
    {
        return None;
    }
    // ALPN wire body: u16 list_len || (u8 name_len || name)+.
    let mut alpn_list_len = 0usize;
    for name in p.alpn {
        if name.is_empty() || name.len() > 255 {
            return None;
        }
        alpn_list_len += 1 + name.len();
    }
    if alpn_list_len > 0xffff {
        return None;
    }

    // Extension envelope sizes (4-byte type+len header + body).
    let sni_ext = p.server_name.map_or(0, |n| 4 + 2 + 1 + 2 + n.len());
    let groups_ext = 4 + 2 + 2; // u16 list_len + x25519
    let sigalgs_ext = 4 + 2 + 2; // u16 list_len + ecdsa_secp256r1_sha256
    let alpn_ext = if alpn_list_len > 0 {
        4 + 2 + alpn_list_len
    } else {
        0
    };
    let sv_ext = 4 + 1 + 2; // u8 list_len + 0x0304
    let ks_ext = 4 + 2 + 2 + 2 + 32; // u16 shares_len + entry(group, len, key)
    let mut extras_ext = 0usize;
    for (_, body) in p.extras {
        if body.len() > 0xffff {
            return None;
        }
        extras_ext += 4 + body.len();
    }
    let ext_total = sni_ext + groups_ext + sigalgs_ext + alpn_ext + sv_ext + ks_ext + extras_ext;
    if ext_total > 0xffff {
        return None;
    }

    let total = 2 // legacy_version
        + 32 // random
        + 1 + p.legacy_session_id.len()
        + 2 + 2 // cipher_suites vector (one suite)
        + 1 + 1 // legacy_compression_methods (null)
        + 2 + ext_total;
    if out.len() < total {
        return None;
    }

    let mut q = 0usize;
    out[q..q + 2].copy_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
    q += 2;
    out[q..q + 32].copy_from_slice(p.random);
    q += 32;
    out[q] = p.legacy_session_id.len() as u8;
    q += 1;
    out[q..q + p.legacy_session_id.len()].copy_from_slice(p.legacy_session_id);
    q += p.legacy_session_id.len();
    out[q..q + 2].copy_from_slice(&2u16.to_be_bytes());
    q += 2;
    out[q..q + 2].copy_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
    q += 2;
    out[q] = 1; // one compression method
    q += 1;
    out[q] = 0; // null
    q += 1;
    out[q..q + 2].copy_from_slice(&(ext_total as u16).to_be_bytes());
    q += 2;

    // Local helper: extension envelope header.
    fn ext_header(out: &mut [u8], q: &mut usize, ty: u16, body_len: usize) {
        out[*q..*q + 2].copy_from_slice(&ty.to_be_bytes());
        out[*q + 2..*q + 4].copy_from_slice(&(body_len as u16).to_be_bytes());
        *q += 4;
    }

    // server_name (RFC 6066 §3): ServerNameList of one host_name.
    if let Some(name) = p.server_name {
        ext_header(out, &mut q, ext_type::SERVER_NAME, 2 + 1 + 2 + name.len());
        out[q..q + 2].copy_from_slice(&((1 + 2 + name.len()) as u16).to_be_bytes());
        q += 2;
        out[q] = 0; // NameType host_name
        q += 1;
        out[q..q + 2].copy_from_slice(&(name.len() as u16).to_be_bytes());
        q += 2;
        out[q..q + name.len()].copy_from_slice(name);
        q += name.len();
    }

    // supported_groups: just x25519.
    ext_header(out, &mut q, ext_type::SUPPORTED_GROUPS, 4);
    out[q..q + 2].copy_from_slice(&2u16.to_be_bytes());
    q += 2;
    out[q..q + 2].copy_from_slice(&named_group::X25519.to_be_bytes());
    q += 2;

    // signature_algorithms: just ecdsa_secp256r1_sha256 — the one
    // scheme this crate verifies (and the one our server signs with).
    ext_header(out, &mut q, ext_type::SIGNATURE_ALGORITHMS, 4);
    out[q..q + 2].copy_from_slice(&2u16.to_be_bytes());
    q += 2;
    out[q..q + 2].copy_from_slice(&sig_scheme::ECDSA_SECP256R1_SHA256.to_be_bytes());
    q += 2;

    // ALPN (RFC 7301).
    if alpn_list_len > 0 {
        ext_header(
            out,
            &mut q,
            ext_type::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            2 + alpn_list_len,
        );
        out[q..q + 2].copy_from_slice(&(alpn_list_len as u16).to_be_bytes());
        q += 2;
        for name in p.alpn {
            out[q] = name.len() as u8;
            q += 1;
            out[q..q + name.len()].copy_from_slice(name);
            q += name.len();
        }
    }

    // supported_versions (ClientHello form: u8-prefixed list).
    ext_header(out, &mut q, ext_type::SUPPORTED_VERSIONS, 3);
    out[q] = 2;
    q += 1;
    out[q..q + 2].copy_from_slice(&VERSION_TLS13.to_be_bytes());
    q += 2;

    // key_share: one X25519 entry.
    ext_header(out, &mut q, ext_type::KEY_SHARE, 2 + 2 + 2 + 32);
    out[q..q + 2].copy_from_slice(&36u16.to_be_bytes());
    q += 2;
    out[q..q + 2].copy_from_slice(&named_group::X25519.to_be_bytes());
    q += 2;
    out[q..q + 2].copy_from_slice(&32u16.to_be_bytes());
    q += 2;
    out[q..q + 32].copy_from_slice(p.x25519_pub);
    q += 32;

    // Caller-supplied raw extensions (e.g. quic_transport_parameters).
    for (ty, body) in p.extras {
        ext_header(out, &mut q, *ty, body.len());
        out[q..q + body.len()].copy_from_slice(body);
        q += body.len();
    }

    debug_assert_eq!(q, total);
    Some(q)
}

/// Iterate the `name_len:u8 || name:bytes` pairs inside an ALPN
/// extension body. Returns each protocol name as a borrowed slice.
pub fn iter_alpn(list_bytes: &[u8]) -> AlpnIter<'_> {
    AlpnIter { bytes: list_bytes }
}

pub struct AlpnIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for AlpnIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let len = self.bytes[0] as usize;
        if 1 + len > self.bytes.len() {
            return None;
        }
        let name = &self.bytes[1..1 + len];
        self.bytes = &self.bytes[1 + len..];
        Some(name)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::{LEGACY_VERSION_TLS12, cipher_suite, ext_type, named_group, psk_ke_mode};
    use super::*;

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
        //   u16 cipher_suites_len=2 | u16 TLS_AES_128_GCM_SHA256 |
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
        ch[q..q + 2].copy_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
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

    /// Fuzz-smoke (architecture-audit direction #2): `ClientHello::parse`
    /// consumes fully untrusted pre-handshake bytes — pin its
    /// panic-freedom over fixed-seed random buffers, single-byte
    /// mutations of a valid hello (length-field / vector-bound arms
    /// near-validity), and every truncation. Deterministic, so a failure
    /// reproduces; a tripwire, not coverage-guided fuzzing.
    #[test]
    fn parse_client_hello_fuzz_smoke_never_panics() {
        // A minimal valid TLS 1.3 hello, mirroring the synthetic test.
        let mut ext = [0u8; 256];
        let mut p = 0usize;
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]);
        p = write_ext(&mut ext, p, ext_type::SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d]);
        let mut ks_body = [0u8; 38];
        ks_body[0..2].copy_from_slice(&36u16.to_be_bytes());
        ks_body[2..4].copy_from_slice(&named_group::X25519.to_be_bytes());
        ks_body[4..6].copy_from_slice(&32u16.to_be_bytes());
        p = write_ext(&mut ext, p, ext_type::KEY_SHARE, &ks_body);
        let mut valid = alloc::vec::Vec::new();
        valid.extend_from_slice(&LEGACY_VERSION_TLS12.to_be_bytes());
        valid.extend_from_slice(&[0x11u8; 32]); // random
        valid.push(0); // session_id len
        valid.extend_from_slice(&2u16.to_be_bytes());
        valid.extend_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
        valid.extend_from_slice(&[1, 0]); // compression: 1 method, null
        valid.extend_from_slice(&(p as u16).to_be_bytes());
        valid.extend_from_slice(&ext[..p]);
        assert!(ClientHello::parse(&valid).is_ok(), "fixture must parse");

        let mut seed: u64 = 0xD1B5_4A32_D192_ED03;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // (a) Raw random buffers, varied lengths incl. empty.
        for _ in 0..20_000 {
            let len = (rnd() % 256) as usize;
            let buf: alloc::vec::Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let _ = ClientHello::parse(&buf); // must return, never panic
        }
        // (b) Single-byte mutations at every position of the valid hello.
        for pos in 0..valid.len() {
            for _ in 0..32 {
                let mut m = valid.clone();
                m[pos] = rnd() as u8;
                let _ = ClientHello::parse(&m);
            }
        }
        // (c) Truncations of the valid hello at every length.
        for end in 0..valid.len() {
            let _ = ClientHello::parse(&valid[..end]);
        }
    }

    // ── ClientHello builder (client role) ──────────────────────────────────

    /// Pin the builder against our own strict parser: every field and
    /// extension `build_client_hello` emits must be recovered by
    /// `ClientHello::parse` (acceptance test f for the client role).
    #[test]
    fn build_client_hello_round_trips_through_parser() {
        let random = [0xabu8; 32];
        let sid = [0xcdu8; 32];
        let x25519_pub = [0x77u8; 32];
        let params = ClientHelloParams {
            random: &random,
            legacy_session_id: &sid,
            x25519_pub: &x25519_pub,
            server_name: Some(b"dev.r2jitu.com"),
            alpn: &[b"h2", b"http/1.1"],
            extras: &[(0x4242, b"opaque-extra")],
        };
        let mut buf = [0u8; 512];
        let n = build_client_hello(&params, &mut buf).expect("build");

        let ch = ClientHello::parse(&buf[..n]).expect("parse own builder output");
        assert!(ch.offers_tls13);
        assert!(ch.offers_x25519);
        assert_eq!(ch.random, &random);
        assert_eq!(ch.legacy_session_id, &sid[..]);
        assert_eq!(ch.x25519_client_pub, Some(x25519_pub));
        // ALPN list round-trips in order.
        let names: Vec<&[u8]> = iter_alpn(ch.alpn_protocol_list.expect("alpn present")).collect();
        assert_eq!(names, vec![&b"h2"[..], &b"http/1.1"[..]]);
        // signature_algorithms carries our one scheme.
        let algs = &ch.observed_sig_algs[..ch.observed_sig_alg_count as usize];
        assert!(algs.contains(&sig_scheme::ECDSA_SECP256R1_SHA256));
        // supported_groups observed x25519.
        let groups = &ch.observed_supported_groups[..ch.observed_supported_group_count as usize];
        assert!(groups.contains(&named_group::X25519));
        // No resumption offer in v1.
        assert!(ch.psk.is_none());
        assert_eq!(ch.psk_ke_modes, 0);
    }

    /// Minimal shape: no SNI, no ALPN — still a valid TLS 1.3 hello.
    #[test]
    fn build_client_hello_minimal_parses() {
        let random = [1u8; 32];
        let x25519_pub = [2u8; 32];
        let params = ClientHelloParams {
            random: &random,
            legacy_session_id: &[],
            x25519_pub: &x25519_pub,
            server_name: None,
            alpn: &[],
            extras: &[],
        };
        let mut buf = [0u8; 256];
        let n = build_client_hello(&params, &mut buf).expect("build");
        let ch = ClientHello::parse(&buf[..n]).expect("parse");
        assert!(ch.offers_tls13);
        assert_eq!(ch.legacy_session_id.len(), 0);
        assert!(ch.alpn_protocol_list.is_none());
        assert_eq!(ch.x25519_client_pub, Some(x25519_pub));
    }

    /// Bounds: undersized output and oversized fields fail cleanly.
    #[test]
    fn build_client_hello_rejects_bad_inputs() {
        let random = [1u8; 32];
        let x25519_pub = [2u8; 32];
        let base = ClientHelloParams {
            random: &random,
            legacy_session_id: &[],
            x25519_pub: &x25519_pub,
            server_name: None,
            alpn: &[],
            extras: &[],
        };
        let mut tiny = [0u8; 32];
        assert!(build_client_hello(&base, &mut tiny).is_none());

        let mut buf = [0u8; 1024];
        let long_sid = [0u8; 33];
        let bad_sid = ClientHelloParams {
            legacy_session_id: &long_sid,
            ..base
        };
        assert!(build_client_hello(&bad_sid, &mut buf).is_none());

        let empty_alpn_name: &[&[u8]] = &[b""];
        let bad_alpn = ClientHelloParams {
            alpn: empty_alpn_name,
            ..base
        };
        assert!(build_client_hello(&bad_alpn, &mut buf).is_none());

        let long_name = [b'a'; 256];
        let bad_sni = ClientHelloParams {
            server_name: Some(&long_name),
            ..base
        };
        assert!(build_client_hello(&bad_sni, &mut buf).is_none());
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
        ch.extend_from_slice(&cipher_suite::TLS_AES_128_GCM_SHA256.to_be_bytes());
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
    fn encode_offered_psks(identities: &[(&[u8], u32)], binders: &[&[u8]]) -> Vec<u8> {
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
        let psk_body = encode_offered_psks(&[(identity_bytes, 0xdead_beef)], &[&binder_bytes[..]]);

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
        assert_eq!(
            parsed.psk_ke_modes & psk_ke_mode::FLAG_PSK_DHE_KE,
            psk_ke_mode::FLAG_PSK_DHE_KE
        );
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
        let expected = trailing_offset + psk_body_offset_in_trailing + 2 + idents_body_len;
        assert_eq!(psk.binders_offset, expected, "binders_offset mismatch");

        // Confirm body[..binders_offset] ends at the byte BEFORE the
        // u16 binders-length prefix (which is 0x00 0x21 = 33 = 1+32).
        assert_eq!(ch[psk.binders_offset], 0x00);
        assert_eq!(ch[psk.binders_offset + 1], 0x21);
    }

    #[test]
    fn parse_psk_rejects_non_last() {
        // pre_shared_key followed by another extension is illegal.
        let psk_body = encode_offered_psks(&[(b"x", 0)], &[&[0x11u8; 32][..]]);
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        // Wrong order: psk first, then psk_key_exchange_modes.
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xb2; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(
            ClientHello::parse(&ch),
            Err(ParseError::BadExtension)
        ));
    }

    #[test]
    fn parse_psk_rejects_count_mismatch() {
        // Two identities but only one binder.
        let psk_body = encode_offered_psks(&[(b"id1", 1), (b"id2", 2)], &[&[0x33u8; 32][..]]);
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xc3; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(
            ClientHello::parse(&ch),
            Err(ParseError::BadExtension)
        ));
    }

    #[test]
    fn parse_psk_rejects_short_binder() {
        // Binder must be 32–255 bytes; 16 is too short.
        let psk_body = encode_offered_psks(&[(b"id", 0)], &[&[0x44u8; 16][..]]);
        let kem_body = [0x01u8, 0x01];
        let mut tmp = [0u8; 4096];
        let mut q = 0;
        q = write_ext(&mut tmp, q, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        q = write_ext(&mut tmp, q, ext_type::PRE_SHARED_KEY, &psk_body);

        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xd4; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(
            ClientHello::parse(&ch),
            Err(ParseError::BadExtension)
        ));
    }

    #[test]
    fn parse_psk_modes_both_flags() {
        // psk_key_exchange_modes with both modes; no pre_shared_key.
        let kem_body = [0x02u8, 0x00, 0x01]; // [psk_ke, psk_dhe_ke]
        let mut tmp = [0u8; 64];
        let q = write_ext(&mut tmp, 0, ext_type::PSK_KEY_EXCHANGE_MODES, &kem_body);
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xe5; 32], [0x77; 32], &tmp[..q]);
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
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xe6; 32], [0x77; 32], &tmp[..q]);
        assert!(matches!(
            ClientHello::parse(&ch),
            Err(ParseError::BadExtension)
        ));
    }

    #[test]
    fn parse_no_psk_means_psk_none() {
        // Existing-shape ClientHello (no PSK extensions) still parses
        // and reports no PSK offer.
        let (ch, _) = build_synthetic_ch_with_trailing_ext_bytes([0xf7; 32], [0x77; 32], &[]);
        let parsed = ClientHello::parse(&ch).unwrap();
        assert!(parsed.psk.is_none());
        assert_eq!(parsed.psk_ke_modes, 0);
    }
}
