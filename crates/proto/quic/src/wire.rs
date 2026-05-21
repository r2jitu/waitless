// net/quic_wire.rs — RFC 9000 wire-format primitives (sans-io).
//
// Variable-length integer encoding (RFC 9000 §16), long-header
// (§17.2) and short-header (§17.3) packet parsing, and packet
// number truncation/reconstruction (§17.1, A.3). Pure byte-slice
// in/out — no I/O, no allocation, no state.
//
// Scope (this module is just the wire format):
// - VARINT encode + decode
// - Long header: type / version / DCID / SCID + Initial token /
//   payload-length parse
// - Short header: 1-RTT first-byte split + DCID
// - Packet number decode: (truncated, expected) -> full
//
// Out of scope:
// - Frame type parsing (lives in `quic_frame.rs` in commit N+1)
// - Header protection / packet protection (lives in `quic_crypto`)
// - Connection state, ACK ranges, congestion control, etc.
// - Version 1 only (the universal "salt" + initial keys); no
//   negotiation packets, no Retry handling.

// (no-std declaration is in lib.rs after the merger from
// //crates/net:quic_wire into //crates/proto/quic.)

// ============================================================================
// Constants — RFC 9000 §17
// ============================================================================

/// QUIC version 1 (RFC 9000 §15). Anything else gets a Version
/// Negotiation packet — out of scope here.
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// First-byte fixed bit (§17.2 / §17.3): always 1 for QUIC v1.
pub const FIXED_BIT: u8 = 0x40;

/// First-byte form bit: 1 = long header, 0 = short header.
pub const HEADER_FORM_LONG: u8 = 0x80;

/// Long-header packet types (after `(b >> 4) & 0x3`).
pub mod long_packet_type {
    pub const INITIAL: u8 = 0x0;
    pub const ZERO_RTT: u8 = 0x1;
    pub const HANDSHAKE: u8 = 0x2;
    pub const RETRY: u8 = 0x3;
}

/// Maximum allowed Connection ID length, per QUIC v1 (§17.2 caps
/// DCID/SCID encoded in long-header at 20 bytes).
pub const MAX_CID_LEN: usize = 20;

/// Maximum encodable VARINT (six 8-byte forms, top two bits = 11):
/// 2^62 - 1 (RFC 9000 §16).
pub const MAX_VARINT: u64 = (1u64 << 62) - 1;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// Input ended before the structure could be fully parsed.
    Truncated,
    /// A length field exceeded what the spec permits (e.g. a CID
    /// length > 20 in QUIC v1, or a varint > 2^62-1 on encode).
    BadLength,
    /// First-byte field doesn't match the expected form (e.g.
    /// `parse_long_header` invoked on a short-header packet).
    WrongForm,
    /// `Fixed Bit` (RFC 9000 §17.2 / §17.3) was not 1. Per
    /// RFC 9001 §3 servers MAY discard such packets; we surface
    /// it so the caller can route the discard.
    BadFixedBit,
    /// QUIC version field on the wire is not `QUIC_VERSION_1`.
    /// Server is expected to emit a Version Negotiation reply.
    UnsupportedVersion(u32),
    /// Output buffer too small.
    OutputTooSmall,
}

// ============================================================================
// Variable-length integers (RFC 9000 §16)
// ============================================================================
//
// Two-bit length prefix in the high bits of the first byte:
//   00 → 1-byte VARINT, value 0..63                    (mask 0x3f)
//   01 → 2-byte VARINT, value 0..16383                 (mask 0x3fff)
//   10 → 4-byte VARINT, value 0..1_073_741_823         (mask 0x3fff_ffff)
//   11 → 8-byte VARINT, value 0..2^62-1                (mask 0x3fff_ffff_ffff_ffff)

/// Length (in bytes) of the VARINT encoded by `first_byte`.
#[inline]
pub fn varint_len_from_first_byte(first_byte: u8) -> usize {
    1usize << ((first_byte >> 6) & 0x3)
}

/// Parse a VARINT from `data`. On success returns `(value, bytes_consumed)`.
pub fn read_varint(data: &[u8]) -> Result<(u64, usize), WireError> {
    if data.is_empty() {
        return Err(WireError::Truncated);
    }
    let first = data[0];
    let len = varint_len_from_first_byte(first);
    if data.len() < len {
        return Err(WireError::Truncated);
    }
    // Mask the two length-prefix bits out of the high byte before
    // assembling. Below the BE assembly is equivalent to:
    //   `value = data[..len] interpreted as BE u64`
    // with bit 6/7 of the top byte cleared.
    let mut v: u64 = (first & 0x3f) as u64;
    for &b in &data[1..len] {
        v = (v << 8) | b as u64;
    }
    Ok((v, len))
}

/// Encode `value` as a VARINT into `out`. Writes the smallest
/// representation that fits. Returns bytes written.
pub fn write_varint(value: u64, out: &mut [u8]) -> Result<usize, WireError> {
    if value > MAX_VARINT {
        return Err(WireError::BadLength);
    }
    let (len, prefix): (usize, u8) = if value < (1 << 6) {
        (1, 0x00)
    } else if value < (1 << 14) {
        (2, 0x40)
    } else if value < (1 << 30) {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    if out.len() < len {
        return Err(WireError::OutputTooSmall);
    }
    // Big-endian assembly with the prefix OR'd into the high byte.
    for (i, b) in out.iter_mut().enumerate().take(len) {
        *b = ((value >> (8 * (len - 1 - i))) & 0xff) as u8;
    }
    out[0] |= prefix;
    Ok(len)
}

// ============================================================================
// Long header (RFC 9000 §17.2)
// ============================================================================
//
// First byte (long header):
//   Header Form (1)  = 1
//   Fixed Bit (1)    = 1
//   Long Packet Type (2)  -- 00=Initial, 01=0-RTT, 10=Handshake, 11=Retry
//   Type-Specific Bits (4)
// followed by:
//   Version (32)
//   DCID Length (8)  + DCID (variable, 0..20 bytes in v1)
//   SCID Length (8)  + SCID (variable, 0..20 bytes in v1)
//   ... type-specific tail (token + payload-length for Initial,
//                           payload-length for Handshake/0-RTT,
//                           Retry token + integrity tag for Retry)

/// Parsed view of a long-header packet's *common* preamble (the
/// fixed fields shared by Initial / 0-RTT / Handshake / Retry).
/// Type-specific tails are surfaced via [`InitialHeader`] etc.
#[derive(Clone, Copy, Debug)]
pub struct LongHeaderPreamble<'a> {
    /// Raw first byte. Type-specific bits (low 4) include packet-
    /// number length minus 1 for Initial / 0-RTT / Handshake;
    /// callers strip header-protection before interpreting.
    pub first_byte: u8,
    pub long_type: u8,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    /// Offset of the byte immediately AFTER the SCID — i.e. where
    /// the type-specific tail starts. Equals the number of bytes
    /// the preamble itself consumed.
    pub tail_offset: usize,
}

/// Parse the common long-header preamble (everything up through
/// `Source Connection ID`). Returns the parsed view and `tail_offset`
/// for callers to continue parsing type-specific fields.
pub fn parse_long_header_preamble(data: &[u8]) -> Result<LongHeaderPreamble<'_>, WireError> {
    if data.is_empty() {
        return Err(WireError::Truncated);
    }
    let first = data[0];
    if first & HEADER_FORM_LONG == 0 {
        return Err(WireError::WrongForm);
    }
    if first & FIXED_BIT == 0 {
        return Err(WireError::BadFixedBit);
    }
    let long_type = (first >> 4) & 0x3;

    if data.len() < 1 + 4 + 1 {
        return Err(WireError::Truncated);
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    // Reject unknown versions early so the caller can route to
    // Version Negotiation. Retry packets also carry a version, but
    // RFC 9000 §17.2.5 says servers send Retry under v1, so
    // version=1 covers them too.
    if version != QUIC_VERSION_1 {
        return Err(WireError::UnsupportedVersion(version));
    }

    let dcid_len = data[5] as usize;
    if dcid_len > MAX_CID_LEN {
        return Err(WireError::BadLength);
    }
    if data.len() < 1 + 4 + 1 + dcid_len + 1 {
        return Err(WireError::Truncated);
    }
    let dcid = &data[6..6 + dcid_len];

    let scid_len_offset = 6 + dcid_len;
    let scid_len = data[scid_len_offset] as usize;
    if scid_len > MAX_CID_LEN {
        return Err(WireError::BadLength);
    }
    let scid_start = scid_len_offset + 1;
    let scid_end = scid_start + scid_len;
    if data.len() < scid_end {
        return Err(WireError::Truncated);
    }
    let scid = &data[scid_start..scid_end];

    Ok(LongHeaderPreamble {
        first_byte: first,
        long_type,
        version,
        dcid,
        scid,
        tail_offset: scid_end,
    })
}

/// Parsed Initial packet header (preamble + Token + Length).
/// Per §17.2.2:
///   Token Length (i)  -- VARINT
///   Token (..)        -- TLEN bytes
///   Length (i)        -- VARINT, length of (PN + protected payload)
#[derive(Clone, Copy, Debug)]
pub struct InitialHeader<'a> {
    pub preamble: LongHeaderPreamble<'a>,
    pub token: &'a [u8],
    /// `Length` field per RFC 9000 §17.2.2 — VARINT covering
    /// `Packet Number || Protected Payload`. Caller uses this to
    /// know the upper bound of this packet's bytes.
    pub length: u64,
    /// Offset (within the input slice) of the byte immediately
    /// after the `Length` VARINT. The PN starts here once header
    /// protection is removed.
    pub pn_offset: usize,
}

/// Parse a long-header Initial packet up through the `Length`
/// VARINT. Caller is responsible for header protection removal +
/// packet-number decoding (which depend on initial keys derived
/// from the DCID — see RFC 9001 §5.2).
pub fn parse_initial_header(data: &[u8]) -> Result<InitialHeader<'_>, WireError> {
    let preamble = parse_long_header_preamble(data)?;
    if preamble.long_type != long_packet_type::INITIAL {
        return Err(WireError::WrongForm);
    }
    let mut p = preamble.tail_offset;
    let (token_len, n) = read_varint(&data[p..])?;
    p += n;
    if (token_len as usize) > data.len() - p {
        return Err(WireError::Truncated);
    }
    let token_end = p + token_len as usize;
    let token = &data[p..token_end];
    p = token_end;
    let (length, n) = read_varint(&data[p..])?;
    p += n;
    Ok(InitialHeader {
        preamble,
        token,
        length,
        pn_offset: p,
    })
}

/// Long-header Handshake / 0-RTT packet (§17.2.3, §17.2.4): no
/// Token, just `Length`. Same shape after the preamble.
#[derive(Clone, Copy, Debug)]
pub struct LongPayloadHeader<'a> {
    pub preamble: LongHeaderPreamble<'a>,
    pub length: u64,
    pub pn_offset: usize,
}

/// Parse a long-header Handshake or 0-RTT packet up through `Length`.
pub fn parse_long_payload_header(data: &[u8]) -> Result<LongPayloadHeader<'_>, WireError> {
    let preamble = parse_long_header_preamble(data)?;
    if preamble.long_type != long_packet_type::HANDSHAKE
        && preamble.long_type != long_packet_type::ZERO_RTT
    {
        return Err(WireError::WrongForm);
    }
    let mut p = preamble.tail_offset;
    let (length, n) = read_varint(&data[p..])?;
    p += n;
    Ok(LongPayloadHeader {
        preamble,
        length,
        pn_offset: p,
    })
}

// ============================================================================
// Short header (RFC 9000 §17.3)
// ============================================================================
//
// First byte (short header, 1-RTT):
//   Header Form (1)  = 0
//   Fixed Bit (1)    = 1
//   Spin Bit (1)
//   Reserved (2)        -- protected; sender SHOULD set 00
//   Key Phase (1)       -- protected
//   PN Length - 1 (2)   -- protected
// followed by:
//   Destination Connection ID  -- length is endpoint-known
//                                  (caller passes it in)
//   Packet Number              -- 1..4 bytes, protected
//   Payload                    -- protected
//
// The DCID length isn't on the wire for short-header packets —
// receiver must agree with sender out-of-band on the length per
// RFC 9000 §5.1. Callers track this from the connection's
// negotiated `local_cid_len`.

#[derive(Clone, Copy, Debug)]
pub struct ShortHeader<'a> {
    pub first_byte: u8,
    pub dcid: &'a [u8],
    /// Offset of the byte immediately after DCID — where the
    /// (still-protected) PN starts.
    pub pn_offset: usize,
}

/// Parse a short-header (1-RTT) packet's DCID. `dcid_len` is the
/// receiver-side connection ID length (negotiated out-of-band; we
/// pin it at connection-create time). Returns the DCID slice and
/// the offset where the protected packet number starts.
pub fn parse_short_header<'a>(
    data: &'a [u8],
    dcid_len: usize,
) -> Result<ShortHeader<'a>, WireError> {
    if dcid_len > MAX_CID_LEN {
        return Err(WireError::BadLength);
    }
    if data.is_empty() {
        return Err(WireError::Truncated);
    }
    let first = data[0];
    if first & HEADER_FORM_LONG != 0 {
        return Err(WireError::WrongForm);
    }
    if first & FIXED_BIT == 0 {
        return Err(WireError::BadFixedBit);
    }
    if data.len() < 1 + dcid_len {
        return Err(WireError::Truncated);
    }
    let dcid = &data[1..1 + dcid_len];
    Ok(ShortHeader {
        first_byte: first,
        dcid,
        pn_offset: 1 + dcid_len,
    })
}

// ============================================================================
// Packet number decoding (RFC 9000 §17.1, App A.3)
// ============================================================================

/// Decode a truncated, on-wire packet number into the full 62-bit
/// space, given `largest_pn` (the largest PN we've previously
/// decoded in this number space). `truncated_pn_len` ∈ {1,2,3,4}.
///
/// Mirrors the algorithm from RFC 9000 Appendix A.3 verbatim — pick
/// the candidate closest to `expected = largest_pn + 1`, with the
/// half-window distance check to disambiguate wrap edges.
pub fn decode_packet_number(largest_pn: u64, truncated_pn: u64, truncated_pn_len: usize) -> u64 {
    debug_assert!(matches!(truncated_pn_len, 1..=4));
    let pn_nbits: u64 = (truncated_pn_len as u64) * 8;
    let expected_pn = largest_pn.wrapping_add(1);
    let pn_win: u64 = 1u64 << pn_nbits;
    let pn_hwin: u64 = pn_win / 2;
    let pn_mask: u64 = pn_win - 1;

    // Candidate PN sharing low pn_nbits with `truncated_pn`,
    // closest to `expected_pn`.
    let candidate = (expected_pn & !pn_mask) | truncated_pn;
    if candidate.wrapping_add(pn_hwin) <= expected_pn && candidate < (1u64 << 62) - pn_win {
        candidate.wrapping_add(pn_win)
    } else if candidate > expected_pn.wrapping_add(pn_hwin) && candidate >= pn_win {
        candidate.wrapping_sub(pn_win)
    } else {
        candidate
    }
}

/// Encode `pn` into the smallest number of bytes such that, given
/// the largest acked PN (`largest_acked_pn`, or `None` if we haven't
/// seen any ACK yet), the receiver's `decode_packet_number`
/// algorithm reconstructs `pn` unambiguously. Per RFC 9000 §17.1:
/// `num_unacked = pn - largest_acked + 1`, and the encoded length
/// is the minimum that fits at least `2 * num_unacked - 1`.
///
/// Returns `bytes_written` and writes the big-endian truncated PN
/// into the front of `out`. `out.len()` must be at least 4.
pub fn encode_packet_number(
    pn: u64,
    largest_acked_pn: Option<u64>,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if out.len() < 4 {
        return Err(WireError::OutputTooSmall);
    }
    // The spec uses (2 * num_unacked - 1) as the floor; we pick the
    // smallest representation that exceeds it.
    let needed_bits = match largest_acked_pn {
        None => 64u32, // No ACK seen → encode every bit (we'll downsize below).
        Some(largest) => {
            // num_unacked = pn - largest, but we treat (largest >= pn)
            // defensively as 1.
            let num_unacked = pn.saturating_sub(largest).max(1);
            let floor = num_unacked.saturating_mul(2).saturating_sub(1);
            // bit length of `floor`.
            64 - floor.leading_zeros()
        }
    };
    let len = if needed_bits <= 8 {
        1
    } else if needed_bits <= 16 {
        2
    } else if needed_bits <= 24 {
        3
    } else {
        4
    };
    let mask = if len == 4 {
        u32::MAX
    } else {
        (1u32 << (len * 8)) - 1
    };
    let truncated = (pn as u32) & mask;
    for (i, b) in out.iter_mut().enumerate().take(len) {
        *b = ((truncated >> (8 * (len - 1 - i))) & 0xff) as u8;
    }
    Ok(len)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── VARINT — RFC 9000 §16 examples ────────────────────────────────────

    #[test]
    fn varint_rfc_examples_round_trip() {
        // From RFC 9000 §16, table at end of section. (value, bytes)
        let cases: &[(u64, &[u8])] = &[
            (
                151_288_809_941_952_652,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (15_293, &[0x7b, 0xbd]),
            (151, &[0x40, 0x97]),
            (37, &[0x25]),
        ];
        for (val, encoded) in cases {
            // Decode
            let (v, n) = read_varint(encoded).unwrap();
            assert_eq!(v, *val, "decode {encoded:?}");
            assert_eq!(n, encoded.len());

            // Encode → must produce the canonical-length form.
            let mut buf = [0u8; 8];
            let n = write_varint(*val, &mut buf).unwrap();
            assert_eq!(&buf[..n], *encoded, "encode {val}");
        }
    }

    #[test]
    fn varint_rejects_oversize_value() {
        let mut buf = [0u8; 8];
        assert!(write_varint(MAX_VARINT, &mut buf).is_ok());
        assert_eq!(
            write_varint(MAX_VARINT + 1, &mut buf),
            Err(WireError::BadLength)
        );
    }

    #[test]
    fn varint_rejects_truncated() {
        // First byte says 8-byte form but only 4 follow.
        let buf = [0xc2u8, 0x19, 0x7c, 0x5e];
        assert_eq!(read_varint(&buf), Err(WireError::Truncated));
    }

    #[test]
    fn varint_short_buffer_on_encode() {
        let mut buf = [0u8; 1];
        assert_eq!(write_varint(1000, &mut buf), Err(WireError::OutputTooSmall));
    }

    #[test]
    fn varint_first_byte_length() {
        assert_eq!(varint_len_from_first_byte(0x00), 1);
        assert_eq!(varint_len_from_first_byte(0x40), 2);
        assert_eq!(varint_len_from_first_byte(0x80), 4);
        assert_eq!(varint_len_from_first_byte(0xc0), 8);
    }

    // ── Long header / Initial ──────────────────────────────────────────────

    #[test]
    fn parse_initial_header_minimal() {
        // Build a minimal Initial: type=Initial, version=1, DCID=8,
        // SCID=0, Token Len=0, Length=0x01.
        let dcid = [0x11u8; 8];
        let mut buf = vec![];
        buf.push(0xc0); // long(1) | fixed(1) | type=Initial(00) | low4=0
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(&dcid);
        buf.push(0); // SCID len = 0
        buf.push(0); // Token Length VARINT = 0
        buf.push(0x01); // Length VARINT = 1

        let h = parse_initial_header(&buf).unwrap();
        assert_eq!(h.preamble.long_type, long_packet_type::INITIAL);
        assert_eq!(h.preamble.version, QUIC_VERSION_1);
        assert_eq!(h.preamble.dcid, &dcid[..]);
        assert_eq!(h.preamble.scid.len(), 0);
        assert_eq!(h.token.len(), 0);
        assert_eq!(h.length, 1);
        assert_eq!(h.pn_offset, buf.len());
    }

    #[test]
    fn parse_long_header_rejects_short_form() {
        let buf = [0x40u8]; // form=short, fixed=1
        assert!(matches!(
            parse_long_header_preamble(&buf),
            Err(WireError::WrongForm)
        ));
    }

    #[test]
    fn parse_long_header_rejects_zero_fixed_bit() {
        let buf = [0x80u8]; // form=long, fixed=0
        assert!(matches!(
            parse_long_header_preamble(&buf),
            Err(WireError::BadFixedBit)
        ));
    }

    #[test]
    fn parse_long_header_rejects_unknown_version() {
        let mut buf = vec![0xc0];
        buf.extend_from_slice(&0x00abcdefu32.to_be_bytes());
        buf.push(0);
        buf.push(0);
        match parse_long_header_preamble(&buf) {
            Err(WireError::UnsupportedVersion(v)) => assert_eq!(v, 0x00abcdef),
            x => panic!("expected UnsupportedVersion, got {x:?}"),
        }
    }

    #[test]
    fn parse_long_header_rejects_oversize_cid() {
        let mut buf = vec![0xc0];
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.push(MAX_CID_LEN as u8 + 1); // illegal in v1
        assert!(matches!(
            parse_long_header_preamble(&buf),
            Err(WireError::BadLength)
        ));
    }

    #[test]
    fn parse_handshake_header() {
        let mut buf = vec![];
        buf.push(0xe0); // long | fixed | type=Handshake(10) | low4=0
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.push(0);
        buf.push(0);
        buf.push(0x40);
        buf.push(0x05); // Length VARINT = 5

        let h = parse_long_payload_header(&buf).unwrap();
        assert_eq!(h.preamble.long_type, long_packet_type::HANDSHAKE);
        assert_eq!(h.length, 5);
    }

    #[test]
    fn parse_long_payload_rejects_initial_type() {
        let mut buf = vec![0xc0];
        buf.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        buf.push(0);
        buf.push(0);
        buf.push(0); // Token Len = 0
        buf.push(0); // Length VARINT = 0
        assert!(matches!(
            parse_long_payload_header(&buf),
            Err(WireError::WrongForm)
        ));
    }

    // ── Short header ─────────────────────────────────────────────────────

    #[test]
    fn parse_short_header_known_dcid_len() {
        let dcid = [0xab, 0xcd, 0xef, 0x12];
        let mut buf = vec![0x40]; // form=short, fixed=1, low6=0
        buf.extend_from_slice(&dcid);
        buf.push(0xff); // protected PN starts here
        let h = parse_short_header(&buf, dcid.len()).unwrap();
        assert_eq!(h.first_byte, 0x40);
        assert_eq!(h.dcid, &dcid[..]);
        assert_eq!(h.pn_offset, 1 + dcid.len());
    }

    #[test]
    fn parse_short_header_rejects_long_form() {
        let buf = [0xc0u8, 0, 0, 0, 0];
        assert!(matches!(
            parse_short_header(&buf, 0),
            Err(WireError::WrongForm)
        ));
    }

    #[test]
    fn parse_short_header_truncated() {
        let buf = [0x40u8]; // first byte only, no DCID
        assert!(matches!(
            parse_short_header(&buf, 8),
            Err(WireError::Truncated)
        ));
    }

    // ── Packet number decoding — RFC 9000 Appendix A.3 ───────────────────

    #[test]
    fn decode_packet_number_appendix_example() {
        // RFC 9000 §A.3 example:
        //   largest_pn = 0xa82f30ea
        //   truncated_pn = 0x9b32 (2 bytes)
        //   expected:    0xa82f9b32
        let full = decode_packet_number(0xa82f_30ea, 0x9b32, 2);
        assert_eq!(full, 0xa82f_9b32);
    }

    #[test]
    fn decode_packet_number_window_edge() {
        // Just past the half-window: truncated value of 0 with a
        // 1-byte PN and largest_pn=0x80 → expected=0x81.
        // pn_win=256, pn_hwin=128. candidate = 0x80 & !0xff | 0x00 = 0.
        // candidate + pn_hwin = 128 <= 0x81 → wrap: result = 256.
        let full = decode_packet_number(0x80, 0x00, 1);
        assert_eq!(full, 0x100);
    }

    #[test]
    fn decode_packet_number_below_window() {
        // truncated=0xff (1B), largest_pn=0x100, expected=0x101.
        // candidate = 0x100 & !0xff | 0xff = 0xff. 0xff + 128 = 0x17f
        // > 0x101 → no wrap-up. 0xff is below expected → no wrap-down.
        // result = 0xff.
        let full = decode_packet_number(0x100, 0xff, 1);
        assert_eq!(full, 0xff);
    }

    #[test]
    fn encode_packet_number_no_acks_uses_4_bytes() {
        let mut out = [0u8; 4];
        let n = encode_packet_number(0x1234_5678, None, &mut out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..n], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn encode_packet_number_few_unacked_uses_minimum() {
        // largest_acked = 100, pn = 101 → num_unacked=1, floor=1,
        // bits=1 → 1-byte encoding.
        let mut out = [0u8; 4];
        let n = encode_packet_number(101, Some(100), &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0], 101u8);
    }

    #[test]
    fn encode_decode_round_trip_random_walk() {
        // Encoding then decoding should yield the original PN as
        // long as the encoder picked enough bytes (= the contract).
        let mut largest = 0u64;
        for pn in [1u64, 5, 100, 200, 1234, 65535, 65536, 100_000_000] {
            let mut out = [0u8; 4];
            let n = encode_packet_number(pn, Some(largest), &mut out).unwrap();
            let mut truncated = 0u64;
            for &byte in &out[..n] {
                truncated = (truncated << 8) | byte as u64;
            }
            let decoded = decode_packet_number(largest, truncated, n);
            assert_eq!(decoded, pn, "pn={pn} largest={largest} bytes={n}");
            largest = pn;
        }
    }

    #[test]
    fn varint_bounds_each_form() {
        let cases: &[(u64, usize)] = &[
            (0, 1),
            (63, 1),
            (64, 2),
            (16383, 2),
            (16384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX_VARINT, 8),
        ];
        let mut buf = [0u8; 8];
        for (val, expected_len) in cases {
            let n = write_varint(*val, &mut buf).unwrap();
            assert_eq!(
                n, *expected_len,
                "value {val} should encode to {expected_len} bytes"
            );
            let (decoded, _) = read_varint(&buf[..n]).unwrap();
            assert_eq!(decoded, *val);
        }
    }
}
