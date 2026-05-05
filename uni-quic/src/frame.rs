// uni-quic/src/frame.rs — RFC 9000 §19 frame codec (sans-io).
//
// Parses and encodes every frame the v1 server needs to interop
// with curl/quinn/quiche over a 1-RTT HTTP/3 connection:
//
//   0x00       PADDING
//   0x01       PING
//   0x02..03   ACK (without and with ECN counts)
//   0x06       CRYPTO
//   0x07       NEW_TOKEN  (skip)
//   0x08..0f   STREAM (with OFF/LEN/FIN flag combinations)
//   0x10       MAX_DATA           (skip)
//   0x11       MAX_STREAM_DATA    (skip)
//   0x12..13   MAX_STREAMS        (skip)
//   0x14       DATA_BLOCKED       (skip)
//   0x15       STREAM_DATA_BLOCKED (skip)
//   0x16..17   STREAMS_BLOCKED    (skip)
//   0x18       NEW_CONNECTION_ID  (skip)
//   0x19       RETIRE_CONNECTION_ID (skip)
//   0x1a..1b   PATH_CHALLENGE / PATH_RESPONSE (skip)
//   0x1c..1d   CONNECTION_CLOSE (transport- and application-layer)
//   0x1e       HANDSHAKE_DONE
//
// Pure protocol layer. The connection state machine drives this
// over decrypted packet payloads from `crate::crypto::open_*` and
// builds outbound payloads that go back into `crate::crypto::seal_*`.
//
// "Skip" frames are parsed enough to advance past their wire
// length (so coalesced frames after them keep parsing) but the
// connection layer doesn't act on them — flow control reactivity
// and CID rotation are out of scope for the MVP server. Adding
// real handling later only changes the `dispatch_frames` arm.
//
// Out of scope (no parser yet — would close the connection on receipt):
//   RESET_STREAM, STOP_SENDING, DATAGRAM (RFC 9221).

// (no-std declaration is in lib.rs. `wire` is now this crate's
// sibling module rather than a separate crate.)

use crate::wire::{read_varint, write_varint, WireError};

// ============================================================================
// Frame type bytes (RFC 9000 §19)
// ============================================================================

pub mod ftype {
    pub const PADDING: u8 = 0x00;
    pub const PING: u8 = 0x01;
    pub const ACK: u8 = 0x02;
    pub const ACK_ECN: u8 = 0x03;
    pub const CRYPTO: u8 = 0x06;

    /// Base byte for STREAM frames (§19.8). Low 3 bits are flags:
    ///   bit 0 = FIN
    ///   bit 1 = LEN  (explicit Length field present)
    ///   bit 2 = OFF  (explicit Offset field present, otherwise 0)
    pub const STREAM_BASE: u8 = 0x08;
    pub const STREAM_FLAG_FIN: u8 = 0x01;
    pub const STREAM_FLAG_LEN: u8 = 0x02;
    pub const STREAM_FLAG_OFF: u8 = 0x04;
    pub const STREAM_MAX: u8 = 0x0f;

    pub const NEW_TOKEN: u8 = 0x07;
    pub const MAX_DATA: u8 = 0x10;
    pub const MAX_STREAM_DATA: u8 = 0x11;
    pub const MAX_STREAMS_BIDI: u8 = 0x12;
    pub const MAX_STREAMS_UNI: u8 = 0x13;
    pub const DATA_BLOCKED: u8 = 0x14;
    pub const STREAM_DATA_BLOCKED: u8 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u8 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u8 = 0x17;
    pub const NEW_CONNECTION_ID: u8 = 0x18;
    pub const RETIRE_CONNECTION_ID: u8 = 0x19;
    pub const PATH_CHALLENGE: u8 = 0x1a;
    pub const PATH_RESPONSE: u8 = 0x1b;
    pub const CONNECTION_CLOSE_TRANSPORT: u8 = 0x1c;
    pub const CONNECTION_CLOSE_APPLICATION: u8 = 0x1d;
    pub const HANDSHAKE_DONE: u8 = 0x1e;
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Input ran out partway through parsing a frame.
    Truncated,
    /// A length field exceeded what's available.
    BadLength,
    /// Frame type byte not recognized in this scope. Caller may
    /// surface this as a CONNECTION_CLOSE(FRAME_ENCODING_ERROR)
    /// or, for unknown types in the §19 reserved range, drop.
    UnknownFrameType(u8),
    /// ACK ranges declared more bytes than the payload can supply.
    BadAckRanges,
    /// Output buffer too small.
    OutputTooSmall,
}

impl From<WireError> for FrameError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Truncated => FrameError::Truncated,
            WireError::BadLength => FrameError::BadLength,
            WireError::OutputTooSmall => FrameError::OutputTooSmall,
            // Other wire errors (form/version) shouldn't reach
            // frame-level parsing — surface as BadLength so the
            // caller still treats it as a malformed payload.
            _ => FrameError::BadLength,
        }
    }
}

// ============================================================================
// Frame view — slices borrow from the decrypted payload buffer
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding,
    Ping,
    /// ACK frame. `ack_ranges` is a borrow into the payload bytes
    /// containing the (gap, ack_range_length) varint pairs that
    /// follow `first_ack_range`. Use [`AckRanges`] to iterate.
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: AckRanges<'a>,
        /// `Some((ect0, ect1, ce))` when the type byte was
        /// 0x03 (ACK_ECN). Hot path doesn't need ECN today;
        /// expose for future PMTUD / congestion-aware code.
        ecn: Option<EcnCounts>,
    },
    /// CRYPTO frame — TLS handshake bytes for the current packet
    /// number space (Initial/Handshake/1-RTT).
    Crypto { offset: u64, data: &'a [u8] },
    Stream {
        stream_id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    /// 0x1c — error originated in the QUIC transport layer.
    ConnectionCloseTransport {
        error_code: u64,
        frame_type: u64,
        reason: &'a [u8],
    },
    /// 0x1d — error originated in the application protocol (HTTP/3).
    ConnectionCloseApplication {
        error_code: u64,
        reason: &'a [u8],
    },
    HandshakeDone,
    /// Wire-recognized frame whose semantics the connection layer
    /// doesn't act on yet. Carries the type byte for diagnostics —
    /// upgrading to a typed variant is a one-arm change in dispatch.
    Skipped {
        kind: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// Iterator over the (gap, ack_range_length) pairs trailing the
/// `first_ack_range` field of an ACK frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRanges<'a> {
    bytes: &'a [u8],
    /// Number of additional ranges still to consume. Pre-validated
    /// at parse time: the remaining `bytes` are guaranteed to hold
    /// exactly `count` (gap, length) varint pairs.
    count: u64,
}

impl<'a> Iterator for AckRanges<'a> {
    type Item = (u64, u64); // (gap, ack_range_length)
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        let (gap, n) = read_varint(self.bytes).ok()?;
        let (length, m) = read_varint(&self.bytes[n..]).ok()?;
        self.bytes = &self.bytes[n + m..];
        self.count -= 1;
        Some((gap, length))
    }
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse one frame from the front of `data`. Returns the frame
/// view + bytes consumed.
pub fn parse_frame(data: &[u8]) -> Result<(Frame<'_>, usize), FrameError> {
    if data.is_empty() {
        return Err(FrameError::Truncated);
    }
    let t = data[0];
    let rest = &data[1..];
    let frame_total_offset = 1usize;

    match t {
        ftype::PADDING => Ok((Frame::Padding, 1)),
        ftype::PING => Ok((Frame::Ping, 1)),
        ftype::ACK | ftype::ACK_ECN => parse_ack(rest, t == ftype::ACK_ECN, frame_total_offset),
        ftype::CRYPTO => parse_crypto(rest, frame_total_offset),
        b if (ftype::STREAM_BASE..=ftype::STREAM_MAX).contains(&b) => {
            parse_stream(rest, b, frame_total_offset)
        }
        ftype::CONNECTION_CLOSE_TRANSPORT => parse_close_transport(rest, frame_total_offset),
        ftype::CONNECTION_CLOSE_APPLICATION => {
            parse_close_application(rest, frame_total_offset)
        }
        ftype::HANDSHAKE_DONE => Ok((Frame::HandshakeDone, 1)),
        ftype::NEW_TOKEN => skip_var_len_field(rest, t, frame_total_offset),
        ftype::MAX_DATA
        | ftype::MAX_STREAMS_BIDI
        | ftype::MAX_STREAMS_UNI
        | ftype::DATA_BLOCKED
        | ftype::STREAMS_BLOCKED_BIDI
        | ftype::STREAMS_BLOCKED_UNI
        | ftype::RETIRE_CONNECTION_ID => skip_one_varint(rest, t, frame_total_offset),
        ftype::MAX_STREAM_DATA | ftype::STREAM_DATA_BLOCKED => {
            skip_two_varints(rest, t, frame_total_offset)
        }
        ftype::NEW_CONNECTION_ID => skip_new_connection_id(rest, t, frame_total_offset),
        ftype::PATH_CHALLENGE | ftype::PATH_RESPONSE => {
            skip_fixed(rest, t, 8, frame_total_offset)
        }
        other => Err(FrameError::UnknownFrameType(other)),
    }
}

// ── Skip helpers ─────────────────────────────────────────────────

fn skip_one_varint(body: &[u8], kind: u8, header: usize) -> Result<(Frame<'_>, usize), FrameError> {
    let (_v, n) = read_varint(body)?;
    Ok((Frame::Skipped { kind }, header + n))
}

fn skip_two_varints(
    body: &[u8],
    kind: u8,
    header: usize,
) -> Result<(Frame<'_>, usize), FrameError> {
    let (_a, n) = read_varint(body)?;
    let (_b, m) = read_varint(&body[n..])?;
    Ok((Frame::Skipped { kind }, header + n + m))
}

fn skip_var_len_field(
    body: &[u8],
    kind: u8,
    header: usize,
) -> Result<(Frame<'_>, usize), FrameError> {
    // NEW_TOKEN: u8 0x07 || varint token_len || token bytes
    let (token_len, n) = read_varint(body)?;
    let token_len = token_len as usize;
    if token_len > body.len() - n {
        return Err(FrameError::BadLength);
    }
    Ok((Frame::Skipped { kind }, header + n + token_len))
}

fn skip_new_connection_id(
    body: &[u8],
    kind: u8,
    header: usize,
) -> Result<(Frame<'_>, usize), FrameError> {
    // NEW_CONNECTION_ID: varint sequence_number || varint retire_prior_to
    //   || u8 cid_len || cid_len bytes || 16 bytes stateless_reset_token.
    let (_seq, n) = read_varint(body)?;
    let (_retire, m) = read_varint(&body[n..])?;
    let after_varints = n + m;
    if after_varints + 1 > body.len() {
        return Err(FrameError::BadLength);
    }
    let cid_len = body[after_varints] as usize;
    let total_after_header = after_varints + 1 + cid_len + 16;
    if total_after_header > body.len() {
        return Err(FrameError::BadLength);
    }
    Ok((Frame::Skipped { kind }, header + total_after_header))
}

fn skip_fixed(
    body: &[u8],
    kind: u8,
    n: usize,
    header: usize,
) -> Result<(Frame<'_>, usize), FrameError> {
    if body.len() < n {
        return Err(FrameError::Truncated);
    }
    Ok((Frame::Skipped { kind }, header + n))
}

fn parse_ack<'a>(
    body: &'a [u8],
    is_ecn: bool,
    header_consumed: usize,
) -> Result<(Frame<'a>, usize), FrameError> {
    let mut p = 0usize;
    let (largest, n) = read_varint(&body[p..])?;
    p += n;
    let (ack_delay, n) = read_varint(&body[p..])?;
    p += n;
    let (range_count, n) = read_varint(&body[p..])?;
    p += n;
    let (first_ack_range, n) = read_varint(&body[p..])?;
    p += n;

    // Collect the (gap, length) varint pairs up front so we can
    // bound the slice; iteration in AckRanges trusts that bound.
    let ranges_start = p;
    for _ in 0..range_count {
        let (_, n1) = read_varint(&body[p..])?;
        p += n1;
        let (_, n2) = read_varint(&body[p..])?;
        p += n2;
    }
    let ranges_bytes = &body[ranges_start..p];
    let ranges = AckRanges { bytes: ranges_bytes, count: range_count };

    let ecn = if is_ecn {
        let (ect0, n) = read_varint(&body[p..])?;
        p += n;
        let (ect1, n) = read_varint(&body[p..])?;
        p += n;
        let (ce, n) = read_varint(&body[p..])?;
        p += n;
        Some(EcnCounts { ect0, ect1, ce })
    } else {
        None
    };

    Ok((
        Frame::Ack {
            largest_acknowledged: largest,
            ack_delay,
            first_ack_range,
            ack_ranges: ranges,
            ecn,
        },
        header_consumed + p,
    ))
}

fn parse_crypto<'a>(
    body: &'a [u8],
    header_consumed: usize,
) -> Result<(Frame<'a>, usize), FrameError> {
    let mut p = 0usize;
    let (offset, n) = read_varint(&body[p..])?;
    p += n;
    let (length, n) = read_varint(&body[p..])?;
    p += n;
    let length = length as usize;
    if length > body.len() - p {
        return Err(FrameError::Truncated);
    }
    let data = &body[p..p + length];
    p += length;
    Ok((Frame::Crypto { offset, data }, header_consumed + p))
}

fn parse_stream<'a>(
    body: &'a [u8],
    type_byte: u8,
    header_consumed: usize,
) -> Result<(Frame<'a>, usize), FrameError> {
    let has_off = type_byte & ftype::STREAM_FLAG_OFF != 0;
    let has_len = type_byte & ftype::STREAM_FLAG_LEN != 0;
    let fin = type_byte & ftype::STREAM_FLAG_FIN != 0;

    let mut p = 0usize;
    let (stream_id, n) = read_varint(&body[p..])?;
    p += n;
    let offset = if has_off {
        let (v, n) = read_varint(&body[p..])?;
        p += n;
        v
    } else {
        0
    };

    // If LEN is unset, the STREAM frame extends to the end of the
    // packet payload. The caller passes us only this frame's bytes
    // because they don't know the boundary either — that means the
    // STREAM frame MUST be the LAST frame in the payload, and we
    // consume `body[p..]` as data. The state machine enforces
    // "STREAM-without-LEN is last" at a higher level.
    let (data, len_consumed) = if has_len {
        let (length, n) = read_varint(&body[p..])?;
        p += n;
        let length = length as usize;
        if length > body.len() - p {
            return Err(FrameError::Truncated);
        }
        (&body[p..p + length], length)
    } else {
        let d = &body[p..];
        (d, d.len())
    };
    p += len_consumed;

    Ok((
        Frame::Stream { stream_id, offset, data, fin },
        header_consumed + p,
    ))
}

fn parse_close_transport<'a>(
    body: &'a [u8],
    header_consumed: usize,
) -> Result<(Frame<'a>, usize), FrameError> {
    let mut p = 0usize;
    let (error_code, n) = read_varint(&body[p..])?;
    p += n;
    let (frame_type, n) = read_varint(&body[p..])?;
    p += n;
    let (reason_len, n) = read_varint(&body[p..])?;
    p += n;
    let reason_len = reason_len as usize;
    if reason_len > body.len() - p {
        return Err(FrameError::Truncated);
    }
    let reason = &body[p..p + reason_len];
    p += reason_len;
    Ok((
        Frame::ConnectionCloseTransport {
            error_code,
            frame_type,
            reason,
        },
        header_consumed + p,
    ))
}

fn parse_close_application<'a>(
    body: &'a [u8],
    header_consumed: usize,
) -> Result<(Frame<'a>, usize), FrameError> {
    let mut p = 0usize;
    let (error_code, n) = read_varint(&body[p..])?;
    p += n;
    let (reason_len, n) = read_varint(&body[p..])?;
    p += n;
    let reason_len = reason_len as usize;
    if reason_len > body.len() - p {
        return Err(FrameError::Truncated);
    }
    let reason = &body[p..p + reason_len];
    p += reason_len;
    Ok((
        Frame::ConnectionCloseApplication { error_code, reason },
        header_consumed + p,
    ))
}

// ============================================================================
// Encoding
// ============================================================================

/// Write a CRYPTO frame `(offset, data)` into `out`. Returns bytes
/// written. Inverse of `parse_frame` for the CRYPTO case.
pub fn write_crypto(offset: u64, data: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::CRYPTO;
    let mut p = 1usize;
    p += write_varint(offset, &mut out[p..])?;
    p += write_varint(data.len() as u64, &mut out[p..])?;
    if out.len() - p < data.len() {
        return Err(FrameError::OutputTooSmall);
    }
    out[p..p + data.len()].copy_from_slice(data);
    p += data.len();
    Ok(p)
}

/// Write a STREAM frame `(stream_id, offset, fin, data)` with the
/// OFF + LEN flags both set. Returns bytes written. The connection
/// layer always sends with explicit length so multiple frames can
/// coalesce in one packet; LEN-omitted "extends-to-end-of-payload"
/// is reserved for the case where it's the only or last frame.
pub fn write_stream(
    stream_id: u64,
    offset: u64,
    fin: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    let mut t = ftype::STREAM_BASE | ftype::STREAM_FLAG_OFF | ftype::STREAM_FLAG_LEN;
    if fin {
        t |= ftype::STREAM_FLAG_FIN;
    }
    out[0] = t;
    let mut p = 1usize;
    p += write_varint(stream_id, &mut out[p..])?;
    p += write_varint(offset, &mut out[p..])?;
    p += write_varint(data.len() as u64, &mut out[p..])?;
    if out.len() - p < data.len() {
        return Err(FrameError::OutputTooSmall);
    }
    out[p..p + data.len()].copy_from_slice(data);
    p += data.len();
    Ok(p)
}

/// Write an ACK frame. `additional_ranges` is `(gap, ack_range_length)`
/// varint pairs in network order (oldest gap first); pass an empty
/// slice for a single-range ACK.
pub fn write_ack(
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    additional_ranges: &[(u64, u64)],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::ACK;
    let mut p = 1usize;
    p += write_varint(largest_acknowledged, &mut out[p..])?;
    p += write_varint(ack_delay, &mut out[p..])?;
    p += write_varint(additional_ranges.len() as u64, &mut out[p..])?;
    p += write_varint(first_ack_range, &mut out[p..])?;
    for &(gap, length) in additional_ranges {
        p += write_varint(gap, &mut out[p..])?;
        p += write_varint(length, &mut out[p..])?;
    }
    Ok(p)
}

/// Write a CONNECTION_CLOSE (transport) frame.
pub fn write_close_transport(
    error_code: u64,
    frame_type: u64,
    reason: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::CONNECTION_CLOSE_TRANSPORT;
    let mut p = 1usize;
    p += write_varint(error_code, &mut out[p..])?;
    p += write_varint(frame_type, &mut out[p..])?;
    p += write_varint(reason.len() as u64, &mut out[p..])?;
    if out.len() - p < reason.len() {
        return Err(FrameError::OutputTooSmall);
    }
    out[p..p + reason.len()].copy_from_slice(reason);
    p += reason.len();
    Ok(p)
}

/// Single-byte PADDING / PING / HANDSHAKE_DONE writers.
pub fn write_padding(out: &mut [u8]) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::PADDING;
    Ok(1)
}
pub fn write_ping(out: &mut [u8]) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::PING;
    Ok(1)
}
pub fn write_handshake_done(out: &mut [u8]) -> Result<usize, FrameError> {
    if out.is_empty() {
        return Err(FrameError::OutputTooSmall);
    }
    out[0] = ftype::HANDSHAKE_DONE;
    Ok(1)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_padding_and_ping() {
        let buf = [0x00u8];
        let (f, n) = parse_frame(&buf).unwrap();
        assert_eq!(f, Frame::Padding);
        assert_eq!(n, 1);

        let buf = [0x01u8];
        let (f, n) = parse_frame(&buf).unwrap();
        assert_eq!(f, Frame::Ping);
        assert_eq!(n, 1);
    }

    #[test]
    fn parse_handshake_done() {
        let (f, n) = parse_frame(&[0x1eu8]).unwrap();
        assert_eq!(f, Frame::HandshakeDone);
        assert_eq!(n, 1);
    }

    #[test]
    fn parse_unknown_frame_type() {
        // 0x20 sits past every defined v1 frame type — still
        // unknown territory. Future expansion would wire up arms
        // for these as needed.
        let r = parse_frame(&[0x20u8]);
        assert!(matches!(r, Err(FrameError::UnknownFrameType(0x20))));
    }

    #[test]
    fn skip_max_data_consumes_one_varint() {
        // type=0x10 || varint(7) = 1 + 1 bytes (7 fits in 6-bit form).
        let buf = [0x10u8, 0x07];
        let (f, n) = parse_frame(&buf).unwrap();
        assert!(matches!(f, Frame::Skipped { kind: 0x10 }));
        assert_eq!(n, 2);
    }

    #[test]
    fn skip_new_connection_id_full_layout() {
        // type=0x18 || seq=1 || retire=0 || cid_len=4 || cid=0xa1a2a3a4 || token[16]
        let mut buf = vec![0x18u8, 0x01, 0x00, 0x04, 0xa1, 0xa2, 0xa3, 0xa4];
        buf.extend_from_slice(&[0xff; 16]);
        let (f, n) = parse_frame(&buf).unwrap();
        assert!(matches!(f, Frame::Skipped { kind: 0x18 }));
        assert_eq!(n, buf.len());
    }

    #[test]
    fn skip_path_challenge_consumes_8_bytes() {
        let buf = [0x1au8, 1, 2, 3, 4, 5, 6, 7, 8];
        let (f, n) = parse_frame(&buf).unwrap();
        assert!(matches!(f, Frame::Skipped { kind: 0x1a }));
        assert_eq!(n, 9);
    }

    #[test]
    fn write_stream_round_trip() {
        let mut buf = [0u8; 32];
        let n = write_stream(7, 4, true, b"hello", &mut buf).unwrap();
        let (f, parsed_n) = parse_frame(&buf[..n]).unwrap();
        match f {
            Frame::Stream { stream_id, offset, data, fin } => {
                assert_eq!(stream_id, 7);
                assert_eq!(offset, 4);
                assert!(fin);
                assert_eq!(data, b"hello");
            }
            _ => panic!("expected Stream"),
        }
        assert_eq!(parsed_n, n);
    }

    #[test]
    fn crypto_round_trip() {
        let payload = b"\x06some-tls-handshake-bytes";
        // Build via writer, parse back.
        let mut out = [0u8; 64];
        let n = write_crypto(0, &payload[1..], &mut out).unwrap();
        let (f, parsed_n) = parse_frame(&out[..n]).unwrap();
        assert_eq!(parsed_n, n);
        match f {
            Frame::Crypto { offset, data } => {
                assert_eq!(offset, 0);
                assert_eq!(data, &payload[1..]);
            }
            _ => panic!("expected Crypto, got {f:?}"),
        }
    }

    #[test]
    fn crypto_offset_nonzero() {
        let mut out = [0u8; 32];
        let n = write_crypto(1234, b"data", &mut out).unwrap();
        let (f, _) = parse_frame(&out[..n]).unwrap();
        match f {
            Frame::Crypto { offset, data } => {
                assert_eq!(offset, 1234);
                assert_eq!(data, b"data");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ack_single_range_round_trip() {
        let mut out = [0u8; 32];
        let n = write_ack(100, 0, 5, &[], &mut out).unwrap();
        let (f, _) = parse_frame(&out[..n]).unwrap();
        match f {
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                mut ack_ranges,
                ecn,
            } => {
                assert_eq!(largest_acknowledged, 100);
                assert_eq!(ack_delay, 0);
                assert_eq!(first_ack_range, 5);
                assert!(ack_ranges.next().is_none());
                assert!(ecn.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ack_multi_range_round_trip() {
        // Largest=100, first=5 (i.e. acks [95,100]).
        // Then gaps: (gap=2, length=3) → acks [89,92], (gap=0, length=1) → acks [86,87].
        let mut out = [0u8; 64];
        let n = write_ack(100, 1, 5, &[(2, 3), (0, 1)], &mut out).unwrap();
        let (f, _) = parse_frame(&out[..n]).unwrap();
        match f {
            Frame::Ack { mut ack_ranges, .. } => {
                assert_eq!(ack_ranges.next(), Some((2, 3)));
                assert_eq!(ack_ranges.next(), Some((0, 1)));
                assert!(ack_ranges.next().is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn ack_ecn_decodes() {
        // Manually build an ACK_ECN frame.
        let mut out = [0u8; 32];
        out[0] = ftype::ACK_ECN;
        let mut p = 1;
        p += write_varint(50, &mut out[p..]).unwrap(); // largest
        p += write_varint(0, &mut out[p..]).unwrap();  // delay
        p += write_varint(0, &mut out[p..]).unwrap();  // range_count
        p += write_varint(2, &mut out[p..]).unwrap();  // first_ack_range
        p += write_varint(7, &mut out[p..]).unwrap();  // ect0
        p += write_varint(8, &mut out[p..]).unwrap();  // ect1
        p += write_varint(9, &mut out[p..]).unwrap();  // ce
        let (f, n) = parse_frame(&out[..p]).unwrap();
        assert_eq!(n, p);
        match f {
            Frame::Ack { ecn: Some(c), .. } => {
                assert_eq!(c.ect0, 7);
                assert_eq!(c.ect1, 8);
                assert_eq!(c.ce, 9);
            }
            other => panic!("expected ACK_ECN, got {other:?}"),
        }
    }

    #[test]
    fn ack_truncated_in_ranges() {
        // Type=ACK, largest=10, delay=0, range_count=2 (claims 2 pairs)
        // first_ack_range=0, then only ONE pair follows (gap=0, length=1)
        // — second pair missing.
        let mut buf = vec![0x02u8];
        buf.extend_from_slice(&[10, 0, 2, 0, 0, 1]);
        // Each varint here is 1 byte (under 64). The frame parser's
        // bounded-pair loop should hit Truncated on the missing pair.
        let r = parse_frame(&buf);
        assert!(matches!(r, Err(FrameError::Truncated)));
    }

    #[test]
    fn stream_with_offset_len_and_fin() {
        // Build STREAM with OFF, LEN, FIN flags.
        let body = b"hello";
        let mut out = [0u8; 32];
        out[0] = ftype::STREAM_BASE
            | ftype::STREAM_FLAG_OFF
            | ftype::STREAM_FLAG_LEN
            | ftype::STREAM_FLAG_FIN;
        let mut p = 1;
        p += write_varint(7, &mut out[p..]).unwrap(); // stream_id
        p += write_varint(42, &mut out[p..]).unwrap(); // offset
        p += write_varint(body.len() as u64, &mut out[p..]).unwrap();
        out[p..p + body.len()].copy_from_slice(body);
        p += body.len();

        let (f, n) = parse_frame(&out[..p]).unwrap();
        assert_eq!(n, p);
        match f {
            Frame::Stream { stream_id, offset, data, fin } => {
                assert_eq!(stream_id, 7);
                assert_eq!(offset, 42);
                assert_eq!(data, body);
                assert!(fin);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn stream_without_len_consumes_to_end() {
        // STREAM frame with no LEN flag: data extends to end of buffer.
        let body = b"trailing-bytes";
        let mut out = [0u8; 32];
        out[0] = ftype::STREAM_BASE; // no flags
        out[1] = 0; // stream_id varint = 0 (fits in 1 byte)
        out[2..2 + body.len()].copy_from_slice(body);
        let total = 2 + body.len();
        let (f, n) = parse_frame(&out[..total]).unwrap();
        assert_eq!(n, total);
        match f {
            Frame::Stream { stream_id, offset, data, fin } => {
                assert_eq!(stream_id, 0);
                assert_eq!(offset, 0);
                assert_eq!(data, body);
                assert!(!fin);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn connection_close_transport_round_trip() {
        let mut out = [0u8; 64];
        let n = write_close_transport(0x42, 0x06, b"oops", &mut out).unwrap();
        let (f, parsed_n) = parse_frame(&out[..n]).unwrap();
        assert_eq!(parsed_n, n);
        match f {
            Frame::ConnectionCloseTransport { error_code, frame_type, reason } => {
                assert_eq!(error_code, 0x42);
                assert_eq!(frame_type, 0x06);
                assert_eq!(reason, b"oops");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn connection_close_application_parses() {
        // Manually-built APP_CLOSE: type=0x1d, error_code=0x100, reason="bye".
        let mut out = [0u8; 32];
        out[0] = ftype::CONNECTION_CLOSE_APPLICATION;
        let mut p = 1;
        p += write_varint(0x100, &mut out[p..]).unwrap();
        p += write_varint(3, &mut out[p..]).unwrap();
        out[p..p + 3].copy_from_slice(b"bye");
        p += 3;
        let (f, n) = parse_frame(&out[..p]).unwrap();
        assert_eq!(n, p);
        match f {
            Frame::ConnectionCloseApplication { error_code, reason } => {
                assert_eq!(error_code, 0x100);
                assert_eq!(reason, b"bye");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn write_one_byte_frames() {
        let mut out = [0u8; 4];
        assert_eq!(write_padding(&mut out).unwrap(), 1);
        assert_eq!(out[0], 0x00);
        assert_eq!(write_ping(&mut out).unwrap(), 1);
        assert_eq!(out[0], 0x01);
        assert_eq!(write_handshake_done(&mut out).unwrap(), 1);
        assert_eq!(out[0], 0x1e);

        // Empty buffer → OutputTooSmall.
        let mut empty: [u8; 0] = [];
        assert!(matches!(
            write_padding(&mut empty),
            Err(FrameError::OutputTooSmall)
        ));
    }

    #[test]
    fn parse_packet_payload_walks_multiple_frames() {
        // Packet payload: PADDING ×3, ACK, CRYPTO, PING.
        let mut buf = vec![];
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        let mut tmp = [0u8; 32];
        let n = write_ack(10, 0, 0, &[], &mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
        let n = write_crypto(0, b"hs", &mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
        buf.push(0x01); // PING

        let mut p = 0;
        let mut count = 0;
        while p < buf.len() {
            let (_, consumed) = parse_frame(&buf[p..]).unwrap();
            p += consumed;
            count += 1;
        }
        // 3 PADDING + 1 ACK + 1 CRYPTO + 1 PING = 6 frames.
        assert_eq!(count, 6);
        assert_eq!(p, buf.len());
    }
}
