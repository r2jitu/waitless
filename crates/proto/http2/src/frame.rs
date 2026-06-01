// crates/proto/http2/src/frame.rs — RFC 7540 §4-6 frame codec.
//
// Every HTTP/2 frame is a fixed 9-byte header followed by a payload:
//
//   +-----------------------------------------------+
//   | Length (24)                                   |
//   +---------------+---------------+---------------+
//   | Type (8)      | Flags (8)     |
//   +-+-------------+---------------+-------------------------------+
//   |R| Stream Identifier (31)                                     |
//   +=+=============================================================+
//   | Frame Payload (Length octets)                              ...
//   +---------------------------------------------------------------+
//
// Sans-io: pure byte-level parse/serialize. The server (`server.rs`)
// owns the buffering and the per-type semantics; this module only
// knows the wire shape.

use alloc::vec::Vec;

/// The client connection preface (RFC 7540 §3.5) — exactly these 24
/// bytes precede the client's first SETTINGS frame.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Fixed frame-header length in bytes.
pub const FRAME_HEADER_LEN: usize = 9;

/// Frame type codes (RFC 7540 §11.2 / §6).
pub mod ftype {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// Frame flag bits (meaning is per-type; the values overlap by design).
pub mod flags {
    /// DATA / HEADERS: last frame of the stream.
    pub const END_STREAM: u8 = 0x1;
    /// SETTINGS / PING: acknowledgement.
    pub const ACK: u8 = 0x1;
    /// HEADERS / CONTINUATION: header block complete.
    pub const END_HEADERS: u8 = 0x4;
    /// DATA / HEADERS / PUSH_PROMISE: payload is padded.
    pub const PADDED: u8 = 0x8;
    /// HEADERS: a priority section precedes the header block.
    pub const PRIORITY: u8 = 0x20;
}

/// SETTINGS parameter identifiers (RFC 7540 §6.5.2).
pub mod settings_id {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// Error codes (RFC 7540 §7), used in RST_STREAM and GOAWAY.
pub mod error {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
}

/// A parsed frame header (the 9-byte prefix).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length (24-bit on the wire).
    pub length: u32,
    pub ty: u8,
    pub flags: u8,
    /// Stream identifier (31-bit; the reserved high bit is masked off).
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a 9-byte frame header. The reserved high bit of the
    /// stream-id word is ignored on receipt per RFC 7540 §4.1.
    pub fn parse(buf: &[u8]) -> FrameHeader {
        debug_assert!(buf.len() >= FRAME_HEADER_LEN);
        let length = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        let ty = buf[3];
        let flags = buf[4];
        let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        FrameHeader {
            length,
            ty,
            flags,
            stream_id,
        }
    }

    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Append a 9-byte frame header to `out`.
pub fn push_frame_header(out: &mut Vec<u8>, length: u32, ty: u8, flags: u8, stream_id: u32) {
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.push(ty);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
}

/// Append a complete frame (header + payload) to `out`.
pub fn push_frame(out: &mut Vec<u8>, ty: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    push_frame_header(out, payload.len() as u32, ty, flags, stream_id);
    out.extend_from_slice(payload);
}

/// Append a SETTINGS frame carrying the given `(id, value)` params.
pub fn push_settings(out: &mut Vec<u8>, params: &[(u16, u32)]) {
    let len = (params.len() * 6) as u32;
    push_frame_header(out, len, ftype::SETTINGS, 0, 0);
    for (id, val) in params {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&val.to_be_bytes());
    }
}

/// Append an empty SETTINGS frame with the ACK flag set.
pub fn push_settings_ack(out: &mut Vec<u8>) {
    push_frame_header(out, 0, ftype::SETTINGS, flags::ACK, 0);
}

/// Append a WINDOW_UPDATE frame crediting `increment` to `stream_id`
/// (stream 0 = connection-level).
pub fn push_window_update(out: &mut Vec<u8>, stream_id: u32, increment: u32) {
    push_frame_header(out, 4, ftype::WINDOW_UPDATE, 0, stream_id);
    out.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
}

/// Append a RST_STREAM frame with the given error code.
pub fn push_rst_stream(out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    push_frame_header(out, 4, ftype::RST_STREAM, 0, stream_id);
    out.extend_from_slice(&error_code.to_be_bytes());
}

/// Append a GOAWAY frame (RFC 7540 §6.8): last processed stream id +
/// error code, with no debug data.
pub fn push_goaway(out: &mut Vec<u8>, last_stream_id: u32, error_code: u32) {
    push_frame_header(out, 8, ftype::GOAWAY, 0, 0);
    out.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(&error_code.to_be_bytes());
}

/// Append a PING ACK echoing the 8-byte opaque payload.
pub fn push_ping_ack(out: &mut Vec<u8>, opaque: &[u8; 8]) {
    push_frame_header(out, 8, ftype::PING, flags::ACK, 0);
    out.extend_from_slice(opaque);
}

/// Iterate `(id, value)` pairs in a SETTINGS payload. Returns `None`
/// if the payload length isn't a multiple of 6 (FRAME_SIZE_ERROR).
pub fn parse_settings(payload: &[u8]) -> Option<impl Iterator<Item = (u16, u32)> + '_> {
    if !payload.len().is_multiple_of(6) {
        return None;
    }
    Some(payload.chunks_exact(6).map(|c| {
        let id = u16::from_be_bytes([c[0], c[1]]);
        let val = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
        (id, val)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn header_round_trip() {
        let mut out = Vec::new();
        push_frame_header(&mut out, 0x1234, ftype::DATA, flags::END_STREAM, 5);
        assert_eq!(out.len(), FRAME_HEADER_LEN);
        let h = FrameHeader::parse(&out);
        assert_eq!(h.length, 0x1234);
        assert_eq!(h.ty, ftype::DATA);
        assert!(h.has_flag(flags::END_STREAM));
        assert_eq!(h.stream_id, 5);
    }

    #[test]
    fn parse_masks_reserved_bit() {
        // Stream id word with the reserved high bit set.
        let buf = [0, 0, 0, ftype::HEADERS, 0, 0x80, 0, 0, 0x03];
        let h = FrameHeader::parse(&buf);
        assert_eq!(h.stream_id, 3);
    }

    #[test]
    fn settings_round_trip() {
        let mut out = Vec::new();
        push_settings(
            &mut out,
            &[
                (settings_id::MAX_CONCURRENT_STREAMS, 100),
                (settings_id::INITIAL_WINDOW_SIZE, 65535),
            ],
        );
        let h = FrameHeader::parse(&out);
        assert_eq!(h.ty, ftype::SETTINGS);
        assert_eq!(h.length, 12);
        let pairs: Vec<(u16, u32)> = parse_settings(&out[FRAME_HEADER_LEN..]).unwrap().collect();
        assert_eq!(
            pairs,
            vec![
                (settings_id::MAX_CONCURRENT_STREAMS, 100),
                (settings_id::INITIAL_WINDOW_SIZE, 65535)
            ]
        );
    }

    #[test]
    fn settings_bad_length_rejected() {
        assert!(parse_settings(&[0, 1, 2]).is_none());
    }

    #[test]
    fn window_update_payload() {
        let mut out = Vec::new();
        push_window_update(&mut out, 3, 1000);
        let h = FrameHeader::parse(&out);
        assert_eq!(h.ty, ftype::WINDOW_UPDATE);
        assert_eq!(h.stream_id, 3);
        let inc = u32::from_be_bytes([out[9], out[10], out[11], out[12]]);
        assert_eq!(inc, 1000);
    }
}
