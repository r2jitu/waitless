// uni-http3/src/frame.rs — RFC 9114 §7 frame codec.
//
// HTTP/3 frames live INSIDE QUIC streams (not packets). Each
// frame is a `(varint type, varint length, payload)` triple,
// where the varint encoding is the same QUIC variable-length
// integer codec used by transport parameters.
//
// Scope (request/response server MVP):
//
//   0x00  DATA      — request/response body bytes
//   0x01  HEADERS   — QPACK-encoded field section
//   0x04  SETTINGS  — control-stream-only; (id, value) varint pairs
//   0x07  GOAWAY    — varint stream/push id; signals shutdown
//
// Out of scope:
//
//   PUSH_PROMISE (0x05), MAX_PUSH_ID (0x0d), CANCEL_PUSH (0x03)
//   — server push isn't supported.
//   Reserved frame types (h3 grease + h2 frame-type clash range)
//   — we skip-by-length on receive.

#![allow(dead_code)]

use alloc::vec::Vec;

// Re-use the QUIC varint codec from //uni-quic — H3 frames use the
// exact same encoding (RFC 9114 §7).
use quic::wire::{WireError, read_varint, write_varint};

/// Frame type codes (RFC 9114 §11.2.1 / §7.2).
pub mod ftype {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Truncated,
    BadLength,
    OutputTooSmall,
}

impl From<WireError> for FrameError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Truncated => FrameError::Truncated,
            WireError::BadLength => FrameError::BadLength,
            WireError::OutputTooSmall => FrameError::OutputTooSmall,
            _ => FrameError::BadLength,
        }
    }
}

/// Parsed H3 frame view. Borrows from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Data(&'a [u8]),
    Headers(&'a [u8]),
    /// Settings frame body — caller can iterate `(id, value)` pairs
    /// via `parse_settings`. The MVP server doesn't act on any
    /// settings; it just acknowledges the frame's presence on the
    /// peer's control stream.
    Settings(&'a [u8]),
    GoAway(u64),
    /// Recognised-but-unhandled frame (push, max_push_id, grease,
    /// reserved). Caller skips the bytes.
    Skipped {
        ty: u64,
    },
}

/// Try to parse one frame from the head of `data`. Returns the
/// frame view + bytes consumed. `Truncated` means more bytes
/// haven't arrived yet — caller should buffer and retry.
pub fn parse_frame(data: &[u8]) -> Result<(Frame<'_>, usize), FrameError> {
    let (ty, n1) = read_varint(data)?;
    let rest = &data[n1..];
    let (len, n2) = read_varint(rest)?;
    let len = len as usize;
    let body_start = n1 + n2;
    if data.len() - body_start < len {
        return Err(FrameError::Truncated);
    }
    let body = &data[body_start..body_start + len];
    let total = body_start + len;
    let frame = match ty {
        ftype::DATA => Frame::Data(body),
        ftype::HEADERS => Frame::Headers(body),
        ftype::SETTINGS => Frame::Settings(body),
        ftype::GOAWAY => {
            let (id, _) = read_varint(body)?;
            Frame::GoAway(id)
        }
        other => Frame::Skipped { ty: other },
    };
    Ok((frame, total))
}

/// Iterate `(id, value)` varint pairs in a SETTINGS body.
pub fn parse_settings(mut body: &[u8]) -> Result<Vec<(u64, u64)>, FrameError> {
    let mut out = Vec::new();
    while !body.is_empty() {
        let (id, n) = read_varint(body)?;
        body = &body[n..];
        let (val, n) = read_varint(body)?;
        body = &body[n..];
        out.push((id, val));
    }
    Ok(out)
}

/// Write a frame `(ty, payload)` into `out`. Returns bytes written.
pub fn write_frame(ty: u64, payload: &[u8], out: &mut [u8]) -> Result<usize, FrameError> {
    let mut p = 0usize;
    p += write_varint(ty, &mut out[p..])?;
    p += write_varint(payload.len() as u64, &mut out[p..])?;
    if out.len() - p < payload.len() {
        return Err(FrameError::OutputTooSmall);
    }
    out[p..p + payload.len()].copy_from_slice(payload);
    Ok(p + payload.len())
}

/// Append an H3 frame HEADER ([type-varint][length-varint]) to
/// `out` without copying the body. Caller appends the body
/// separately (typically `extend_from_slice`). This pairs with
/// the `append_stream_header` pattern in uni-quic and lets the
/// HTTP/3 server write its response directly into one buffer
/// rather than through tmp Vecs.
pub fn append_frame_header(
    ty: u64,
    body_len: usize,
    out: &mut alloc::vec::Vec<u8>,
) -> Result<(), FrameError> {
    let mut tmp = [0u8; 8];
    let n = write_varint(ty, &mut tmp)?;
    out.extend_from_slice(&tmp[..n]);
    let n = write_varint(body_len as u64, &mut tmp)?;
    out.extend_from_slice(&tmp[..n]);
    Ok(())
}

/// Slice-target variant of [`append_frame_header`]. Writes
/// `[type-varint][length-varint]` into `out`, returning the
/// total number of bytes written. Used by the H3 framing
/// builder to write straight into a stack scratch (then
/// `IOBuf::prepend` / `append_slice` into the framing IOBuf's
/// reserved headroom/tailroom) — avoiding the per-request
/// `Vec<u8>` allocation that the Vec-target variant requires.
pub fn write_frame_header(ty: u64, body_len: usize, out: &mut [u8]) -> Result<usize, FrameError> {
    let mut p = 0usize;
    p += write_varint(ty, &mut out[p..])?;
    p += write_varint(body_len as u64, &mut out[p..])?;
    Ok(p)
}

/// Convenience: write a SETTINGS frame with empty body. Used by the
/// server's control stream — we declare nothing beyond defaults
/// (no QPACK dynamic table, no extra capacity).
pub fn write_empty_settings(out: &mut [u8]) -> Result<usize, FrameError> {
    write_frame(ftype::SETTINGS, &[], out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_data() {
        let mut buf = [0u8; 32];
        let n = write_frame(ftype::DATA, b"hello", &mut buf).unwrap();
        let (f, parsed_n) = parse_frame(&buf[..n]).unwrap();
        assert_eq!(parsed_n, n);
        assert!(matches!(f, Frame::Data(b"hello")));
    }

    #[test]
    fn round_trip_headers() {
        let mut buf = [0u8; 32];
        let n = write_frame(ftype::HEADERS, b"\xab\xcd", &mut buf).unwrap();
        let (f, _) = parse_frame(&buf[..n]).unwrap();
        match f {
            Frame::Headers(body) => assert_eq!(body, &[0xab, 0xcd]),
            _ => panic!("expected Headers"),
        }
    }

    #[test]
    fn settings_pairs_iterate() {
        // body: (0x01, 0x40), (0x06, 0x04096) — varint-encoded.
        let mut buf = [0u8; 32];
        let mut p = 0;
        p += write_varint(0x01, &mut buf[p..]).unwrap();
        p += write_varint(0x40, &mut buf[p..]).unwrap();
        p += write_varint(0x06, &mut buf[p..]).unwrap();
        p += write_varint(0x4096, &mut buf[p..]).unwrap();
        let pairs = parse_settings(&buf[..p]).unwrap();
        assert_eq!(pairs, alloc::vec![(0x01u64, 0x40u64), (0x06, 0x4096)]);
    }

    #[test]
    fn unknown_type_becomes_skipped() {
        let mut buf = [0u8; 32];
        let n = write_frame(0x33, b"xy", &mut buf).unwrap();
        let (f, _) = parse_frame(&buf[..n]).unwrap();
        assert!(matches!(f, Frame::Skipped { ty: 0x33 }));
    }

    #[test]
    fn truncated_body_signals_truncated() {
        // Type=DATA, length=10, but only 4 body bytes follow.
        let mut buf = alloc::vec::Vec::new();
        let mut tmp = [0u8; 8];
        let n = write_varint(ftype::DATA, &mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
        let n = write_varint(10, &mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n]);
        buf.extend_from_slice(b"abcd");
        let r = parse_frame(&buf);
        assert_eq!(r, Err(FrameError::Truncated));
    }
}
