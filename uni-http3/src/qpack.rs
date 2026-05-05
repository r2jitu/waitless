// uni-http3/src/qpack.rs — QPACK (RFC 9204) encoder + decoder, static-only.
//
// QPACK is a header compression scheme adapted from HPACK to play
// nicely with QUIC's stream-loss model. It splits the dynamic
// table into a separate "encoder stream" / "decoder stream" pair
// so streams can decode independently. We sidestep all of that
// complexity by advertising `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`,
// which prohibits the encoder from referencing the dynamic table.
// All field-line representations end up either:
//
//   * Indexed Field Line referencing the static table, OR
//   * Literal Field Line With Name Reference to the static table, OR
//   * Literal Field Line With Literal Name (raw name + value).
//
// Every prefix encoded by the peer starts with `Required Insert
// Count = 0` and `Base = 0` (a single zero varint each). Anything
// else with our settings is a protocol violation.
//
// Decode supports H=1 (Huffman) for both names and values (curl
// uses Huffman). Encode never sets H; emits raw octets.

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::huffman;
use crate::static_table;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackError {
    Truncated,
    BadPrefix,
    BadInstruction,
    StaticIndexOutOfRange,
    HuffmanFailed,
    Utf8(usize), // (where) - kept for diagnostics
}

/// One decoded field line.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// Decode a QPACK-encoded field section into `(req_insert_count,
/// base, fields)`. We require `req_insert_count == 0 && base == 0`
/// (no dynamic table) — anything else means the peer ignored our
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY=0 advertisement.
pub fn decode_field_section(input: &[u8]) -> Result<Vec<Field>, QpackError> {
    // Required Insert Count: prefixed integer with N=8.
    let (ric, n) = read_prefixed_int(input, 8)?;
    let mut bytes = &input[n..];
    if ric != 0 {
        return Err(QpackError::BadPrefix);
    }
    // Base: 1-bit sign + prefixed integer N=7.
    if bytes.is_empty() {
        return Err(QpackError::Truncated);
    }
    let _sign = bytes[0] & 0x80 != 0;
    let (base, n) = read_prefixed_int(bytes, 7)?;
    bytes = &bytes[n..];
    if base != 0 {
        return Err(QpackError::BadPrefix);
    }

    let mut out = Vec::new();
    while !bytes.is_empty() {
        let first = bytes[0];
        if first & 0x80 != 0 {
            // Indexed Field Line. Bit 6 is T (1=static).
            // Index is N=6.
            if first & 0x40 == 0 {
                // Dynamic table reference — we said capacity=0,
                // so this is a protocol error.
                return Err(QpackError::BadInstruction);
            }
            let (idx, n) = read_prefixed_int(bytes, 6)?;
            bytes = &bytes[n..];
            let entry = static_table::lookup(idx as usize)
                .ok_or(QpackError::StaticIndexOutOfRange)?;
            out.push(Field {
                name: entry.name.to_vec(),
                value: entry.value.to_vec(),
            });
        } else if first & 0x40 != 0 {
            // Literal Field Line With Name Reference.
            // 0 1 N T x x x x  → bit 4 T (1=static), N=4 idx in 4 bits.
            // (Bit 5 is N=never-index, ignored on receive.)
            let t_static = first & 0x10 != 0;
            if !t_static {
                return Err(QpackError::BadInstruction);
            }
            let (idx, n) = read_prefixed_int(bytes, 4)?;
            bytes = &bytes[n..];
            let entry = static_table::lookup(idx as usize)
                .ok_or(QpackError::StaticIndexOutOfRange)?;
            let (value, n) = read_string(bytes, 7)?;
            bytes = &bytes[n..];
            out.push(Field {
                name: entry.name.to_vec(),
                value,
            });
        } else if first & 0x20 != 0 {
            // Literal Field Line With Literal Name.
            // 0 0 1 N H x x x  → name follows as a string with N=3
            // length prefix (after the H bit).
            let (name, n) = read_string(bytes, 3)?;
            bytes = &bytes[n..];
            let (value, n) = read_string(bytes, 7)?;
            bytes = &bytes[n..];
            out.push(Field { name, value });
        } else {
            // 0 0 0 1 ...  → Indexed Field Line With Post-Base Index
            // 0 0 0 0 ...  → Literal Field Line With Post-Base Name Reference
            // Both reference the dynamic table; with capacity=0 it's a violation.
            return Err(QpackError::BadInstruction);
        }
    }
    Ok(out)
}

/// Read a prefixed-integer per RFC 7541 §5.1 with `prefix_bits` of
/// the first byte holding the small-value form. Returns `(value,
/// bytes_consumed)`.
fn read_prefixed_int(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), QpackError> {
    if buf.is_empty() {
        return Err(QpackError::Truncated);
    }
    // Compute mask via u16 to avoid `1u8 << 8` overflow when
    // prefix_bits == 8 (full-byte prefix, used for Required Insert
    // Count in QPACK §4.5.1.1).
    let mask: u8 = (((1u16 << prefix_bits) - 1) & 0xff) as u8;
    let v0 = (buf[0] & mask) as u64;
    if v0 < mask as u64 {
        return Ok((v0, 1));
    }
    let mut value = v0;
    let mut p = 1usize;
    let mut shift: u32 = 0;
    loop {
        if p >= buf.len() {
            return Err(QpackError::Truncated);
        }
        let b = buf[p];
        p += 1;
        value = value
            .checked_add(((b & 0x7f) as u64) << shift)
            .ok_or(QpackError::BadInstruction)?;
        if b & 0x80 == 0 {
            return Ok((value, p));
        }
        shift += 7;
        if shift > 63 {
            return Err(QpackError::BadInstruction);
        }
    }
}

/// Read a string field-line argument: `H || prefixed_int_len ||
/// bytes`. `prefix_bits_for_len` is the number of bits the length
/// integer uses inside the H-marker byte (e.g. 7 for value strings,
/// 3 for literal-name strings).
fn read_string(buf: &[u8], prefix_bits_for_len: u8) -> Result<(Vec<u8>, usize), QpackError> {
    if buf.is_empty() {
        return Err(QpackError::Truncated);
    }
    let h_mask: u8 = 1 << prefix_bits_for_len;
    let h = buf[0] & h_mask != 0;
    let (len, n) = read_prefixed_int(buf, prefix_bits_for_len)?;
    let len = len as usize;
    if buf.len() - n < len {
        return Err(QpackError::Truncated);
    }
    let raw = &buf[n..n + len];
    let bytes_total = n + len;
    if h {
        let mut decoded = Vec::with_capacity(len * 2);
        huffman::decode(raw, &mut decoded).map_err(|_| QpackError::HuffmanFailed)?;
        Ok((decoded, bytes_total))
    } else {
        Ok((raw.to_vec(), bytes_total))
    }
}

// ============================================================================
// Encoder
// ============================================================================

/// Encode a list of `(name, value)` headers into `out`. Always
/// emits `req_insert_count=0`, `base=0` (no dynamic table).
pub fn encode_field_section(headers: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
    // Prefix: Required Insert Count (1 byte 0x00) || S=0,Base=0 (0x00).
    out.push(0);
    out.push(0);

    for (name, value) in headers {
        if let Some(idx) = static_table::find_exact(name, value) {
            // Indexed Field Line: 1 1 idx[6].
            write_prefixed_int(idx as u64, 6, 0b1100_0000, out);
        } else if let Some(name_idx) = static_table::find_name(name) {
            // Literal Field Line With Name Reference: 0 1 N=0 T=1 idx[4].
            write_prefixed_int(name_idx as u64, 4, 0b0101_0000, out);
            // Value: H=0 len[7] bytes.
            write_prefixed_int(value.len() as u64, 7, 0, out);
            out.extend_from_slice(value);
        } else {
            // Literal Field Line With Literal Name:
            //   0 0 1 N=0 H=0 len[3] (name bytes) H=0 len[7] (value bytes).
            write_prefixed_int(name.len() as u64, 3, 0b0010_0000, out);
            out.extend_from_slice(name);
            write_prefixed_int(value.len() as u64, 7, 0, out);
            out.extend_from_slice(value);
        }
    }
}

fn write_prefixed_int(value: u64, prefix_bits: u8, prefix_byte: u8, out: &mut Vec<u8>) {
    let mask: u64 = (1u64 << prefix_bits) - 1;
    if value < mask {
        out.push(prefix_byte | (value as u8));
        return;
    }
    out.push(prefix_byte | (mask as u8));
    let mut v = value - mask;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_indexed_status_200() {
        let headers: &[(&[u8], &[u8])] = &[(b":status", b"200")];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, b":status");
        assert_eq!(decoded[0].value, b"200");
    }

    #[test]
    fn round_trip_literal_with_name_ref() {
        let headers: &[(&[u8], &[u8])] = &[(b":status", b"199")];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(decoded[0].name, b":status");
        assert_eq!(decoded[0].value, b"199");
    }

    #[test]
    fn round_trip_literal_with_literal_name() {
        let headers: &[(&[u8], &[u8])] = &[(b"x-custom", b"hello")];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(decoded[0].name, b"x-custom");
        assert_eq!(decoded[0].value, b"hello");
    }

    #[test]
    fn decode_huffman_value() {
        // Manually construct a section where the value is Huffman-
        // encoded "no-cache" (RFC 7541 §C.4.2).
        let mut buf = Vec::new();
        buf.push(0); // RIC = 0
        buf.push(0); // Base = 0
        // Literal Field Line With Literal Name: 0 0 1 N=0 H=0 len[3]=
        // (name "x" len=1)
        buf.push(0b0010_0001); // 0010 0 001 → name len=1, H=0
        buf.push(b'x');
        // Value: H=1, len=6 bytes.
        buf.push(0b1000_0110); // H=1 len=6
        buf.extend_from_slice(&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(decoded[0].name, b"x");
        assert_eq!(decoded[0].value, b"no-cache");
    }

    #[test]
    fn decode_multiple_fields() {
        // Encode three headers and round-trip.
        let headers: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
        ];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].name, b":method");
        assert_eq!(decoded[0].value, b"GET");
        assert_eq!(decoded[1].name, b":path");
        assert_eq!(decoded[1].value, b"/");
        assert_eq!(decoded[2].name, b":scheme");
        assert_eq!(decoded[2].value, b"https");
    }
}
