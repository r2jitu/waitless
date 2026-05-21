// crates/proto/http3/src/qpack.rs — QPACK (RFC 9204) encoder + decoder, static-only.
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

/// One decoded field line. Both fields use `Cow<'static, [u8]>`
/// so indexed-static-table references stay borrowed against the
/// program's static table instead of being copied to a fresh
/// `Vec<u8>` per request — for Chrome's typical 8-10-header
/// HTTP/3 GET that's 16-20 fewer allocations per request hot
/// path. Literal names/values still allocate (Cow::Owned), as
/// they must.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: alloc::borrow::Cow<'static, [u8]>,
    pub value: alloc::borrow::Cow<'static, [u8]>,
}

/// Push-style sink for the streaming decoder. Each decoded field
/// invokes `on_field(name, value)` with byte slices that are
/// valid only for the duration of the call — the sink must copy
/// what it wants to keep before returning. Names/values may be
/// borrowed from the program's static QPACK table (when the
/// peer used an indexed reference) OR from a caller-provided
/// scratch buffer (when the peer sent a literal). Either way
/// the sink sees the decoded plaintext bytes; H=Huffman is
/// already unrolled.
///
/// Using this API instead of `decode_field_section` (which
/// returns `Vec<Field>` with each literal value boxed in a
/// `Cow::Owned(Vec<u8>)`) is the difference between
/// "1 alloc per literal field" and "0 allocs per field" on the
/// H3 request hot path. The H3 server's `RequestSink` (in
/// `server.rs`) implements this trait by memcpy'ing names and
/// values straight into the fixed-size `http::Request`
/// header arrays — no intermediate `Field` materialization.
///
/// Pattern matches what nghttp3 / lsqpack / quiche all do; the
/// trait is just the Rust expression of the C "decoder fires a
/// header_block_data_cb per header" pattern.
pub trait FieldSink {
    fn on_field(&mut self, name: &[u8], value: &[u8]);
}

/// Streaming decode — calls `sink.on_field(name, value)` for
/// each decoded field line and never allocates. `name_scratch`
/// and `value_scratch` are caller-owned (typically stack
/// arrays) used for Huffman decode and raw literal collection;
/// they get overwritten on every literal. Size them for the
/// worst-case Huffman expansion (4× the encoded length) of the
/// largest header in your traffic — Chrome's `user-agent` at
/// ~200 bytes encoded is the upper bound for typical browser
/// traffic, well under 4 KiB after expansion.
///
/// Same wire-format coverage as `decode_field_section`:
/// rejects all dynamic-table references (we advertise
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY=0`) and `req_insert_count
/// != 0` / `base != 0` prefix values.
pub fn decode_field_section_into<S: FieldSink>(
    input: &[u8],
    name_scratch: &mut [u8],
    value_scratch: &mut [u8],
    sink: &mut S,
) -> Result<(), QpackError> {
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

    while !bytes.is_empty() {
        let first = bytes[0];
        if first & 0x80 != 0 {
            // Indexed Field Line. Bit 6 is T (1=static).
            if first & 0x40 == 0 {
                return Err(QpackError::BadInstruction);
            }
            let (idx, n) = read_prefixed_int(bytes, 6)?;
            bytes = &bytes[n..];
            let entry =
                static_table::lookup(idx as usize).ok_or(QpackError::StaticIndexOutOfRange)?;
            // Both name and value live in the program's static
            // QPACK table — pass borrowed slices straight to the
            // sink without touching the scratch.
            sink.on_field(entry.name, entry.value);
        } else if first & 0x40 != 0 {
            // Literal Field Line With Name Reference.
            let t_static = first & 0x10 != 0;
            if !t_static {
                return Err(QpackError::BadInstruction);
            }
            let (idx, n) = read_prefixed_int(bytes, 4)?;
            bytes = &bytes[n..];
            let entry =
                static_table::lookup(idx as usize).ok_or(QpackError::StaticIndexOutOfRange)?;
            let (value_len, n) = read_string_into(bytes, 7, value_scratch)?;
            bytes = &bytes[n..];
            sink.on_field(entry.name, &value_scratch[..value_len]);
        } else if first & 0x20 != 0 {
            // Literal Field Line With Literal Name.
            let (name_len, n) = read_string_into(bytes, 3, name_scratch)?;
            bytes = &bytes[n..];
            let (value_len, n) = read_string_into(bytes, 7, value_scratch)?;
            bytes = &bytes[n..];
            // Need to split borrows: name in name_scratch, value
            // in value_scratch, both referenced in one call.
            sink.on_field(&name_scratch[..name_len], &value_scratch[..value_len]);
        } else {
            return Err(QpackError::BadInstruction);
        }
    }
    Ok(())
}

/// Decode a QPACK-encoded field section into a `Vec<Field>`.
/// Convenience wrapper for tests and any caller that wants the
/// fields owned. The H3 server uses
/// `decode_field_section_into` instead so it can stream the
/// decoded headers straight into the `Request` without ever
/// materialising the intermediate `Field` collection.
pub fn decode_field_section(input: &[u8]) -> Result<Vec<Field>, QpackError> {
    struct Collect {
        out: Vec<Field>,
    }
    impl FieldSink for Collect {
        fn on_field(&mut self, name: &[u8], value: &[u8]) {
            // Try to recover the static-table borrow: if the
            // bytes match an entry in the static table (cheap
            // comparison via lookup_by_name_value), we can keep
            // the name/value as `Cow::Borrowed`. For the literal
            // paths we copy into Owned. The streaming API has
            // already lost the "is this a static-table ref"
            // signal, so we re-derive via lookup. Rare path — only
            // called from tests and the legacy API; the hot path
            // doesn't go through this.
            let (n, v) = if let Some(idx) = static_table::find_exact(name, value) {
                if let Some(entry) = static_table::lookup(idx as usize) {
                    (
                        alloc::borrow::Cow::Borrowed(entry.name),
                        alloc::borrow::Cow::Borrowed(entry.value),
                    )
                } else {
                    (
                        alloc::borrow::Cow::Owned(name.to_vec()),
                        alloc::borrow::Cow::Owned(value.to_vec()),
                    )
                }
            } else if let Some(name_idx) = static_table::find_name(name) {
                if let Some(entry) = static_table::lookup(name_idx as usize) {
                    (
                        alloc::borrow::Cow::Borrowed(entry.name),
                        alloc::borrow::Cow::Owned(value.to_vec()),
                    )
                } else {
                    (
                        alloc::borrow::Cow::Owned(name.to_vec()),
                        alloc::borrow::Cow::Owned(value.to_vec()),
                    )
                }
            } else {
                (
                    alloc::borrow::Cow::Owned(name.to_vec()),
                    alloc::borrow::Cow::Owned(value.to_vec()),
                )
            };
            self.out.push(Field { name: n, value: v });
        }
    }
    let mut name_scratch = [0u8; 256];
    let mut value_scratch = [0u8; 4096];
    let mut sink = Collect { out: Vec::new() };
    decode_field_section_into(input, &mut name_scratch, &mut value_scratch, &mut sink)?;
    Ok(sink.out)
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

/// Read a string field-line argument into a caller-provided
/// scratch slice. Returns `(decoded_len, bytes_consumed_from_buf)`.
/// Allocation-free — Huffman expands directly into `out`, raw
/// bytes get memcpy'd. Errors on `Truncated` if the wire bytes
/// run out, `HuffmanFailed` if the input is malformed Huffman,
/// or `HuffmanFailed` (via the underlying decoder) if `out` is
/// smaller than the worst-case 4× expansion.
fn read_string_into(
    buf: &[u8],
    prefix_bits_for_len: u8,
    out: &mut [u8],
) -> Result<(usize, usize), QpackError> {
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
        let decoded_len =
            huffman::decode_into_slice(raw, out).map_err(|_| QpackError::HuffmanFailed)?;
        Ok((decoded_len, bytes_total))
    } else {
        if raw.len() > out.len() {
            return Err(QpackError::HuffmanFailed); // scratch overflow
        }
        out[..raw.len()].copy_from_slice(raw);
        Ok((raw.len(), bytes_total))
    }
}

// ============================================================================
// Encoder
// ============================================================================

/// Encode a list of `(name, value)` headers into a caller-owned
/// slice. Returns bytes written, or `QpackError::Truncated` if
/// `out` is too small. Always emits `req_insert_count=0`,
/// `base=0` (no dynamic table) per our SETTINGS advertisement.
///
/// Slice-target variant — what the H3 framing builder calls so
/// the QPACK body lands directly in an `IOBuf`'s payload region
/// (with reserved headroom for the H3 HEADERS frame header to
/// be prepended in place afterward). No intermediate `Vec<u8>`,
/// no per-conn scratch, no qpack→framing memcpy.
pub fn encode_field_section_into(
    headers: &[(&[u8], &[u8])],
    out: &mut [u8],
) -> Result<usize, QpackError> {
    let mut w = SliceWriter::new(out);
    encode_impl(headers, &mut w);
    if w.overflow {
        Err(QpackError::Truncated)
    } else {
        Ok(w.pos)
    }
}

/// Vec-target variant. Convenience wrapper for tests and any
/// caller that wants the bytes in an owned buffer; the H3 hot
/// path uses `encode_field_section_into` directly.
pub fn encode_field_section(headers: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
    let mut w = VecWriter { out };
    encode_impl(headers, &mut w);
}

/// Internal byte-writer abstraction so the encoder body can
/// emit into either a fixed-size slice (`SliceWriter`) or a
/// growable Vec (`VecWriter`) without code duplication. The
/// trait stays private — public callers pick a target via the
/// two `encode_field_section{,_into}` entry points.
trait QpackWriter {
    fn write(&mut self, byte: u8);
    fn write_slice(&mut self, slice: &[u8]);
}

struct VecWriter<'a> {
    out: &'a mut Vec<u8>,
}
impl QpackWriter for VecWriter<'_> {
    fn write(&mut self, byte: u8) {
        self.out.push(byte);
    }
    fn write_slice(&mut self, slice: &[u8]) {
        self.out.extend_from_slice(slice);
    }
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    pos: usize,
    overflow: bool,
}
impl<'a> SliceWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        SliceWriter {
            out,
            pos: 0,
            overflow: false,
        }
    }
}
impl QpackWriter for SliceWriter<'_> {
    fn write(&mut self, byte: u8) {
        if self.pos < self.out.len() {
            self.out[self.pos] = byte;
        } else {
            self.overflow = true;
        }
        self.pos += 1;
    }
    fn write_slice(&mut self, slice: &[u8]) {
        let n = slice.len();
        if self.pos + n <= self.out.len() {
            self.out[self.pos..self.pos + n].copy_from_slice(slice);
        } else {
            self.overflow = true;
        }
        self.pos += n;
    }
}

fn encode_impl<W: QpackWriter>(headers: &[(&[u8], &[u8])], w: &mut W) {
    // Prefix: Required Insert Count (1 byte 0x00) || S=0,Base=0 (0x00).
    w.write(0);
    w.write(0);

    for (name, value) in headers {
        if let Some(idx) = static_table::find_exact(name, value) {
            // Indexed Field Line: 1 1 idx[6].
            write_prefixed_int(idx as u64, 6, 0b1100_0000, w);
        } else if let Some(name_idx) = static_table::find_name(name) {
            // Literal Field Line With Name Reference: 0 1 N=0 T=1 idx[4].
            write_prefixed_int(name_idx as u64, 4, 0b0101_0000, w);
            // Value: H=0 len[7] bytes.
            write_prefixed_int(value.len() as u64, 7, 0, w);
            w.write_slice(value);
        } else {
            // Literal Field Line With Literal Name:
            //   0 0 1 N=0 H=0 len[3] (name bytes) H=0 len[7] (value bytes).
            write_prefixed_int(name.len() as u64, 3, 0b0010_0000, w);
            w.write_slice(name);
            write_prefixed_int(value.len() as u64, 7, 0, w);
            w.write_slice(value);
        }
    }
}

fn write_prefixed_int<W: QpackWriter>(value: u64, prefix_bits: u8, prefix_byte: u8, w: &mut W) {
    let mask: u64 = (1u64 << prefix_bits) - 1;
    if value < mask {
        w.write(prefix_byte | (value as u8));
        return;
    }
    w.write(prefix_byte | (mask as u8));
    let mut v = value - mask;
    while v >= 128 {
        w.write((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    w.write(v as u8);
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
        assert_eq!(&*decoded[0].name, b":status".as_slice());
        assert_eq!(&*decoded[0].value, b"200".as_slice());
    }

    #[test]
    fn round_trip_literal_with_name_ref() {
        let headers: &[(&[u8], &[u8])] = &[(b":status", b"199")];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(&*decoded[0].name, b":status".as_slice());
        assert_eq!(&*decoded[0].value, b"199".as_slice());
    }

    #[test]
    fn round_trip_literal_with_literal_name() {
        let headers: &[(&[u8], &[u8])] = &[(b"x-custom", b"hello")];
        let mut buf = Vec::new();
        encode_field_section(headers, &mut buf);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(&*decoded[0].name, b"x-custom".as_slice());
        assert_eq!(&*decoded[0].value, b"hello".as_slice());
    }

    #[test]
    fn decode_huffman_value() {
        // Manually construct a section where the value is Huffman-
        // encoded "no-cache" (RFC 7541 §C.4.2).
        // Section prefix + one Literal Field Line With Literal Name:
        //   [0]      RIC = 0
        //   [1]      Base = 0
        //   [2]      0b0010_0001 → 0010 0 001: name len=1, H=0
        //   [3]      b'x'        → name "x"
        //   [4]      0b1000_0110 → value H=1, len=6
        let mut buf = vec![0u8, 0, 0b0010_0001, b'x', 0b1000_0110];
        // Value bytes: Huffman-encoded "no-cache" (6 bytes).
        buf.extend_from_slice(&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]);
        let decoded = decode_field_section(&buf).unwrap();
        assert_eq!(&*decoded[0].name, b"x".as_slice());
        assert_eq!(&*decoded[0].value, b"no-cache".as_slice());
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
        assert_eq!(&*decoded[0].name, b":method".as_slice());
        assert_eq!(&*decoded[0].value, b"GET".as_slice());
        assert_eq!(&*decoded[1].name, b":path".as_slice());
        assert_eq!(&*decoded[1].value, b"/".as_slice());
        assert_eq!(&*decoded[2].name, b":scheme".as_slice());
        assert_eq!(&*decoded[2].value, b"https".as_slice());
    }
}
