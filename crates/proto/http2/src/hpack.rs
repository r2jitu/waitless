// crates/proto/http2/src/hpack.rs — HPACK (RFC 7541) header compression.
//
// HPACK is QPACK's simpler cousin: the same prefixed-integer / string
// primitives and the same RFC 7541 Huffman code (shared via
// `//crates/proto/field-huffman`), a different static table
// (`static_table.rs`, 61 entries), and a dynamic table *without*
// QPACK's encoder/decoder-stream reordering dance — HPACK rides one
// ordered stream (the HTTP/2 connection's HEADERS/CONTINUATION
// sequence), so the dynamic table is a plain FIFO updated in place.
//
// Decode is correctness-critical: real clients (curl/nghttp2,
// browsers) *do* use the dynamic table — incremental-indexing
// instructions on the first request, dynamic references on later ones
// — so the decoder must implement the full table (insert, evict,
// size-update) even though our encoder never uses it.
//
// Encode is deliberately stateless: responses are emitted as static-
// indexed (`:status: 200`) or "literal without indexing" field lines
// with raw (H=0) octets. That is always RFC-legal and means our
// encoder holds no dynamic-table state to keep in sync — the same
// simplification `proto/http3`'s QPACK encoder makes.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::static_table::{self, STATIC_TABLE_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    /// Wire bytes ran out mid-representation.
    Truncated,
    /// Indexed reference to index 0, or a static/dynamic index past
    /// the end of the table.
    InvalidIndex,
    /// A prefixed integer overflowed u64 (malformed / hostile input).
    IntegerOverflow,
    /// A Huffman-coded string failed to decode (bad padding / EOS /
    /// scratch overflow).
    HuffmanFailed,
    /// A literal string was longer than the caller's scratch buffer.
    StringTooLong,
    /// A dynamic-table size-update asked for more than the
    /// `SETTINGS_HEADER_TABLE_SIZE` we advertised (RFC 7541 §6.3).
    TableSizeExceeded,
    /// The decompressed header list exceeded
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` — an HPACK-bomb guard
    /// (RFC 7541 §7.* / the H2-2 DoS item).
    HeaderListTooLarge,
}

/// Push-style sink for the streaming decoder — one call per decoded
/// field line, with byte slices valid only for the call (copy what you
/// keep). Mirrors `proto/http3`'s QPACK `FieldSink`; the H2 server's
/// request sink memcpys straight into the fixed-size `http::Request`.
pub trait FieldSink {
    fn on_field(&mut self, name: &[u8], value: &[u8]);
}

/// Per-entry overhead the dynamic table charges, RFC 7541 §4.1: the
/// "size" of an entry is its name length + value length + 32.
const ENTRY_OVERHEAD: usize = 32;

// ============================================================================
// Decoder (stateful — owns the dynamic table)
// ============================================================================

pub struct Decoder {
    /// Dynamic table, newest entry at the front (index 0). Absolute
    /// HPACK index `i` (i > 61) maps to `dynamic[i - 62]`.
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Current total size = Σ(name + value + 32) over `dynamic`.
    size: usize,
    /// Current dynamic-table max size. Starts at `hard_max`; the peer
    /// can shrink/grow it (up to `hard_max`) via size-update.
    max_size: usize,
    /// `SETTINGS_HEADER_TABLE_SIZE` we advertised — the hard ceiling a
    /// size-update may not exceed.
    hard_max: usize,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` — the decompressed-size cap.
    max_header_list_size: usize,
}

impl Decoder {
    pub fn new(hard_max: usize, max_header_list_size: usize) -> Self {
        Decoder {
            dynamic: VecDeque::new(),
            size: 0,
            max_size: hard_max,
            hard_max,
            max_header_list_size,
        }
    }

    /// Decode one complete header block, calling `sink.on_field` for
    /// each field. `name_scratch` / `value_scratch` are caller-owned
    /// working buffers (for Huffman expansion and literal collection),
    /// sized for the largest single name / value in the traffic. Never
    /// allocates beyond the dynamic-table inserts.
    pub fn decode<S: FieldSink>(
        &mut self,
        input: &[u8],
        name_scratch: &mut [u8],
        value_scratch: &mut [u8],
        sink: &mut S,
    ) -> Result<(), HpackError> {
        let mut pos = 0usize;
        let mut list_size = 0usize;
        while pos < input.len() {
            let b = input[pos];
            if b & 0x80 != 0 {
                // §6.1 Indexed Header Field — 7-bit prefix index.
                let (idx, n) = read_int(&input[pos..], 7)?;
                pos += n;
                let idx = idx as usize;
                if idx == 0 {
                    return Err(HpackError::InvalidIndex);
                }
                let (nl, vl) = self.resolve_into(idx, name_scratch, value_scratch)?;
                account(&mut list_size, self.max_header_list_size, nl, vl)?;
                sink.on_field(&name_scratch[..nl], &value_scratch[..vl]);
            } else if b & 0x40 != 0 {
                // §6.2.1 Literal with Incremental Indexing — 6-bit name index.
                let (idx, n) = read_int(&input[pos..], 6)?;
                pos += n;
                let nl = self.read_name(idx as usize, &input[pos..], name_scratch, &mut pos)?;
                let (vl, vc) = read_string(&input[pos..], value_scratch)?;
                pos += vc;
                account(&mut list_size, self.max_header_list_size, nl, vl)?;
                sink.on_field(&name_scratch[..nl], &value_scratch[..vl]);
                self.insert(&name_scratch[..nl], &value_scratch[..vl]);
            } else if b & 0x20 != 0 {
                // §6.3 Dynamic Table Size Update — 5-bit prefix.
                let (new_max, n) = read_int(&input[pos..], 5)?;
                pos += n;
                self.set_max_size(new_max as usize)?;
            } else {
                // §6.2.2 Literal without Indexing (0x00) / §6.2.3 Never
                // Indexed (0x10) — both 4-bit name index, neither
                // touches the dynamic table.
                let (idx, n) = read_int(&input[pos..], 4)?;
                pos += n;
                let nl = self.read_name(idx as usize, &input[pos..], name_scratch, &mut pos)?;
                let (vl, vc) = read_string(&input[pos..], value_scratch)?;
                pos += vc;
                account(&mut list_size, self.max_header_list_size, nl, vl)?;
                sink.on_field(&name_scratch[..nl], &value_scratch[..vl]);
            }
        }
        Ok(())
    }

    /// Resolve a literal field's name: index 0 → read a literal string
    /// from the wire into `name_scratch` (advancing `*pos`); otherwise
    /// copy the referenced table name into `name_scratch`. Returns the
    /// name length. Copying (rather than borrowing) frees the dynamic
    /// table for the subsequent `insert`.
    fn read_name(
        &self,
        idx: usize,
        wire: &[u8],
        name_scratch: &mut [u8],
        pos: &mut usize,
    ) -> Result<usize, HpackError> {
        if idx == 0 {
            let (nl, nc) = read_string(wire, name_scratch)?;
            *pos += nc;
            Ok(nl)
        } else {
            let name = self.name_at(idx)?;
            if name.len() > name_scratch.len() {
                return Err(HpackError::StringTooLong);
            }
            name_scratch[..name.len()].copy_from_slice(name);
            Ok(name.len())
        }
    }

    /// Copy the name and value of indexed entry `idx` into the two
    /// scratch buffers; returns their lengths.
    fn resolve_into(
        &self,
        idx: usize,
        name_out: &mut [u8],
        value_out: &mut [u8],
    ) -> Result<(usize, usize), HpackError> {
        let (name, value): (&[u8], &[u8]) = if idx <= STATIC_TABLE_LEN {
            let e = static_table::lookup(idx).ok_or(HpackError::InvalidIndex)?;
            (e.name, e.value)
        } else {
            let e = self
                .dynamic
                .get(idx - STATIC_TABLE_LEN - 1)
                .ok_or(HpackError::InvalidIndex)?;
            (&e.0, &e.1)
        };
        if name.len() > name_out.len() || value.len() > value_out.len() {
            return Err(HpackError::StringTooLong);
        }
        name_out[..name.len()].copy_from_slice(name);
        value_out[..value.len()].copy_from_slice(value);
        Ok((name.len(), value.len()))
    }

    /// Borrow the name of table entry `idx` (1-based, static then
    /// dynamic).
    fn name_at(&self, idx: usize) -> Result<&[u8], HpackError> {
        if idx <= STATIC_TABLE_LEN {
            static_table::lookup(idx)
                .map(|e| e.name)
                .ok_or(HpackError::InvalidIndex)
        } else {
            self.dynamic
                .get(idx - STATIC_TABLE_LEN - 1)
                .map(|e| e.0.as_slice())
                .ok_or(HpackError::InvalidIndex)
        }
    }

    /// Insert a fresh `(name, value)` at the front of the dynamic
    /// table, evicting oldest entries until it fits (RFC 7541 §4.4). An
    /// entry larger than the whole table clears the table and is not
    /// inserted — still legal, and the field was already emitted.
    fn insert(&mut self, name: &[u8], value: &[u8]) {
        let entry_size = name.len() + value.len() + ENTRY_OVERHEAD;
        self.evict_to(self.max_size.saturating_sub(entry_size));
        if entry_size > self.max_size {
            // Doesn't fit even in an empty table — evict_to already
            // emptied it; drop the entry.
            return;
        }
        self.dynamic.push_front((name.to_vec(), value.to_vec()));
        self.size += entry_size;
    }

    /// Apply a dynamic-table size update (RFC 7541 §6.3). Refuses to
    /// exceed the advertised `SETTINGS_HEADER_TABLE_SIZE`.
    fn set_max_size(&mut self, new_max: usize) -> Result<(), HpackError> {
        if new_max > self.hard_max {
            return Err(HpackError::TableSizeExceeded);
        }
        self.max_size = new_max;
        self.evict_to(new_max);
        Ok(())
    }

    /// Evict oldest entries (table back) until `size <= target`.
    fn evict_to(&mut self, target: usize) {
        while self.size > target {
            match self.dynamic.pop_back() {
                Some((n, v)) => self.size -= n.len() + v.len() + ENTRY_OVERHEAD,
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
    }

    /// Test/diagnostic accessor: number of entries in the dynamic table.
    #[cfg(test)]
    pub fn dynamic_len(&self) -> usize {
        self.dynamic.len()
    }
}

/// Accumulate the decompressed header-list size and enforce the cap.
fn account(
    list_size: &mut usize,
    max: usize,
    name_len: usize,
    value_len: usize,
) -> Result<(), HpackError> {
    *list_size += name_len + value_len + ENTRY_OVERHEAD;
    if *list_size > max {
        return Err(HpackError::HeaderListTooLarge);
    }
    Ok(())
}

/// Read an HPACK prefixed integer (RFC 7541 §5.1). `prefix_bits` ∈ 1..=7
/// (4/5/6/7 in practice). Returns `(value, bytes_consumed)`.
fn read_int(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), HpackError> {
    if buf.is_empty() {
        return Err(HpackError::Truncated);
    }
    let mask: u8 = (((1u16 << prefix_bits) - 1) & 0xff) as u8;
    let v0 = (buf[0] & mask) as u64;
    if v0 < mask as u64 {
        return Ok((v0, 1));
    }
    let mut value = mask as u64;
    let mut p = 1usize;
    let mut shift: u32 = 0;
    loop {
        if p >= buf.len() {
            return Err(HpackError::Truncated);
        }
        let b = buf[p];
        p += 1;
        value = value
            .checked_add(((b & 0x7f) as u64) << shift)
            .ok_or(HpackError::IntegerOverflow)?;
        if b & 0x80 == 0 {
            return Ok((value, p));
        }
        shift += 7;
        if shift > 63 {
            return Err(HpackError::IntegerOverflow);
        }
    }
}

/// Read an HPACK string literal (RFC 7541 §5.2) into `out`. Returns
/// `(decoded_len, bytes_consumed_from_buf)`. Huffman-decodes when the
/// H bit is set.
fn read_string(buf: &[u8], out: &mut [u8]) -> Result<(usize, usize), HpackError> {
    if buf.is_empty() {
        return Err(HpackError::Truncated);
    }
    let huffman = buf[0] & 0x80 != 0;
    let (len, n) = read_int(buf, 7)?;
    let len = len as usize;
    if buf.len() - n < len {
        return Err(HpackError::Truncated);
    }
    let raw = &buf[n..n + len];
    let total = n + len;
    if huffman {
        let dlen =
            field_huffman::decode_into_slice(raw, out).map_err(|_| HpackError::HuffmanFailed)?;
        Ok((dlen, total))
    } else {
        if raw.len() > out.len() {
            return Err(HpackError::StringTooLong);
        }
        out[..raw.len()].copy_from_slice(raw);
        Ok((raw.len(), total))
    }
}

// ============================================================================
// Encoder (stateless — never uses the dynamic table)
// ============================================================================

/// Longest header name we lowercase on the stack before emitting. Every
/// name our server emits (`:status`, `content-type`, `content-length`,
/// `alt-svc`, `location`, `set-cookie`, …) is well under this; a longer
/// name falls back to a heap buffer.
const LC_STACK: usize = 64;

/// Encode a list of `(name, value)` headers into `out` as an HPACK
/// header block. Header names are lowercased (HTTP/2 requires lowercase
/// field names, RFC 7540 §8.1.2). Stateless: emits static-indexed lines
/// for exact matches and "literal without indexing" (H=0) otherwise, so
/// it never mutates a dynamic table.
pub fn encode_header_list(headers: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
    for (name, value) in headers {
        let mut stack = [0u8; LC_STACK];
        let lname = lowercase(name, &mut stack);
        encode_one(lname, value, out);
    }
}

fn encode_one(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
    if let Some(idx) = static_table::find_exact(name, value) {
        // §6.1 Indexed Header Field: 1xxxxxxx.
        write_int(out, idx as u64, 7, 0x80);
        return;
    }
    // §6.2.2 Literal without Indexing: top nibble 0000, 4-bit name index.
    match static_table::find_name(name) {
        Some(name_idx) => write_int(out, name_idx as u64, 4, 0x00),
        None => {
            write_int(out, 0, 4, 0x00);
            write_string(out, name);
        }
    }
    write_string(out, value);
}

/// Lowercase `name` into `stack`; returns a slice over the lowercased
/// bytes. Falls back to allocating only for the (unexpected) name
/// longer than `LC_STACK`. The returned slice borrows `stack` for the
/// stack path — callers use it immediately.
fn lowercase<'a>(name: &[u8], stack: &'a mut [u8; LC_STACK]) -> &'a [u8] {
    if name.len() <= LC_STACK {
        for (i, &b) in name.iter().enumerate() {
            stack[i] = b.to_ascii_lowercase();
        }
        &stack[..name.len()]
    } else {
        // Pathologically long name — leak a lowercased copy. Never hit
        // by our own emitted headers; present only so a hostile app
        // header can't smuggle uppercase onto the wire.
        let v: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        alloc::boxed::Box::leak(v.into_boxed_slice())
    }
}

/// Emit an HPACK string literal with H=0 (raw octets — always legal).
fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    // H bit lives in bit 7 of the length's first byte; H=0, so the
    // length is a plain 7-bit-prefix integer with a zero high bit.
    write_int(out, s.len() as u64, 7, 0x00);
    out.extend_from_slice(s);
}

/// Write an HPACK prefixed integer with the given prefix bits and the
/// `prefix_byte` high bits already set.
fn write_int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, prefix_byte: u8) {
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
    use alloc::vec;

    type Pair = (Vec<u8>, Vec<u8>);

    struct Collect {
        fields: Vec<Pair>,
    }
    impl FieldSink for Collect {
        fn on_field(&mut self, name: &[u8], value: &[u8]) {
            self.fields.push((name.to_vec(), value.to_vec()));
        }
    }

    fn decode_all(dec: &mut Decoder, input: &[u8]) -> Result<Vec<Pair>, HpackError> {
        let mut ns = [0u8; 4096];
        let mut vs = [0u8; 4096];
        let mut sink = Collect { fields: Vec::new() };
        dec.decode(input, &mut ns, &mut vs, &mut sink)?;
        Ok(sink.fields)
    }

    fn new_dec() -> Decoder {
        Decoder::new(4096, 1 << 20)
    }

    #[test]
    fn decode_indexed_static() {
        // 0x82 = indexed, index 2 = (:method, GET).
        let fields = decode_all(&mut new_dec(), &[0x82]).unwrap();
        assert_eq!(fields, vec![(b":method".to_vec(), b"GET".to_vec())]);
    }

    #[test]
    fn decode_rfc7541_c3_first_request() {
        // RFC 7541 §C.3.1 — first request with incremental indexing.
        // :method GET, :scheme http, :path /, :authority www.example.com
        let input = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let mut dec = new_dec();
        let fields = decode_all(&mut dec, &input).unwrap();
        assert_eq!(
            fields,
            vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]
        );
        // The :authority literal was added to the dynamic table.
        assert_eq!(dec.dynamic_len(), 1);
    }

    #[test]
    fn decode_dynamic_reference_second_request() {
        // After C.3.1 the dynamic table holds (:authority www.example.com)
        // at index 62. C.3.2's representation 0xbe is "indexed, index 62".
        let mut dec = new_dec();
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        decode_all(&mut dec, &first).unwrap();
        // 0xbe references dynamic index 62 → (:authority www.example.com).
        let fields = decode_all(&mut dec, &[0xbe]).unwrap();
        assert_eq!(
            fields,
            vec![(b":authority".to_vec(), b"www.example.com".to_vec())]
        );
    }

    #[test]
    fn decode_huffman_value() {
        // RFC 7541 §C.4.1: :authority www.example.com, Huffman value.
        // 0x41 = literal w/ incremental indexing, name index 1 (:authority);
        // 0x8c = H=1, len=12; then 12 Huffman bytes for www.example.com.
        let input = [
            0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let fields = decode_all(&mut new_dec(), &input).unwrap();
        assert_eq!(
            fields,
            vec![(b":authority".to_vec(), b"www.example.com".to_vec())]
        );
    }

    #[test]
    fn size_update_evicts() {
        let mut dec = new_dec();
        // Insert one entry via incremental indexing (literal name "x",
        // literal value "y"): 0x40, len1 "x", len1 "y".
        decode_all(&mut dec, &[0x40, 0x01, b'x', 0x01, b'y']).unwrap();
        assert_eq!(dec.dynamic_len(), 1);
        // Dynamic table size update to 0 (0x20 | 0 = 0x20) evicts all.
        decode_all(&mut dec, &[0x20]).unwrap();
        assert_eq!(dec.dynamic_len(), 0);
    }

    #[test]
    fn size_update_above_hard_max_errors() {
        let mut dec = Decoder::new(4096, 1 << 20);
        // 0x3f + (8192-31) varint = size update to 8192 > 4096.
        let mut buf = Vec::new();
        write_int(&mut buf, 8192, 5, 0x20);
        assert_eq!(decode_all(&mut dec, &buf), Err(HpackError::TableSizeExceeded));
    }

    #[test]
    fn header_list_cap_enforced() {
        // Cap so low that one field overflows it.
        let mut dec = Decoder::new(4096, 10);
        // Indexed :method GET = name(7)+value(3)+32 = 42 > 10.
        assert_eq!(decode_all(&mut dec, &[0x82]), Err(HpackError::HeaderListTooLarge));
    }

    #[test]
    fn invalid_index_zero() {
        // 0x80 = indexed header field, index 0 — illegal.
        assert_eq!(decode_all(&mut new_dec(), &[0x80]), Err(HpackError::InvalidIndex));
    }

    #[test]
    fn encode_status_200_is_indexed() {
        let mut out = Vec::new();
        encode_header_list(&[(b":status", b"200")], &mut out);
        assert_eq!(out, vec![0x88]); // indexed, index 8.
    }

    #[test]
    fn encode_roundtrip_mixed() {
        let headers: &[(&[u8], &[u8])] = &[
            (b":status", b"200"),
            (b"content-type", b"text/html"),
            (b"content-length", b"42"),
            (b"x-custom", b"hello"),
        ];
        let mut out = Vec::new();
        encode_header_list(headers, &mut out);
        let fields = decode_all(&mut new_dec(), &out).unwrap();
        let expect: Vec<Pair> = headers
            .iter()
            .map(|(n, v)| (n.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(fields, expect);
    }

    #[test]
    fn encode_lowercases_names() {
        let mut out = Vec::new();
        encode_header_list(&[(b"Alt-Svc", b"h3=\":443\"")], &mut out);
        let fields = decode_all(&mut new_dec(), &out).unwrap();
        assert_eq!(fields[0].0, b"alt-svc"); // name lowercased on the wire.
        assert_eq!(fields[0].1, b"h3=\":443\"");
    }
}
