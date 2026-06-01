// crates/proto/http2/src/static_table.rs — HPACK static table (RFC 7541 Appendix A).
//
// 61 fixed `(name, value)` entries, indexed 1..=61 on the wire (index
// 0 is never a valid table reference). The dynamic table continues
// the index space at 62+. Entries are hard-coded `'static` byte
// strings, so lookups are zero-allocation.
//
// This is the HPACK cousin of `proto/http3`'s 99-entry QPACK static
// table — same shape, different contents (HPACK predates QPACK and has
// fewer, differently-ordered entries). The shared piece is the Huffman
// codec (`//crates/proto/field-huffman`), not the table.

/// One static-table entry. References borrow from `'static` arrays in
/// the binary, so lookups never allocate.
pub struct Entry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

/// Number of entries in the HPACK static table — RFC 7541 fixes this
/// at 61. Dynamic-table indices start at `STATIC_TABLE_LEN + 1` (62).
pub const STATIC_TABLE_LEN: usize = 61;

/// Look up a static-table entry by its 1-based HPACK index (1..=61).
/// Returns `None` for index 0 or anything past the table.
pub fn lookup(idx: usize) -> Option<&'static Entry> {
    if idx == 0 {
        return None;
    }
    TABLE.get(idx - 1)
}

/// Search for an exact `(name, value)` match; returns the 1-based
/// static index if found. Used by the encoder to emit an indexed
/// header field. Linear scan over 61 entries — fine for the handful
/// of headers a response carries.
pub fn find_exact(name: &[u8], value: &[u8]) -> Option<usize> {
    for (i, e) in TABLE.iter().enumerate() {
        if e.name == name && e.value == value {
            return Some(i + 1);
        }
    }
    None
}

/// Search for the first entry whose name matches; returns the 1-based
/// static index. Used by the encoder to emit a literal field with a
/// name reference (reusing the table's name when only the value
/// differs, e.g. `:status: 503` → name index 8 from `:status: 200`).
pub fn find_name(name: &[u8]) -> Option<usize> {
    for (i, e) in TABLE.iter().enumerate() {
        if e.name == name {
            return Some(i + 1);
        }
    }
    None
}

// Convenience constants for entries the server commonly emits as an
// indexed `:status`.
pub const IDX_STATUS: usize = 8; // name of entries 8..=14
pub const IDX_STATUS_200: usize = 8;
pub const IDX_STATUS_204: usize = 9;
pub const IDX_STATUS_206: usize = 10;
pub const IDX_STATUS_304: usize = 11;
pub const IDX_STATUS_400: usize = 12;
pub const IDX_STATUS_404: usize = 13;
pub const IDX_STATUS_500: usize = 14;

/// RFC 7541 Appendix A — the 61-entry static table in index order
/// (`TABLE[0]` is HPACK index 1).
const TABLE: &[Entry] = &[
    Entry { name: b":authority", value: b"" },                      // 1
    Entry { name: b":method", value: b"GET" },                      // 2
    Entry { name: b":method", value: b"POST" },                     // 3
    Entry { name: b":path", value: b"/" },                          // 4
    Entry { name: b":path", value: b"/index.html" },                // 5
    Entry { name: b":scheme", value: b"http" },                     // 6
    Entry { name: b":scheme", value: b"https" },                    // 7
    Entry { name: b":status", value: b"200" },                      // 8
    Entry { name: b":status", value: b"204" },                      // 9
    Entry { name: b":status", value: b"206" },                      // 10
    Entry { name: b":status", value: b"304" },                      // 11
    Entry { name: b":status", value: b"400" },                      // 12
    Entry { name: b":status", value: b"404" },                      // 13
    Entry { name: b":status", value: b"500" },                      // 14
    Entry { name: b"accept-charset", value: b"" },                  // 15
    Entry { name: b"accept-encoding", value: b"gzip, deflate" },    // 16
    Entry { name: b"accept-language", value: b"" },                 // 17
    Entry { name: b"accept-ranges", value: b"" },                   // 18
    Entry { name: b"accept", value: b"" },                          // 19
    Entry { name: b"access-control-allow-origin", value: b"" },     // 20
    Entry { name: b"age", value: b"" },                             // 21
    Entry { name: b"allow", value: b"" },                           // 22
    Entry { name: b"authorization", value: b"" },                   // 23
    Entry { name: b"cache-control", value: b"" },                   // 24
    Entry { name: b"content-disposition", value: b"" },             // 25
    Entry { name: b"content-encoding", value: b"" },                // 26
    Entry { name: b"content-language", value: b"" },                // 27
    Entry { name: b"content-length", value: b"" },                  // 28
    Entry { name: b"content-location", value: b"" },                // 29
    Entry { name: b"content-range", value: b"" },                   // 30
    Entry { name: b"content-type", value: b"" },                    // 31
    Entry { name: b"cookie", value: b"" },                          // 32
    Entry { name: b"date", value: b"" },                            // 33
    Entry { name: b"etag", value: b"" },                            // 34
    Entry { name: b"expect", value: b"" },                          // 35
    Entry { name: b"expires", value: b"" },                         // 36
    Entry { name: b"from", value: b"" },                            // 37
    Entry { name: b"host", value: b"" },                            // 38
    Entry { name: b"if-match", value: b"" },                        // 39
    Entry { name: b"if-modified-since", value: b"" },               // 40
    Entry { name: b"if-none-match", value: b"" },                   // 41
    Entry { name: b"if-range", value: b"" },                        // 42
    Entry { name: b"if-unmodified-since", value: b"" },             // 43
    Entry { name: b"last-modified", value: b"" },                   // 44
    Entry { name: b"link", value: b"" },                            // 45
    Entry { name: b"location", value: b"" },                        // 46
    Entry { name: b"max-forwards", value: b"" },                    // 47
    Entry { name: b"proxy-authenticate", value: b"" },              // 48
    Entry { name: b"proxy-authorization", value: b"" },             // 49
    Entry { name: b"range", value: b"" },                           // 50
    Entry { name: b"referer", value: b"" },                         // 51
    Entry { name: b"refresh", value: b"" },                         // 52
    Entry { name: b"retry-after", value: b"" },                     // 53
    Entry { name: b"server", value: b"" },                          // 54
    Entry { name: b"set-cookie", value: b"" },                      // 55
    Entry { name: b"strict-transport-security", value: b"" },       // 56
    Entry { name: b"transfer-encoding", value: b"" },               // 57
    Entry { name: b"user-agent", value: b"" },                      // 58
    Entry { name: b"vary", value: b"" },                            // 59
    Entry { name: b"via", value: b"" },                             // 60
    Entry { name: b"www-authenticate", value: b"" },                // 61
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_61_entries() {
        assert_eq!(TABLE.len(), STATIC_TABLE_LEN);
    }

    #[test]
    fn index_is_one_based() {
        assert!(lookup(0).is_none());
        assert_eq!(lookup(1).unwrap().name, b":authority");
        assert_eq!(lookup(2).unwrap().value, b"GET");
        assert_eq!(lookup(8).unwrap().value, b"200");
        assert_eq!(lookup(61).unwrap().name, b"www-authenticate");
        assert!(lookup(62).is_none());
    }

    #[test]
    fn exact_and_name_lookups() {
        assert_eq!(find_exact(b":method", b"GET"), Some(2));
        assert_eq!(find_exact(b":status", b"200"), Some(8));
        assert_eq!(find_exact(b":status", b"599"), None);
        assert_eq!(find_name(b":status"), Some(8));
        assert_eq!(find_name(b"content-type"), Some(31));
        assert_eq!(find_name(b"x-not-in-table"), None);
    }
}
