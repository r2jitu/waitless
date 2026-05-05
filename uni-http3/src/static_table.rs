// uni-http3/src/static_table.rs — QPACK static table (RFC 9204 Appendix A).
//
// 99 fixed `(name, value)` entries. The QPACK encoder/decoder
// references entries by index; the entries themselves are
// hard-coded constants, not data we negotiate or maintain.
//
// Used by `qpack.rs` for lookups in both directions:
// - decoder: index N → (name, value) → emit field.
// - encoder: (name, value) match → emit indexed field line.
//
// Entries below are lifted directly from RFC 9204 Appendix A. The
// static table encoding instruction in QPACK uses 6-bit indices
// (0..63 fits a single literal), but the table itself extends to
// index 98; values past 63 require longer prefixed-int encodings
// in field-line representations, which is fine — our encoder uses
// the smallest legal form for each.

#![allow(dead_code)]

/// One static-table entry. References borrow from `'static`
/// arrays in the binary, so lookups are zero-allocation.
pub struct Entry {
    pub name: &'static [u8],
    pub value: &'static [u8],
}

/// Look up an entry by index. Returns `None` for out-of-range.
pub fn lookup(idx: usize) -> Option<&'static Entry> {
    TABLE.get(idx)
}

/// Search for an exact `(name, value)` match. Returns the static
/// table index if found. Linear scan over 99 entries; for an MVP
/// server emitting a handful of headers per response this is fine.
pub fn find_exact(name: &[u8], value: &[u8]) -> Option<u8> {
    for (i, e) in TABLE.iter().enumerate() {
        if e.name == name && e.value == value {
            return Some(i as u8);
        }
    }
    None
}

/// Search for the first entry whose name matches. Returns the
/// static table index. Used when encoding "literal field line
/// with name reference" — we reuse the table's name even when
/// the value differs (e.g. `:status: 503` references entry 24
/// `:status: 200` for the name).
pub fn find_name(name: &[u8]) -> Option<u8> {
    for (i, e) in TABLE.iter().enumerate() {
        if e.name == name {
            return Some(i as u8);
        }
    }
    None
}

/// Length of the static table — RFC 9204 §3.1 fixes this at 99.
pub const STATIC_TABLE_LEN: usize = 99;

/// Convenience constants for entries the server commonly emits.
pub const IDX_STATUS_103: u8 = 24;
pub const IDX_STATUS_200: u8 = 25;
pub const IDX_STATUS_304: u8 = 26;
pub const IDX_STATUS_404: u8 = 27;
pub const IDX_STATUS_503: u8 = 28;
pub const IDX_STATUS_100: u8 = 63;
pub const IDX_STATUS_204: u8 = 64;
pub const IDX_STATUS_206: u8 = 65;
pub const IDX_STATUS_302: u8 = 66;
pub const IDX_STATUS_400: u8 = 67;
pub const IDX_STATUS_403: u8 = 68;
pub const IDX_STATUS_421: u8 = 69;
pub const IDX_STATUS_425: u8 = 70;
pub const IDX_STATUS_500: u8 = 71;
pub const IDX_CONTENT_LENGTH: u8 = 4; // value "0" — we override
pub const IDX_CONTENT_TYPE_TEXT_PLAIN: u8 = 53;
pub const IDX_CONTENT_TYPE_TEXT_HTML: u8 = 52;

const TABLE: &[Entry] = &[
    Entry { name: b":authority",          value: b"" },                     // 0
    Entry { name: b":path",               value: b"/" },                    // 1
    Entry { name: b"age",                 value: b"0" },                    // 2
    Entry { name: b"content-disposition", value: b"" },                     // 3
    Entry { name: b"content-length",      value: b"0" },                    // 4
    Entry { name: b"cookie",              value: b"" },                     // 5
    Entry { name: b"date",                value: b"" },                     // 6
    Entry { name: b"etag",                value: b"" },                     // 7
    Entry { name: b"if-modified-since",   value: b"" },                     // 8
    Entry { name: b"if-none-match",       value: b"" },                     // 9
    Entry { name: b"last-modified",       value: b"" },                     // 10
    Entry { name: b"link",                value: b"" },                     // 11
    Entry { name: b"location",            value: b"" },                     // 12
    Entry { name: b"referer",             value: b"" },                     // 13
    Entry { name: b"set-cookie",          value: b"" },                     // 14
    Entry { name: b":method",             value: b"CONNECT" },              // 15
    Entry { name: b":method",             value: b"DELETE" },               // 16
    Entry { name: b":method",             value: b"GET" },                  // 17
    Entry { name: b":method",             value: b"HEAD" },                 // 18
    Entry { name: b":method",             value: b"OPTIONS" },              // 19
    Entry { name: b":method",             value: b"POST" },                 // 20
    Entry { name: b":method",             value: b"PUT" },                  // 21
    Entry { name: b":scheme",             value: b"http" },                 // 22
    Entry { name: b":scheme",             value: b"https" },                // 23
    Entry { name: b":status",             value: b"103" },                  // 24
    Entry { name: b":status",             value: b"200" },                  // 25
    Entry { name: b":status",             value: b"304" },                  // 26
    Entry { name: b":status",             value: b"404" },                  // 27
    Entry { name: b":status",             value: b"503" },                  // 28
    Entry { name: b"accept",              value: b"*/*" },                  // 29
    Entry { name: b"accept",              value: b"application/dns-message" }, // 30
    Entry { name: b"accept-encoding",     value: b"gzip, deflate, br" },    // 31
    Entry { name: b"accept-ranges",       value: b"bytes" },                // 32
    Entry { name: b"access-control-allow-headers", value: b"cache-control" }, // 33
    Entry { name: b"access-control-allow-headers", value: b"content-type" }, // 34
    Entry { name: b"access-control-allow-origin", value: b"*" },            // 35
    Entry { name: b"cache-control",       value: b"max-age=0" },            // 36
    Entry { name: b"cache-control",       value: b"max-age=2592000" },      // 37
    Entry { name: b"cache-control",       value: b"max-age=604800" },       // 38
    Entry { name: b"cache-control",       value: b"no-cache" },             // 39
    Entry { name: b"cache-control",       value: b"no-store" },             // 40
    Entry { name: b"cache-control",       value: b"public, max-age=31536000" }, // 41
    Entry { name: b"content-encoding",    value: b"br" },                   // 42
    Entry { name: b"content-encoding",    value: b"gzip" },                 // 43
    Entry { name: b"content-type",        value: b"application/dns-message" }, // 44
    Entry { name: b"content-type",        value: b"application/javascript" }, // 45
    Entry { name: b"content-type",        value: b"application/json" },     // 46
    Entry { name: b"content-type",        value: b"application/x-www-form-urlencoded" }, // 47
    Entry { name: b"content-type",        value: b"image/gif" },            // 48
    Entry { name: b"content-type",        value: b"image/jpeg" },           // 49
    Entry { name: b"content-type",        value: b"image/png" },            // 50
    Entry { name: b"content-type",        value: b"text/css" },             // 51
    Entry { name: b"content-type",        value: b"text/html; charset=utf-8" }, // 52
    Entry { name: b"content-type",        value: b"text/plain" },           // 53
    Entry { name: b"content-type",        value: b"text/plain;charset=utf-8" }, // 54
    Entry { name: b"range",               value: b"bytes=0-" },             // 55
    Entry { name: b"strict-transport-security", value: b"max-age=31536000" }, // 56
    Entry { name: b"strict-transport-security", value: b"max-age=31536000; includesubdomains" }, // 57
    Entry { name: b"strict-transport-security", value: b"max-age=31536000; includesubdomains; preload" }, // 58
    Entry { name: b"vary",                value: b"accept-encoding" },      // 59
    Entry { name: b"vary",                value: b"origin" },               // 60
    Entry { name: b"x-content-type-options", value: b"nosniff" },           // 61
    Entry { name: b"x-xss-protection",    value: b"1; mode=block" },        // 62
    Entry { name: b":status",             value: b"100" },                  // 63
    Entry { name: b":status",             value: b"204" },                  // 64
    Entry { name: b":status",             value: b"206" },                  // 65
    Entry { name: b":status",             value: b"302" },                  // 66
    Entry { name: b":status",             value: b"400" },                  // 67
    Entry { name: b":status",             value: b"403" },                  // 68
    Entry { name: b":status",             value: b"421" },                  // 69
    Entry { name: b":status",             value: b"425" },                  // 70
    Entry { name: b":status",             value: b"500" },                  // 71
    Entry { name: b"accept-language",     value: b"" },                     // 72
    Entry { name: b"access-control-allow-credentials", value: b"FALSE" },   // 73
    Entry { name: b"access-control-allow-credentials", value: b"TRUE" },    // 74
    Entry { name: b"access-control-allow-headers", value: b"*" },           // 75
    Entry { name: b"access-control-allow-methods", value: b"get" },         // 76
    Entry { name: b"access-control-allow-methods", value: b"get, post, options" }, // 77
    Entry { name: b"access-control-allow-methods", value: b"options" },     // 78
    Entry { name: b"access-control-expose-headers", value: b"content-length" }, // 79
    Entry { name: b"access-control-request-headers", value: b"content-type" }, // 80
    Entry { name: b"access-control-request-method", value: b"get" },        // 81
    Entry { name: b"access-control-request-method", value: b"post" },       // 82
    Entry { name: b"alt-svc",             value: b"clear" },                // 83
    Entry { name: b"authorization",       value: b"" },                     // 84
    Entry { name: b"content-security-policy", value: b"script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    Entry { name: b"early-data",          value: b"1" },                    // 86
    Entry { name: b"expect-ct",           value: b"" },                     // 87
    Entry { name: b"forwarded",           value: b"" },                     // 88
    Entry { name: b"if-range",            value: b"" },                     // 89
    Entry { name: b"origin",              value: b"" },                     // 90
    Entry { name: b"purpose",             value: b"prefetch" },             // 91
    Entry { name: b"server",              value: b"" },                     // 92
    Entry { name: b"timing-allow-origin", value: b"*" },                    // 93
    Entry { name: b"upgrade-insecure-requests", value: b"1" },              // 94
    Entry { name: b"user-agent",          value: b"" },                     // 95
    Entry { name: b"x-forwarded-for",     value: b"" },                     // 96
    Entry { name: b"x-frame-options",     value: b"deny" },                 // 97
    Entry { name: b"x-frame-options",     value: b"sameorigin" },           // 98
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_99_entries() {
        assert_eq!(TABLE.len(), STATIC_TABLE_LEN);
    }

    #[test]
    fn lookup_returns_indexed_entry() {
        let e = lookup(17).unwrap();
        assert_eq!(e.name, b":method");
        assert_eq!(e.value, b"GET");
    }

    #[test]
    fn find_exact_status_200() {
        assert_eq!(find_exact(b":status", b"200"), Some(IDX_STATUS_200));
    }

    #[test]
    fn find_name_unknown_value() {
        // ":status: 503" is in table at idx 28; "999" isn't, but we
        // want the name index so we can emit a literal value.
        let idx = find_name(b":status").unwrap();
        let e = lookup(idx as usize).unwrap();
        assert_eq!(e.name, b":status");
    }
}
