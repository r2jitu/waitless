// HTTP/1.1 request types and parser.
//
// Holds the request-side structures (`Method`, `Header`, `Request`)
// and the byte-level parser that fills them in (`ParserState`,
// `parse_request_with_state`, plus the small scanning / numeric
// helpers it shares with the response side). Also hosts the
// `Host`-header port extraction used by apps that want to advertise
// the same port the client reached them on.

/// HTTP request method. `Unknown` covers anything outside the
/// listed verbs — the parser stores it without erroring; apps that
/// care should reject it themselves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Method {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Head = 4,
    Unknown = 5,
}

pub struct Header {
    pub(crate) name: [u8; 64],
    pub(crate) name_len: usize,
    pub(crate) value: [u8; 256],
    pub(crate) value_len: usize,
}

impl Header {
    const fn new() -> Self {
        Header {
            name: [0; 64],
            name_len: 0,
            value: [0; 256],
            value_len: 0,
        }
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn value(&self) -> &[u8] {
        &self.value[..self.value_len]
    }
}

pub struct Request {
    pub method: Method,
    pub(crate) path: [u8; 256],
    pub(crate) path_len: usize,
    pub(crate) headers: [Header; 16],
    pub(crate) header_count: usize,
    /// Content-Length from the request headers, or 0 if absent.
    /// Authoritative count of body bytes that follow the headers
    /// on the wire — the `BodyReader` handed to the handler will
    /// deliver exactly this many bytes.
    pub(crate) content_length: usize,
    /// Set by the HTTP/1.1 parser when the request is malformed
    /// in a way that must be answered with a hard `400 Bad
    /// Request` + `Connection: close` instead of being dispatched
    /// to a handler. The sole trigger today is a `Transfer-
    /// Encoding: chunked` request — chunked framing is not yet
    /// implemented (item E in docs/rx-path-optimizations.md), and
    /// silently treating its body as length-0 is a request-
    /// smuggling hole. `serve_conn` reads this flag right after
    /// the parse. Always `false` for requests built by the
    /// HTTP/3 frontend, which never sees chunked framing.
    pub(crate) reject: bool,
}

impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}

impl Request {
    pub fn new() -> Self {
        Request {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            content_length: 0,
            reject: false,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Total body length in bytes (declared by the Content-Length
    /// header). The handler reads the body via the `BodyReader`
    /// passed as the second argument; this is the count it will
    /// deliver in total.
    pub fn content_length(&self) -> usize {
        self.content_length
    }

    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name().eq_ignore_ascii_case(name) {
                return Some(self.headers[i].value());
            }
        }
        None
    }

    /// Parse the port number out of the request's `Host` header.
    /// Returns `None` if the header is missing or has no `:port`
    /// suffix. Handles both `host:port` and `[v6-literal]:port`
    /// shapes (RFC 7230 §5.4). Useful for apps that want to emit
    /// `Alt-Svc: h3=":<port>"` advertising the same port the
    /// client used to reach us — typical in dev where the host-
    /// to-guest mapping puts HTTPS on a non-default port.
    pub fn host_port(&self) -> Option<u16> {
        host_header_port(self.header(b"Host")?)
    }

    /// Overwrite the request-target path. Truncates if longer than
    /// the fixed `path` buffer. Used by the HTTP/3 frontend to
    /// install the `:path` pseudo-header into the same `Request`
    /// shape the HTTP/1.1 parser fills in.
    pub fn set_path(&mut self, path: &[u8]) {
        let n = path.len().min(self.path.len());
        self.path[..n].copy_from_slice(&path[..n]);
        self.path_len = n;
    }

    /// Used by the HTTP/3 frontend to install the Content-Length
    /// value it parsed from the QPACK-decoded `content-length`
    /// pseudo-header into the same `Request` shape the HTTP/1.1
    /// parser fills in.
    pub fn set_content_length(&mut self, n: usize) {
        self.content_length = n;
    }

    /// Append a header line `(name, value)`. Drops silently if the
    /// per-Request 16-header cap is full (matches the HTTP/1.1
    /// parser's truncation policy).
    pub fn push_header(&mut self, name: &[u8], value: &[u8]) {
        if self.header_count >= self.headers.len() {
            return;
        }
        let h = &mut self.headers[self.header_count];
        let n = name.len().min(h.name.len());
        h.name[..n].copy_from_slice(&name[..n]);
        h.name_len = n;
        let v = value.len().min(h.value.len());
        h.value[..v].copy_from_slice(&value[..v]);
        h.value_len = v;
        self.header_count += 1;
    }

    pub(crate) fn clear(&mut self) {
        self.method = Method::Unknown;
        self.path_len = 0;
        self.header_count = 0;
        self.content_length = 0;
        self.reject = false;
    }
}

// ---- HTTP request parser ----------------------------------------------------

/// Parser state retained across `parse_request` calls on the same
/// pipelined request. Lets `find_header_end` skip bytes it's
/// already scanned — the previous implementation re-walked the
/// whole accumulated buffer on every recv, costing O(N²) on
/// requests that arrive in many small segments. With this state
/// the scan is amortised O(N) regardless of segment shape.
///
/// `serve_conn` keeps one of these per connection and resets it
/// to `Default::default()` after each successfully-consumed
/// request so the next pipelined request starts a fresh scan.
#[derive(Default)]
pub struct ParserState {
    /// Bytes 0..scan_pos already scanned without finding the
    /// `\r\n\r\n` terminator. New recv data extends past
    /// `scan_pos`; the scan resumes from `scan_pos.saturating_sub(3)`
    /// so a terminator straddling the recv boundary still matches.
    scan_pos: usize,
}

pub(crate) fn parse_request_with_state(
    data: &[u8],
    req: &mut Request,
    state: &mut ParserState,
) -> usize {
    req.clear();

    // Find end of headers ("\r\n\r\n"). Resume from the last
    // scanned position (minus 3 so a terminator straddling the
    // previous-call buffer boundary is caught).
    let resume = state.scan_pos.saturating_sub(3);
    let header_end = find_header_end_from(data, resume);
    if header_end.is_none() {
        // Mark how far we've scanned so the next call doesn't
        // redo this work.
        state.scan_pos = data.len();
        return 0;
    }
    let header_end_pos = header_end.unwrap();

    // Parse request line: "METHOD /path HTTP/1.x\r\n"
    let mut pos = 0;

    if data[pos..].starts_with(b"GET ") {
        req.method = Method::Get;
        pos += 4;
    } else if data[pos..].starts_with(b"POST ") {
        req.method = Method::Post;
        pos += 5;
    } else if data[pos..].starts_with(b"PUT ") {
        req.method = Method::Put;
        pos += 4;
    } else if data[pos..].starts_with(b"DELETE ") {
        req.method = Method::Delete;
        pos += 7;
    } else if data[pos..].starts_with(b"HEAD ") {
        req.method = Method::Head;
        pos += 5;
    } else {
        req.method = Method::Unknown;
    }

    // Extract path
    let mut path_len = 0;
    while pos < data.len()
        && data[pos] != b' '
        && data[pos] != b'\r'
        && data[pos] != b'\n'
        && path_len < 255
    {
        req.path[path_len] = data[pos];
        path_len += 1;
        pos += 1;
    }
    req.path_len = path_len;

    // Skip to end of request line
    while pos < data.len() && data[pos] != b'\n' {
        pos += 1;
    }
    if pos < data.len() {
        pos += 1; // skip \n
    }

    // Parse headers
    while pos < header_end_pos {
        if data[pos] == b'\r' || data[pos] == b'\n' {
            break;
        }

        if req.header_count < 16 {
            let h = &mut req.headers[req.header_count];

            // Header name (up to ':')
            let mut ni = 0;
            while pos < data.len() && data[pos] != b':' && data[pos] != b'\r' && ni < 63 {
                h.name[ni] = data[pos];
                ni += 1;
                pos += 1;
            }
            h.name_len = ni;

            // Skip ':' and spaces
            while pos < data.len() && (data[pos] == b':' || data[pos] == b' ') {
                pos += 1;
            }

            // Header value
            let mut vi = 0;
            while pos < data.len() && data[pos] != b'\r' && data[pos] != b'\n' && vi < 255 {
                h.value[vi] = data[pos];
                vi += 1;
                pos += 1;
            }
            h.value_len = vi;

            req.header_count += 1;
        }

        // Skip to next line
        while pos < data.len() && data[pos] != b'\n' {
            pos += 1;
        }
        if pos < data.len() {
            pos += 1;
        }
    }

    let body_start = header_end_pos + 4; // skip \r\n\r\n

    // Extract Content-Length into the Request so the handler's
    // `BodyReader` knows how many body bytes to deliver. The body
    // bytes themselves stay in the caller's parse buffer (and the
    // transport stream); `serve_conn` constructs the reader against
    // them after this function returns. Bodies that span more than
    // one recv are handled by the streaming reader, NOT by waiting
    // here for all bytes to arrive.
    req.content_length = match req.header(b"Content-Length") {
        Some(cl_val) => parse_usize(cl_val),
        None => 0,
    };

    // Reject `Transfer-Encoding: chunked`. Chunked framing is not
    // implemented yet (deferred to the Phase 4 parser refresh);
    // ignoring the header — which is what the parser did before
    // item E — silently treats the chunk-framed body as a
    // length-0 body, leaving the chunk bytes in the caller's
    // buffer to be misparsed as the next pipelined request: an
    // HTTP request-smuggling vector. Flag it so `serve_conn`
    // answers `400 Bad Request` + `Connection: close` and reads
    // no body. `req.header` already matches the header *name*
    // case-insensitively; `transfer_encoding_is_chunked` matches
    // `chunked` case-insensitively anywhere in the comma-separated
    // transfer-coding list (e.g. `gzip, chunked`).
    req.reject = match req.header(b"Transfer-Encoding") {
        Some(te) => transfer_encoding_is_chunked(te),
        None => false,
    };

    body_start
}

/// Extract the port from an HTTP `Host` header value. Handles:
///   `localhost:8443`           → 8443
///   `localhost`                → None (caller defaults)
///   `[::1]:8443`               → 8443 (v6-literal form, RFC 7230 §5.4)
///   `[::1]`                    → None
/// Anything malformed or out-of-range returns `None`.
fn host_header_port(host: &[u8]) -> Option<u16> {
    let after_host = if host.first() == Some(&b'[') {
        // IPv6 literal: scan past the closing `]` before looking
        // for the `:` separator, otherwise the address's own colons
        // would match first.
        let close = host.iter().position(|&b| b == b']')?;
        &host[close + 1..]
    } else {
        host
    };
    let colon = after_host.iter().position(|&b| b == b':')?;
    let digits = &after_host[colon + 1..];
    if digits.is_empty() {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc * 10 + (b - b'0') as u32;
        if acc > 65535 {
            return None;
        }
    }
    Some(acc as u16)
}

// ---- Helper functions -------------------------------------------------------

/// Locate `\r\n\r\n` (the headers/body terminator) starting from
/// byte `start`. The caller has already scanned `data[..start]`
/// without finding it; this restarts there to avoid the O(N²)
/// re-scan when a request arrives in many small recv segments.
/// Returns the absolute index of the terminator within `data`.
fn find_header_end_from(data: &[u8], start: usize) -> Option<usize> {
    let suffix = data.get(start..)?;
    suffix
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + start)
}

pub(crate) fn parse_usize(data: &[u8]) -> usize {
    let mut n: usize = 0;
    for &b in data {
        if b.is_ascii_digit() {
            n = n * 10 + (b - b'0') as usize;
        } else {
            break;
        }
    }
    n
}

/// True if a `Transfer-Encoding` header value names `chunked` as
/// one of its transfer codings. The value is a comma-separated
/// list (RFC 7230 §3.3.1); each entry is compared case-
/// insensitively with its surrounding optional whitespace
/// trimmed, so `chunked`, `Chunked`, and `gzip, chunked` all
/// return `true` while `gzip` or `identity` return `false`. The
/// caller has already matched the header *name* case-
/// insensitively via `Request::header`.
pub(crate) fn transfer_encoding_is_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

#[cfg(test)]
mod host_port_tests {
    use super::host_header_port;
    #[test]
    fn plain_host_with_port() {
        assert_eq!(host_header_port(b"localhost:8443"), Some(8443));
    }
    #[test]
    fn plain_host_no_port() {
        assert_eq!(host_header_port(b"localhost"), None);
    }
    #[test]
    fn ipv6_with_port() {
        assert_eq!(host_header_port(b"[::1]:8443"), Some(8443));
        assert_eq!(host_header_port(b"[fe80::1%eth0]:443"), Some(443));
    }
    #[test]
    fn ipv6_no_port() {
        assert_eq!(host_header_port(b"[::1]"), None);
    }
    #[test]
    fn malformed() {
        assert_eq!(host_header_port(b"localhost:"), None);
        assert_eq!(host_header_port(b"localhost:abc"), None);
        assert_eq!(host_header_port(b"localhost:65536"), None);
    }
}

/// Item E — the request parser must flag a `Transfer-Encoding:
/// chunked` request for a `400` rejection rather than silently
/// mis-frame its body (an HTTP request-smuggling vector). These
/// tests pin both the value-matching helper and the parser flag.
#[cfg(test)]
mod chunked_reject_tests {
    use super::{ParserState, Request, parse_request_with_state, transfer_encoding_is_chunked};

    /// Parse one request out of `raw` and report `(body_start,
    /// reject)` — `body_start` is the parser's return value (0
    /// means "headers incomplete, need more bytes"), `reject` is
    /// the flag `serve_conn` turns into a 400.
    fn parse(raw: &[u8]) -> (usize, bool) {
        let mut req = Request::new();
        let mut state = ParserState::default();
        let body_start = parse_request_with_state(raw, &mut req, &mut state);
        (body_start, req.reject)
    }

    #[test]
    fn helper_matches_chunked_case_insensitively() {
        assert!(transfer_encoding_is_chunked(b"chunked"));
        assert!(transfer_encoding_is_chunked(b"Chunked"));
        assert!(transfer_encoding_is_chunked(b"CHUNKED"));
    }

    #[test]
    fn helper_matches_chunked_anywhere_in_the_coding_list() {
        assert!(transfer_encoding_is_chunked(b"gzip, chunked"));
        assert!(transfer_encoding_is_chunked(b"chunked, gzip"));
        assert!(transfer_encoding_is_chunked(b"gzip , chunked , deflate"));
    }

    #[test]
    fn helper_ignores_non_chunked_codings() {
        assert!(!transfer_encoding_is_chunked(b""));
        assert!(!transfer_encoding_is_chunked(b"gzip"));
        assert!(!transfer_encoding_is_chunked(b"identity"));
    }

    #[test]
    fn chunked_request_is_flagged_for_rejection() {
        let raw = b"POST /upload HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (body_start, reject) = parse(raw);
        assert!(reject, "a chunked-TE request must be flagged for a 400");
        assert!(
            body_start > 0,
            "headers are complete, body_start must be set"
        );
    }

    #[test]
    fn transfer_encoding_header_name_match_is_case_insensitive() {
        let raw = b"POST / HTTP/1.1\r\ntRaNsFeR-eNcOdInG: chunked\r\n\r\n";
        let (_, reject) = parse(raw);
        assert!(reject);
    }

    #[test]
    fn chunked_in_a_coding_list_is_flagged() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let (_, reject) = parse(raw);
        assert!(reject);
    }

    #[test]
    fn plain_content_length_request_is_not_flagged() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let (body_start, reject) = parse(raw);
        assert!(
            !reject,
            "a normal Content-Length request must not be flagged"
        );
        assert!(body_start > 0);
    }

    #[test]
    fn incomplete_headers_are_not_flagged() {
        // No CRLF-CRLF terminator yet: the parser returns 0
        // ("need more bytes") before it inspects any header.
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n";
        let (body_start, reject) = parse(raw);
        assert_eq!(body_start, 0, "incomplete headers => need more bytes");
        assert!(!reject);
    }
}
