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

/// The parsed request **head** — method, target, headers, declared
/// body length. Built by each transport's frontend (the HTTP/1.1
/// parser, the h2 HPACK `RequestSink`, the h3 QPACK frontend) and
/// reused across keep-alive requests via [`clear`](RequestHead::clear).
/// The handler never sees this directly; it sees [`Request`], which
/// pairs a borrow of this head with the streaming body reader.
pub struct RequestHead {
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

impl Default for RequestHead {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestHead {
    pub fn new() -> Self {
        RequestHead {
            method: Method::Unknown,
            path: [0; 256],
            path_len: 0,
            headers: [const { Header::new() }; 16],
            header_count: 0,
            content_length: 0,
            reject: false,
        }
    }

    /// The request method. An accessor (not just the `pub method`
    /// field) so handlers reach it through the [`Request`] facade's
    /// `Deref` the same way as `path()` / `header()`.
    pub fn method(&self) -> Method {
        self.method
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
        // Reset the per-slot name/value lengths for the slots the
        // previous request filled. The streaming parser APPENDS into
        // these (`name_len += take`, `value_len += take`) and relies
        // on them starting at 0; the buffered `add_header` overwrites
        // and does not. Without this reset a keep-alive request that
        // reuses a slot accumulates onto the prior request's bytes —
        // corrupting the header name so `header()` lookups miss
        // (e.g. `Content-Length` parses as 0, leaving an upload body
        // unconsumed and wedging the next request's HEAD parse).
        for h in &mut self.headers[..self.header_count] {
            h.name_len = 0;
            h.value_len = 0;
        }
        self.header_count = 0;
        self.content_length = 0;
        self.reject = false;
    }
}

// ---- Request: the handler-facing in-message (head + streaming body) ----------

/// The inbound message a handler reads: the parsed [`RequestHead`] plus
/// the streaming request **body**. Symmetric with [`Response`], the
/// out-message a handler writes.
///
/// Head accessors (`method()`, `path()`, `header()`, …) are reached via
/// `Deref<Target = RequestHead>`; the body is read with
/// [`read_chunk`](Request::read_chunk). A bodyless request (typical GET)
/// simply never calls `read_chunk`.
///
/// Built per-dispatch by the transport (borrowing its reused head and
/// owning a fresh [`BodyReader`] over the transport's body source), so
/// the long-lived, reused `RequestHead` carries no lifetime.
///
/// [`Response`]: crate::Response
/// [`BodyReader`]: crate::BodyReader
pub struct Request<'a> {
    head: &'a RequestHead,
    body: crate::body::BodyReader<'a>,
}

impl<'a> Request<'a> {
    /// Pair a borrowed head with a body reader. The transport calls
    /// this at dispatch, then hands `&mut Request` to the handler.
    pub fn new(head: &'a RequestHead, body: crate::body::BodyReader<'a>) -> Self {
        Request { head, body }
    }

    /// Next run of request-body bytes, or `None` at end-of-body / peer
    /// close — the same contract as the underlying
    /// [`BodyReader::chunk`](crate::BodyReader::chunk), now reached
    /// through the request itself.
    pub async fn read_chunk(&mut self) -> Option<crate::body::BodyChunkGuard<'_>> {
        self.body.chunk().await
    }

    /// Reborrow the underlying body reader — for the rare caller that
    /// needs the `BodyReader` API directly (e.g. `remaining()` /
    /// `into_leftover` plumbing inside a transport).
    pub fn body_mut(&mut self) -> &mut crate::body::BodyReader<'a> {
        &mut self.body
    }

    /// Consume the request, surrendering the body reader (so the serve
    /// loop can recover its post-body `leftover` residue).
    pub fn into_body(self) -> crate::body::BodyReader<'a> {
        self.body
    }
}

impl core::ops::Deref for Request<'_> {
    type Target = RequestHead;
    fn deref(&self) -> &RequestHead {
        self.head
    }
}

// ---- HTTP request parser ----------------------------------------------------

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

/// Tests for the `Transfer-Encoding: chunked` value-matching
/// helper. The parser-side `reject`-flag setting is exercised in
/// the streaming parser's own tests (`streaming::tests`).
#[cfg(test)]
mod chunked_helper_tests {
    use super::transfer_encoding_is_chunked;

    #[test]
    fn matches_chunked_case_insensitively() {
        assert!(transfer_encoding_is_chunked(b"chunked"));
        assert!(transfer_encoding_is_chunked(b"Chunked"));
        assert!(transfer_encoding_is_chunked(b"CHUNKED"));
    }

    #[test]
    fn matches_chunked_anywhere_in_the_coding_list() {
        assert!(transfer_encoding_is_chunked(b"gzip, chunked"));
        assert!(transfer_encoding_is_chunked(b"chunked, gzip"));
        assert!(transfer_encoding_is_chunked(b"gzip , chunked , deflate"));
    }

    #[test]
    fn ignores_non_chunked_codings() {
        assert!(!transfer_encoding_is_chunked(b""));
        assert!(!transfer_encoding_is_chunked(b"gzip"));
        assert!(!transfer_encoding_is_chunked(b"identity"));
    }
}
