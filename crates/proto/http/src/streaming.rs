// Streaming HTTP/1.1 request-HEAD parser — the parse path
// `serve_conn` drives.
//
// Byte-fed state machine that writes parsed values directly into a
// caller-supplied `Request` as bytes arrive — no per-conn parse
// buffer, no chunk-to-buffer copy.
//
// The `Request` is the parser's storage. Per-field write cursors
// live in the `Request` itself (`path_len`, `header_count`,
// `headers[i].name_len`, `headers[i].value_len`) — when a chunk
// boundary falls inside a header value, the next `feed()` call
// continues writing at the cursor the previous one left.
//
// State machine — one state per recognisable lexical position in
// the request grammar. Each chunk byte is consumed by exactly one
// transition; the only multi-byte accumulator is `method_buf` (the
// method name is matched against known verbs once the trailing SP
// arrives, not byte-by-byte).
//
// Behaviour:
//
//   * `Method::Unknown` for any verb outside the known list — no
//     error, the handler decides.
//   * Path / header-name / header-value truncated silently at their
//     fixed-buffer caps (256 / 64 / 256 bytes).
//   * Header count truncated silently at 16.
//   * `Content-Length` and `Transfer-Encoding: chunked`
//     interpretation happens at end-of-headers via the per-Request
//     header table lookup.
//
// Strictness deferred (worth tightening when paired with a fuzz
// corpus): reject lone LF / lone CR, embedded CR/LF inside header
// names or values, duplicate / disagreeing `Content-Length` values.

use crate::request::{
    Method, Request, parse_usize, transfer_encoding_is_chunked,
};

/// Per-byte parser state — one variant per distinct cursor position
/// in the HTTP/1.1 request-HEAD grammar.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Accumulating method bytes into `method_buf`; the trailing SP
    /// terminates and triggers verb decoding.
    Method,
    /// Writing bytes into `req.path` until SP terminates the target.
    Target,
    /// Skipping the HTTP-version token (`HTTP/1.1`) until \r.
    Version,
    /// Saw \r at end of request line; expect \n next.
    AfterRequestLineCR,
    /// At the start of a header line. The first byte is either \r
    /// (final CRLF — end of headers) or the first byte of a header
    /// name.
    HeaderLineStart,
    /// Writing bytes into the current header's `name` until `:`
    /// terminates it.
    HeaderName,
    /// Saw `:`; skipping optional whitespace (SP / HTAB) before the
    /// header value starts. Tolerates an empty value (immediate \r).
    HeaderColon,
    /// Writing bytes into the current header's `value` until \r.
    HeaderValue,
    /// Saw \r at end of a header value; expect \n next.
    AfterHeaderValueCR,
    /// Saw \r at the start of a header line (blank line — end of
    /// headers); expect \n next.
    AfterFinalCR,
    /// Headers fully parsed. `feed()` returns `Done`.
    Done,
}

/// Result of feeding a chunk to the parser.
pub(crate) enum FeedResult {
    /// Chunk consumed; more bytes needed to complete the HEAD.
    NeedMore,
    /// HEAD parsing complete after `consumed` bytes of the last
    /// chunk; bytes past that point (if any) are body / next
    /// pipelined request.
    Done { consumed: usize },
}

/// Streaming HTTP/1.1 request-HEAD parser. One per connection;
/// reset between pipelined requests via [`reset`](Self::reset).
pub(crate) struct StreamingRequestParser {
    state: State,
    /// Method name accumulator. The longest method we recognise is
    /// `DELETE` (6 bytes); 8 gives a byte of slack before truncation.
    method_buf: [u8; 8],
    method_buf_len: u8,
    /// Index of the header currently being filled. `Some` whenever
    /// `state` is `HeaderName`, `HeaderColon`, `HeaderValue`, or
    /// `AfterHeaderValueCR`; `None` otherwise.
    current_header: Option<u8>,
}

impl Default for StreamingRequestParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingRequestParser {
    pub(crate) const fn new() -> Self {
        StreamingRequestParser {
            state: State::Method,
            method_buf: [0; 8],
            method_buf_len: 0,
            current_header: None,
        }
    }

    /// Reset for the next pipelined request on the same connection.
    /// `Request::clear` separately resets the value-side state.
    pub(crate) fn reset(&mut self) {
        self.state = State::Method;
        self.method_buf_len = 0;
        self.current_header = None;
    }

    /// Feed the next chunk of bytes. Either returns `NeedMore` (the
    /// whole chunk was consumed) or `Done { consumed }` (the HEAD
    /// terminated `consumed` bytes into the chunk; remaining bytes
    /// belong to body / next pipelined request).
    ///
    /// Must be called with a freshly `clear`'d `Request` on the
    /// first feed of a new request; subsequent feeds within the
    /// same request must reuse the same `Request` so the in-progress
    /// field cursors line up.
    pub(crate) fn feed(&mut self, req: &mut Request, bytes: &[u8]) -> FeedResult {
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            match self.state {
                State::Method => {
                    if b == b' ' {
                        self.decode_method(req);
                        self.state = State::Target;
                    } else if (self.method_buf_len as usize) < self.method_buf.len() {
                        self.method_buf[self.method_buf_len as usize] = b;
                        self.method_buf_len += 1;
                    }
                    // else: silently truncate — `decode_method` will
                    // fall to `Method::Unknown` and the handler
                    // decides.
                    i += 1;
                }
                State::Target => {
                    if b == b' ' {
                        self.state = State::Version;
                    } else if req.path_len < req.path.len() {
                        req.path[req.path_len] = b;
                        req.path_len += 1;
                    }
                    // else: silently truncate at 256 bytes (matches
                    // the buffered parser's behaviour).
                    i += 1;
                }
                State::Version => {
                    // Don't actually store HTTP version — match
                    // buffered parser, which ignores it entirely.
                    if b == b'\r' {
                        self.state = State::AfterRequestLineCR;
                    }
                    // Tolerate lone LF as line terminator (matches
                    // buffered parser, which skipped to '\n').
                    else if b == b'\n' {
                        self.state = State::HeaderLineStart;
                    }
                    i += 1;
                }
                State::AfterRequestLineCR => {
                    // Expect \n; if we got something else, fall
                    // through to HeaderLineStart and reprocess this
                    // byte. Buffered parser silently tolerates lone
                    // \r as well.
                    self.state = State::HeaderLineStart;
                    if b == b'\n' {
                        i += 1;
                    }
                }
                State::HeaderLineStart => {
                    if b == b'\r' {
                        self.state = State::AfterFinalCR;
                        i += 1;
                    } else if b == b'\n' {
                        // Lone-LF blank line — end of headers.
                        self.finish_headers(req);
                        return FeedResult::Done { consumed: i + 1 };
                    } else {
                        // First byte of a new header name. Start a
                        // header slot (if 16-cap not yet reached)
                        // and reprocess this byte under HeaderName.
                        if req.header_count < req.headers.len() {
                            self.current_header = Some(req.header_count as u8);
                            req.header_count += 1;
                        } else {
                            // 16-cap reached — keep parsing but
                            // discard. `current_header = None`
                            // routes HeaderName / HeaderValue to
                            // no-op writes.
                            self.current_header = None;
                        }
                        self.state = State::HeaderName;
                    }
                }
                State::HeaderName => {
                    if b == b':' {
                        self.state = State::HeaderColon;
                    } else if b == b'\r' || b == b'\n' {
                        // Malformed header line — no colon before
                        // CR/LF. Treat as end-of-line and move on
                        // (matches buffered parser's tolerance:
                        // it would skip to next \n).
                        self.state = if b == b'\r' {
                            State::AfterHeaderValueCR
                        } else {
                            State::HeaderLineStart
                        };
                    } else if let Some(idx) = self.current_header {
                        let h = &mut req.headers[idx as usize];
                        if h.name_len < h.name.len() {
                            h.name[h.name_len] = b;
                            h.name_len += 1;
                        }
                    }
                    i += 1;
                }
                State::HeaderColon => {
                    if b == b' ' {
                        // Skip leading SP (matches buffered parser
                        // exactly — it skips `:` + SP, NOT HTAB).
                        // RFC 7230 OWS = SP / HTAB, so HTAB skipping
                        // is the more spec-correct behaviour; deferred
                        // to the C4 strictness pass with all the
                        // other tightenings.
                        i += 1;
                    } else if b == b'\r' {
                        // Empty value.
                        self.state = State::AfterHeaderValueCR;
                        i += 1;
                    } else if b == b'\n' {
                        // Lone-LF empty value.
                        self.state = State::HeaderLineStart;
                        i += 1;
                    } else {
                        // First value byte — reprocess under
                        // HeaderValue.
                        self.state = State::HeaderValue;
                    }
                }
                State::HeaderValue => {
                    if b == b'\r' {
                        self.state = State::AfterHeaderValueCR;
                    } else if b == b'\n' {
                        self.state = State::HeaderLineStart;
                    } else if let Some(idx) = self.current_header {
                        let h = &mut req.headers[idx as usize];
                        if h.value_len < h.value.len() {
                            h.value[h.value_len] = b;
                            h.value_len += 1;
                        }
                    }
                    i += 1;
                }
                State::AfterHeaderValueCR => {
                    // Expect \n; if we got something else, fall
                    // through to HeaderLineStart and reprocess
                    // (matches buffered parser's leniency).
                    self.state = State::HeaderLineStart;
                    if b == b'\n' {
                        i += 1;
                    }
                }
                State::AfterFinalCR => {
                    // Expect \n; on \n the HEAD is complete.
                    // Anything else: treat as the byte AFTER the
                    // HEAD and call it done (matches buffered
                    // parser's "skip past \r\n\r\n" semantics —
                    // it doesn't validate the trailing \n strictly).
                    if b == b'\n' {
                        self.finish_headers(req);
                        return FeedResult::Done { consumed: i + 1 };
                    } else {
                        self.finish_headers(req);
                        return FeedResult::Done { consumed: i };
                    }
                }
                State::Done => {
                    // Should not be re-entered without `reset`.
                    return FeedResult::Done { consumed: i };
                }
            }
        }
        FeedResult::NeedMore
    }

    /// Match the accumulated `method_buf` against the known verbs
    /// and set `req.method`. Anything else: `Method::Unknown`.
    fn decode_method(&self, req: &mut Request) {
        let m = &self.method_buf[..self.method_buf_len as usize];
        req.method = match m {
            b"GET" => Method::Get,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"HEAD" => Method::Head,
            _ => Method::Unknown,
        };
    }

    /// End-of-headers bookkeeping: extract Content-Length, flag
    /// chunked-TE for rejection. Identical to the tail of
    /// `parse_request_with_state`.
    fn finish_headers(&mut self, req: &mut Request) {
        self.state = State::Done;
        req.content_length = match req.header(b"Content-Length") {
            Some(cl_val) => parse_usize(cl_val),
            None => 0,
        };
        req.reject = match req.header(b"Transfer-Encoding") {
            Some(te) => transfer_encoding_is_chunked(te),
            None => false,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Request;
    use alloc::vec::Vec;

    fn feed_whole(raw: &[u8]) -> (Request, FeedResult) {
        let mut req = Request::new();
        let mut p = StreamingRequestParser::new();
        let r = p.feed(&mut req, raw);
        (req, r)
    }

    fn done_consumed(r: &FeedResult) -> Option<usize> {
        match r {
            FeedResult::Done { consumed } => Some(*consumed),
            FeedResult::NeedMore => None,
        }
    }

    #[test]
    fn simple_get_whole() {
        let raw = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
        let (req, r) = feed_whole(raw);
        assert_eq!(done_consumed(&r), Some(raw.len()));
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.path(), b"/health");
        assert_eq!(req.header(b"Host"), Some(b"x".as_slice()));
        assert_eq!(req.content_length, 0);
        assert!(!req.reject);
    }

    #[test]
    fn post_with_content_length_and_body_tail() {
        let raw = b"POST /up HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let (req, r) = feed_whole(raw);
        // HEAD ends after \r\n\r\n; body bytes follow.
        assert_eq!(done_consumed(&r), Some(raw.len() - 5));
        assert_eq!(req.method, Method::Post);
        assert_eq!(req.content_length, 5);
    }

    #[test]
    fn transfer_encoding_chunked_is_rejected_flag() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (req, r) = feed_whole(raw);
        assert_eq!(done_consumed(&r), Some(raw.len()));
        assert!(req.reject);
    }

    #[test]
    fn transfer_encoding_chunked_in_coding_list_is_rejected() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let (req, _) = feed_whole(raw);
        assert!(req.reject);
    }

    #[test]
    fn transfer_encoding_header_name_match_is_case_insensitive() {
        let raw = b"POST / HTTP/1.1\r\ntRaNsFeR-eNcOdInG: chunked\r\n\r\n";
        let (req, _) = feed_whole(raw);
        assert!(req.reject);
    }

    #[test]
    fn plain_content_length_is_not_flagged() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let (req, _) = feed_whole(raw);
        assert!(!req.reject);
        assert_eq!(req.content_length, 5);
    }

    #[test]
    fn incomplete_headers_return_need_more() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n";
        let (req, r) = feed_whole(raw);
        assert!(done_consumed(&r).is_none(), "missing CRLF-CRLF => NeedMore");
        assert!(!req.reject, "reject is only set at end-of-headers");
    }

    #[test]
    fn unknown_method_does_not_error() {
        let raw = b"PATCH /x HTTP/1.1\r\n\r\n";
        let (req, r) = feed_whole(raw);
        assert_eq!(done_consumed(&r), Some(raw.len()));
        assert_eq!(req.method, Method::Unknown);
    }

    #[test]
    fn header_value_with_leading_ows_is_trimmed() {
        let raw = b"GET / HTTP/1.1\r\nX-Custom:    value\r\n\r\n";
        let (req, r) = feed_whole(raw);
        assert!(done_consumed(&r).is_some());
        assert_eq!(req.header(b"X-Custom"), Some(b"value".as_slice()));
    }

    #[test]
    fn header_count_truncates_at_16() {
        let mut raw: Vec<u8> = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..20 {
            raw.extend_from_slice(b"X-N");
            raw.push(b'0' + (i / 10));
            raw.push(b'0' + (i % 10));
            raw.extend_from_slice(b": v\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        let (req, r) = feed_whole(&raw);
        assert!(done_consumed(&r).is_some());
        assert_eq!(req.header_count, 16);
    }

    /// Property test: for every chunk-split point of a canonical
    /// request, feeding the bytes in two halves yields the same
    /// Request as feeding them whole.
    #[test]
    fn split_at_every_boundary_matches_whole_parse() {
        let raw = b"POST /up HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nX-Tag: probe\r\n\r\nhello body!!";
        let (whole_req, whole_r) = feed_whole(raw);
        let whole_consumed = done_consumed(&whole_r).expect("whole parse done");

        for split in 0..=raw.len() {
            let (a, b) = raw.split_at(split);
            let mut req = Request::new();
            let mut p = StreamingRequestParser::new();
            let total_consumed = match p.feed(&mut req, a) {
                FeedResult::Done { consumed } => consumed,
                FeedResult::NeedMore => match p.feed(&mut req, b) {
                    FeedResult::Done { consumed } => a.len() + consumed,
                    FeedResult::NeedMore => {
                        panic!("split={split}: parser still wants more after both halves");
                    }
                },
            };

            assert!(
                total_consumed == whole_consumed,
                "split={split}: HEAD length {total_consumed} != whole {whole_consumed}",
            );
            assert!(req.method == whole_req.method, "split={split}: method differs");
            assert!(req.path() == whole_req.path(), "split={split}: path differs");
            assert!(
                req.header_count == whole_req.header_count,
                "split={split}: header count {} != {}",
                req.header_count, whole_req.header_count,
            );
            for i in 0..req.header_count {
                assert!(
                    req.headers[i].name() == whole_req.headers[i].name(),
                    "split={split}: header[{i}] name differs",
                );
                assert!(
                    req.headers[i].value() == whole_req.headers[i].value(),
                    "split={split}: header[{i}] value differs",
                );
            }
            assert!(
                req.content_length == whole_req.content_length,
                "split={split}: content_length {} != {}",
                req.content_length, whole_req.content_length,
            );
            assert!(req.reject == whole_req.reject, "split={split}: reject differs");
        }
    }
}

