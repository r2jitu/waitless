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
    Method, RequestHead, parse_usize, transfer_encoding_is_chunked,
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
    /// HEAD exceeded the per-request byte cap before reaching the
    /// `\r\n\r\n` terminator. The caller should drop the connection
    /// — without this guard a malicious peer streaming bytes that
    /// never contain a state-terminating delimiter (SP after method,
    /// `:` after header name, `\r` after value, blank line after
    /// headers) holds the parser open forever. Mirrors the old
    /// buffered parser's BUF_SIZE-full → drop-conn behaviour.
    Overflow,
}

/// Per-request cap on HEAD bytes the parser will accept before
/// signalling [`FeedResult::Overflow`]. Matches the legacy
/// `serve_conn` `BUF_SIZE` so the maximum-acceptable HEAD is
/// preserved across the parser swap.
pub(crate) const MAX_HEAD_BYTES: u32 = 16 * 1024;

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
    /// HEAD bytes accepted across all `feed()` calls for this
    /// request — i.e. cumulative across multi-chunk HEADs.
    /// Compared against [`MAX_HEAD_BYTES`] at every byte; reset
    /// by [`reset`](Self::reset) for the next pipelined request.
    /// `saturating_add` against `u32` capacity, so even an
    /// adversarial 4 GiB feed stays well-defined.
    prior_head_bytes: u32,
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
            prior_head_bytes: 0,
        }
    }

    /// Reset for the next pipelined request on the same connection.
    /// `Request::clear` separately resets the value-side state.
    pub(crate) fn reset(&mut self) {
        self.state = State::Method;
        self.method_buf_len = 0;
        self.current_header = None;
        self.prior_head_bytes = 0;
    }

    /// Feed the next chunk of bytes. Either returns `NeedMore` (the
    /// whole chunk was consumed), `Done { consumed }` (the HEAD
    /// terminated `consumed` bytes into the chunk — remaining bytes
    /// belong to body / next pipelined request), or `Overflow` (the
    /// HEAD exceeded [`MAX_HEAD_BYTES`] — caller drops the conn).
    ///
    /// Must be called with a freshly `clear`'d `Request` on the
    /// first feed of a new request; subsequent feeds within the
    /// same request must reuse the same `Request` so the in-progress
    /// field cursors line up.
    pub(crate) fn feed(&mut self, req: &mut RequestHead, bytes: &[u8]) -> FeedResult {
        // Clamp the chunk view to whatever the per-request HEAD-bytes
        // cap still allows. Each "scan-until-delimiter" state below
        // walks `bytes[i..]` with `iter().position()` + bulk
        // `copy_from_slice` — LLVM autovectorises the simple
        // predicates, so a 200-byte header value collapses from
        // 200 branches into one SIMD scan + one memcpy. The cap
        // therefore can't be a per-byte check inside the loop
        // (that would defeat the vectorisation); instead clamp at
        // chunk entry. If a state runs to the end of the clamped
        // view without hitting its delimiter AND we clamped below
        // the original, the request blew past the cap → Overflow.
        let original_len = bytes.len();
        let chunk_cap = (MAX_HEAD_BYTES as usize)
            .saturating_sub(self.prior_head_bytes as usize);
        let bytes = &bytes[..original_len.min(chunk_cap)];
        let chunk_was_capped = bytes.len() < original_len;

        // Pin the parser-side contract: every `Done { consumed }` we
        // return must satisfy `consumed <= bytes.len()`, otherwise
        // the caller's `into_remainder(consumed).expect(...)` panics
        // on something the parser produced. Debug-only — release
        // builds trust the static argument.
        let done = |consumed: usize| -> FeedResult {
            debug_assert!(
                consumed <= bytes.len(),
                "parser returned consumed={consumed} > bytes.len()={}",
                bytes.len(),
            );
            FeedResult::Done { consumed }
        };

        let mut i = 0;
        loop {
            if i >= bytes.len() {
                // Whole (clamped) chunk consumed without reaching
                // the HEAD terminator. Either truly need more, or
                // we clamped below the original → Overflow.
                self.prior_head_bytes = self.prior_head_bytes.saturating_add(i as u32);
                if chunk_was_capped {
                    return FeedResult::Overflow;
                }
                return FeedResult::NeedMore;
            }
            match self.state {
                State::Method => {
                    // Scan until SP. Bulk-append into method_buf
                    // (truncate at 8 bytes; bytes past the cap are
                    // skipped but still consumed). `decode_method`
                    // falls to `Method::Unknown` if the accumulator
                    // doesn't match a known verb.
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b' ')
                        .unwrap_or(span.len());
                    let dst_avail = self.method_buf.len() - self.method_buf_len as usize;
                    let take = end.min(dst_avail);
                    self.method_buf
                        [self.method_buf_len as usize..self.method_buf_len as usize + take]
                        .copy_from_slice(&span[..take]);
                    self.method_buf_len += take as u8;
                    i += end;
                    if i < bytes.len() {
                        // Hit SP — decode and transition.
                        self.decode_method(req);
                        self.state = State::Target;
                        i += 1;
                    }
                }
                State::Target => {
                    // Scan until SP. Single-byte predicate so LLVM
                    // reliably emits a SIMD scan (multi-byte ORs
                    // partially defeated the vectoriser, eating the
                    // perf budget the chunk → buf copy elimination
                    // was supposed to recover). RFC 9112 request-
                    // lines always end the target with SP; a
                    // malformed line with embedded CR/LF in the
                    // path is no longer tolerated here — it'll
                    // either get absorbed into the path field (and
                    // the handler routes 404) or trip Overflow.
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b' ')
                        .unwrap_or(span.len());
                    let dst_avail = req.path.len() - req.path_len;
                    let take = end.min(dst_avail);
                    req.path[req.path_len..req.path_len + take]
                        .copy_from_slice(&span[..take]);
                    req.path_len += take;
                    i += end;
                    if i < bytes.len() {
                        self.state = State::Version;
                        i += 1;
                    }
                }
                State::Version => {
                    // Skip HTTP version token until \r. Single-byte
                    // predicate; lone-LF after the version is no
                    // longer tolerated (RFC 9112 mandates CRLF).
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r')
                        .unwrap_or(span.len());
                    i += end;
                    if i < bytes.len() {
                        self.state = State::AfterRequestLineCR;
                        i += 1;
                    }
                }
                State::AfterRequestLineCR => {
                    // Expect \n; if we got something else, transition
                    // without consuming so HeaderLineStart reprocesses
                    // the byte (matches buffered parser's tolerance).
                    if bytes[i] == b'\n' {
                        i += 1;
                    }
                    self.state = State::HeaderLineStart;
                }
                State::HeaderLineStart => {
                    let b = bytes[i];
                    if b == b'\r' {
                        self.state = State::AfterFinalCR;
                        i += 1;
                    } else if b == b'\n' {
                        // Lone-LF blank line — end of headers.
                        self.finish_headers(req);
                        return done(i + 1);
                    } else {
                        // First byte of a new header name. Start a
                        // header slot (if 16-cap not yet reached);
                        // don't consume — HeaderName will read this
                        // byte on the next loop iter.
                        if req.header_count < req.headers.len() {
                            self.current_header = Some(req.header_count as u8);
                            req.header_count += 1;
                        } else {
                            // 16-cap reached — keep parsing but
                            // discard via `current_header = None`.
                            self.current_header = None;
                        }
                        self.state = State::HeaderName;
                    }
                }
                State::HeaderName => {
                    // Scan until `:`. Single-byte predicate so LLVM
                    // SIMD-vectorises. RFC 9112 header lines always
                    // end the name with `:`; embedded CR/LF in a
                    // header name is malformed and no longer
                    // tolerated here.
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b':')
                        .unwrap_or(span.len());
                    if let Some(idx) = self.current_header {
                        let h = &mut req.headers[idx as usize];
                        let dst_avail = h.name.len() - h.name_len;
                        let take = end.min(dst_avail);
                        h.name[h.name_len..h.name_len + take]
                            .copy_from_slice(&span[..take]);
                        h.name_len += take;
                    }
                    i += end;
                    if i < bytes.len() {
                        self.state = State::HeaderColon;
                        i += 1;
                    }
                }
                State::HeaderColon => {
                    // Skip leading SP (only SP, not HTAB — matches
                    // buffered parser; full OWS is a strictness-pass
                    // tightening).
                    let span = &bytes[i..];
                    let skip = span
                        .iter()
                        .position(|&b| b != b' ')
                        .unwrap_or(span.len());
                    i += skip;
                    if i < bytes.len() {
                        let b = bytes[i];
                        if b == b'\r' {
                            self.state = State::AfterHeaderValueCR;
                            i += 1;
                        } else if b == b'\n' {
                            self.state = State::HeaderLineStart;
                            i += 1;
                        } else {
                            // First value byte — transition without
                            // consuming, HeaderValue picks it up.
                            self.state = State::HeaderValue;
                        }
                    }
                }
                State::HeaderValue => {
                    // Scan until \r. Single-byte predicate;
                    // lone-LF inside values is no longer tolerated
                    // (RFC 9112 mandates CRLF).
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r')
                        .unwrap_or(span.len());
                    if let Some(idx) = self.current_header {
                        let h = &mut req.headers[idx as usize];
                        let dst_avail = h.value.len() - h.value_len;
                        let take = end.min(dst_avail);
                        h.value[h.value_len..h.value_len + take]
                            .copy_from_slice(&span[..take]);
                        h.value_len += take;
                    }
                    i += end;
                    if i < bytes.len() {
                        self.state = State::AfterHeaderValueCR;
                        i += 1;
                    }
                }
                State::AfterHeaderValueCR => {
                    // Expect \n; non-\n falls through to
                    // HeaderLineStart for reprocessing.
                    if bytes[i] == b'\n' {
                        i += 1;
                    }
                    self.state = State::HeaderLineStart;
                }
                State::AfterFinalCR => {
                    // Expect \n; on \n the HEAD is complete.
                    // Anything else: treat as the byte AFTER the
                    // HEAD and call it done (matches buffered
                    // parser's "skip past \r\n\r\n" semantics —
                    // it doesn't validate the trailing \n strictly).
                    if bytes[i] == b'\n' {
                        self.finish_headers(req);
                        return done(i + 1);
                    } else {
                        self.finish_headers(req);
                        return done(i);
                    }
                }
                State::Done => {
                    // Should not be re-entered without `reset`.
                    return done(i);
                }
            }
        }
    }

    /// Match the accumulated `method_buf` against the known verbs
    /// and set `req.method`. Anything else: `Method::Unknown`.
    fn decode_method(&self, req: &mut RequestHead) {
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
    fn finish_headers(&mut self, req: &mut RequestHead) {
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
    use crate::request::RequestHead;
    use alloc::vec::Vec;

    fn feed_whole(raw: &[u8]) -> (RequestHead, FeedResult) {
        let mut req = RequestHead::new();
        let mut p = StreamingRequestParser::new();
        let r = p.feed(&mut req, raw);
        (req, r)
    }

    fn done_consumed(r: &FeedResult) -> Option<usize> {
        match r {
            FeedResult::Done { consumed } => Some(*consumed),
            FeedResult::NeedMore | FeedResult::Overflow => None,
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

    /// Regression: a keep-alive connection reuses one parser +
    /// `Request` across requests, calling `Request::clear()` +
    /// `parser.reset()` between them (as `serve_conn` does). The
    /// streaming parser APPENDS header name/value bytes
    /// (`name_len += take`) and relies on the per-slot lengths
    /// starting at 0. `clear()` reset `header_count` but not those
    /// lengths, so the second request — reusing the same slots —
    /// accumulated onto the first request's stale bytes, corrupting
    /// every header name. `Content-Length` then failed to match,
    /// parsed as 0, and the body was left unconsumed on the wire —
    /// the next HEAD parse choked on the body bytes and overflowed,
    /// wedging keep-alive uploads.
    #[test]
    fn keepalive_reuse_does_not_corrupt_headers() {
        const REQ: &[u8] = b"POST /discard HTTP/1.1\r\nHost: h\r\n\
            Content-Type: application/octet-stream\r\nContent-Length: 262144\r\n\r\n";
        let mut p = StreamingRequestParser::new();
        let mut req = RequestHead::new();

        // First request on the connection — fresh slots, parses fine.
        assert!(matches!(p.feed(&mut req, REQ), FeedResult::Done { .. }));
        assert_eq!(req.content_length, 262144, "1st request CL");
        assert_eq!(req.header(b"Content-Length"), Some(b"262144".as_slice()));

        // serve_conn's per-iteration reset for the next request.
        req.clear();
        p.reset();

        // Second request reuses the same slots — must NOT corrupt.
        assert!(matches!(p.feed(&mut req, REQ), FeedResult::Done { .. }));
        assert_eq!(
            req.content_length, 262144,
            "2nd keep-alive request CL must not be corrupted by stale slot lengths",
        );
        assert_eq!(req.header(b"Content-Length"), Some(b"262144".as_slice()));
        assert_eq!(req.header(b"Host"), Some(b"h".as_slice()));
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

    /// HEAD whose total bytes exceed `MAX_HEAD_BYTES` (16 KiB) is
    /// rejected with `Overflow` before the terminator arrives.
    #[test]
    fn oversize_head_returns_overflow() {
        let mut raw: Vec<u8> = b"GET / HTTP/1.1\r\n".to_vec();
        while raw.len() < (super::MAX_HEAD_BYTES as usize) + 1024 {
            raw.extend_from_slice(b"X-Pad: padpadpadpadpadpadpadpadpad\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        let mut req = RequestHead::new();
        let mut p = StreamingRequestParser::new();
        assert!(matches!(p.feed(&mut req, &raw), FeedResult::Overflow));
    }

    /// DoS shape: peer streams bytes that never contain SP after
    /// the method — without a cap the `Method` state loop accepts
    /// forever. With the cap, the parser bails after
    /// `MAX_HEAD_BYTES`. Defends `serve_conn` against a malicious
    /// peer that holds the connection open indefinitely without
    /// ever producing a parseable HEAD.
    #[test]
    fn dos_no_sp_returns_overflow() {
        let evil = alloc::vec![b'a'; (super::MAX_HEAD_BYTES as usize) + 1];
        let mut req = RequestHead::new();
        let mut p = StreamingRequestParser::new();
        assert!(matches!(p.feed(&mut req, &evil), FeedResult::Overflow));
    }

    /// Multi-chunk version: cap is cumulative across `feed()` calls
    /// for the same request, so an adversarial stream split across
    /// many tiny chunks still trips Overflow at the right total.
    /// Four 4 KiB chunks consume exactly `MAX_HEAD_BYTES`; the
    /// fifth chunk's first byte is past the cap.
    #[test]
    fn dos_no_sp_returns_overflow_across_chunks() {
        let mut req = RequestHead::new();
        let mut p = StreamingRequestParser::new();
        let chunk = alloc::vec![b'a'; 4096];
        for _ in 0..4 {
            assert!(matches!(p.feed(&mut req, &chunk), FeedResult::NeedMore));
        }
        // Fifth chunk: prior == cap, so iter 0 trips immediately.
        assert!(matches!(p.feed(&mut req, &chunk), FeedResult::Overflow));
    }

    /// HEAD just under the cap parses normally — boundary case.
    #[test]
    fn under_cap_succeeds() {
        // X-Pad header is 33 bytes (\"X-Pad: \" + 24 chars + \r\n).
        // Leave a comfortable margin so the loop doesn't overshoot.
        let mut raw: Vec<u8> = b"GET / HTTP/1.1\r\n".to_vec();
        while raw.len() + 200 < (super::MAX_HEAD_BYTES as usize) {
            raw.extend_from_slice(b"X-Pad: padpadpadpadpadpadpadpad\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert!(
            raw.len() < super::MAX_HEAD_BYTES as usize,
            "test setup: HEAD must be under cap (len={} cap={})",
            raw.len(),
            super::MAX_HEAD_BYTES,
        );
        let (req, r) = feed_whole(&raw);
        assert!(done_consumed(&r).is_some());
        assert_eq!(req.method, Method::Get);
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
            let mut req = RequestHead::new();
            let mut p = StreamingRequestParser::new();
            let total_consumed = match p.feed(&mut req, a) {
                FeedResult::Done { consumed } => consumed,
                FeedResult::Overflow => panic!("split={split}: unexpected Overflow on first feed"),
                FeedResult::NeedMore => match p.feed(&mut req, b) {
                    FeedResult::Done { consumed } => a.len() + consumed,
                    FeedResult::Overflow => {
                        panic!("split={split}: unexpected Overflow on second feed")
                    }
                    FeedResult::NeedMore => {
                        panic!("split={split}: parser still wants more after both halves")
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

