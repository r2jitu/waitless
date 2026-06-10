// HTTP/1.1 CLIENT — response parsing, body framing, request writing,
// and the transport-generic `http1_fetch` entry point.
//
// The mirror of the server side: where `streaming.rs` parses request
// HEADs and `response.rs` serialises responses, this module parses
// response HEADs and serialises requests. Same disciplines apply:
//
//   * **Streaming, parse-as-you-go.** `ResponseParser` is a byte-fed
//     state machine writing directly into a caller-supplied
//     `ResponseHead` — chunk boundaries can fall anywhere.
//   * **Attacker-facing hardening.** A malicious SERVER attacks the
//     client, so the response parser and the chunked decoder carry
//     the same discipline as the request parser: bounded everything
//     (status line ≤ 1 KiB, header section ≤ 8 KiB, ≤ 32 headers,
//     chunk size ≤ 16 MiB, trailers ≤ 4 KiB), no panics on any
//     input, distinct errors for over-budget vs malformed.
//   * **RFC 9112 strictness.** Obs-folded header lines and bare CR /
//     bare LF line endings are rejected (§5.2, §2.2); a missing
//     reason phrase is tolerated (§4 — "reason-phrase … OPTIONAL").
//
// Documented v1 limits (each is a deliberate scope cut, not an
// oversight):
//   * No URL parsing, no redirects — callers pass (ip, port, host,
//     path) explicitly.
//   * No connection reuse / pipelining: bytes past the end of one
//     response body are dropped, and the convenience getters send
//     `Connection: close`.
//   * No HEAD requests (their bodyless-response framing rule isn't
//     wired) and no 1xx interim responses (rejected cleanly).
//   * Header name/value storage reuses the server's fixed 64/256-byte
//     slots; longer names/values are silently truncated (the budgets
//     above still bound the wire bytes consumed).
//   * Trailers after the terminal chunk are parsed and DISCARDED.

use alloc::vec::Vec;

use iobuf::IOBuf;

use crate::request::{Header, transfer_encoding_is_chunked};
use crate::response::{hpush, write_usize};
use crate::stream::HttpStream;

// ============================================================================
// Budgets
// ============================================================================

/// Cap on the status line (`HTTP/1.1 200 OK\r\n`), including CRLF.
pub const MAX_STATUS_LINE: usize = 1024;
/// Cap on the header section (everything between the status line and
/// the blank line, including per-line CRLFs and the final CRLF).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Cap on the number of response headers stored / accepted.
pub const MAX_RESPONSE_HEADERS: usize = 32;
/// Largest single chunk a `Transfer-Encoding: chunked` body may
/// declare. Bigger smells like an attack (or a server that should be
/// using Content-Length); reject rather than count down for hours.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// Most hex digits accepted in a chunk-size line. 16 MiB is 0x1000000
/// (7 digits); 8 leaves a leading-zero of slack while keeping the
/// accumulator far from overflow.
pub const MAX_CHUNK_HEX_DIGITS: u8 = 8;
/// Cap on chunk-extension bytes per size line (`;name=value` — we
/// skip them, but bounded).
pub const MAX_CHUNK_EXT_BYTES: u16 = 256;
/// Cap on the trailer section after the terminal 0-chunk. Parsed for
/// framing, then discarded (v1).
pub const MAX_TRAILER_BYTES: u16 = 4096;

// ============================================================================
// ResponseHead
// ============================================================================

/// The parsed response **head**: status code, version flag, header
/// table with case-insensitive lookup, and the three framing facts
/// (`content_length`, `transfer_encoding_chunked`, connection-close)
/// every body-dispatch decision needs.
pub struct ResponseHead {
    /// 100..=999 by construction (exactly three digits parsed).
    pub status: u16,
    /// `true` for `HTTP/1.0` (close-by-default), `false` for `HTTP/1.1`.
    http10: bool,
    /// Heap-boxed: the 32-slot table is ~11 KiB, and a `ResponseHead`
    /// is held across awaits by every fetch future (`http1_fetch` →
    /// `http_get` / `https_get` → their callers). Inline it would
    /// inflate each of those async state machines by ~11 KiB *per
    /// layer* — and futures materialise on the STACK before being
    /// moved into their parent state / `Box::pin`, so a deep client
    /// call chain inside a server handler overran the x86 BSP's
    /// guardless 256 KiB boot stack and silently corrupted adjacent
    /// `.bss` (seen as a wild per-cpu core count → OOB panic under
    /// QEMU x86_64). One cold-path alloc per response keeps every
    /// holder small.
    headers: alloc::boxed::Box<[Header; MAX_RESPONSE_HEADERS]>,
    header_count: usize,
    /// `Some(n)` iff a (valid, all-agreeing) `Content-Length` header
    /// is present. `None` ⇒ no CL header at all.
    content_length: Option<usize>,
    /// `Transfer-Encoding` names `chunked` as one of its codings.
    chunked: bool,
    /// The connection will not be reused: `Connection: close`, or
    /// HTTP/1.0 without `Connection: keep-alive`.
    connection_close: bool,
}

impl Default for ResponseHead {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact manual `Debug` (the fixed header array has no derive):
/// status + framing facts + header count — enough for test failures
/// and probe logs without dumping 10 KiB of slot storage.
impl core::fmt::Debug for ResponseHead {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseHead")
            .field("status", &self.status)
            .field("http10", &self.http10)
            .field("header_count", &self.header_count)
            .field("content_length", &self.content_length)
            .field("chunked", &self.chunked)
            .field("connection_close", &self.connection_close)
            .finish()
    }
}

impl ResponseHead {
    pub fn new() -> Self {
        ResponseHead {
            status: 0,
            http10: false,
            headers: alloc::boxed::Box::new([const { Header::new() }; MAX_RESPONSE_HEADERS]),
            header_count: 0,
            content_length: None,
            chunked: false,
            connection_close: false,
        }
    }

    /// Case-insensitive header lookup (first occurrence), mirroring
    /// `RequestHead::header`.
    pub fn header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name().eq_ignore_ascii_case(name) {
                return Some(self.headers[i].value());
            }
        }
        None
    }

    /// Number of headers stored.
    pub fn header_count(&self) -> usize {
        self.header_count
    }

    /// `Content-Length`, if (validly) declared.
    pub fn content_length(&self) -> Option<usize> {
        self.content_length
    }

    /// `Transfer-Encoding` includes `chunked`.
    pub fn transfer_encoding_chunked(&self) -> bool {
        self.chunked
    }

    /// The server signalled it will close the connection after this
    /// response (`Connection: close`, or HTTP/1.0 default).
    pub fn connection_close(&self) -> bool {
        self.connection_close
    }

    /// `true` when the status line was `HTTP/1.0`.
    pub fn is_http10(&self) -> bool {
        self.http10
    }
}

// ============================================================================
// Response parser
// ============================================================================

/// Why a response HEAD was rejected. Over-budget conditions are
/// distinct variants per the parser's hardening contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseParseError {
    /// Status line exceeded [`MAX_STATUS_LINE`].
    StatusLineTooLong,
    /// Header section exceeded [`MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// More than [`MAX_RESPONSE_HEADERS`] header lines.
    TooManyHeaders,
    /// Not `HTTP/1.0` / `HTTP/1.1`.
    BadVersion,
    /// Malformed status line (non-3-digit code, bare LF, …).
    BadStatusLine,
    /// Malformed header line: empty/whitespace-bearing name, bare LF,
    /// CR/LF embedded where the grammar forbids it.
    BadHeader,
    /// Obs-folded header continuation line (RFC 9112 §5.2 — a server
    /// MUST NOT generate it; we reject rather than unfold).
    ObsFold,
    /// A CR not followed by LF (RFC 9112 §2.2 bare-CR rejection).
    BareCr,
    /// `Content-Length` present but not a clean decimal, overflowing,
    /// or multiple disagreeing values (RFC 9112 §6.3 — must not trust).
    BadContentLength,
}

/// Result of feeding a chunk to [`ResponseParser::feed`].
pub enum ResponseFeed {
    /// Chunk consumed; more bytes needed to complete the HEAD.
    NeedMore,
    /// HEAD complete after `consumed` bytes of the last chunk; bytes
    /// past that point are body.
    Done { consumed: usize },
}

/// Per-byte parser state — one variant per lexical position in the
/// `status-line CRLF *( field-line CRLF ) CRLF` grammar.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PState {
    /// Accumulating the `HTTP/1.x` token until SP.
    Version,
    /// Accumulating the 3-digit status code until SP or CR.
    Code,
    /// Skipping the (optional, ignored) reason phrase until CR.
    Reason,
    /// Saw CR at end of the status line; expect LF.
    StatusCr,
    /// At the start of a header line (or the final blank line).
    HeaderLineStart,
    /// Writing bytes into the current header's name until `:`.
    HeaderName,
    /// Saw `:`; skipping optional SP/HTAB before the value.
    HeaderColon,
    /// Writing bytes into the current header's value until CR.
    HeaderValue,
    /// Saw CR at end of a header value; expect LF.
    ValueCr,
    /// Saw CR on the blank line; expect LF (end of HEAD).
    FinalCr,
    /// HEAD fully parsed.
    Done,
}

/// Streaming HTTP/1.1 response-HEAD parser — the client mirror of
/// `StreamingRequestParser`. One per in-flight response; feed inbound
/// chunks until `Done`. After an error the parser is poisoned and
/// every later `feed` returns the same error.
pub struct ResponseParser {
    state: PState,
    /// `HTTP/1.1` is exactly 8 bytes; a 9th pre-SP byte is an error.
    ver_buf: [u8; 8],
    ver_len: u8,
    code_digits: u8,
    /// Index of the header currently being filled.
    current: u8,
    /// Cumulative status-line bytes across feeds (budget check).
    status_bytes: u32,
    /// Cumulative header-section bytes across feeds (budget check).
    header_bytes: u32,
    /// Sticky failure: set on first error, returned forever after.
    failed: Option<ResponseParseError>,
}

impl Default for ResponseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseParser {
    pub const fn new() -> Self {
        ResponseParser {
            state: PState::Version,
            ver_buf: [0; 8],
            ver_len: 0,
            code_digits: 0,
            current: 0,
            status_bytes: 0,
            header_bytes: 0,
            failed: None,
        }
    }

    fn fail(&mut self, e: ResponseParseError) -> ResponseParseError {
        self.failed = Some(e);
        e
    }

    /// Count `n` status-line bytes against [`MAX_STATUS_LINE`].
    fn note_status(&mut self, n: usize) -> Result<(), ResponseParseError> {
        self.status_bytes = self.status_bytes.saturating_add(n as u32);
        if self.status_bytes as usize > MAX_STATUS_LINE {
            return Err(ResponseParseError::StatusLineTooLong);
        }
        Ok(())
    }

    /// Count `n` header-section bytes against [`MAX_HEADER_BYTES`].
    fn note_header(&mut self, n: usize) -> Result<(), ResponseParseError> {
        self.header_bytes = self.header_bytes.saturating_add(n as u32);
        if self.header_bytes as usize > MAX_HEADER_BYTES {
            return Err(ResponseParseError::HeadersTooLarge);
        }
        Ok(())
    }

    /// Feed the next chunk. `Ok(NeedMore)` — whole chunk consumed,
    /// HEAD incomplete; `Ok(Done { consumed })` — HEAD terminated
    /// `consumed` bytes in (the rest is body); `Err` — malformed /
    /// over-budget, connection is unusable.
    ///
    /// Must be called with a fresh `ResponseHead` on the first feed;
    /// later feeds for the same response reuse the same head (the
    /// in-progress field cursors live there, like the request parser).
    pub fn feed(
        &mut self,
        head: &mut ResponseHead,
        bytes: &[u8],
    ) -> Result<ResponseFeed, ResponseParseError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        match self.feed_inner(head, bytes) {
            Ok(r) => Ok(r),
            Err(e) => Err(self.fail(e)),
        }
    }

    fn feed_inner(
        &mut self,
        head: &mut ResponseHead,
        bytes: &[u8],
    ) -> Result<ResponseFeed, ResponseParseError> {
        let mut i = 0usize;
        loop {
            if i >= bytes.len() {
                return Ok(ResponseFeed::NeedMore);
            }
            match self.state {
                PState::Version => {
                    // Scan until SP; the token must fit `ver_buf`
                    // exactly (`HTTP/1.x` is 8 bytes — anything longer
                    // is not a version we speak).
                    let span = &bytes[i..];
                    let end = span.iter().position(|&b| b == b' ').unwrap_or(span.len());
                    let avail = self.ver_buf.len() - self.ver_len as usize;
                    if end > avail {
                        return Err(ResponseParseError::BadVersion);
                    }
                    self.ver_buf[self.ver_len as usize..self.ver_len as usize + end]
                        .copy_from_slice(&span[..end]);
                    self.ver_len += end as u8;
                    self.note_status(end)?;
                    i += end;
                    if i < bytes.len() {
                        match &self.ver_buf[..self.ver_len as usize] {
                            b"HTTP/1.1" => head.http10 = false,
                            b"HTTP/1.0" => head.http10 = true,
                            _ => return Err(ResponseParseError::BadVersion),
                        }
                        self.note_status(1)?; // the SP
                        self.state = PState::Code;
                        i += 1;
                    }
                }
                PState::Code => {
                    // Exactly three digits, then SP (reason follows)
                    // or CR (reason absent — tolerated per RFC 9112 §4).
                    while i < bytes.len() {
                        let b = bytes[i];
                        if b.is_ascii_digit() {
                            if self.code_digits == 3 {
                                return Err(ResponseParseError::BadStatusLine);
                            }
                            head.status = head.status * 10 + (b - b'0') as u16;
                            self.code_digits += 1;
                            self.note_status(1)?;
                            i += 1;
                        } else if b == b' ' || b == b'\r' {
                            if self.code_digits != 3 {
                                return Err(ResponseParseError::BadStatusLine);
                            }
                            self.note_status(1)?;
                            self.state = if b == b' ' {
                                PState::Reason
                            } else {
                                PState::StatusCr
                            };
                            i += 1;
                            break;
                        } else {
                            return Err(ResponseParseError::BadStatusLine);
                        }
                    }
                }
                PState::Reason => {
                    // Ignored bytes until CR. A bare LF here is the
                    // strict-CRLF rejection.
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r' || b == b'\n')
                        .unwrap_or(span.len());
                    self.note_status(end)?;
                    i += end;
                    if i < bytes.len() {
                        if bytes[i] == b'\n' {
                            return Err(ResponseParseError::BadStatusLine);
                        }
                        self.note_status(1)?;
                        self.state = PState::StatusCr;
                        i += 1;
                    }
                }
                PState::StatusCr => {
                    if bytes[i] != b'\n' {
                        return Err(ResponseParseError::BareCr);
                    }
                    self.note_status(1)?;
                    self.state = PState::HeaderLineStart;
                    i += 1;
                }
                PState::HeaderLineStart => {
                    let b = bytes[i];
                    if b == b'\r' {
                        self.note_header(1)?;
                        self.state = PState::FinalCr;
                        i += 1;
                    } else if b == b'\n' {
                        // Lone-LF blank line — strict CRLF only.
                        return Err(ResponseParseError::BadHeader);
                    } else if b == b' ' || b == b'\t' {
                        return Err(ResponseParseError::ObsFold);
                    } else {
                        if head.header_count == MAX_RESPONSE_HEADERS {
                            return Err(ResponseParseError::TooManyHeaders);
                        }
                        self.current = head.header_count as u8;
                        head.header_count += 1;
                        // Don't consume — HeaderName reads this byte.
                        self.state = PState::HeaderName;
                    }
                }
                PState::HeaderName => {
                    // Scan until `:`. SP/HTAB before the colon and any
                    // embedded CR/LF are malformed (RFC 9112 §5.1).
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| {
                            b == b':' || b == b'\r' || b == b'\n' || b == b' ' || b == b'\t'
                        })
                        .unwrap_or(span.len());
                    {
                        let h = &mut head.headers[self.current as usize];
                        let avail = h.name.len() - h.name_len;
                        let take = end.min(avail);
                        h.name[h.name_len..h.name_len + take].copy_from_slice(&span[..take]);
                        h.name_len += take;
                    }
                    self.note_header(end)?;
                    i += end;
                    if i < bytes.len() {
                        if bytes[i] != b':' {
                            return Err(ResponseParseError::BadHeader);
                        }
                        if head.headers[self.current as usize].name_len == 0 {
                            return Err(ResponseParseError::BadHeader);
                        }
                        self.note_header(1)?;
                        self.state = PState::HeaderColon;
                        i += 1;
                    }
                }
                PState::HeaderColon => {
                    // Skip optional whitespace (OWS = *( SP / HTAB )).
                    let span = &bytes[i..];
                    let skip = span
                        .iter()
                        .position(|&b| b != b' ' && b != b'\t')
                        .unwrap_or(span.len());
                    self.note_header(skip)?;
                    i += skip;
                    if i < bytes.len() {
                        let b = bytes[i];
                        if b == b'\r' {
                            self.note_header(1)?;
                            self.state = PState::ValueCr;
                            i += 1;
                        } else if b == b'\n' {
                            return Err(ResponseParseError::BadHeader);
                        } else {
                            self.state = PState::HeaderValue;
                        }
                    }
                }
                PState::HeaderValue => {
                    let span = &bytes[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r' || b == b'\n')
                        .unwrap_or(span.len());
                    {
                        let h = &mut head.headers[self.current as usize];
                        let avail = h.value.len() - h.value_len;
                        let take = end.min(avail);
                        h.value[h.value_len..h.value_len + take].copy_from_slice(&span[..take]);
                        h.value_len += take;
                    }
                    self.note_header(end)?;
                    i += end;
                    if i < bytes.len() {
                        if bytes[i] == b'\n' {
                            return Err(ResponseParseError::BadHeader);
                        }
                        // Field values exclude trailing OWS (RFC 9110
                        // §5.5) — trim what the wire carried.
                        let h = &mut head.headers[self.current as usize];
                        while h.value_len > 0
                            && matches!(h.value[h.value_len - 1], b' ' | b'\t')
                        {
                            h.value_len -= 1;
                        }
                        self.note_header(1)?;
                        self.state = PState::ValueCr;
                        i += 1;
                    }
                }
                PState::ValueCr => {
                    if bytes[i] != b'\n' {
                        return Err(ResponseParseError::BareCr);
                    }
                    self.note_header(1)?;
                    self.state = PState::HeaderLineStart;
                    i += 1;
                }
                PState::FinalCr => {
                    if bytes[i] != b'\n' {
                        return Err(ResponseParseError::BareCr);
                    }
                    self.state = PState::Done;
                    finish_head(head)?;
                    let consumed = i + 1;
                    debug_assert!(consumed <= bytes.len());
                    return Ok(ResponseFeed::Done { consumed });
                }
                PState::Done => {
                    // Re-fed after Done without a fresh parser: report
                    // the boundary, consume nothing.
                    return Ok(ResponseFeed::Done { consumed: i });
                }
            }
        }
    }
}

/// End-of-head bookkeeping: derive the framing facts. Distinct from
/// the request side: `Content-Length` is parsed STRICTLY (all-digit,
/// overflow-checked, all occurrences must agree — RFC 9112 §6.3).
fn finish_head(head: &mut ResponseHead) -> Result<(), ResponseParseError> {
    let mut cl: Option<usize> = None;
    for i in 0..head.header_count {
        let h = &head.headers[i];
        if h.name().eq_ignore_ascii_case(b"Content-Length") {
            let v = parse_strict_decimal(h.value())
                .ok_or(ResponseParseError::BadContentLength)?;
            if let Some(prev) = cl
                && prev != v
            {
                return Err(ResponseParseError::BadContentLength);
            }
            cl = Some(v);
        }
    }
    head.content_length = cl;
    head.chunked = head
        .header(b"Transfer-Encoding")
        .is_some_and(transfer_encoding_is_chunked);

    // Connection semantics: an explicit `close` token closes; an
    // HTTP/1.0 response closes unless `keep-alive` is explicit.
    let (mut has_close, mut has_keepalive) = (false, false);
    if let Some(v) = head.header(b"Connection") {
        for token in v.split(|&b| b == b',') {
            let t = token.trim_ascii();
            if t.eq_ignore_ascii_case(b"close") {
                has_close = true;
            } else if t.eq_ignore_ascii_case(b"keep-alive") {
                has_keepalive = true;
            }
        }
    }
    head.connection_close = has_close || (head.http10 && !has_keepalive);
    Ok(())
}

/// Strict ASCII-decimal parse: non-empty, digits only, overflow-checked.
fn parse_strict_decimal(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(n)
}

// ============================================================================
// Chunked transfer decoder (RFC 9112 §7.1)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkedError {
    /// Chunk-size line isn't `1*HEXDIG [;ext] CRLF`, or the hex run
    /// exceeded [`MAX_CHUNK_HEX_DIGITS`].
    BadSize,
    /// Declared chunk size exceeds [`MAX_CHUNK_SIZE`].
    ChunkTooLarge,
    /// Chunk-extension run exceeded [`MAX_CHUNK_EXT_BYTES`].
    ExtTooLong,
    /// CR without LF / LF without CR where the chunk grammar demands
    /// CRLF.
    BadFraming,
    /// Trailer section exceeded [`MAX_TRAILER_BYTES`].
    TrailerTooLarge,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CState {
    /// Reading hex digits of the chunk-size line.
    Size,
    /// Skipping a chunk extension (`;…`) until CR.
    SizeExt,
    /// Saw CR after size/ext; expect LF.
    SizeCr,
    /// Consuming chunk data; `usize` payload tracked in `remaining`.
    Data,
    /// Saw all data bytes; expect CR.
    DataCr,
    /// Expect LF after the data CR.
    DataLf,
    /// At the start of a trailer line (after the 0-chunk).
    TrailerStart,
    /// Skipping a (discarded) trailer field line until CR.
    TrailerLine,
    /// Saw CR inside the trailer section; expect LF.
    TrailerLineCr,
    /// Saw CR on the trailer-ending blank line; expect LF.
    TrailerEndCr,
    /// Terminal CRLF consumed — body complete.
    Done,
}

/// Incremental chunked-body decoder. Feed inbound bytes, collect
/// decoded body bytes; chunk boundaries may straddle feeds anywhere
/// (1-byte-at-a-time torture-tested). Trailers are parsed for framing
/// and DISCARDED (v1). After an error the decoder is poisoned.
pub struct ChunkedDecoder {
    state: CState,
    /// Declared size accumulator while parsing the hex line, then the
    /// not-yet-delivered byte count of the current chunk's data.
    remaining: usize,
    hex_digits: u8,
    ext_bytes: u16,
    trailer_bytes: u16,
    failed: Option<ChunkedError>,
}

impl Default for ChunkedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedDecoder {
    pub const fn new() -> Self {
        ChunkedDecoder {
            state: CState::Size,
            remaining: 0,
            hex_digits: 0,
            ext_bytes: 0,
            trailer_bytes: 0,
            failed: None,
        }
    }

    /// `true` once the terminal 0-chunk + trailer CRLF have been
    /// consumed.
    pub fn is_done(&self) -> bool {
        self.state == CState::Done
    }

    /// Decode as much of `input` as possible, appending decoded body
    /// bytes to `out`. Returns the number of input bytes consumed —
    /// always `input.len()` unless the terminal CRLF lands mid-chunk
    /// (bytes past it belong to the next response and are left
    /// unconsumed).
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, ChunkedError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        match self.feed_inner(input, out) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.failed = Some(e);
                Err(e)
            }
        }
    }

    fn feed_inner(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<usize, ChunkedError> {
        let mut i = 0usize;
        while i < input.len() {
            match self.state {
                CState::Size => {
                    let b = input[i];
                    if let Some(v) = hex_val(b) {
                        if self.hex_digits == MAX_CHUNK_HEX_DIGITS {
                            return Err(ChunkedError::BadSize);
                        }
                        self.hex_digits += 1;
                        // 8 hex digits max ⇒ remaining < 2^32, no
                        // overflow on 64-bit; the size cap rejects
                        // anything past 16 MiB right here anyway.
                        self.remaining = (self.remaining << 4) | v as usize;
                        if self.remaining > MAX_CHUNK_SIZE {
                            return Err(ChunkedError::ChunkTooLarge);
                        }
                        i += 1;
                    } else if b == b';' {
                        if self.hex_digits == 0 {
                            return Err(ChunkedError::BadSize);
                        }
                        self.state = CState::SizeExt;
                        i += 1;
                    } else if b == b'\r' {
                        if self.hex_digits == 0 {
                            return Err(ChunkedError::BadSize);
                        }
                        self.state = CState::SizeCr;
                        i += 1;
                    } else {
                        return Err(ChunkedError::BadSize);
                    }
                }
                CState::SizeExt => {
                    // Skip until CR; bare LF rejected; bounded.
                    let span = &input[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r' || b == b'\n')
                        .unwrap_or(span.len());
                    self.ext_bytes = self.ext_bytes.saturating_add(end as u16);
                    if self.ext_bytes > MAX_CHUNK_EXT_BYTES {
                        return Err(ChunkedError::ExtTooLong);
                    }
                    i += end;
                    if i < input.len() {
                        if input[i] == b'\n' {
                            return Err(ChunkedError::BadFraming);
                        }
                        self.state = CState::SizeCr;
                        i += 1;
                    }
                }
                CState::SizeCr => {
                    if input[i] != b'\n' {
                        return Err(ChunkedError::BadFraming);
                    }
                    i += 1;
                    self.hex_digits = 0;
                    self.ext_bytes = 0;
                    if self.remaining == 0 {
                        self.state = CState::TrailerStart;
                    } else {
                        self.state = CState::Data;
                    }
                }
                CState::Data => {
                    let take = self.remaining.min(input.len() - i);
                    out.extend_from_slice(&input[i..i + take]);
                    self.remaining -= take;
                    i += take;
                    if self.remaining == 0 {
                        self.state = CState::DataCr;
                    }
                }
                CState::DataCr => {
                    if input[i] != b'\r' {
                        return Err(ChunkedError::BadFraming);
                    }
                    self.state = CState::DataLf;
                    i += 1;
                }
                CState::DataLf => {
                    if input[i] != b'\n' {
                        return Err(ChunkedError::BadFraming);
                    }
                    self.state = CState::Size;
                    i += 1;
                }
                CState::TrailerStart => {
                    let b = input[i];
                    self.trailer_bytes = self.trailer_bytes.saturating_add(1);
                    if self.trailer_bytes > MAX_TRAILER_BYTES {
                        return Err(ChunkedError::TrailerTooLarge);
                    }
                    if b == b'\r' {
                        self.state = CState::TrailerEndCr;
                    } else if b == b'\n' {
                        return Err(ChunkedError::BadFraming);
                    } else {
                        self.state = CState::TrailerLine;
                    }
                    i += 1;
                }
                CState::TrailerLine => {
                    // Discarded trailer field; scan to CR, bounded.
                    let span = &input[i..];
                    let end = span
                        .iter()
                        .position(|&b| b == b'\r' || b == b'\n')
                        .unwrap_or(span.len());
                    self.trailer_bytes = self.trailer_bytes.saturating_add(end as u16 + 1);
                    if self.trailer_bytes > MAX_TRAILER_BYTES {
                        return Err(ChunkedError::TrailerTooLarge);
                    }
                    i += end;
                    if i < input.len() {
                        if input[i] == b'\n' {
                            return Err(ChunkedError::BadFraming);
                        }
                        self.state = CState::TrailerLineCr;
                        i += 1;
                    }
                }
                CState::TrailerLineCr => {
                    if input[i] != b'\n' {
                        return Err(ChunkedError::BadFraming);
                    }
                    self.state = CState::TrailerStart;
                    i += 1;
                }
                CState::TrailerEndCr => {
                    if input[i] != b'\n' {
                        return Err(ChunkedError::BadFraming);
                    }
                    self.state = CState::Done;
                    i += 1;
                    // Terminal CRLF consumed — leave any tail for the
                    // caller (next pipelined response, dropped in v1).
                    return Ok(i);
                }
                CState::Done => return Ok(i),
            }
        }
        Ok(i)
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Body framing dispatch
// ============================================================================

/// How the response body is delimited on the wire (RFC 9112 §6.3,
/// response side, no-HEAD-requests v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// 204 / 304 — never a body, whatever the headers say.
    NoBody,
    /// Exactly `n` bytes follow the head.
    ContentLength(usize),
    /// `Transfer-Encoding: chunked` (takes precedence over any
    /// Content-Length — §6.3 rule 3).
    Chunked,
    /// Neither chunked nor Content-Length: the body runs to
    /// connection close (the HTTP/1.0 / `Connection: close` shape).
    ReadToEof,
}

/// Derive the body framing from a parsed head. 1xx interim responses
/// are the caller's problem ([`http1_fetch`] rejects them before
/// asking).
pub fn body_framing(head: &ResponseHead) -> BodyFraming {
    if head.status == 204 || head.status == 304 {
        return BodyFraming::NoBody;
    }
    if head.transfer_encoding_chunked() {
        return BodyFraming::Chunked;
    }
    if let Some(n) = head.content_length() {
        return BodyFraming::ContentLength(n);
    }
    BodyFraming::ReadToEof
}

// ============================================================================
// ClientBodyReader
// ============================================================================

/// Body-read failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// Transport EOF before the framing said the body was complete
    /// (mid-Content-Length, or mid-chunk).
    Truncated,
    /// Chunked-framing violation from the decoder.
    Chunked(ChunkedError),
    /// `read_to_vec` cap exceeded (or allocation refused).
    TooLarge,
}

/// Streaming reader for a response body: wraps the borrowed transport
/// stream + the framing mode and yields body bytes incrementally.
/// The client mirror of the server's `BodyReader`.
///
/// Zero-copy on the Content-Length fast path: a transport chunk that
/// lies entirely inside the body is handed through as the owned
/// `IOBuf` the transport surfaced (NIC RX buffer / TLS plaintext
/// view). The chunked path copies across the decoder — fine for v1.
///
/// v1: bytes past the end of the body (the start of a pipelined next
/// response) are dropped — the client does not reuse connections.
pub struct ClientBodyReader<'a, S: HttpStream> {
    stream: &'a mut S,
    /// Body bytes that rode in with the response head.
    prebuf: Option<IOBuf>,
    state: BodyState,
}

enum BodyState {
    NoBody,
    ContentLength { remaining: usize },
    Chunked { dec: ChunkedDecoder },
    ReadToEof,
}

impl<'a, S: HttpStream> ClientBodyReader<'a, S> {
    /// Pair the stream with the framing mode; `prebuf` carries any
    /// body bytes that arrived in the same chunk as the head.
    pub fn new(stream: &'a mut S, prebuf: Option<IOBuf>, framing: BodyFraming) -> Self {
        let state = match framing {
            BodyFraming::NoBody => BodyState::NoBody,
            BodyFraming::ContentLength(0) => BodyState::ContentLength { remaining: 0 },
            BodyFraming::ContentLength(n) => BodyState::ContentLength { remaining: n },
            BodyFraming::Chunked => BodyState::Chunked {
                dec: ChunkedDecoder::new(),
            },
            BodyFraming::ReadToEof => BodyState::ReadToEof,
        };
        ClientBodyReader {
            stream,
            prebuf,
            state,
        }
    }

    /// Bytes still owed on a Content-Length body; 0 for the other
    /// framings (their callers consume via `next_chunk` until `None`).
    pub fn remaining(&self) -> usize {
        match &self.state {
            BodyState::ContentLength { remaining } => *remaining,
            _ => 0,
        }
    }

    /// Next run of decoded body bytes. `Ok(None)` is the clean end of
    /// body; `Err` is a framing violation or a truncating transport
    /// close.
    pub async fn next_chunk(&mut self) -> Result<Option<IOBuf>, BodyError> {
        loop {
            // Phase 1: terminal-state checks (no transport touch).
            match &self.state {
                BodyState::NoBody => return Ok(None),
                BodyState::ContentLength { remaining } if *remaining == 0 => return Ok(None),
                BodyState::Chunked { dec } if dec.is_done() => return Ok(None),
                _ => {}
            }
            // Phase 2: pull bytes — prebuf first, then the transport.
            let src = match self.prebuf.take() {
                Some(b) => Some(b),
                None => self.stream.recv_chunk().await.map(|g| g.into_owned()),
            };
            // Phase 3: run the framing.
            match &mut self.state {
                BodyState::NoBody => return Ok(None),
                BodyState::ContentLength { remaining } => {
                    let Some(src) = src else {
                        return Err(BodyError::Truncated);
                    };
                    let n = src.data().len();
                    if n == 0 {
                        continue;
                    }
                    if n <= *remaining {
                        // Fast path: whole chunk is body — zero copy.
                        *remaining -= n;
                        return Ok(Some(src));
                    }
                    // Straddle past the body end: copy the body-side
                    // prefix, drop the residue (v1 — no conn reuse).
                    let take = *remaining;
                    let mut v: Vec<u8> = Vec::new();
                    if v.try_reserve_exact(take).is_err() {
                        return Err(BodyError::TooLarge);
                    }
                    v.extend_from_slice(&src.data()[..take]);
                    *remaining = 0;
                    return Ok(Some(IOBuf::from(v)));
                }
                BodyState::Chunked { dec } => {
                    let Some(src) = src else {
                        return Err(BodyError::Truncated);
                    };
                    let mut out: Vec<u8> = Vec::new();
                    let _consumed = dec.feed(src.data(), &mut out).map_err(BodyError::Chunked)?;
                    // Bytes past the terminal CRLF (consumed < len)
                    // would be the next pipelined response — dropped.
                    if !out.is_empty() {
                        return Ok(Some(IOBuf::from(out)));
                    }
                    if dec.is_done() {
                        return Ok(None);
                    }
                    // Pure framing bytes — keep pulling.
                }
                BodyState::ReadToEof => {
                    match src {
                        // Close IS the body terminator here.
                        None => return Ok(None),
                        Some(b) if b.data().is_empty() => continue,
                        Some(b) => return Ok(Some(b)),
                    }
                }
            }
        }
    }

    /// Drain the whole body into a bounded `Vec`. `Err(TooLarge)` past
    /// `cap` — the caller names its budget explicitly.
    pub async fn read_to_vec(&mut self, cap: usize) -> Result<Vec<u8>, BodyError> {
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.next_chunk().await? {
                None => return Ok(out),
                Some(b) => {
                    let data = b.data();
                    if out.len() + data.len() > cap || out.try_reserve(data.len()).is_err() {
                        return Err(BodyError::TooLarge);
                    }
                    out.extend_from_slice(data);
                }
            }
        }
    }
}

// ============================================================================
// Request writer
// ============================================================================

/// One outbound request, by parts. No URL parsing — the caller names
/// the target explicitly. `headers` must not include `Host`,
/// `Content-Length`, or `Connection` (the writer owns those; no
/// de-dup in v1).
pub struct FetchRequest<'a> {
    /// e.g. `b"GET"` / `b"POST"`. v1: do not send `HEAD` (its
    /// bodyless-response framing rule is not implemented).
    pub method: &'a [u8],
    /// Origin-form request target, e.g. `b"/health"`.
    pub path: &'a [u8],
    /// `Host` header value.
    pub host: &'a [u8],
    /// Additional headers, written verbatim.
    pub headers: &'a [(&'a [u8], &'a [u8])],
    /// Optional body; `Some` emits `Content-Length` (even for 0).
    pub body: Option<&'a [u8]>,
    /// `true` ⇒ `Connection: close`. Default keep-alive (HTTP/1.1
    /// implicit) — the writer emits no Connection header then.
    pub close: bool,
}

impl<'a> FetchRequest<'a> {
    /// The common GET shape: no extra headers, no body, keep-alive.
    pub fn get(host: &'a [u8], path: &'a [u8]) -> Self {
        FetchRequest {
            method: b"GET",
            path,
            host,
            headers: &[],
            body: None,
            close: false,
        }
    }
}

/// Serialise a request (head + optional body) into one exactly-sized
/// IOBuf of wire bytes. Always `HTTP/1.1`.
pub fn serialize_request(req: &FetchRequest<'_>) -> IOBuf {
    // Exact-ish capacity: fixed framing + caller parts. `hpush`
    // debug-asserts (and release-truncates) on overflow, so the slack
    // constant covers every fixed literal below with margin.
    let mut cap = req.method.len() + req.path.len() + req.host.len() + 96;
    for (n, v) in req.headers {
        cap += n.len() + v.len() + 4;
    }
    cap += req.body.map_or(0, |b| b.len());

    let mut buf = crate::body_iobuf(cap);
    hpush(&mut buf, req.method);
    hpush(&mut buf, b" ");
    hpush(&mut buf, req.path);
    hpush(&mut buf, b" HTTP/1.1\r\nHost: ");
    hpush(&mut buf, req.host);
    hpush(&mut buf, b"\r\n");
    for (n, v) in req.headers {
        hpush(&mut buf, n);
        hpush(&mut buf, b": ");
        hpush(&mut buf, v);
        hpush(&mut buf, b"\r\n");
    }
    if let Some(body) = req.body {
        hpush(&mut buf, b"Content-Length: ");
        let mut len_buf = [0u8; 20];
        let n = write_usize(&mut len_buf, body.len());
        hpush(&mut buf, &len_buf[..n]);
        hpush(&mut buf, b"\r\n");
    }
    if req.close {
        hpush(&mut buf, b"Connection: close\r\n");
    }
    hpush(&mut buf, b"\r\n");
    if let Some(body) = req.body {
        hpush(&mut buf, body);
    }
    buf
}

// ============================================================================
// http1_fetch — the transport-generic request/response exchange
// ============================================================================

/// Why a fetch failed before (or at) the response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// Transport send failed.
    Send,
    /// Peer closed before a complete response head arrived.
    ClosedBeforeResponse,
    /// Malformed / over-budget response head.
    Parse(ResponseParseError),
    /// 1xx interim response — unsupported in v1 (we never send
    /// `Expect`, so a compliant server has no reason to emit one).
    Interim,
}

/// Send one HTTP/1.1 request over `stream` and parse the response
/// head. Transport-generic: `S` is any [`HttpStream`] — a plain
/// `TcpStream` or a client-side TLS stream alike.
///
/// On success returns the parsed [`ResponseHead`] plus a
/// [`ClientBodyReader`] positioned at the first body byte (any body
/// bytes that rode in with the head are carried as its prebuf).
pub async fn http1_fetch<'s, S: HttpStream>(
    stream: &'s mut S,
    req: &FetchRequest<'_>,
) -> Result<(ResponseHead, ClientBodyReader<'s, S>), FetchError> {
    // Ship the request.
    let mut chain = crate::IOBufChain::new();
    chain.push_back(serialize_request(req));
    stream.send(&mut chain).await.map_err(|_| FetchError::Send)?;

    // Parse the response head, chunk by chunk.
    let mut head = ResponseHead::new();
    let mut parser = ResponseParser::new();
    let prebuf: Option<IOBuf> = loop {
        let Some(guard) = stream.recv_chunk().await else {
            return Err(FetchError::ClosedBeforeResponse);
        };
        match parser.feed(&mut head, guard.data()) {
            Ok(ResponseFeed::Done { consumed }) => {
                break guard
                    .into_remainder(consumed)
                    .expect("consumed <= data().len()");
            }
            Ok(ResponseFeed::NeedMore) => drop(guard),
            Err(e) => return Err(FetchError::Parse(e)),
        }
    };

    if (100..200).contains(&head.status) {
        return Err(FetchError::Interim);
    }
    let framing = body_framing(&head);
    Ok((head, ClientBodyReader::new(stream, prebuf, framing)))
}

// ============================================================================
// Convenience getters
// ============================================================================

/// Failure stage of [`http_get`] — keeps the underlying error so a
/// caller (e.g. a probe endpoint) can name the failing stage.
#[derive(Debug)]
pub enum GetError {
    /// TCP connect failed (the `TcpConnectError` distinguishes the
    /// resolve stage from refusal/timeout).
    Connect(waitless::runtime::TcpConnectError),
    /// Request/response exchange failed.
    Fetch(FetchError),
    /// Body read failed (truncated / bad chunking / over cap).
    Body(BodyError),
}

/// One-shot plain-HTTP GET: connect, fetch, read the body into a
/// bounded `Vec` (≤ `body_cap`), `Connection: close`. No URL parsing,
/// no redirects (v1 — documented above).
pub async fn http_get(
    ip: waitless::runtime::IpAddr,
    port: u16,
    host: &[u8],
    path: &[u8],
    body_cap: usize,
) -> Result<(ResponseHead, Vec<u8>), GetError> {
    let mut stream = waitless::tcp_connect(ip, port)
        .await
        .map_err(GetError::Connect)?;
    let mut req = FetchRequest::get(host, path);
    req.close = true;
    let (head, mut body) = http1_fetch(&mut stream, &req)
        .await
        .map_err(GetError::Fetch)?;
    let bytes = body.read_to_vec(body_cap).await.map_err(GetError::Body)?;
    Ok((head, bytes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod parser_tests {
    use super::*;
    use alloc::vec::Vec;

    fn parse_whole(raw: &[u8]) -> Result<(ResponseHead, usize), ResponseParseError> {
        let mut head = ResponseHead::new();
        let mut p = ResponseParser::new();
        match p.feed(&mut head, raw)? {
            ResponseFeed::Done { consumed } => Ok((head, consumed)),
            ResponseFeed::NeedMore => panic!("head incomplete"),
        }
    }

    #[test]
    fn simple_200_with_reason() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (head, consumed) = parse_whole(raw).unwrap();
        assert_eq!(head.status, 200);
        assert!(!head.is_http10());
        assert_eq!(head.content_length(), Some(5));
        assert!(!head.transfer_encoding_chunked());
        assert!(!head.connection_close());
        assert_eq!(consumed, raw.len() - 5);
    }

    #[test]
    fn reason_phrase_absent_is_tolerated() {
        // Both shapes: `200\r\n` and `200 \r\n` (empty reason).
        let (head, _) = parse_whole(b"HTTP/1.1 404\r\n\r\n").unwrap();
        assert_eq!(head.status, 404);
        let (head, _) = parse_whole(b"HTTP/1.1 404 \r\n\r\n").unwrap();
        assert_eq!(head.status, 404);
    }

    #[test]
    fn reason_with_spaces_and_symbols() {
        let (head, _) = parse_whole(b"HTTP/1.1 500 Internal Server Error!\r\n\r\n").unwrap();
        assert_eq!(head.status, 500);
    }

    #[test]
    fn http10_flags_version_and_default_close() {
        let (head, _) = parse_whole(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        assert!(head.is_http10());
        assert!(head.connection_close(), "1.0 defaults to close");
        let (head, _) =
            parse_whole(b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n").unwrap();
        assert!(!head.connection_close(), "explicit keep-alive on 1.0");
    }

    #[test]
    fn connection_close_token_in_list() {
        let (head, _) =
            parse_whole(b"HTTP/1.1 200 OK\r\nConnection: foo, Close\r\n\r\n").unwrap();
        assert!(head.connection_close());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let (head, _) =
            parse_whole(b"HTTP/1.1 200 OK\r\nX-Custom-Tag:   probe  \r\n\r\n").unwrap();
        assert_eq!(head.header(b"x-custom-tag"), Some(b"probe".as_slice()));
        assert_eq!(head.header(b"X-CUSTOM-TAG"), Some(b"probe".as_slice()));
        assert_eq!(head.header(b"missing"), None);
    }

    #[test]
    fn chunked_te_flag_set() {
        let (head, _) =
            parse_whole(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap();
        assert!(head.transfer_encoding_chunked());
        assert_eq!(body_framing(&head), BodyFraming::Chunked);
    }

    #[test]
    fn framing_dispatch_matrix() {
        let (head, _) = parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n").unwrap();
        assert_eq!(body_framing(&head), BodyFraming::ContentLength(7));

        // Chunked beats Content-Length (RFC 9112 §6.3 rule 3).
        let (head, _) = parse_whole(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(body_framing(&head), BodyFraming::Chunked);

        let (head, _) = parse_whole(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").unwrap();
        assert_eq!(body_framing(&head), BodyFraming::ReadToEof);

        let (head, _) = parse_whole(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(body_framing(&head), BodyFraming::NoBody);
        let (head, _) =
            parse_whole(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n").unwrap();
        assert_eq!(body_framing(&head), BodyFraming::NoBody);
    }

    #[test]
    fn bad_version_rejected() {
        assert_eq!(
            parse_whole(b"HTTP/2.0 200 OK\r\n\r\n").unwrap_err(),
            ResponseParseError::BadVersion,
        );
        assert_eq!(
            parse_whole(b"ICY 200 OK\r\n\r\n").unwrap_err(),
            ResponseParseError::BadVersion,
        );
        assert_eq!(
            parse_whole(b"HTTP/1.11 200 OK\r\n\r\n").unwrap_err(),
            ResponseParseError::BadVersion,
        );
    }

    #[test]
    fn bad_status_code_rejected() {
        assert!(parse_whole(b"HTTP/1.1 20 OK\r\n\r\n").is_err());
        assert!(parse_whole(b"HTTP/1.1 2000 OK\r\n\r\n").is_err());
        assert!(parse_whole(b"HTTP/1.1 2x0 OK\r\n\r\n").is_err());
        assert!(parse_whole(b"HTTP/1.1  200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn obs_fold_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nX-A: one\r\n two\r\n\r\n";
        assert_eq!(parse_whole(raw).unwrap_err(), ResponseParseError::ObsFold);
    }

    #[test]
    fn bare_cr_and_bare_lf_rejected() {
        // CR not followed by LF, in each position.
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\rX\r\n\r\n").unwrap_err(),
            ResponseParseError::BareCr,
        );
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nX-A: v\rX\r\n\r\n").unwrap_err(),
            ResponseParseError::BareCr,
        );
        // Lone-LF line endings (strict CRLF).
        assert!(parse_whole(b"HTTP/1.1 200 OK\n\r\n").is_err());
        assert!(parse_whole(b"HTTP/1.1 200 OK\r\nX-A: v\n\r\n").is_err());
    }

    #[test]
    fn header_name_with_space_or_empty_rejected() {
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n").unwrap_err(),
            ResponseParseError::BadHeader,
        );
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\n: v\r\n\r\n").unwrap_err(),
            ResponseParseError::BadHeader,
        );
    }

    #[test]
    fn bad_content_length_rejected() {
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: 12a\r\n\r\n").unwrap_err(),
            ResponseParseError::BadContentLength,
        );
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n").unwrap_err(),
            ResponseParseError::BadContentLength,
        );
        // 2^64-ish overflow.
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n")
                .unwrap_err(),
            ResponseParseError::BadContentLength,
        );
        // Disagreeing duplicates.
        assert_eq!(
            parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
                .unwrap_err(),
            ResponseParseError::BadContentLength,
        );
        // Agreeing duplicates are fine.
        let (head, _) =
            parse_whole(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n")
                .unwrap();
        assert_eq!(head.content_length(), Some(5));
    }

    #[test]
    fn status_line_over_budget_rejected() {
        let mut raw: Vec<u8> = b"HTTP/1.1 200 ".to_vec();
        raw.extend(core::iter::repeat_n(b'x', MAX_STATUS_LINE + 16));
        raw.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_whole(&raw).unwrap_err(),
            ResponseParseError::StatusLineTooLong,
        );
    }

    #[test]
    fn header_section_over_budget_rejected() {
        let mut raw: Vec<u8> = b"HTTP/1.1 200 OK\r\n".to_vec();
        // Stay under the 32-header cap while blowing the byte budget:
        // 31 headers x ~330 B ≈ 10 KiB > 8 KiB.
        for i in 0..31 {
            raw.extend_from_slice(b"X-Pad-");
            raw.push(b'a' + (i % 26));
            raw.extend_from_slice(b": ");
            raw.extend(core::iter::repeat_n(b'v', 320));
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert_eq!(
            parse_whole(&raw).unwrap_err(),
            ResponseParseError::HeadersTooLarge,
        );
    }

    #[test]
    fn too_many_headers_rejected() {
        let mut raw: Vec<u8> = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..(MAX_RESPONSE_HEADERS + 1) {
            raw.extend_from_slice(b"X-N");
            raw.push(b'0' + ((i / 10) % 10) as u8);
            raw.push(b'0' + (i % 10) as u8);
            raw.extend_from_slice(b": v\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert_eq!(
            parse_whole(&raw).unwrap_err(),
            ResponseParseError::TooManyHeaders,
        );
    }

    #[test]
    fn interim_status_parses_as_head() {
        // 1xx is rejected at the fetch layer; the parser itself
        // parses it like any other head.
        let (head, _) = parse_whole(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_eq!(head.status, 100);
    }

    /// Property: for every split point of a canonical response, the
    /// two-feed parse equals the whole parse.
    #[test]
    fn split_at_every_boundary_matches_whole_parse() {
        let raw = b"HTTP/1.1 200 OK\r\nHost: example.com\r\nContent-Length: 12\r\nX-Tag: probe\r\nConnection: close\r\n\r\nhello world!";
        let (whole, whole_consumed) = parse_whole(raw).unwrap();

        for split in 0..=raw.len() {
            let (a, b) = raw.split_at(split);
            let mut head = ResponseHead::new();
            let mut p = ResponseParser::new();
            let consumed = match p.feed(&mut head, a).unwrap() {
                ResponseFeed::Done { consumed } => consumed,
                ResponseFeed::NeedMore => match p.feed(&mut head, b).unwrap() {
                    ResponseFeed::Done { consumed } => a.len() + consumed,
                    ResponseFeed::NeedMore => panic!("split={split}: still incomplete"),
                },
            };
            assert_eq!(consumed, whole_consumed, "split={split}");
            assert_eq!(head.status, whole.status, "split={split}");
            assert_eq!(head.content_length(), whole.content_length(), "split={split}");
            assert_eq!(head.connection_close(), whole.connection_close(), "split={split}");
            assert_eq!(head.header_count(), whole.header_count(), "split={split}");
            assert_eq!(head.header(b"x-tag"), whole.header(b"x-tag"), "split={split}");
        }
    }

    /// Fuzz-smoke: random byte soup, random chunking — must never
    /// panic (errors are fine; that's the point).
    #[test]
    fn fuzz_smoke_never_panics() {
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5_000 {
            let len = (rnd() % 600) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let mut head = ResponseHead::new();
            let mut p = ResponseParser::new();
            let mut off = 0usize;
            while off < buf.len() {
                let take = 1 + (rnd() % 64) as usize;
                let end = (off + take).min(buf.len());
                match p.feed(&mut head, &buf[off..end]) {
                    Ok(ResponseFeed::NeedMore) => off = end,
                    Ok(ResponseFeed::Done { .. }) | Err(_) => break,
                }
            }
        }
        // Mutations of a real head — single-byte corruption sweep.
        let real = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Tag: a\r\n\r\nbody";
        for pos in 0..real.len() {
            for _ in 0..4 {
                let mut m = real.to_vec();
                m[pos] = rnd() as u8;
                let mut head = ResponseHead::new();
                let mut p = ResponseParser::new();
                let _ = p.feed(&mut head, &m);
            }
        }
    }
}

#[cfg(test)]
mod chunked_tests {
    use super::*;
    use alloc::vec::Vec;

    fn decode_whole(raw: &[u8]) -> Result<(Vec<u8>, usize, bool), ChunkedError> {
        let mut dec = ChunkedDecoder::new();
        let mut out = Vec::new();
        let consumed = dec.feed(raw, &mut out)?;
        Ok((out, consumed, dec.is_done()))
    }

    /// The RFC 9112 §7.1 example body, byte for byte.
    #[test]
    fn rfc_example_decodes() {
        let raw = b"4\r\nWiki\r\n7\r\npedia i\r\nB\r\nn \r\nchunks.\r\n0\r\n\r\n";
        let (out, consumed, done) = decode_whole(raw).unwrap();
        assert_eq!(out, b"Wikipedia in \r\nchunks.");
        assert_eq!(consumed, raw.len());
        assert!(done);
    }

    /// 1-byte-at-a-time torture: every boundary straddles a feed.
    #[test]
    fn one_byte_at_a_time_torture() {
        let raw = b"4\r\nWiki\r\n7\r\npedia i\r\nB\r\nn \r\nchunks.\r\n0\r\nTrailer-A: 1\r\n\r\n";
        let mut dec = ChunkedDecoder::new();
        let mut out = Vec::new();
        for &b in raw.iter() {
            let consumed = dec.feed(&[b], &mut out).unwrap();
            assert_eq!(consumed, 1);
        }
        assert!(dec.is_done());
        assert_eq!(out, b"Wikipedia in \r\nchunks.");
    }

    #[test]
    fn chunk_extensions_skipped() {
        let raw = b"4;name=value;x=\"y\"\r\nWiki\r\n0\r\n\r\n";
        let (out, _, done) = decode_whole(raw).unwrap();
        assert_eq!(out, b"Wiki");
        assert!(done);
    }

    #[test]
    fn trailers_parsed_and_discarded() {
        let raw = b"3\r\nabc\r\n0\r\nExpires: never\r\nX-Sum: 99\r\n\r\nNEXT";
        let (out, consumed, done) = decode_whole(raw).unwrap();
        assert_eq!(out, b"abc");
        assert!(done);
        // Terminal CRLF consumed; the pipelined tail is NOT.
        assert_eq!(consumed, raw.len() - 4);
    }

    #[test]
    fn uppercase_hex_ok() {
        let raw = b"A\r\n0123456789\r\n0\r\n\r\n";
        let (out, _, done) = decode_whole(raw).unwrap();
        assert_eq!(out, b"0123456789");
        assert!(done);
    }

    #[test]
    fn bad_hex_rejected() {
        assert_eq!(decode_whole(b"zz\r\n\r\n").unwrap_err(), ChunkedError::BadSize);
        // Empty size line.
        assert_eq!(decode_whole(b"\r\n").unwrap_err(), ChunkedError::BadSize);
    }

    #[test]
    fn overlong_hex_rejected() {
        // 9 hex digits — over MAX_CHUNK_HEX_DIGITS even with leading
        // zeros.
        assert_eq!(
            decode_whole(b"000000001\r\nx\r\n0\r\n\r\n").unwrap_err(),
            ChunkedError::BadSize,
        );
    }

    #[test]
    fn oversize_chunk_rejected() {
        // 0x1000001 = 16 MiB + 1.
        assert_eq!(
            decode_whole(b"1000001\r\n").unwrap_err(),
            ChunkedError::ChunkTooLarge,
        );
    }

    #[test]
    fn missing_crlf_after_data_rejected() {
        assert_eq!(
            decode_whole(b"3\r\nabcXY").unwrap_err(),
            ChunkedError::BadFraming,
        );
    }

    #[test]
    fn bare_lf_size_line_rejected() {
        assert_eq!(decode_whole(b"3\nabc\r\n0\r\n\r\n").unwrap_err(), ChunkedError::BadSize);
    }

    #[test]
    fn trailer_over_budget_rejected() {
        let mut raw: Vec<u8> = b"1\r\nx\r\n0\r\n".to_vec();
        for _ in 0..200 {
            raw.extend_from_slice(b"X-Pad: ");
            raw.extend(core::iter::repeat_n(b'v', 32));
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        assert_eq!(decode_whole(&raw).unwrap_err(), ChunkedError::TrailerTooLarge);
    }

    /// Fuzz-smoke for the decoder: random bytes, random feed sizes —
    /// never panics.
    #[test]
    fn fuzz_smoke_never_panics() {
        let mut seed: u64 = 0xD1B5_4A32_D192_ED03;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5_000 {
            let len = (rnd() % 400) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            let mut dec = ChunkedDecoder::new();
            let mut out = Vec::new();
            let mut off = 0usize;
            while off < buf.len() {
                let take = 1 + (rnd() % 32) as usize;
                let end = (off + take).min(buf.len());
                match dec.feed(&buf[off..end], &mut out) {
                    Ok(n) => {
                        off += n;
                        if dec.is_done() || n == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;
    use crate::request::{Method, RequestHead};
    use crate::streaming::{FeedResult, StreamingRequestParser};

    /// THE writer pin: serialise a request, feed it to our own
    /// server-side request parser, recover every field. Guards the
    /// writer against the strictest consumer we have.
    #[test]
    fn writer_roundtrips_through_server_parser() {
        let req = FetchRequest {
            method: b"POST",
            path: b"/up?x=1",
            host: b"example.com:8080",
            headers: &[(b"X-Tag", b"probe"), (b"Accept", b"*/*")],
            body: Some(b"hello"),
            close: false,
        };
        let wire = serialize_request(&req);

        let mut parsed = RequestHead::new();
        let mut p = StreamingRequestParser::new();
        let consumed = match p.feed(&mut parsed, wire.data()) {
            FeedResult::Done { consumed } => consumed,
            _ => panic!("server parser did not complete on writer output"),
        };
        assert_eq!(parsed.method(), Method::Post);
        assert_eq!(parsed.path(), b"/up?x=1");
        assert_eq!(parsed.header(b"Host"), Some(b"example.com:8080".as_slice()));
        assert_eq!(parsed.header(b"X-Tag"), Some(b"probe".as_slice()));
        assert_eq!(parsed.header(b"Accept"), Some(b"*/*".as_slice()));
        assert_eq!(parsed.content_length(), 5);
        assert_eq!(&wire.data()[consumed..], b"hello", "body follows the head");
    }

    #[test]
    fn get_shape_no_cl_no_connection() {
        let wire = serialize_request(&FetchRequest::get(b"h", b"/"));
        let s = wire.data();
        assert!(s.starts_with(b"GET / HTTP/1.1\r\nHost: h\r\n"));
        assert!(s.ends_with(b"\r\n\r\n"));
        assert!(!s.windows(14).any(|w| w == b"Content-Length"), "no CL without body");
        assert!(!s.windows(10).any(|w| w == b"Connection"), "keep-alive implicit");
    }

    #[test]
    fn close_optin_emits_connection_close() {
        let mut req = FetchRequest::get(b"h", b"/x");
        req.close = true;
        let wire = serialize_request(&req);
        let s = wire.data();
        assert!(
            s.windows(19).any(|w| w == b"Connection: close\r\n"),
            "close opt-in must be on the wire",
        );
    }

    #[test]
    fn empty_body_still_emits_cl_zero() {
        let req = FetchRequest {
            method: b"POST",
            path: b"/p",
            host: b"h",
            headers: &[],
            body: Some(b""),
            close: false,
        };
        let wire = serialize_request(&req);
        assert!(wire.data().windows(21).any(|w| w == b"Content-Length: 0\r\n\r\n"));
    }
}

#[cfg(test)]
mod body_reader_tests {
    use super::*;
    use crate::stream::HttpStream;
    use alloc::collections::VecDeque;
    use alloc::rc::Rc;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use iobuf::{IOBufChain, RecvChunkGuard};

    /// Pre-canned chunk transport, mirroring the serve_conn tests'
    /// MockStream: `None` entries (and exhaustion) signal EOF.
    struct MockStream {
        chunks: Rc<RefCell<VecDeque<Option<Vec<u8>>>>>,
        sent: Rc<RefCell<Vec<u8>>>,
    }

    impl HttpStream for MockStream {
        async fn recv_chunk(&mut self) -> Option<RecvChunkGuard<'_>> {
            match self.chunks.borrow_mut().pop_front() {
                Some(Some(bytes)) => Some(RecvChunkGuard::new(IOBuf::from(bytes))),
                Some(None) | None => None,
            }
        }
        async fn send(&mut self, chain: &mut IOBufChain) -> Result<(), ()> {
            let mut sent = self.sent.borrow_mut();
            while let Some(part) = chain.pop_front() {
                sent.extend_from_slice(part.data());
            }
            Ok(())
        }
    }

    fn mock(chunks: Vec<Option<Vec<u8>>>) -> (MockStream, Rc<RefCell<Vec<u8>>>) {
        let sent = Rc::new(RefCell::new(Vec::new()));
        (
            MockStream {
                chunks: Rc::new(RefCell::new(VecDeque::from(chunks))),
                sent: Rc::clone(&sent),
            },
            sent,
        )
    }

    /// Single-poll executor — every mock future resolves on first poll.
    fn block_on<F: Future>(mut fut: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` is a local that is not moved after this pin.
        let fut = unsafe { Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("test future pended unexpectedly"),
        }
    }

    #[test]
    fn content_length_spans_prebuf_and_stream() {
        let (mut s, _) = mock(alloc::vec![Some(b"world".to_vec()), None]);
        let prebuf = Some(IOBuf::from(b"hello ".to_vec()));
        let mut r = ClientBodyReader::new(&mut s, prebuf, BodyFraming::ContentLength(11));
        let out = block_on(r.read_to_vec(64)).unwrap();
        assert_eq!(out, b"hello world");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn content_length_truncation_is_an_error() {
        let (mut s, _) = mock(alloc::vec![Some(b"par".to_vec()), None]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::ContentLength(10));
        assert_eq!(block_on(r.read_to_vec(64)).unwrap_err(), BodyError::Truncated);
    }

    #[test]
    fn content_length_straddle_drops_pipelined_tail() {
        // Chunk carries 4 body bytes + the next response's head.
        let (mut s, _) = mock(alloc::vec![Some(b"BODYHTTP/1.1 200 OK\r\n".to_vec()), None]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::ContentLength(4));
        let out = block_on(r.read_to_vec(64)).unwrap();
        assert_eq!(out, b"BODY");
    }

    #[test]
    fn chunked_across_transport_chunks() {
        // The encoded body split at awkward points.
        let (mut s, _) = mock(alloc::vec![
            Some(b"4\r".to_vec()),
            Some(b"\nWi".to_vec()),
            Some(b"ki\r\n0\r".to_vec()),
            Some(b"\n\r\n".to_vec()),
            None,
        ]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::Chunked);
        let out = block_on(r.read_to_vec(64)).unwrap();
        assert_eq!(out, b"Wiki");
        // Clean end afterwards.
        assert!(block_on(r.next_chunk()).unwrap().is_none());
    }

    #[test]
    fn chunked_truncation_is_an_error() {
        let (mut s, _) = mock(alloc::vec![Some(b"4\r\nWi".to_vec()), None]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::Chunked);
        assert_eq!(block_on(r.read_to_vec(64)).unwrap_err(), BodyError::Truncated);
    }

    #[test]
    fn read_to_eof_consumes_until_close() {
        let (mut s, _) = mock(alloc::vec![
            Some(b"part-one;".to_vec()),
            Some(b"part-two".to_vec()),
            None,
        ]);
        let prebuf = Some(IOBuf::from(b"head-tail;".to_vec()));
        let mut r = ClientBodyReader::new(&mut s, prebuf, BodyFraming::ReadToEof);
        let out = block_on(r.read_to_vec(64)).unwrap();
        assert_eq!(out, b"head-tail;part-one;part-two");
    }

    #[test]
    fn no_body_yields_nothing() {
        let (mut s, _) = mock(alloc::vec![None]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::NoBody);
        assert!(block_on(r.next_chunk()).unwrap().is_none());
    }

    #[test]
    fn read_to_vec_cap_is_enforced() {
        let (mut s, _) = mock(alloc::vec![Some(alloc::vec![b'x'; 100]), None]);
        let mut r = ClientBodyReader::new(&mut s, None, BodyFraming::ContentLength(100));
        assert_eq!(block_on(r.read_to_vec(50)).unwrap_err(), BodyError::TooLarge);
    }

    /// End-to-end over the mock transport: http1_fetch sends the
    /// request and parses head + body off pre-canned wire bytes.
    #[test]
    fn http1_fetch_end_to_end_over_mock() {
        let (mut s, sent) = mock(alloc::vec![
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Tag: t\r\n\r\nhello".to_vec()),
            Some(b" world".to_vec()),
            None,
        ]);
        let out = block_on(async {
            let req = FetchRequest::get(b"unit.test", b"/hello");
            let (head, mut body) = http1_fetch(&mut s, &req).await.unwrap();
            assert_eq!(head.status, 200);
            assert_eq!(head.header(b"x-tag"), Some(b"t".as_slice()));
            body.read_to_vec(64).await.unwrap()
        });
        assert_eq!(out, b"hello world");
        let sent = sent.borrow();
        assert!(sent.starts_with(b"GET /hello HTTP/1.1\r\nHost: unit.test\r\n"));
    }

    /// Head split across transport chunks, body chunked.
    #[test]
    fn http1_fetch_split_head_then_chunked_body() {
        let (mut s, _) = mock(alloc::vec![
            Some(b"HTTP/1.1 200".to_vec()),
            Some(b" OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWi".to_vec()),
            Some(b"ki\r\n0\r\n\r\n".to_vec()),
            None,
        ]);
        let out = block_on(async {
            let req = FetchRequest::get(b"unit.test", b"/c");
            let (head, mut body) = http1_fetch(&mut s, &req).await.unwrap();
            assert!(head.transfer_encoding_chunked());
            body.read_to_vec(64).await.unwrap()
        });
        assert_eq!(out, b"Wiki");
    }

    #[test]
    fn http1_fetch_rejects_interim_and_garbage() {
        let (mut s, _) = mock(alloc::vec![
            Some(b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()),
            None,
        ]);
        let err = block_on(async {
            http1_fetch(&mut s, &FetchRequest::get(b"h", b"/")).await.err()
        });
        assert!(matches!(err, Some(FetchError::Interim)));

        let (mut s, _) = mock(alloc::vec![Some(b"SSH-2.0-OpenSSH\r\n".to_vec()), None]);
        let err = block_on(async {
            http1_fetch(&mut s, &FetchRequest::get(b"h", b"/")).await.err()
        });
        assert!(matches!(err, Some(FetchError::Parse(_))));

        let (mut s, _) = mock(alloc::vec![None]);
        let err = block_on(async {
            http1_fetch(&mut s, &FetchRequest::get(b"h", b"/")).await.err()
        });
        assert!(matches!(err, Some(FetchError::ClosedBeforeResponse)));
    }
}
