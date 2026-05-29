// crates/proto/http/src/diag.rs — observability for the HTTP/1.1 server.
//
// The observability doctrine (`docs/observability.md`) applied to
// the HTTP/1.1 keep-alive loop (`serve_conn`). HTTP/1.1 had zero
// diagnostics: a connection that timed out, overflowed its parse
// buffer, or got a `400` for a smuggling-shaped request left no
// trace at all.
//
// `Counters` plus `LAST_REJECT` close that. Surfaced as the
// `"http"` block of `/obs` via `write_obs_json`. `http` builds on
// the host and the app links it directly, so — like `tls` /
// `http3` — no `waitless_backend` seam is needed.

use core::fmt;

use obs::{Counter, LastEvent, ObsRecord};

use crate::{Method, Request};

/// One counter per HTTP/1.1 connection / request lifecycle event.
/// Field names are the stable tokens; a counter and the line that
/// bumps it share a name so a grep lands on both.
pub struct Counters {
    /// One per accepted connection that entered `serve_conn`.
    pub connections_served: Counter,
    /// One complete request HEAD parsed (status line + headers
    /// terminated by `\r\n\r\n`). Pipelined requests each bump.
    pub requests_parsed: Counter,
    /// One response shipped to the wire without a transport error.
    pub responses_sent: Counter,
    /// A request the parser flagged malformed — today only
    /// `Transfer-Encoding: chunked`, which we don't frame yet and
    /// must not mis-frame (a request-smuggling vector). Answered
    /// `400 Bad Request` + `Connection: close`. Read `LAST_REJECT`
    /// for the offending path; subset of `requests_parsed`.
    pub requests_rejected: Counter,
    /// The streaming parser's per-request HEAD-bytes cap
    /// (`streaming::MAX_HEAD_BYTES`, 16 KiB) fired before the
    /// `\r\n\r\n` terminator arrived. Either the peer sent a HEAD
    /// genuinely larger than the cap, or — the DoS shape — the peer
    /// streamed bytes that never contained a state-terminating
    /// delimiter. The connection is dropped.
    pub header_buffer_overflow: Counter,
    /// The handler left body bytes unread and draining them off
    /// the transport stream failed (an error mid-body). The
    /// connection is dropped — its keep-alive position can no
    /// longer be trusted to sit at the next request boundary.
    pub body_drain_failed: Counter,
    /// `stream.send` of a response returned `Err` — the transport
    /// (TCP / TLS) failed mid-write. The connection is dropped.
    pub send_failed: Counter,
    /// A connection hit the 30 s keep-alive idle timeout with no
    /// inbound data and was torn down.
    pub idle_timeout: Counter,
    /// `recv` returned 0 — the peer closed, or a fatal recv error.
    /// The ordinary end of a keep-alive connection.
    pub peer_eof: Counter,
    /// Cumulative cycles in `StreamingRequestParser::feed` — the HEAD
    /// parse cost. Per-stage profiling (cf. `RUNTIME_CYCLES`); divide
    /// by `requests_parsed` for cy/req. Sums across cores (a single
    /// shared atomic — per-request frequency, not per-packet, so
    /// uncontended-enough to not perturb the measurement).
    pub parse_cycles: Counter,
    /// Cumulative cycles in the handler call (`(*handler)(..).await`).
    /// For sync handlers like `/health` this is the handler body; an
    /// awaiting handler would fold its park time in here (so this is
    /// only a clean CPU figure for non-awaiting handlers).
    pub handler_cycles: Counter,
    /// Cumulative cycles building the response wire bytes
    /// (`write_response_into_iobuf` + body-part chaining).
    pub build_cycles: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            connections_served: Counter::new(),
            requests_parsed: Counter::new(),
            responses_sent: Counter::new(),
            requests_rejected: Counter::new(),
            header_buffer_overflow: Counter::new(),
            body_drain_failed: Counter::new(),
            send_failed: Counter::new(),
            idle_timeout: Counter::new(),
            peer_eof: Counter::new(),
            parse_cycles: Counter::new(),
            handler_cycles: Counter::new(),
            build_cycles: Counter::new(),
        }
    }
}

/// Process-wide HTTP/1.1 counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent rejected request — the method + path that drew a
/// hard `400`. Retained so a smuggling-shaped request that drove a
/// `400` is identifiable after the fact.
pub static LAST_REJECT: LastEvent<RejectRecord> = LastEvent::new();

/// Longest request path retained in a `RejectRecord`. A rejected
/// request's path prefix is enough to identify the client / route;
/// the parser's own path buffer is 256 B, so this truncates.
const PATH_CAP: usize = 128;

/// Snapshot payload for `LAST_REJECT`.
#[derive(Clone, Copy)]
pub struct RejectRecord {
    /// Request method as a stable token.
    method: &'static str,
    /// Request-target path bytes, truncated to `PATH_CAP`.
    path: [u8; PATH_CAP],
    /// Valid length of `path`.
    path_len: u16,
}

impl ObsRecord for RejectRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"method\":\"{}\",\"path\":\"", self.method)?;
        write_json_escaped(w, &self.path[..self.path_len as usize])?;
        w.write_str("\"")
    }
}

/// Write `bytes` as the contents of a JSON string — control bytes
/// and the two structural characters escaped. A request path is
/// attacker-controlled, so it cannot be interpolated raw.
fn write_json_escaped(w: &mut dyn fmt::Write, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        match b {
            b'"' => w.write_str("\\\"")?,
            b'\\' => w.write_str("\\\\")?,
            0x20..=0x7e => w.write_char(b as char)?,
            _ => write!(w, "\\u{b:04x}")?,
        }
    }
    Ok(())
}

/// Stable token for a request `Method`.
fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Head => "HEAD",
        Method::Unknown => "UNKNOWN",
    }
}

/// Record a rejected request: bump `requests_rejected` and snapshot
/// the method + path into `LAST_REJECT`. Called by `serve_conn`
/// when the parser sets `Request::reject`.
pub fn record_reject(req: &Request) {
    COUNTERS.requests_rejected.bump();
    let path = req.path();
    let n = path.len().min(PATH_CAP);
    let mut buf = [0u8; PATH_CAP];
    buf[..n].copy_from_slice(&path[..n]);
    LAST_REJECT.record(RejectRecord {
        method: method_str(req.method),
        path: buf,
        path_len: n as u16,
    });
}

/// Counter `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 12] {
    let c = &COUNTERS;
    [
        ("connections_served", c.connections_served.get()),
        ("requests_parsed", c.requests_parsed.get()),
        ("responses_sent", c.responses_sent.get()),
        ("requests_rejected", c.requests_rejected.get()),
        ("header_buffer_overflow", c.header_buffer_overflow.get()),
        ("body_drain_failed", c.body_drain_failed.get()),
        ("send_failed", c.send_failed.get()),
        ("idle_timeout", c.idle_timeout.get()),
        ("peer_eof", c.peer_eof.get()),
        ("parse_cycles", c.parse_cycles.get()),
        ("handler_cycles", c.handler_cycles.get()),
        ("build_cycles", c.build_cycles.get()),
    ]
}

/// Render the HTTP/1.1 observability block as a JSON object — every
/// counter flat, then the `LAST_REJECT` snapshot. This is http's
/// `/obs` block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_REJECT.write_json(w, "last_reject")?;
    w.write_str("}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn write_obs_json_is_one_object() {
        let mut s = String::new();
        write_obs_json(&mut s).unwrap();
        assert!(s.starts_with('{') && s.ends_with('}'));
        assert!(s.contains("\"connections_served\":"));
        assert!(s.contains("\"last_reject\":{\"count\":"));
    }

    #[test]
    fn record_reject_populates_last_reject() {
        let (before, _) = LAST_REJECT.snapshot();
        let rejected = COUNTERS.requests_rejected.get();
        let mut req = Request::new();
        req.method = Method::Post;
        req.set_path(b"/upload");
        record_reject(&req);
        let (count, last) = LAST_REJECT.snapshot();
        assert_eq!(count, before + 1);
        assert_eq!(COUNTERS.requests_rejected.get(), rejected + 1);
        let rec = last.expect("recorded");
        assert_eq!(rec.method, "POST");
        assert_eq!(&rec.path[..rec.path_len as usize], b"/upload");
    }

    #[test]
    fn reject_path_is_json_escaped() {
        let mut s = String::new();
        write_json_escaped(&mut s, b"/a\"b\\c\x01").unwrap();
        assert_eq!(s, "/a\\\"b\\\\c\\u0001");
    }
}
