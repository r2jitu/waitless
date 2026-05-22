// crates/proto/http3/src/diag.rs — observability for the HTTP/3 server.
//
// HTTP/3 under the observability doctrine (`docs/observability.md`).
// Counters use the shared `obs::Counter`; `h3_drop!` / `h3_event!`
// wrap the drop / lifecycle sites (gated by a runtime log level —
// default `Drops`, override via the `h3.log=silent|drops|events`
// boot-arg token). `h3_drop!` also records `LAST_DROP`. Surfaced as
// the `"http3"` block of `/obs` via `write_obs_json`; http3 builds
// on the host and the app links it directly, so no seam is needed.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use obs::{Counter, LastEvent, ObsRecord};

/// One counter per HTTP/3 drop reason / lifecycle event. Field names
/// match the `h3_drop!` / `h3_event!` reason argument exactly so a
/// grep for the log line lands on the counter and vice versa.
pub struct Counters {
    /// One peer-initiated bidi (request) stream entered
    /// `handle_request`. Bumps once per HTTP/3 request received.
    pub requests_received: Counter,
    /// `handle_request` reached the response-write step
    /// (handler returned a Response). The handler may still take
    /// time to ship its bytes, but the H3 layer's job is done.
    pub requests_handled: Counter,
    /// Request stream got `RECV_CAP` worth of bytes before a
    /// complete frame could be parsed — body too big or framing
    /// junk. We close the stream to free reaper conditions.
    pub recv_buffer_overflow: Counter,
    /// `frame::parse_frame` returned a non-Truncated error —
    /// frame type / length is malformed, peer is buggy or this
    /// isn't really HTTP/3 traffic.
    pub frame_parse_error: Counter,
    /// Stream FIN'd (eof) but no HEADERS frame ever arrived. A
    /// well-formed HTTP/3 request MUST have HEADERS, so this is
    /// usually a peer bug.
    pub no_headers_seen: Counter,
    /// QPACK decode of the HEADERS frame body failed —
    /// truncated, dynamic-table reference we can't resolve
    /// (we negotiated capacity 0 so this should never fire),
    /// or malformed Huffman.
    pub qpack_decode_error: Counter,
    /// QPACK encode of the response header section overflowed
    /// the per-request reserve (`QPACK_BODY_RESERVE`). Should
    /// not fire for our 3-header response shape; if it does,
    /// either a content-type is unusually long or
    /// `with_header` added enough custom headers to exceed
    /// the reserve. Bump `QPACK_BODY_RESERVE` if this counter
    /// stays nonzero in production.
    pub qpack_encode_overflow: Counter,
    /// One server-initiated stream-level write. Most apps emit
    /// 1–2 of these per request (HEADERS + DATA combined into
    /// a single send_fin call); deviations from that ratio
    /// hint at unusual handler shapes.
    pub responses_sent: Counter,
    /// One uni stream the peer opened (control / qpack
    /// encoder / qpack decoder). We don't actively drain
    /// these; bytes accumulate harmlessly in their recv
    /// buffer. Bumps once per peer uni stream observed.
    pub peer_uni_streams_seen: Counter,
    /// One bidi peer stream that we don't recognize as a
    /// request (id & 0x3 != 0). Shouldn't happen — clients
    /// never initiate server-style bidi.
    pub unexpected_bidi: Counter,
    /// `handle_request` finished its read loop (received FIN +
    /// HEADERS frame). Pair with `requests_received` — the gap
    /// between is "stuck inside the read loop".
    pub read_loop_completed: Counter,
    /// QPACK decode succeeded and we're about to call the user
    /// handler. Pair with `read_loop_completed` — the gap is
    /// "stuck during request building / QPACK decode" (rare;
    /// QPACK is sync).
    pub user_handler_invoked: Counter,
    /// User handler returned a Response. Pair with
    /// `user_handler_invoked` — the gap is "stuck inside the
    /// user handler future".
    pub user_handler_returned: Counter,
    /// `write_response` returned. The gap from
    /// `user_handler_returned` is "stuck inside the QUIC send
    /// path" (flush_outbound, sock.send_to, etc.).
    pub write_response_completed: Counter,
    /// First poll of the user handler future entered the closure
    /// body (bumped synchronously inside the future before any
    /// await). A gap from `user_handler_invoked` means the
    /// handler future was constructed but never actually polled
    /// — i.e. the handle_conn task is suspended somewhere
    /// between `handler(req)` and the first `.await` poll of
    /// the resulting future.
    pub user_handler_polled: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            requests_received: Counter::new(),
            requests_handled: Counter::new(),
            recv_buffer_overflow: Counter::new(),
            frame_parse_error: Counter::new(),
            no_headers_seen: Counter::new(),
            qpack_decode_error: Counter::new(),
            qpack_encode_overflow: Counter::new(),
            responses_sent: Counter::new(),
            peer_uni_streams_seen: Counter::new(),
            unexpected_bidi: Counter::new(),
            read_loop_completed: Counter::new(),
            user_handler_invoked: Counter::new(),
            user_handler_returned: Counter::new(),
            write_response_completed: Counter::new(),
            user_handler_polled: Counter::new(),
        }
    }
}

/// Process-wide HTTP/3 counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent `h3_drop!` site — which drop fired last, retained
/// even when serial logging is off.
pub static LAST_DROP: LastEvent<DropRecord> = LastEvent::new();

/// Snapshot payload for `LAST_DROP`.
#[derive(Clone, Copy)]
pub struct DropRecord {
    /// The `h3_drop!` reason — a counter field name.
    pub reason: &'static str,
}

impl ObsRecord for DropRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"reason\":\"{}\"", self.reason)
    }
}

/// Record an `h3_drop!` site into `LAST_DROP`. Called by the macro.
pub fn record_drop(reason: &'static str) {
    LAST_DROP.record(DropRecord { reason });
}

// ── Log-level gating ────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Silent = 0,
    Drops = 1,
    Events = 2,
}

const LEVEL_DEFAULT: u8 = LogLevel::Drops as u8;
static LEVEL: AtomicU8 = AtomicU8::new(LEVEL_DEFAULT);
static LEVEL_INIT: AtomicBool = AtomicBool::new(false);

pub fn set_log_level(level: LogLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
    LEVEL_INIT.store(true, Ordering::Relaxed);
}

pub fn log_level() -> LogLevel {
    match LEVEL.load(Ordering::Relaxed) {
        0 => LogLevel::Silent,
        2 => LogLevel::Events,
        _ => LogLevel::Drops,
    }
}

fn init_from_boot_args() {
    if !waitless::boot_info::is_initialized() {
        LEVEL_INIT.store(true, Ordering::Relaxed);
        return;
    }
    let args = waitless::boot_info().boot_args;
    for tok in args.split_whitespace() {
        if let Some(v) = tok.strip_prefix("h3.log=") {
            let lvl = match v {
                "silent" | "off" | "0" => LogLevel::Silent as u8,
                "drops" | "1" => LogLevel::Drops as u8,
                "events" | "verbose" | "2" => LogLevel::Events as u8,
                _ => continue,
            };
            LEVEL.store(lvl, Ordering::Relaxed);
        }
    }
    LEVEL_INIT.store(true, Ordering::Relaxed);
}

#[inline]
pub fn should_log_drop() -> bool {
    if !LEVEL_INIT.load(Ordering::Relaxed) {
        init_from_boot_args();
    }
    LEVEL.load(Ordering::Relaxed) >= LogLevel::Drops as u8
}

#[inline]
pub fn should_log_event() -> bool {
    if !LEVEL_INIT.load(Ordering::Relaxed) {
        init_from_boot_args();
    }
    LEVEL.load(Ordering::Relaxed) >= LogLevel::Events as u8
}

/// Counter `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 15] {
    let c = &COUNTERS;
    [
        ("requests_received", c.requests_received.get()),
        ("requests_handled", c.requests_handled.get()),
        ("recv_buffer_overflow", c.recv_buffer_overflow.get()),
        ("frame_parse_error", c.frame_parse_error.get()),
        ("no_headers_seen", c.no_headers_seen.get()),
        ("qpack_decode_error", c.qpack_decode_error.get()),
        ("qpack_encode_overflow", c.qpack_encode_overflow.get()),
        ("responses_sent", c.responses_sent.get()),
        ("peer_uni_streams_seen", c.peer_uni_streams_seen.get()),
        ("unexpected_bidi", c.unexpected_bidi.get()),
        ("read_loop_completed", c.read_loop_completed.get()),
        ("user_handler_invoked", c.user_handler_invoked.get()),
        ("user_handler_returned", c.user_handler_returned.get()),
        ("write_response_completed", c.write_response_completed.get()),
        ("user_handler_polled", c.user_handler_polled.get()),
    ]
}

/// Render the HTTP/3 observability block as a JSON object — every
/// counter flat, then the `LAST_DROP` snapshot. This is http3's
/// `/obs` block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_DROP.write_json(w, "last_drop")?;
    w.write_str("}")
}

// ── Macros ──────────────────────────────────────────────────────

/// Drop-site macro: bumps the counter, records `LAST_DROP`, and (if
/// the log level allows) logs a single line.
#[macro_export]
macro_rules! h3_drop {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::COUNTERS.$field.bump();
        $crate::diag::record_drop(::core::stringify!($field));
        if $crate::diag::should_log_drop() {
            ::waitless::println!("[h3-drop {}] {}", ::core::stringify!($field),
                ::core::format_args!($($arg)*));
        }
    }};
}

/// Event-site macro: bumps the counter, optionally logs at `Events`
/// level (a step above `Drops`).
#[macro_export]
macro_rules! h3_event {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::COUNTERS.$field.bump();
        if $crate::diag::should_log_event() {
            ::waitless::println!("[h3-event {}] {}", ::core::stringify!($field),
                ::core::format_args!($($arg)*));
        }
    }};
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
        assert!(s.contains("\"requests_received\":"));
        assert!(s.contains("\"last_drop\":{\"count\":"));
    }

    #[test]
    fn record_drop_populates_last_drop() {
        let (before, _) = LAST_DROP.snapshot();
        record_drop("frame_parse_error");
        let (count, last) = LAST_DROP.snapshot();
        assert_eq!(count, before + 1);
        assert_eq!(last.expect("recorded").reason, "frame_parse_error");
    }
}
