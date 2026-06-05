// crates/proto/http2/src/diag.rs — observability for the HTTP/2 server.
//
// HTTP/2 under the observability doctrine (`docs/observability.md`):
// `obs::Counter`s plus a `LAST_DROP` `LastEvent`, surfaced as the
// `"http2"` block of `/obs` via `write_obs_json`. `h2_drop!` /
// `h2_event!` mirror the http3 macros; the log gate is the
// `h2.log=silent|drops|events` boot-arg token (default `drops`).

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use obs::{Counter, LastEvent, ObsRecord};

/// One counter per HTTP/2 lifecycle / drop reason. Field names match
/// the `h2_drop!` / `h2_event!` reason argument so a grep lands on
/// both the log line and the counter.
pub struct Counters {
    /// One H2 connection entered the serve loop (preface accepted).
    pub connections_served: Counter,
    /// A request stream reached END_STREAM and a `Request` was built.
    pub requests_received: Counter,
    /// The user handler returned a `Response` for a request stream.
    pub requests_handled: Counter,
    /// A complete response (HEADERS + DATA + END_STREAM) was flushed.
    pub responses_sent: Counter,
    /// Client connection preface bytes didn't match the RFC 7540 §3.5
    /// magic — not really HTTP/2 traffic; the conn is dropped.
    pub bad_preface: Counter,
    /// A frame header / payload was malformed (bad length, frame on
    /// the wrong stream, etc.) → connection error.
    pub frame_error: Counter,
    /// HPACK decode of a header block failed → COMPRESSION_ERROR.
    pub hpack_error: Counter,
    /// A decompressed header list exceeded
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (H2-2 HPACK-bomb guard).
    pub header_list_too_large: Counter,
    /// A header block (HEADERS + CONTINUATION) exceeded the byte cap
    /// before END_HEADERS (H2-5 CONTINUATION-flood guard).
    pub header_block_too_large: Counter,
    /// A new stream was refused because the concurrent-stream cap was
    /// reached (H2-4 MAX_CONCURRENT_STREAMS enforcement).
    pub stream_refused: Counter,
    /// The connection was torn down for excessive stream resets /
    /// open-then-cancel churn (H2-1 Rapid Reset / CVE-2023-44487).
    pub rapid_reset_abort: Counter,
    /// A flow-control window was violated by the peer → conn error.
    pub flow_control_error: Counter,
    /// A GOAWAY frame was emitted (graceful or error shutdown).
    pub goaway_sent: Counter,
    /// Cumulative cycles in HPACK decode (`hpack.decode` per request
    /// header block). Profiling — divide by `requests_received`.
    pub decode_cycles: Counter,
    /// Cumulative cycles encoding response headers
    /// (`encode_response_headers` per response). Divide by
    /// `responses_sent`.
    pub encode_cycles: Counter,
    /// Cumulative cycles framing responses onto the wire (the
    /// `next_output_frame` drain in `flush`, excluding the send await).
    /// Divide by `responses_sent`.
    pub frame_cycles: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            connections_served: Counter::new(),
            requests_received: Counter::new(),
            requests_handled: Counter::new(),
            responses_sent: Counter::new(),
            bad_preface: Counter::new(),
            frame_error: Counter::new(),
            hpack_error: Counter::new(),
            header_list_too_large: Counter::new(),
            header_block_too_large: Counter::new(),
            stream_refused: Counter::new(),
            rapid_reset_abort: Counter::new(),
            flow_control_error: Counter::new(),
            goaway_sent: Counter::new(),
            decode_cycles: Counter::new(),
            encode_cycles: Counter::new(),
            frame_cycles: Counter::new(),
        }
    }
}

/// Process-wide HTTP/2 counters.
pub static COUNTERS: Counters = Counters::new();

/// Most recent `h2_drop!` site.
pub static LAST_DROP: LastEvent<DropRecord> = LastEvent::new();

/// Snapshot payload for `LAST_DROP`.
#[derive(Clone, Copy)]
pub struct DropRecord {
    pub reason: &'static str,
}

impl ObsRecord for DropRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"reason\":\"{}\"", self.reason)
    }
}

/// Record an `h2_drop!` site into `LAST_DROP`. Called by the macro.
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
        if let Some(v) = tok.strip_prefix("h2.log=") {
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
pub fn snapshot() -> [(&'static str, u64); 16] {
    let c = &COUNTERS;
    [
        ("connections_served", c.connections_served.get()),
        ("requests_received", c.requests_received.get()),
        ("requests_handled", c.requests_handled.get()),
        ("responses_sent", c.responses_sent.get()),
        ("bad_preface", c.bad_preface.get()),
        ("frame_error", c.frame_error.get()),
        ("hpack_error", c.hpack_error.get()),
        ("header_list_too_large", c.header_list_too_large.get()),
        ("header_block_too_large", c.header_block_too_large.get()),
        ("stream_refused", c.stream_refused.get()),
        ("rapid_reset_abort", c.rapid_reset_abort.get()),
        ("flow_control_error", c.flow_control_error.get()),
        ("goaway_sent", c.goaway_sent.get()),
        ("decode_cycles", c.decode_cycles.get()),
        ("encode_cycles", c.encode_cycles.get()),
        ("frame_cycles", c.frame_cycles.get()),
    ]
}

/// Render the HTTP/2 observability block as a JSON object — every
/// counter flat, then the `LAST_DROP` snapshot. This is http2's `/obs`
/// block.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_DROP.write_json(w, "last_drop")?;
    w.write_str("}")
}

// ── Macros ──────────────────────────────────────────────────────

/// Drop-site macro: bump the counter, record `LAST_DROP`, optionally log.
#[macro_export]
macro_rules! h2_drop {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::COUNTERS.$field.bump();
        $crate::diag::record_drop(::core::stringify!($field));
        if $crate::diag::should_log_drop() {
            ::waitless::println!("[h2-drop {}] {}", ::core::stringify!($field),
                ::core::format_args!($($arg)*));
        }
    }};
}

/// Event-site macro: bump the counter, optionally log at `Events` level.
#[macro_export]
macro_rules! h2_event {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::COUNTERS.$field.bump();
        if $crate::diag::should_log_event() {
            ::waitless::println!("[h2-event {}] {}", ::core::stringify!($field),
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
}
