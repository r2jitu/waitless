// uni-http3/src/diag.rs — observability for the HTTP/3 server.
//
// Mirrors the shape of `uni-quic::diag`: typed atomic counters
// for every drop reason and lifecycle event, plus `h3_drop!` /
// `h3_event!` macros gated by a runtime log level. Default level
// is `Drops`; override via the `h3.log=silent|drops|events` token
// in `uni::boot_info().boot_args`. Counters are always live so a
// future stats endpoint can dump them.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Per-server-counter struct. Fields are named to match the
/// `h3_drop!` / `h3_event!` reason argument exactly so a grep
/// for the log line lands on the counter and vice versa.
pub struct Counters {
    /// One peer-initiated bidi (request) stream entered
    /// `handle_request`. Bumps once per HTTP/3 request received.
    pub requests_received: AtomicU64,
    /// `handle_request` reached the response-write step
    /// (handler returned a Response). The handler may still take
    /// time to ship its bytes, but the H3 layer's job is done.
    pub requests_handled: AtomicU64,
    /// Request stream got `RECV_CAP` worth of bytes before a
    /// complete frame could be parsed — body too big or framing
    /// junk. We close the stream to free reaper conditions.
    pub recv_buffer_overflow: AtomicU64,
    /// `frame::parse_frame` returned a non-Truncated error —
    /// frame type / length is malformed, peer is buggy or this
    /// isn't really HTTP/3 traffic.
    pub frame_parse_error: AtomicU64,
    /// Stream FIN'd (eof) but no HEADERS frame ever arrived. A
    /// well-formed HTTP/3 request MUST have HEADERS, so this is
    /// usually a peer bug.
    pub no_headers_seen: AtomicU64,
    /// QPACK decode of the HEADERS frame body failed —
    /// truncated, dynamic-table reference we can't resolve
    /// (we negotiated capacity 0 so this should never fire),
    /// or malformed Huffman.
    pub qpack_decode_error: AtomicU64,
    /// One server-initiated stream-level write. Most apps emit
    /// 1–2 of these per request (HEADERS + DATA combined into
    /// a single send_fin call); deviations from that ratio
    /// hint at unusual handler shapes.
    pub responses_sent: AtomicU64,
    /// One uni stream the peer opened (control / qpack
    /// encoder / qpack decoder). We don't actively drain
    /// these; bytes accumulate harmlessly in their recv
    /// buffer. Bumps once per peer uni stream observed.
    pub peer_uni_streams_seen: AtomicU64,
    /// One bidi peer stream that we don't recognize as a
    /// request (id & 0x3 != 0). Shouldn't happen — clients
    /// never initiate server-style bidi.
    pub unexpected_bidi: AtomicU64,
    /// `handle_request` finished its read loop (received FIN +
    /// HEADERS frame). Pair with `requests_received` — the gap
    /// between is "stuck inside the read loop".
    pub read_loop_completed: AtomicU64,
    /// QPACK decode succeeded and we're about to call the user
    /// handler. Pair with `read_loop_completed` — the gap is
    /// "stuck during request building / QPACK decode" (rare;
    /// QPACK is sync).
    pub user_handler_invoked: AtomicU64,
    /// User handler returned a Response. Pair with
    /// `user_handler_invoked` — the gap is "stuck inside the
    /// user handler future".
    pub user_handler_returned: AtomicU64,
    /// `write_response` returned. The gap from
    /// `user_handler_returned` is "stuck inside the QUIC send
    /// path" (flush_outbound, sock.send_to, etc.).
    pub write_response_completed: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            requests_received: AtomicU64::new(0),
            requests_handled: AtomicU64::new(0),
            recv_buffer_overflow: AtomicU64::new(0),
            frame_parse_error: AtomicU64::new(0),
            no_headers_seen: AtomicU64::new(0),
            qpack_decode_error: AtomicU64::new(0),
            responses_sent: AtomicU64::new(0),
            peer_uni_streams_seen: AtomicU64::new(0),
            unexpected_bidi: AtomicU64::new(0),
            read_loop_completed: AtomicU64::new(0),
            user_handler_invoked: AtomicU64::new(0),
            user_handler_returned: AtomicU64::new(0),
            write_response_completed: AtomicU64::new(0),
        }
    }
}

pub static COUNTERS: Counters = Counters::new();

#[inline]
pub fn bump(field: &AtomicU64) {
    field.fetch_add(1, Ordering::Relaxed);
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
static LEVEL_INIT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

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
    if !uni::boot_info::is_initialized() {
        LEVEL_INIT.store(true, Ordering::Relaxed);
        return;
    }
    let args = uni::boot_info().boot_args;
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

pub fn snapshot() -> [(&'static str, u64); 13] {
    let c = &COUNTERS;
    [
        ("requests_received", c.requests_received.load(Ordering::Relaxed)),
        ("requests_handled", c.requests_handled.load(Ordering::Relaxed)),
        ("recv_buffer_overflow", c.recv_buffer_overflow.load(Ordering::Relaxed)),
        ("frame_parse_error", c.frame_parse_error.load(Ordering::Relaxed)),
        ("no_headers_seen", c.no_headers_seen.load(Ordering::Relaxed)),
        ("qpack_decode_error", c.qpack_decode_error.load(Ordering::Relaxed)),
        ("responses_sent", c.responses_sent.load(Ordering::Relaxed)),
        ("peer_uni_streams_seen", c.peer_uni_streams_seen.load(Ordering::Relaxed)),
        ("unexpected_bidi", c.unexpected_bidi.load(Ordering::Relaxed)),
        ("read_loop_completed", c.read_loop_completed.load(Ordering::Relaxed)),
        ("user_handler_invoked", c.user_handler_invoked.load(Ordering::Relaxed)),
        ("user_handler_returned", c.user_handler_returned.load(Ordering::Relaxed)),
        ("write_response_completed", c.write_response_completed.load(Ordering::Relaxed)),
    ]
}

// ── Macros ──────────────────────────────────────────────────────

/// Drop-site macro: bumps the counter, optionally logs.
#[macro_export]
macro_rules! h3_drop {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$field);
        if $crate::diag::should_log_drop() {
            uni::println!("[h3-drop {}] {}", stringify!($field),
                ::core::format_args!($($arg)*));
        }
    }};
}

/// Event-site macro: bumps the counter, optionally logs at
/// `Events` level (a step above `Drops`).
#[macro_export]
macro_rules! h3_event {
    ($field:ident, $($arg:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$field);
        if $crate::diag::should_log_event() {
            uni::println!("[h3-event {}] {}", stringify!($field),
                ::core::format_args!($($arg)*));
        }
    }};
}
