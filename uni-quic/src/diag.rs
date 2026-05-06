// uni-quic/src/diag.rs — observability for the QUIC stack.
//
// Every place in the QUIC stack that historically said "this is bad,
// drop the packet/conn and move on" now goes through `quic_drop!`.
// The macro both:
//
//   1. Increments a typed counter in `Counters` (atomic, lock-free)
//   2. Emits a single-line log via `uni::println!` so the operator can
//      see the failure in real time
//
// `quic_event!` mirrors the same shape for non-failure events worth
// surfacing (new conn allocated, handshake completed, packet sent).
// Together they replace the silent `Err(_) -> drop` and
// `match _ => {}` patterns that turned every QUIC interop bug into
// "client times out 30 seconds later, no idea why".
//
// Cost: each call site is one atomic increment + (gated) one
// `uni::println!`. The println is gated by the runtime log level
// (`LogLevel` below) so benchmark builds pay only the increment.
// Default is `Drops` — failure events log, normal events don't.
// Override via the `quic.log=silent|drops|events` token in
// `uni::boot_info().boot_args`, parsed on first macro invocation.
// The counters are always live so a future `/debug/quic_stats`
// endpoint can dump them on demand without code changes.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// One atomic counter per drop / event reason. Cheap to read in bulk
/// for a stats dump, cheap to increment on the hot path.
///
/// Every field is named to match the `quic_drop!` / `quic_event!`
/// reason argument exactly so a grep for the log line lands on the
/// counter and vice versa.
pub struct Counters {
    // ── Endpoint-side drops (listener_loop) ──────────────────────
    /// Datagram arrived but `extract_dcid` rejected it (truncated /
    /// FIXED_BIT clear / wrong-length DCID). Junk packets, scanners.
    pub no_dcid: AtomicU64,
    /// Long-header non-Initial packet for an unknown DCID — peer
    /// retried with a stale CID, or genuinely random traffic.
    pub unknown_long_header: AtomicU64,
    /// Short-header packet for a CID that doesn't decode to any of
    /// our slots. Routine after a conn has fully closed.
    pub unknown_short_header: AtomicU64,
    /// Slot table is full; new conn refused. If this fires under
    /// normal load the table needs to grow.
    pub slot_table_full: AtomicU64,
    /// `getrandom` failed when minting CID nonce or per-conn seed.
    /// Should be impossible — surface anyway because if it does
    /// happen we'd otherwise silently lose conns.
    pub rng_failed: AtomicU64,

    // ── Conn-side drops (process_one_packet & friends) ───────────
    /// Long-header preamble parse failed (truncated / malformed).
    pub long_header_parse: AtomicU64,
    /// Initial header parse failed AFTER the long-header preamble
    /// (token-length / payload-length varint malformed).
    pub initial_header_parse: AtomicU64,
    /// AEAD decryption failed on an inbound packet. Either the peer
    /// is using stale keys or we derived the wrong ones.
    pub aead_decrypt_failed: AtomicU64,
    /// Inbound frame parser couldn't classify a frame type.
    pub unknown_frame: AtomicU64,
    /// We received a packet at a level we have no keys for (e.g.
    /// 1-RTT before handshake confirms).
    pub bad_state: AtomicU64,
    /// Unspecified wire-format error not covered by a more specific
    /// counter above. Aggregates the long tail so they're at least
    /// visible.
    pub other_wire: AtomicU64,

    // ── TLS-side drops ───────────────────────────────────────────
    /// ClientHello rejected by the parser / validator (missing
    /// x25519, no chacha20 cipher suite, malformed extension, etc.).
    pub unsupported_client: AtomicU64,
    /// TLS internal error not attributable to peer input.
    pub tls_internal: AtomicU64,

    // ── Events (positive signal) ─────────────────────────────────
    /// New conn allocated for an Initial packet.
    pub conns_allocated: AtomicU64,
    /// Initial-DCID lookup hit — the multi-packet ClientHello path
    /// did its job. If this stays at 0 under browser traffic the
    /// fix isn't reaching the right callers.
    pub initial_dcid_hit: AtomicU64,
    /// Handshake completed (Established).
    pub handshakes_completed: AtomicU64,
    /// NewSessionTicket emitted to a client after a fresh
    /// handshake. The client may present this ticket on a later
    /// connection to skip Cert/CV (Phase B) or to send 0-RTT data
    /// (Phase C). Counter rate ≈ rate of fresh handshakes once
    /// resumption support lands; `0` means clients have no path to
    /// resume.
    pub tickets_emitted: AtomicU64,
    /// PSK in ClientHello validated successfully and resumption
    /// went through (server skipped Cert+CV in the response). Ratio
    /// `tickets_accepted / handshakes_completed` ≈ resumption hit
    /// rate.
    pub tickets_accepted: AtomicU64,
    /// 0-RTT (early-data) packet-protection keys derived. Fires
    /// once per resumed handshake before the first 0-RTT packet
    /// can be unprotected.
    pub early_keys_derived: AtomicU64,
    /// Inbound 0-RTT packet successfully unprotected and frames
    /// dispatched. Counter rate = peer's effective 0-RTT request
    /// volume after our acceptance policy.
    pub zero_rtt_accepted: AtomicU64,
    /// Peer-initiated 1-RTT key update (KEY_PHASE bit flipped) that
    /// we successfully decrypted with the next-phase keys, then
    /// rotated. Per RFC 9001 §6 each KU is a once-per-flight event;
    /// browsers / mobile clients rotate every ~thousands of packets,
    /// so under sustained load this counter ticks slowly. A sudden
    /// spike paired with a spike in `aead_decrypt_failed` indicates
    /// a malfunctioning peer or an attacker probing for stale-keys
    /// behavior.
    pub key_updates_accepted: AtomicU64,
    /// 0-RTT packet arrived before we'd derived the early-data recv
    /// keys (multi-packet CH still in flight, OR 0-RTT in its own
    /// datagram that arrived before the CH-completing Initial). The
    /// packet is buffered and replayed when keys land. Common at
    /// connection start; persistent growth indicates the peer keeps
    /// sending undecryptable 0-RTT or our key-derivation is stuck.
    pub zero_rtt_buffered: AtomicU64,
    /// Buffered 0-RTT packets dropped because the handshake
    /// completed without resumption (e.g. peer presented a stale
    /// ticket). Counter equals packets dropped, not connections —
    /// a single peer-rejection can drop several pending packets at
    /// once. Expected to fire briefly after a server reboot when
    /// clients optimistically replay with the previous key's tickets.
    pub zero_rtt_unresumable: AtomicU64,
    /// Connection torn down because no inbound datagram arrived
    /// inside the negotiated `max_idle_timeout` window (RFC 9000
    /// §10.1). Each fire = one slot freed. Sustained growth at idle
    /// is normal hygiene; growth correlated with active traffic
    /// would mean datagrams are getting stuck in the inbox or
    /// `last_recv_us` isn't refreshing — investigate via
    /// `[quic-event idle_timeouts]` log lines.
    pub idle_timeouts: AtomicU64,
    /// One CONNECTION_CLOSE frame was emitted to the peer because
    /// `process_datagram` returned `Err` or the application asked
    /// the conn to close (RFC 9000 §10.2). Lets the peer tear its
    /// state down immediately instead of waiting for its own idle
    /// timer. Each fire = one packet on the wire, then the conn
    /// task exits.
    pub connection_closes_emitted: AtomicU64,
    /// One packet declared lost by the packet-threshold rule
    /// (RFC 9002 §6.1.1: `pn < largest_acked - kPacketThreshold`).
    /// Counter only — we don't yet retransmit the frames that
    /// were in those packets, so on a lossy network handshakes
    /// can stall. Sustained growth on a healthy localhost link
    /// would point at a misordered ACK or an off-by-one in the
    /// detection logic, not real loss.
    pub packets_lost_threshold: AtomicU64,
    /// One packet declared lost by the time-threshold rule
    /// (RFC 9002 §6.1.2): older than the largest acked AND aged
    /// past `max(9/8 * max(SRTT, latest_rtt), kGranularity)`.
    /// Same caveat as `packets_lost_threshold` w.r.t. retx.
    pub packets_lost_time: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            no_dcid: AtomicU64::new(0),
            unknown_long_header: AtomicU64::new(0),
            unknown_short_header: AtomicU64::new(0),
            slot_table_full: AtomicU64::new(0),
            rng_failed: AtomicU64::new(0),
            long_header_parse: AtomicU64::new(0),
            initial_header_parse: AtomicU64::new(0),
            aead_decrypt_failed: AtomicU64::new(0),
            unknown_frame: AtomicU64::new(0),
            bad_state: AtomicU64::new(0),
            other_wire: AtomicU64::new(0),
            unsupported_client: AtomicU64::new(0),
            tls_internal: AtomicU64::new(0),
            conns_allocated: AtomicU64::new(0),
            initial_dcid_hit: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            tickets_emitted: AtomicU64::new(0),
            tickets_accepted: AtomicU64::new(0),
            early_keys_derived: AtomicU64::new(0),
            zero_rtt_accepted: AtomicU64::new(0),
            key_updates_accepted: AtomicU64::new(0),
            zero_rtt_buffered: AtomicU64::new(0),
            zero_rtt_unresumable: AtomicU64::new(0),
            idle_timeouts: AtomicU64::new(0),
            connection_closes_emitted: AtomicU64::new(0),
            packets_lost_threshold: AtomicU64::new(0),
            packets_lost_time: AtomicU64::new(0),
        }
    }
}

/// Process-wide counters. Atomic increment from any worker; reads
/// can be lossy without synchronisation by design (we only need them
/// for diagnostics).
pub static COUNTERS: Counters = Counters::new();

/// Bump a named counter by 1.
#[inline]
pub fn bump(field: &AtomicU64) {
    field.fetch_add(1, Ordering::Relaxed);
}

// ── Log-level gating ────────────────────────────────────────────────
//
// The macros below check this u8 before printing. Counter increments
// are unaffected — they're cheap and always run, so `/debug/quic_stats`
// stays accurate even in `Silent` mode.
//
//   0 = Silent  (counters only; for benchmarks)
//   1 = Drops   (failures only; default — drops are rare on a
//                healthy server, so this is cheap in production)
//   2 = Events  (drops + positive events: conn alloc, handshake
//                done, ticket emit/accept, etc. — for debug)
//
// Stored as AtomicU8 with relaxed ordering. Hot-path access is one
// load + one branch.

/// Public representation of the log level. Apps call
/// `set_log_level(LogLevel::Events)` to enable verbose logging at
/// runtime; the default is `Drops`.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Silent = 0,
    Drops = 1,
    Events = 2,
}

const LEVEL_DEFAULT: u8 = LogLevel::Drops as u8;
static LEVEL: AtomicU8 = AtomicU8::new(LEVEL_DEFAULT);
/// Whether we've parsed `boot_info().boot_args` yet. First macro
/// invocation triggers the parse; subsequent calls hit the cached
/// `LEVEL` directly.
static LEVEL_INIT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Override the log level explicitly. Useful for tests, benchmarks,
/// or when an app wants to force-enable verbose logging without
/// rebooting (e.g. on receipt of a debug command). Stable across
/// concurrent calls; last writer wins.
pub fn set_log_level(level: LogLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
    // Mark "init done" so we don't overwrite the explicit choice
    // with a boot_args parse on the next macro call.
    LEVEL_INIT.store(true, Ordering::Relaxed);
}

/// Current log level. Exposed for tests / a future stats endpoint.
pub fn log_level() -> LogLevel {
    match LEVEL.load(Ordering::Relaxed) {
        0 => LogLevel::Silent,
        2 => LogLevel::Events,
        _ => LogLevel::Drops,
    }
}

/// Internal: parse `boot_info().boot_args` once and cache the
/// resulting level. Looks for the `quic.log=<level>` token (any
/// position in the args string). Unknown tokens are ignored;
/// missing token leaves the default in place.
fn init_from_boot_args() {
    // Boot info is published before app `init()` runs on every
    // backend, so the call here is safe — but we still guard to
    // avoid a panic if some test-only code path runs us before init.
    if !uni::boot_info::is_initialized() {
        LEVEL_INIT.store(true, Ordering::Relaxed);
        return;
    }
    let args = uni::boot_info().boot_args;
    for tok in args.split_whitespace() {
        if let Some(v) = tok.strip_prefix("quic.log=") {
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

/// Should `quic_drop!` print? Internal helper used by the macro
/// expansion. Inline so the cold init path stays out of the hot
/// path's I-cache footprint.
#[inline]
pub fn should_log_drop() -> bool {
    if !LEVEL_INIT.load(Ordering::Relaxed) {
        init_from_boot_args();
    }
    LEVEL.load(Ordering::Relaxed) >= LogLevel::Drops as u8
}

/// Should `quic_event!` print? Same shape as `should_log_drop` but
/// requires `Events` level — drops fire below this threshold.
#[inline]
pub fn should_log_event() -> bool {
    if !LEVEL_INIT.load(Ordering::Relaxed) {
        init_from_boot_args();
    }
    LEVEL.load(Ordering::Relaxed) >= LogLevel::Events as u8
}

/// Snapshot of every counter, for `/debug/quic_stats`-style dumps.
/// Returns `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 27] {
    let c = &COUNTERS;
    [
        ("no_dcid", c.no_dcid.load(Ordering::Relaxed)),
        ("unknown_long_header", c.unknown_long_header.load(Ordering::Relaxed)),
        ("unknown_short_header", c.unknown_short_header.load(Ordering::Relaxed)),
        ("slot_table_full", c.slot_table_full.load(Ordering::Relaxed)),
        ("rng_failed", c.rng_failed.load(Ordering::Relaxed)),
        ("long_header_parse", c.long_header_parse.load(Ordering::Relaxed)),
        ("initial_header_parse", c.initial_header_parse.load(Ordering::Relaxed)),
        ("aead_decrypt_failed", c.aead_decrypt_failed.load(Ordering::Relaxed)),
        ("unknown_frame", c.unknown_frame.load(Ordering::Relaxed)),
        ("bad_state", c.bad_state.load(Ordering::Relaxed)),
        ("other_wire", c.other_wire.load(Ordering::Relaxed)),
        ("unsupported_client", c.unsupported_client.load(Ordering::Relaxed)),
        ("tls_internal", c.tls_internal.load(Ordering::Relaxed)),
        ("conns_allocated", c.conns_allocated.load(Ordering::Relaxed)),
        ("initial_dcid_hit", c.initial_dcid_hit.load(Ordering::Relaxed)),
        ("handshakes_completed", c.handshakes_completed.load(Ordering::Relaxed)),
        ("tickets_emitted", c.tickets_emitted.load(Ordering::Relaxed)),
        ("tickets_accepted", c.tickets_accepted.load(Ordering::Relaxed)),
        ("early_keys_derived", c.early_keys_derived.load(Ordering::Relaxed)),
        ("zero_rtt_accepted", c.zero_rtt_accepted.load(Ordering::Relaxed)),
        ("key_updates_accepted", c.key_updates_accepted.load(Ordering::Relaxed)),
        ("zero_rtt_buffered", c.zero_rtt_buffered.load(Ordering::Relaxed)),
        ("zero_rtt_unresumable", c.zero_rtt_unresumable.load(Ordering::Relaxed)),
        ("idle_timeouts", c.idle_timeouts.load(Ordering::Relaxed)),
        ("connection_closes_emitted", c.connection_closes_emitted.load(Ordering::Relaxed)),
        ("packets_lost_threshold", c.packets_lost_threshold.load(Ordering::Relaxed)),
        ("packets_lost_time", c.packets_lost_time.load(Ordering::Relaxed)),
    ]
}

/// Drop-site macro: increments the named counter and (if the log
/// level allows) logs a single line. Use for "we couldn't continue
/// here, packet/conn is being dropped" — never for normal completion.
///
/// The first arg is the bare counter field name from `Counters`;
/// the rest is `format_args!`-shape detail.
///
/// Counter increments unconditionally; the println is gated by
/// `LogLevel >= Drops` (the default). Benchmark builds set
/// `quic.log=silent` in `boot_args` and pay only the increment.
///
/// Example:
///   `quic_drop!(unsupported_client, "no x25519 in CH key_share");`
#[macro_export]
macro_rules! quic_drop {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        if $crate::diag::should_log_drop() {
            ::uni::println!(
                "[quic-drop {}] {}",
                stringify!($reason),
                ::core::format_args!($($detail)*),
            );
        }
    }};
    ($reason:ident) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        if $crate::diag::should_log_drop() {
            ::uni::println!("[quic-drop {}]", stringify!($reason));
        }
    }};
}

/// Event-site macro: same shape as `quic_drop!` but for positive /
/// progress events. Gated by `LogLevel >= Events` so the default
/// `Drops` level keeps these silent — they're useful for
/// per-handshake debugging but noise during steady-state load.
#[macro_export]
macro_rules! quic_event {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        if $crate::diag::should_log_event() {
            ::uni::println!(
                "[quic-event {}] {}",
                stringify!($reason),
                ::core::format_args!($($detail)*),
            );
        }
    }};
    ($reason:ident) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        if $crate::diag::should_log_event() {
            ::uni::println!("[quic-event {}]", stringify!($reason));
        }
    }};
}
