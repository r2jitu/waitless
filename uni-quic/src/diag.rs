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
// Cost: each call site is one atomic increment + one `uni::println!`.
// In release builds the println goes to the serial console; in
// no-output environments (`UNI_QUIC_QUIET=1` someday — left as a
// follow-up) it can be silenced. The counters are always live so
// `/debug/quic_stats` (also a follow-up) can dump them on demand
// without code changes.

use core::sync::atomic::{AtomicU64, Ordering};

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

/// Snapshot of every counter, for `/debug/quic_stats`-style dumps.
/// Returns `(name, value)` pairs in declaration order.
pub fn snapshot() -> [(&'static str, u64); 16] {
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
    ]
}

/// Drop-site macro: increments the named counter and logs a single
/// line to the serial console with the reason + a caller-supplied
/// detail string. Use for "we couldn't continue here, packet/conn
/// is being dropped" — never for normal completion.
///
/// The first arg is the bare counter field name from `Counters`;
/// the rest is `format_args!`-shape detail.
///
/// Example:
///   `quic_drop!(unsupported_client, "no x25519 in CH key_share");`
#[macro_export]
macro_rules! quic_drop {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        ::uni::println!(
            "[quic-drop {}] {}",
            stringify!($reason),
            ::core::format_args!($($detail)*),
        );
    }};
    ($reason:ident) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        ::uni::println!("[quic-drop {}]", stringify!($reason));
    }};
}

/// Event-site macro: same shape as `quic_drop!` but for positive /
/// progress events. Same logging cost; conceptually distinct so
/// operators can grep `quic-event` vs `quic-drop` separately.
#[macro_export]
macro_rules! quic_event {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        ::uni::println!(
            "[quic-event {}] {}",
            stringify!($reason),
            ::core::format_args!($($detail)*),
        );
    }};
    ($reason:ident) => {{
        $crate::diag::bump(&$crate::diag::COUNTERS.$reason);
        ::uni::println!("[quic-event {}]", stringify!($reason));
    }};
}
