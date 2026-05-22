// crates/proto/quic/src/diag.rs — observability for the QUIC stack.
//
// QUIC is the reference implementation of the observability doctrine
// (`docs/observability.md`). Five things live here:
//
//   1. `Counters` — one `obs::Counter` per drop / event reason.
//      Cheap (relaxed atomic), always live.
//   2. `quic_drop!` / `quic_event!` — macros that wrap every place
//      the stack historically said "this is bad, drop the
//      packet/conn and move on". They bump the counter and (gated
//      by log level) emit a single line, replacing the silent
//      `Err(_) -> drop` and `match _ => {}` patterns.
//   3. `quic_bug!` — for a genuinely unexpected condition (an
//      invariant not holding). Logs to serial UNCONDITIONALLY: a
//      broken assumption is loud, regardless of log level.
//   4. `LastEvent` snapshot slots — `LAST_DROP`, `LAST_BUG`,
//      `LAST_CONN_CLOSE`, `LAST_CONN_EXIT`. A counter says *how
//      many*; a snapshot retains *what the most recent one looked
//      like*, including the invariant inputs you would otherwise
//      have to redeploy to capture. The h3-over-gve bug needed
//      exactly this — the stack counted idle timeouts but discarded
//      the 81 ms `last_recv_age` that proved the timeout spurious.
//   5. `LatencyHist` slots — `REQUEST_LATENCY`, `INBOX_WAIT`. The
//      performance pillar: how long the RX→TX path takes. Sampled
//      on warm paths (per request / per datagram) — sound because
//      a histogram `record` is the cost class of a counter.
//
// Cost: a counter / histogram `record` is a handful of relaxed
// atomics. A `LastEvent` snapshot `record` takes a `Spinlock`, so
// it is COLD PATH ONLY — connection close, conn-task teardown, drop
// sites. Never per packet on a healthy flow. The `quic_drop!`
// println is gated by the runtime
// log level (`LogLevel` below); benchmark builds pay only the
// increment. Default is `Drops` — failure events log, normal
// events don't. Override via the `quic.log=silent|drops|events`
// token in `waitless::boot_info().boot_args`.
//
// Everything here is surfaced via `/quic_stats` and `/obs` without
// a code change — see `write_obs_json`.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use obs::{Counter, LastEvent, LatencyHist, ObsRecord};

/// One counter per drop / event reason. Cheap to read in bulk for a
/// stats dump, cheap to increment on the hot path.
///
/// Every field is named to match the `quic_drop!` / `quic_event!`
/// reason argument exactly so a grep for the log line lands on the
/// counter and vice versa.
pub struct Counters {
    // ── Endpoint-side drops (listener_loop) ──────────────────────
    /// Datagram arrived but `extract_dcid` rejected it (truncated /
    /// FIXED_BIT clear / wrong-length DCID). Junk packets, scanners.
    pub no_dcid: Counter,
    /// Long-header non-Initial packet for an unknown DCID — peer
    /// retried with a stale CID, or genuinely random traffic.
    pub unknown_long_header: Counter,
    /// Short-header packet for a CID that doesn't decode to any of
    /// our slots. Routine after a conn has fully closed.
    pub unknown_short_header: Counter,
    /// Slot table is full; new conn refused. If this fires under
    /// normal load the table needs to grow.
    pub slot_table_full: Counter,
    /// `getrandom` failed when minting CID nonce or per-conn seed.
    /// Should be impossible — surface anyway because if it does
    /// happen we'd otherwise silently lose conns.
    pub rng_failed: Counter,

    // ── Conn-side drops (process_one_packet & friends) ───────────
    /// Long-header preamble parse failed (truncated / malformed).
    pub long_header_parse: Counter,
    /// Initial header parse failed AFTER the long-header preamble
    /// (token-length / payload-length varint malformed).
    pub initial_header_parse: Counter,
    /// AEAD decryption failed on an inbound packet. Either the peer
    /// is using stale keys or we derived the wrong ones.
    pub aead_decrypt_failed: Counter,
    /// Inbound frame parser couldn't classify a frame type.
    pub unknown_frame: Counter,
    /// We received a packet at a level we have no keys for (e.g.
    /// 1-RTT before handshake confirms).
    pub bad_state: Counter,
    /// Late Initial-level packet arrived after we discarded our
    /// Initial keys per RFC 9001 §4.9.1 (first received Handshake
    /// packet from the peer means both sides have moved past
    /// Initial). Counts the harmless straggler retransmits that
    /// previously surfaced as `aead_decrypt_failed` against stale
    /// keys.
    pub late_initial_dropped: Counter,
    /// Mirror of `late_initial_dropped` for Handshake-level
    /// stragglers after we've discarded Handshake keys per RFC
    /// 9001 §4.9.2 (TLS handshake confirmed).
    pub late_handshake_dropped: Counter,
    /// Unspecified wire-format error not covered by a more specific
    /// counter above. Aggregates the long tail so they're at least
    /// visible.
    pub other_wire: Counter,

    // ── TLS-side drops ───────────────────────────────────────────
    /// ClientHello rejected by the parser / validator (missing
    /// x25519, no chacha20 cipher suite, malformed extension, etc.).
    pub unsupported_client: Counter,
    /// TLS internal error not attributable to peer input.
    pub tls_internal: Counter,

    // ── Events (positive signal) ─────────────────────────────────
    /// New conn allocated for an Initial packet.
    pub conns_allocated: Counter,
    /// `Connection`'s `Drop` impl fired. Compare against
    /// `conns_allocated` at shutdown — a non-zero gap means N
    /// connections didn't drop, and their per-stream BTreeMaps,
    /// recv/send pools, and outbound recycle Vecs leak. If
    /// `(conns_allocated - conns_dropped) > 0` after
    /// `drain_all_arenas`, an `Rc<RefCell<Connection>>` is held
    /// somewhere outside the conn-task / user-handler future
    /// pair we expect to cover.
    pub conns_dropped: Counter,
    /// Initial-DCID lookup hit — the multi-packet ClientHello path
    /// did its job. If this stays at 0 under browser traffic the
    /// fix isn't reaching the right callers.
    pub initial_dcid_hit: Counter,
    /// Handshake completed (Established).
    pub handshakes_completed: Counter,
    /// NewSessionTicket emitted to a client after a fresh
    /// handshake. The client may present this ticket on a later
    /// connection to skip Cert/CV (Phase B) or to send 0-RTT data
    /// (Phase C). Counter rate ≈ rate of fresh handshakes once
    /// resumption support lands; `0` means clients have no path to
    /// resume.
    pub tickets_emitted: Counter,
    /// PSK in ClientHello validated successfully and resumption
    /// went through (server skipped Cert+CV in the response). Ratio
    /// `tickets_accepted / handshakes_completed` ≈ resumption hit
    /// rate.
    pub tickets_accepted: Counter,
    /// 0-RTT (early-data) packet-protection keys derived. Fires
    /// once per resumed handshake before the first 0-RTT packet
    /// can be unprotected.
    pub early_keys_derived: Counter,
    /// Inbound 0-RTT packet successfully unprotected and frames
    /// dispatched. Counter rate = peer's effective 0-RTT request
    /// volume after our acceptance policy.
    pub zero_rtt_accepted: Counter,
    /// Peer-initiated 1-RTT key update (KEY_PHASE bit flipped) that
    /// we successfully decrypted with the next-phase keys, then
    /// rotated. Per RFC 9001 §6 each KU is a once-per-flight event;
    /// browsers / mobile clients rotate every ~thousands of packets,
    /// so under sustained load this counter ticks slowly. A sudden
    /// spike paired with a spike in `aead_decrypt_failed` indicates
    /// a malfunctioning peer or an attacker probing for stale-keys
    /// behavior.
    pub key_updates_accepted: Counter,
    /// 0-RTT packet arrived before we'd derived the early-data recv
    /// keys (multi-packet CH still in flight, OR 0-RTT in its own
    /// datagram that arrived before the CH-completing Initial). The
    /// packet is buffered and replayed when keys land. Common at
    /// connection start; persistent growth indicates the peer keeps
    /// sending undecryptable 0-RTT or our key-derivation is stuck.
    pub zero_rtt_buffered: Counter,
    /// Buffered 0-RTT packets dropped because the handshake
    /// completed without resumption (e.g. peer presented a stale
    /// ticket). Counter equals packets dropped, not connections —
    /// a single peer-rejection can drop several pending packets at
    /// once. Expected to fire briefly after a server reboot when
    /// clients optimistically replay with the previous key's tickets.
    pub zero_rtt_unresumable: Counter,
    /// Connection torn down because no inbound datagram arrived
    /// inside the negotiated `max_idle_timeout` window (RFC 9000
    /// §10.1). Each fire = one slot freed, and one conn-task exit
    /// (so `idle_timeouts` is the idle term of `conn_tasks_exited`).
    /// Sustained growth at idle is normal hygiene; growth correlated
    /// with active traffic would mean datagrams are getting stuck
    /// in the inbox or `last_recv_us` isn't refreshing — read
    /// `LAST_CONN_EXIT`, whose `last_recv_age_us` vs `idle_us` is
    /// the exact pair the h3-over-gve bug turned on.
    pub idle_timeouts: Counter,
    /// One CONNECTION_CLOSE frame was emitted to the peer because
    /// `process_datagram` returned `Err` or the application asked
    /// the conn to close (RFC 9000 §10.2). Lets the peer tear its
    /// state down immediately instead of waiting for its own idle
    /// timer. Each fire = one packet on the wire, then the conn
    /// task exits.
    pub connection_closes_emitted: Counter,
    /// One CONNECTION_CLOSE frame was *received* from the peer
    /// (RFC 9000 §19.19, transport or application origin). The peer
    /// asked us to tear down; the conn enters `Failed` and the task
    /// exits via the `conn_task_exit_conn_failed` path. The
    /// error_code / frame_type / reason the peer sent — discarded
    /// before this counter existed — are retained in
    /// `LAST_CONN_CLOSE`.
    pub conn_closes_received: Counter,
    /// One packet declared lost by the packet-threshold rule
    /// (RFC 9002 §6.1.1: `pn < largest_acked - kPacketThreshold`).
    /// Counter only — we don't yet retransmit the frames that
    /// were in those packets, so on a lossy network handshakes
    /// can stall. Sustained growth on a healthy localhost link
    /// would point at a misordered ACK or an off-by-one in the
    /// detection logic, not real loss.
    pub packets_lost_threshold: Counter,
    /// One packet declared lost by the time-threshold rule
    /// (RFC 9002 §6.1.2): older than the largest acked AND aged
    /// past `max(9/8 * max(SRTT, latest_rtt), kGranularity)`.
    /// Same caveat as `packets_lost_threshold` w.r.t. retx.
    pub packets_lost_time: Counter,
    /// One PTO probe packet was emitted because the PTO timer
    /// fired before any ACK confirmed our most-recent ack-eliciting
    /// send (RFC 9002 §6.2). The probe is a PING-only packet at
    /// the level with the oldest unacked send. A bumped counter
    /// without matching `packets_lost_*` growth means the network
    /// is just slow / the peer is briefly unresponsive; a bumped
    /// counter with matching loss growth means real loss.
    pub pto_probes_sent: Counter,
    /// Total RecvStream entries ever created (one per peer-initiated
    /// stream that arrived). Pair with `streams_reaped` to spot a
    /// leak: if `recv_streams_created - streams_reaped` keeps
    /// climbing, some sid is stuck with one side done and the other
    /// dangling — usually a request stream where the handler bailed
    /// without sending a response.
    pub recv_streams_created: Counter,
    /// Total SendStream entries ever created (one per stream the app
    /// or H3 layer wrote to). For HTTP/3 servers each request creates
    /// one of these.
    pub send_streams_created: Counter,
    /// Streams pruned by `reap_finished_streams` after both sides
    /// FIN'd and buffers drained. Should track 1:1 with completed
    /// requests; lag means streams aren't reaching the reapable
    /// state.
    pub streams_reaped: Counter,
    /// Listener tried to push a datagram into a full
    /// `ConnInbox` (DEFAULT_CAPACITY=256) — usually because the
    /// peer is bursting faster than the conn task can drain.
    /// The datagram is dropped on the floor; QUIC retransmit on
    /// the peer's side eventually recovers, manifesting as a
    /// stall followed by `aead_decrypt_failed` lines for late-
    /// arriving stragglers.
    pub inbox_full_drops: Counter,

    // ── Conn-task lifecycle ──────────────────────────────────────
    /// One pass through the per-conn task loop: dequeue (or
    /// timer-fire), process_datagram, flush, drain. A flat
    /// counter that should be ticking continuously while a conn
    /// is alive — if `/quic_stats` shows it frozen for several
    /// seconds, the conn task is wedged (deadlock, runaway
    /// loop, or stuck in send_to). If it's ticking but
    /// throughput is zero, the bottleneck is downstream.
    pub conn_task_iterations: Counter,
    /// One per-connection task reached an exit path, recorded its
    /// `LAST_CONN_EXIT` snapshot, and freed its slot. Converges to
    /// `conns_allocated` as connections close; a persistent gap
    /// means tasks are wedged and not reaching teardown. Equals
    /// `idle_timeouts + conn_task_exit_inbox_closed +
    /// conn_task_exit_process_error + conn_task_exit_conn_failed`
    /// by construction.
    pub conn_tasks_exited: Counter,
    /// Conn task exited because its `ConnInbox` closed (listener
    /// torn down, slot reclaimed) while it was awaiting the next
    /// datagram. Routine at shutdown; growth during steady-state
    /// operation means slots are being reclaimed out from under
    /// live conns.
    pub conn_task_exit_inbox_closed: Counter,
    /// Conn task exited because `process_datagram` returned `Err` —
    /// the task sealed a CONNECTION_CLOSE and tore down. Growth
    /// means inbound traffic is hitting a fatal parse/decrypt
    /// failure; cross-check `LAST_DROP` (what failed last) and
    /// `LAST_CONN_EXIT` (which conn).
    pub conn_task_exit_process_error: Counter,
    /// Conn task exited because the connection entered `Failed`
    /// outside the process-error path — most often a peer
    /// CONNECTION_CLOSE (see `conn_closes_received` + the
    /// `LAST_CONN_CLOSE` detail) or an app-initiated close.
    pub conn_task_exit_conn_failed: Counter,
    /// `QuicConn::recv`'s watchdog fired: a request handler's `recv`
    /// await ran past the 5 s stuck threshold without the stream
    /// making progress. A handler should get data or observe
    /// `Failed` long before that — so each fire is a genuine wedge
    /// (a handler bug, or a stream stuck half-open). Raised via
    /// `quic_bug!`: logged to serial unconditionally, with the sid
    /// and recv-stream state in `LAST_BUG`.
    pub handler_stuck: Counter,

    // ── Flush / datagram throughput ──────────────────────────────
    /// One call to `flush_outbound`. Bumps from both
    /// `process_datagram` (once per inbound datagram) and
    /// `QuicConn::send`/`send_fin` (once per app write).
    pub flush_calls: Counter,
    /// One UDP datagram successfully drained from
    /// `conn.outbound` and handed to `sock.send_to`. Pair with
    /// `flush_calls` to see fan-out (packets-per-flush).
    pub datagrams_sent: Counter,
    /// One inbound datagram processed (parse + dispatch). Pair
    /// with `inbox_full_drops` to see drop ratio under load.
    pub datagrams_processed: Counter,
    /// Outbound datagram suppressed by the anti-amplification
    /// limit (RFC 9000 §8.1.2). Bumps when the path isn't yet
    /// validated and emitting the packet would exceed 3× the
    /// bytes received from the peer. The packet is dropped (not
    /// truncated); the peer treats it as loss and we'll retry
    /// once enough peer bytes accumulate, or once a Handshake
    /// packet arrives and the limit is lifted entirely.
    pub anti_amp_throttled: Counter,
    /// Cumulative AEAD-sealed bytes (payload + frames protected
    /// per packet, before the 16-byte tag). Pair with
    /// `aead_seal_packets` to compute average packet size; pair
    /// with the wall clock to compute encrypt throughput. The
    /// AEAD primitive used is AES-128-GCM (negotiated by
    /// TLS_AES_128_GCM_SHA256, our only ciphersuite).
    pub aead_seal_bytes: Counter,
    /// Number of packets that went through the AEAD seal.
    pub aead_seal_packets: Counter,
    /// Cumulative AEAD-opened bytes on inbound packets. Same
    /// semantics as `aead_seal_bytes` for the RX direction.
    pub aead_open_bytes: Counter,
    /// Number of packets that went through the AEAD open
    /// (successful decrypts only; failed opens bump
    /// `aead_decrypt_failed`).
    pub aead_open_packets: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            no_dcid: Counter::new(),
            unknown_long_header: Counter::new(),
            unknown_short_header: Counter::new(),
            slot_table_full: Counter::new(),
            rng_failed: Counter::new(),
            long_header_parse: Counter::new(),
            initial_header_parse: Counter::new(),
            aead_decrypt_failed: Counter::new(),
            unknown_frame: Counter::new(),
            bad_state: Counter::new(),
            late_initial_dropped: Counter::new(),
            late_handshake_dropped: Counter::new(),
            other_wire: Counter::new(),
            unsupported_client: Counter::new(),
            tls_internal: Counter::new(),
            conns_allocated: Counter::new(),
            conns_dropped: Counter::new(),
            initial_dcid_hit: Counter::new(),
            handshakes_completed: Counter::new(),
            tickets_emitted: Counter::new(),
            tickets_accepted: Counter::new(),
            early_keys_derived: Counter::new(),
            zero_rtt_accepted: Counter::new(),
            key_updates_accepted: Counter::new(),
            zero_rtt_buffered: Counter::new(),
            zero_rtt_unresumable: Counter::new(),
            idle_timeouts: Counter::new(),
            connection_closes_emitted: Counter::new(),
            conn_closes_received: Counter::new(),
            packets_lost_threshold: Counter::new(),
            packets_lost_time: Counter::new(),
            pto_probes_sent: Counter::new(),
            recv_streams_created: Counter::new(),
            send_streams_created: Counter::new(),
            streams_reaped: Counter::new(),
            inbox_full_drops: Counter::new(),
            conn_task_iterations: Counter::new(),
            conn_tasks_exited: Counter::new(),
            conn_task_exit_inbox_closed: Counter::new(),
            conn_task_exit_process_error: Counter::new(),
            conn_task_exit_conn_failed: Counter::new(),
            handler_stuck: Counter::new(),
            flush_calls: Counter::new(),
            datagrams_sent: Counter::new(),
            datagrams_processed: Counter::new(),
            anti_amp_throttled: Counter::new(),
            aead_seal_bytes: Counter::new(),
            aead_seal_packets: Counter::new(),
            aead_open_bytes: Counter::new(),
            aead_open_packets: Counter::new(),
        }
    }
}

/// Process-wide counters. Atomic increment from any worker; reads
/// can be lossy without synchronisation by design (we only need them
/// for diagnostics).
pub static COUNTERS: Counters = Counters::new();

// ── Last-occurrence snapshots ───────────────────────────────────────
//
// Cold-path `LastEvent` slots that retain the decisive context of the
// most recent occurrence of a category — the half of the doctrine a
// bare counter can't supply. Recorded via the helpers below; rendered
// by `write_obs_json`.

/// Most recent failure drop (any `quic_drop!` site). Tells you which
/// drop fired last and when even when serial logging is off.
pub static LAST_DROP: LastEvent<DropRecord> = LastEvent::new();

/// Most recent invariant violation (any `quic_bug!` site). Distinct
/// from `LAST_DROP`: a drop is an *expected* failure, a bug is a
/// *broken assumption*. Check this slot first — a non-zero `count`
/// means a "can't happen" did. The full context is on serial
/// (`quic_bug!` logs unconditionally).
pub static LAST_BUG: LastEvent<DropRecord> = LastEvent::new();

/// Most recent CONNECTION_CLOSE frame *received* from a peer. Holds
/// the error_code / frame_type / reason the frame dispatcher used to
/// discard via `{ .. }`.
pub static LAST_CONN_CLOSE: LastEvent<ConnCloseRecord> = LastEvent::new();

/// Most recent conn-task teardown. Holds the exit reason plus the
/// invariant inputs — `last_recv_age_us` vs `idle_us` — that decide
/// whether an idle-timeout exit was legitimate.
pub static LAST_CONN_EXIT: LastEvent<ConnExitRecord> = LastEvent::new();

// ── Performance histograms (microseconds) ───────────────────────────
//
// The performance pillar (see `docs/observability.md`). `record` is
// the cost class of a `Counter`, so these sample warm paths — per
// request and per datagram — which the failure-pillar `LastEvent`
// slots above never may.

/// RX→TX request service latency: inbound datagram arrival →
/// response FIN encoded. Sampled once per request — a request and
/// its response share a `sid`, so the arrival timestamp threads
/// `Datagram` → `RecvStream` → `SendStream` and the sample fires
/// when the response stream reaches `FinSent`.
pub static REQUEST_LATENCY: LatencyHist = LatencyHist::new();

/// Inbox queue wait: listener `recv_from` → conn-task dequeue.
/// Sampled per datagram; isolates scheduling / queueing delay out
/// of `REQUEST_LATENCY`.
pub static INBOX_WAIT: LatencyHist = LatencyHist::new();

/// Snapshot payload for `LAST_DROP`.
#[derive(Clone, Copy)]
pub struct DropRecord {
    /// The `quic_drop!` reason — a counter field name, always
    /// identifier-safe so it needs no JSON escaping.
    pub reason: &'static str,
    /// `tls::ticket::now_us()` at the drop.
    pub at_us: u64,
}

impl ObsRecord for DropRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"reason\":\"{}\",\"at_us\":{}", self.reason, self.at_us)
    }
}

/// Snapshot payload for `LAST_CONN_CLOSE`.
#[derive(Clone, Copy)]
pub struct ConnCloseRecord {
    /// `true` = application close (0x1d, RFC 9000 §19.19); `false` =
    /// transport close (0x1c).
    pub is_app: bool,
    /// Peer-supplied error code. Transport codes are RFC 9000 §20.1;
    /// application codes are protocol-defined (HTTP/3 = RFC 9114 §8.1).
    pub error_code: u64,
    /// Frame type the peer blamed (transport closes only; `0` for
    /// application closes, which carry no frame_type field).
    pub frame_type: u64,
    /// Peer reason phrase, truncated to 32 bytes.
    pub reason: [u8; 32],
    /// Valid prefix length of `reason` (≤ 32).
    pub reason_len: u8,
    /// `tls::ticket::now_us()` at receipt.
    pub at_us: u64,
}

impl ObsRecord for ConnCloseRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "\"origin\":\"{}\",\"error_code\":{},\"frame_type\":{},\"at_us\":{},\"reason\":\"",
            if self.is_app { "application" } else { "transport" },
            self.error_code,
            self.frame_type,
            self.at_us,
        )?;
        write_json_ascii(w, &self.reason[..self.reason_len as usize])?;
        w.write_str("\"")
    }
}

/// Which conn-task loop-exit path was taken. One per `break` site in
/// `endpoint::conn_task`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitReason {
    /// No inbound datagram for the full `max_idle_timeout` window
    /// (RFC 9000 §10.1) — either of the two idle break sites.
    IdleTimeout,
    /// The `ConnInbox` closed while the task awaited it.
    InboxClosed,
    /// `process_datagram` returned `Err`; the task sealed a
    /// CONNECTION_CLOSE and tore down.
    ProcessError,
    /// The connection reached `Failed` state outside the
    /// process-error path (peer close, app close).
    ConnFailed,
}

impl ExitReason {
    /// Stable lowercase token for logs / JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            ExitReason::IdleTimeout => "idle_timeout",
            ExitReason::InboxClosed => "inbox_closed",
            ExitReason::ProcessError => "process_error",
            ExitReason::ConnFailed => "conn_failed",
        }
    }
}

/// Snapshot payload for `LAST_CONN_EXIT`.
#[derive(Clone, Copy)]
pub struct ConnExitRecord {
    /// Which exit path the conn task took.
    pub reason: ExitReason,
    /// The local CID we issued for the connection (8 bytes).
    pub local_cid: [u8; 8],
    /// Conn-task loop iterations this connection ran before exit.
    pub iterations: u64,
    /// Age of the last received datagram at exit. For an
    /// `IdleTimeout` exit this should be ≥ `idle_us`; a value well
    /// below it means a spurious reap — the h3-over-gve bug.
    pub last_recv_age_us: u64,
    /// The negotiated idle window the age above was compared to.
    pub idle_us: u64,
    /// `tls::ticket::now_us()` at exit.
    pub at_us: u64,
}

impl ObsRecord for ConnExitRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(w, "\"reason\":\"{}\",\"local_cid\":\"", self.reason.as_str())?;
        for b in &self.local_cid {
            write!(w, "{b:02x}")?;
        }
        write!(
            w,
            "\",\"iterations\":{},\"last_recv_age_us\":{},\"idle_us\":{},\"at_us\":{}",
            self.iterations, self.last_recv_age_us, self.idle_us, self.at_us,
        )
    }
}

/// Write `bytes` as the inner content of a JSON string, mapping
/// anything that isn't safe printable ASCII to `.`. Peer reason
/// phrases are attacker-controlled, so we never emit a raw quote,
/// backslash, or control byte that could break the surrounding JSON.
fn write_json_ascii(w: &mut dyn fmt::Write, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        let c = if (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\' {
            b as char
        } else {
            '.'
        };
        w.write_char(c)?;
    }
    Ok(())
}

/// Record a `quic_drop!` site into `LAST_DROP`. Called by the macro;
/// not meant for direct use.
pub fn record_drop(reason: &'static str) {
    LAST_DROP.record(DropRecord {
        reason,
        at_us: tls::ticket::now_us(),
    });
}

/// Record a `quic_bug!` site into `LAST_BUG`. Called by the macro;
/// not meant for direct use.
pub fn record_bug(reason: &'static str) {
    LAST_BUG.record(DropRecord {
        reason,
        at_us: tls::ticket::now_us(),
    });
}

/// Record a received CONNECTION_CLOSE: bump `conn_closes_received`
/// and snapshot the peer's error_code / frame_type / reason into
/// `LAST_CONN_CLOSE`. `frame_type` is `0` for application closes.
pub fn record_conn_close(is_app: bool, error_code: u64, frame_type: u64, reason: &[u8]) {
    COUNTERS.conn_closes_received.bump();
    let n = reason.len().min(32);
    let mut buf = [0u8; 32];
    buf[..n].copy_from_slice(&reason[..n]);
    LAST_CONN_CLOSE.record(ConnCloseRecord {
        is_app,
        error_code,
        frame_type,
        reason: buf,
        reason_len: n as u8,
        at_us: tls::ticket::now_us(),
    });
}

/// Record a conn-task exit: bump the per-reason counter (and the
/// `conn_tasks_exited` total) and snapshot the teardown context into
/// `LAST_CONN_EXIT`. The `IdleTimeout` reason has no dedicated
/// counter — `idle_timeouts` already covers it (see that field).
pub fn record_conn_exit(
    reason: ExitReason,
    local_cid: &[u8],
    iterations: u64,
    last_recv_age_us: u64,
    idle_us: u64,
) {
    COUNTERS.conn_tasks_exited.bump();
    match reason {
        ExitReason::IdleTimeout => {}
        ExitReason::InboxClosed => COUNTERS.conn_task_exit_inbox_closed.bump(),
        ExitReason::ProcessError => COUNTERS.conn_task_exit_process_error.bump(),
        ExitReason::ConnFailed => COUNTERS.conn_task_exit_conn_failed.bump(),
    }
    let n = local_cid.len().min(8);
    let mut cid = [0u8; 8];
    cid[..n].copy_from_slice(&local_cid[..n]);
    LAST_CONN_EXIT.record(ConnExitRecord {
        reason,
        local_cid: cid,
        iterations,
        last_recv_age_us,
        idle_us,
        at_us: tls::ticket::now_us(),
    });
}

// ── Log-level gating ────────────────────────────────────────────────
//
// The macros below check this u8 before printing. Counter increments
// are unaffected — they're cheap and always run, so `/quic_stats`
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
static LEVEL_INIT: AtomicBool = AtomicBool::new(false);

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
    if !waitless::boot_info::is_initialized() {
        LEVEL_INIT.store(true, Ordering::Relaxed);
        return;
    }
    let args = waitless::boot_info().boot_args;
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

/// Snapshot of every drop / event counter, for `/quic_stats`-style
/// dumps. Returns `(name, value)` pairs in declaration order. The
/// four AEAD throughput counters are intentionally excluded — they
/// are surfaced separately under `/stats`.
pub fn snapshot() -> [(&'static str, u64); 46] {
    let c = &COUNTERS;
    [
        ("no_dcid", c.no_dcid.get()),
        ("unknown_long_header", c.unknown_long_header.get()),
        ("unknown_short_header", c.unknown_short_header.get()),
        ("slot_table_full", c.slot_table_full.get()),
        ("rng_failed", c.rng_failed.get()),
        ("long_header_parse", c.long_header_parse.get()),
        ("initial_header_parse", c.initial_header_parse.get()),
        ("aead_decrypt_failed", c.aead_decrypt_failed.get()),
        ("unknown_frame", c.unknown_frame.get()),
        ("bad_state", c.bad_state.get()),
        ("late_initial_dropped", c.late_initial_dropped.get()),
        ("late_handshake_dropped", c.late_handshake_dropped.get()),
        ("other_wire", c.other_wire.get()),
        ("unsupported_client", c.unsupported_client.get()),
        ("tls_internal", c.tls_internal.get()),
        ("conns_allocated", c.conns_allocated.get()),
        ("conns_dropped", c.conns_dropped.get()),
        ("initial_dcid_hit", c.initial_dcid_hit.get()),
        ("handshakes_completed", c.handshakes_completed.get()),
        ("tickets_emitted", c.tickets_emitted.get()),
        ("tickets_accepted", c.tickets_accepted.get()),
        ("early_keys_derived", c.early_keys_derived.get()),
        ("zero_rtt_accepted", c.zero_rtt_accepted.get()),
        ("key_updates_accepted", c.key_updates_accepted.get()),
        ("zero_rtt_buffered", c.zero_rtt_buffered.get()),
        ("zero_rtt_unresumable", c.zero_rtt_unresumable.get()),
        ("idle_timeouts", c.idle_timeouts.get()),
        ("connection_closes_emitted", c.connection_closes_emitted.get()),
        ("conn_closes_received", c.conn_closes_received.get()),
        ("packets_lost_threshold", c.packets_lost_threshold.get()),
        ("packets_lost_time", c.packets_lost_time.get()),
        ("pto_probes_sent", c.pto_probes_sent.get()),
        ("recv_streams_created", c.recv_streams_created.get()),
        ("send_streams_created", c.send_streams_created.get()),
        ("streams_reaped", c.streams_reaped.get()),
        ("inbox_full_drops", c.inbox_full_drops.get()),
        ("conn_task_iterations", c.conn_task_iterations.get()),
        ("conn_tasks_exited", c.conn_tasks_exited.get()),
        (
            "conn_task_exit_inbox_closed",
            c.conn_task_exit_inbox_closed.get(),
        ),
        (
            "conn_task_exit_process_error",
            c.conn_task_exit_process_error.get(),
        ),
        (
            "conn_task_exit_conn_failed",
            c.conn_task_exit_conn_failed.get(),
        ),
        ("handler_stuck", c.handler_stuck.get()),
        ("flush_calls", c.flush_calls.get()),
        ("datagrams_sent", c.datagrams_sent.get()),
        ("datagrams_processed", c.datagrams_processed.get()),
        ("anti_amp_throttled", c.anti_amp_throttled.get()),
    ]
}

/// Render the full QUIC observability block as a JSON object —
/// every drop / event counter as a flat `"name":value` member, then
/// the `LastEvent` snapshots and `LatencyHist`s as nested objects.
/// This is QUIC's contribution to the `/obs` surface and the body
/// of `/quic_stats`;
/// see `docs/observability.md` for the convention.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_DROP.write_json(w, "last_drop")?;
    w.write_str(",")?;
    LAST_BUG.write_json(w, "last_bug")?;
    w.write_str(",")?;
    LAST_CONN_CLOSE.write_json(w, "last_conn_close")?;
    w.write_str(",")?;
    LAST_CONN_EXIT.write_json(w, "last_conn_exit")?;
    w.write_str(",")?;
    REQUEST_LATENCY.write_json(w, "request_latency_us")?;
    w.write_str(",")?;
    INBOX_WAIT.write_json(w, "inbox_wait_us")?;
    w.write_str("}")
}

/// Drop-site macro: increments the named counter, records the drop
/// into `LAST_DROP`, and (if the log level allows) logs a single
/// line. Use for "we couldn't continue here, packet/conn is being
/// dropped" — never for normal completion.
///
/// The first arg is the bare counter field name from `Counters`;
/// the rest is `format_args!`-shape detail.
///
/// Counter increment + `LAST_DROP` record run unconditionally; the
/// println is gated by `LogLevel >= Drops` (the default). Benchmark
/// builds set `quic.log=silent` in `boot_args` and pay only the
/// increment + the cold-path snapshot.
///
/// Example:
///   `quic_drop!(unsupported_client, "no x25519 in CH key_share");`
#[macro_export]
macro_rules! quic_drop {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::COUNTERS.$reason.bump();
        $crate::diag::record_drop(::core::stringify!($reason));
        if $crate::diag::should_log_drop() {
            ::waitless::println!(
                "[quic-drop {}] {}",
                ::core::stringify!($reason),
                ::core::format_args!($($detail)*),
            );
        }
    }};
    ($reason:ident) => {{
        $crate::diag::COUNTERS.$reason.bump();
        $crate::diag::record_drop(::core::stringify!($reason));
        if $crate::diag::should_log_drop() {
            ::waitless::println!("[quic-drop {}]", ::core::stringify!($reason));
        }
    }};
}

/// Event-site macro: same shape as `quic_drop!` but for positive /
/// progress events. Gated by `LogLevel >= Events` so the default
/// `Drops` level keeps these silent — they're useful for
/// per-handshake debugging but noise during steady-state load.
/// Events do not feed `LAST_DROP` (it is a failure-only slot).
#[macro_export]
macro_rules! quic_event {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::COUNTERS.$reason.bump();
        if $crate::diag::should_log_event() {
            ::waitless::println!(
                "[quic-event {}] {}",
                ::core::stringify!($reason),
                ::core::format_args!($($detail)*),
            );
        }
    }};
    ($reason:ident) => {{
        $crate::diag::COUNTERS.$reason.bump();
        if $crate::diag::should_log_event() {
            ::waitless::println!("[quic-event {}]", ::core::stringify!($reason));
        }
    }};
}

/// Invariant-violation macro — for a genuinely unexpected condition,
/// an assumption the code relies on that did not hold (doctrine
/// principle 6: *a broken assumption is loud*).
///
/// Unlike `quic_drop!` (gated, for routine/expected failures) this
/// logs to serial **unconditionally** — regardless of the `quic.log`
/// level, including `silent` benchmark builds — because a counter
/// ticking 0→1 on an unwatched dashboard is not a signal. It also
/// bumps the named counter and records `LAST_BUG`. Such sites are
/// cold by definition (a "can't happen" that happens often was
/// never an invariant), so the unconditional println costs nothing
/// in practice.
///
/// Example:
///   `quic_bug!(rng_failed, "getrandom failed minting CID nonce");`
#[macro_export]
macro_rules! quic_bug {
    ($reason:ident, $($detail:tt)*) => {{
        $crate::diag::COUNTERS.$reason.bump();
        $crate::diag::record_bug(::core::stringify!($reason));
        ::waitless::println!(
            "[quic-bug {}] {}",
            ::core::stringify!($reason),
            ::core::format_args!($($detail)*),
        );
    }};
    ($reason:ident) => {{
        $crate::diag::COUNTERS.$reason.bump();
        $crate::diag::record_bug(::core::stringify!($reason));
        ::waitless::println!("[quic-bug {}]", ::core::stringify!($reason));
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn conn_close_record_renders_and_sanitizes() {
        let mut rec = ConnCloseRecord {
            is_app: true,
            error_code: 0x010c,
            frame_type: 0,
            reason: [0u8; 32],
            reason_len: 0,
            at_us: 1234,
        };
        // A reason with a quote + control byte must not break JSON.
        let raw = b"bad\"\x01reason";
        rec.reason[..raw.len()].copy_from_slice(raw);
        rec.reason_len = raw.len() as u8;
        let mut s = String::new();
        rec.write_fields(&mut s).unwrap();
        assert_eq!(
            s,
            "\"origin\":\"application\",\"error_code\":268,\"frame_type\":0,\
             \"at_us\":1234,\"reason\":\"bad..reason\""
        );
    }

    #[test]
    fn conn_exit_record_carries_idle_invariants() {
        let rec = ConnExitRecord {
            reason: ExitReason::IdleTimeout,
            local_cid: [0xa1, 0xb2, 0xc3, 0xd4, 0, 0, 0, 0],
            iterations: 7,
            // The h3-bug shape: aged only 81 ms inside a 30 s window.
            last_recv_age_us: 81_000,
            idle_us: 30_000_000,
            at_us: 9_000,
        };
        let mut s = String::new();
        rec.write_fields(&mut s).unwrap();
        assert_eq!(
            s,
            "\"reason\":\"idle_timeout\",\"local_cid\":\"a1b2c3d40000000\
             0\",\"iterations\":7,\"last_recv_age_us\":81000,\
             \"idle_us\":30000000,\"at_us\":9000"
        );
    }

    #[test]
    fn record_conn_close_bumps_counter_and_snapshot() {
        let before = COUNTERS.conn_closes_received.get();
        let (before_count, _) = LAST_CONN_CLOSE.snapshot();
        record_conn_close(false, 0x0a, 0x06, b"protocol_violation");
        assert_eq!(COUNTERS.conn_closes_received.get(), before + 1);
        let (count, last) = LAST_CONN_CLOSE.snapshot();
        assert_eq!(count, before_count + 1);
        let last = last.expect("recorded");
        assert!(!last.is_app);
        assert_eq!(last.error_code, 0x0a);
        assert_eq!(last.frame_type, 0x06);
        assert_eq!(&last.reason[..last.reason_len as usize], b"protocol_violation");
    }

    #[test]
    fn record_bug_populates_last_bug_snapshot() {
        let (before, _) = LAST_BUG.snapshot();
        record_bug("handler_stuck");
        let (count, last) = LAST_BUG.snapshot();
        assert_eq!(count, before + 1);
        assert_eq!(last.expect("recorded").reason, "handler_stuck");
    }

    #[test]
    fn write_obs_json_is_one_object() {
        let mut s = String::new();
        write_obs_json(&mut s).unwrap();
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        // Counters present as flat members; snapshots nested.
        assert!(s.contains("\"idle_timeouts\":"));
        assert!(s.contains("\"handler_stuck\":"));
        assert!(s.contains("\"last_conn_exit\":{\"count\":"));
        // The invariant-violation slot is distinct from `last_drop`.
        assert!(s.contains("\"last_bug\":{\"count\":"));
        // Performance pillar: the RX→TX latency histograms.
        assert!(s.contains("\"request_latency_us\":{\"count\":"));
        assert!(s.contains("\"inbox_wait_us\":{\"count\":"));
    }
}
