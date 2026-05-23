// net/tcp/diag.rs — observability for the TCP stack.
//
// Applies the observability doctrine (`docs/observability.md`) to
// TCP, mirroring `quic::diag`. Two pillars:
//
//   * `Counters` — one `obs::Counter` per event. Wraps the four
//     pre-existing diagnostic atomics (`syn_rx`, `synack_tx`, the
//     `rx_chunk_*` pair) and adds the connection-lifecycle, reset,
//     congestion-window, and retransmit events the stack used to
//     leave untraced.
//   * `LastEvent` snapshots — `LAST_RST`, `LAST_TEARDOWN`, and
//     `LAST_ACK_UNSENT` retain the decisive context of the most
//     recent reset, connection teardown, and rejected ACK. A counter
//     says an anomaly fired; the snapshot says what it looked like.
//
// Cold path only — every site here fires at most once per
// connection (accept, reset, teardown), per RTO, or per persist
// probe, never per segment. Surfaced as the `"tcp"` block of `/obs`
// via `write_obs_json`, which crosses the `os:none` → app boundary
// through `waitless_backend::tcp_obs_json`.

use core::fmt;

use obs::{Counter, LastEvent, ObsRecord};

use crate::state::TcpState;

/// One counter per TCP event. Field names match the doctrine's
/// grep-the-name-find-the-counter convention.
pub struct Counters {
    // ── RX / handshake ───────────────────────────────────────────
    /// SYN (no-ACK) segments that reached `tcp_receive`. Compare
    /// against the peer's SYN-sent count to localize ingress drops
    /// below TCP (NIC / RX driver).
    pub syn_rx: Counter,
    /// SYN-ACK segments emitted in reply to a SYN.
    pub synack_tx: Counter,
    /// Three-way handshake completed — a connection reached
    /// `Established`. Pair with `conns_freed` to watch live count.
    pub conns_established: Counter,
    /// Inbound segments whose ACK field was above `SND.NXT` —
    /// acknowledging data we never sent (RFC 9293 §3.10.7.4). Each
    /// was answered with a bare ACK and dropped. A real peer never
    /// does this; a non-zero count is a confused peer or a blind
    /// off-path injection. `LAST_ACK_UNSENT` has the rejected
    /// `SEG.ACK` and the `SND.NXT` it failed against.
    pub ack_unsent: Counter,

    // ── Teardown ─────────────────────────────────────────────────
    /// Connections freed, all reasons. Equals the sum of the
    /// per-reason teardown counters below plus the graceful closes
    /// (passive close, TimeWait expiry) that have no dedicated
    /// counter — read `LAST_TEARDOWN` for the most recent reason.
    pub conns_freed: Counter,
    /// RST segments received from a peer. `LAST_RST.in_window`
    /// distinguishes a legitimate reset from a blind off-path
    /// injection we dropped (RFC 5961 §3.2).
    pub rst_received: Counter,
    /// RST segments we emitted — a SYN to a port with no listener,
    /// or an RX-ring allocation failure refusing a connection.
    pub rst_sent: Counter,
    /// A connection torn down because RFC 6298 data retransmission
    /// hit `RTX_MAX_RETRIES` with no progress — the peer went away
    /// mid-stream. Anomalous; `LAST_TEARDOWN` has the state.
    pub rtx_giveups: Counter,
    /// A half-closed connection torn down because our FIN went
    /// unacknowledged `FIN_RETX_MAX` times. Anomalous.
    pub fin_giveups: Counter,
    /// A connection aborted because `PERSIST_MAX_PROBES` zero-window
    /// probes went unanswered — the peer kept its receive window
    /// shut. Anomalous; `LAST_TEARDOWN` has the state.
    pub persist_giveups: Counter,

    // ── Resource pressure (genuinely unexpected) ─────────────────
    /// `alloc_connection` found no free slot AND no half-closed
    /// slot to reclaim — a SYN was dropped on the floor. Should not
    /// happen below the pool's ~64k-slot/core ceiling; sustained
    /// growth means a connection leak or a SYN flood.
    pub pool_exhausted: Counter,
    /// `alloc_connection` had to forcibly reclaim a half-closed
    /// slot (FinWait/LastAck/TimeWait/CloseWait) to satisfy a SYN.
    /// The stack is at its slot ceiling; graceful closes aren't
    /// keeping up with accept rate.
    pub pool_reclaimed: Counter,
    /// A SYN was refused because the per-conn RX ring could not be
    /// heap-allocated. Heap exhaustion — genuinely unexpected.
    pub rx_ring_oom: Counter,
    /// A send could not grow the per-conn retransmit ring — heap
    /// exhaustion. Retransmit coverage is suspended (`rtx_overflow`)
    /// until the unacked window drains. Genuinely unexpected.
    pub rtx_buf_oom: Counter,

    // ── Retransmission ───────────────────────────────────────────
    /// RFC 6298 data retransmissions — the oldest unacked segment
    /// resent after its RTO expired.
    pub data_retransmits: Counter,
    /// FIN retransmissions — a `FinWait1` / `LastAck` FIN resent
    /// because the peer hadn't acknowledged it.
    pub fin_retransmits: Counter,
    /// RFC 9293 §3.8.6.1 zero-window probes — one bare ACK emitted
    /// per persist-timer expiry while a peer keeps its window shut.
    pub persist_probes: Counter,

    // ── recv_chunk zero-copy accounting ──────────────────────────
    /// `recv_chunk` resolved via the zero-copy device-buffer stash.
    pub rx_chunk_stash_hits: Counter,
    /// `recv_chunk` resolved via the copying ring-drain fallback.
    /// `stash / (stash + ring_drain)` is the live zero-copy ratio.
    pub rx_chunk_ring_drain: Counter,

    // ── High-conn scan-cost instrumentation ──────────────────────
    // EXPERIMENTAL — added during the bench/pareto-rig cliff
    // investigation to identify which O(pool_size) loops dominate
    // at high conn counts. Ratios `iterations / calls` give the
    // average scan depth; if `accept_iterations` per `accept_calls`
    // tracks pool size, the accept scan is hot.
    pub accept_calls: Counter,
    pub accept_iterations: Counter,
    pub linear_find_calls: Counter,
    pub linear_find_iterations: Counter,
    pub hash_find_probes: Counter,
    pub syn_scan_calls: Counter,
    pub syn_scan_iterations: Counter,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            syn_rx: Counter::new(),
            synack_tx: Counter::new(),
            conns_established: Counter::new(),
            ack_unsent: Counter::new(),
            conns_freed: Counter::new(),
            rst_received: Counter::new(),
            rst_sent: Counter::new(),
            rtx_giveups: Counter::new(),
            fin_giveups: Counter::new(),
            persist_giveups: Counter::new(),
            pool_exhausted: Counter::new(),
            pool_reclaimed: Counter::new(),
            rx_ring_oom: Counter::new(),
            rtx_buf_oom: Counter::new(),
            data_retransmits: Counter::new(),
            fin_retransmits: Counter::new(),
            persist_probes: Counter::new(),
            rx_chunk_stash_hits: Counter::new(),
            rx_chunk_ring_drain: Counter::new(),
            accept_calls: Counter::new(),
            accept_iterations: Counter::new(),
            linear_find_calls: Counter::new(),
            linear_find_iterations: Counter::new(),
            hash_find_probes: Counter::new(),
            syn_scan_calls: Counter::new(),
            syn_scan_iterations: Counter::new(),
        }
    }
}

/// Process-wide TCP counters. Relaxed atomics; lossy reads by design.
pub static COUNTERS: Counters = Counters::new();

/// Most recent RST received from a peer — the context the bare
/// `rst_received` count discards.
pub static LAST_RST: LastEvent<RstRecord> = LastEvent::new();

/// Most recent connection teardown — the state it died in and why.
pub static LAST_TEARDOWN: LastEvent<TeardownRecord> = LastEvent::new();

/// Most recent inbound ACK rejected as acknowledging unsent data —
/// the RFC 9293 §3.10.7.4 acceptability inputs the bare `ack_unsent`
/// count discards.
pub static LAST_ACK_UNSENT: LastEvent<AckUnsentRecord> = LastEvent::new();

/// Snapshot payload for `LAST_RST`.
#[derive(Clone, Copy)]
pub struct RstRecord {
    pub peer_port: u16,
    pub local_port: u16,
    /// The RST segment's sequence number.
    pub seg_seq: u32,
    /// Our `rcv_nxt` at the time — the RFC 5961 accept test is
    /// `seg_seq == rcv_nxt`.
    pub rcv_nxt: u32,
    /// `true` ⇒ the reset was in-sequence and tore the connection
    /// down; `false` ⇒ out-of-window, dropped (a blind injection or
    /// a stale straggler).
    pub in_window: bool,
    /// Connection state when the RST arrived.
    pub conn_state: TcpState,
    /// `kernel_core::clock::now_ms()` at receipt.
    pub at_ms: u64,
}

impl ObsRecord for RstRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "\"peer_port\":{},\"local_port\":{},\"seg_seq\":{},\"rcv_nxt\":{},\
             \"in_window\":{},\"conn_state\":\"{}\",\"at_ms\":{}",
            self.peer_port,
            self.local_port,
            self.seg_seq,
            self.rcv_nxt,
            self.in_window,
            state_name(self.conn_state),
            self.at_ms,
        )
    }
}

/// Snapshot payload for `LAST_ACK_UNSENT` — an inbound segment whose
/// ACK acknowledged data past `SND.NXT`.
#[derive(Clone, Copy)]
pub struct AckUnsentRecord {
    pub peer_port: u16,
    pub local_port: u16,
    /// The rejected `SEG.ACK` — acknowledged data we never sent.
    pub seg_ack: u32,
    /// `SND.UNA` at receipt — the oldest unacknowledged byte.
    pub snd_una: u32,
    /// `SND.NXT` at receipt — the acceptability bound `SEG.ACK`
    /// exceeded (the test is `SEG.ACK > SND.NXT`).
    pub snd_nxt: u32,
    /// Connection state when the segment arrived.
    pub conn_state: TcpState,
    /// `kernel_core::clock::now_ms()` at receipt.
    pub at_ms: u64,
}

impl ObsRecord for AckUnsentRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "\"peer_port\":{},\"local_port\":{},\"seg_ack\":{},\"snd_una\":{},\
             \"snd_nxt\":{},\"conn_state\":\"{}\",\"at_ms\":{}",
            self.peer_port,
            self.local_port,
            self.seg_ack,
            self.snd_una,
            self.snd_nxt,
            state_name(self.conn_state),
            self.at_ms,
        )
    }
}

/// Why a connection was torn down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TeardownReason {
    /// In-window RST from the peer.
    PeerReset,
    /// Passive close completed — peer FIN'd, we FIN'd, peer ACK'd
    /// our FIN (`LastAck` → freed).
    PassiveClose,
    /// Active close completed — the 2×MSL `TimeWait` hold elapsed.
    TimeWaitExpiry,
    /// RFC 6298 data retransmission gave up (`RTX_MAX_RETRIES`).
    RtxGiveup,
    /// FIN retransmission gave up (`FIN_RETX_MAX`).
    FinGiveup,
    /// Zero-window persist gave up (`PERSIST_MAX_PROBES`).
    PersistGiveup,
    /// The connection was force-reclaimed to free a pool slot.
    PoolReclaim,
    /// A SYN's RX-ring allocation failed; the just-allocated slot
    /// was freed again.
    RxRingOom,
}

impl TeardownReason {
    /// Stable lowercase token for logs / JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            TeardownReason::PeerReset => "peer_reset",
            TeardownReason::PassiveClose => "passive_close",
            TeardownReason::TimeWaitExpiry => "time_wait_expiry",
            TeardownReason::RtxGiveup => "rtx_giveup",
            TeardownReason::FinGiveup => "fin_giveup",
            TeardownReason::PersistGiveup => "persist_giveup",
            TeardownReason::PoolReclaim => "pool_reclaim",
            TeardownReason::RxRingOom => "rx_ring_oom",
        }
    }
}

/// Snapshot payload for `LAST_TEARDOWN`.
#[derive(Clone, Copy)]
pub struct TeardownRecord {
    pub reason: TeardownReason,
    /// Connection state at teardown.
    pub state: TcpState,
    /// `kernel_core::clock::now_ms()` at teardown.
    pub at_ms: u64,
}

impl ObsRecord for TeardownRecord {
    fn write_fields(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "\"reason\":\"{}\",\"state\":\"{}\",\"at_ms\":{}",
            self.reason.as_str(),
            state_name(self.state),
            self.at_ms,
        )
    }
}

/// Stable lowercase name for a `TcpState` — for JSON / logs.
pub fn state_name(s: TcpState) -> &'static str {
    match s {
        TcpState::Closed => "closed",
        TcpState::Listen => "listen",
        TcpState::SynReceived => "syn_received",
        TcpState::Established => "established",
        TcpState::FinWait1 => "fin_wait1",
        TcpState::FinWait2 => "fin_wait2",
        TcpState::CloseWait => "close_wait",
        TcpState::LastAck => "last_ack",
        TcpState::TimeWait => "time_wait",
    }
}

/// Record a received RST: bump `rst_received` and snapshot the
/// RFC 5961 accept test inputs into `LAST_RST`.
pub fn record_rst(
    peer_port: u16,
    local_port: u16,
    seg_seq: u32,
    rcv_nxt: u32,
    in_window: bool,
    conn_state: TcpState,
) {
    COUNTERS.rst_received.bump();
    LAST_RST.record(RstRecord {
        peer_port,
        local_port,
        seg_seq,
        rcv_nxt,
        in_window,
        conn_state,
        at_ms: kernel_core::clock::now_ms(),
    });
}

/// Record an inbound ACK rejected as acknowledging unsent data
/// (`SEG.ACK > SND.NXT`): bump `ack_unsent` and snapshot the
/// RFC 9293 §3.10.7.4 acceptability inputs into `LAST_ACK_UNSENT`.
pub fn record_ack_unsent(
    peer_port: u16,
    local_port: u16,
    seg_ack: u32,
    snd_una: u32,
    snd_nxt: u32,
    conn_state: TcpState,
) {
    COUNTERS.ack_unsent.bump();
    LAST_ACK_UNSENT.record(AckUnsentRecord {
        peer_port,
        local_port,
        seg_ack,
        snd_una,
        snd_nxt,
        conn_state,
        at_ms: kernel_core::clock::now_ms(),
    });
}

/// Record a connection teardown: bump `conns_freed` (+ the
/// per-reason counter for an anomalous reason) and snapshot the
/// state + reason into `LAST_TEARDOWN`. Call with the connection's
/// state captured *before* `free_connection` resets it.
pub fn record_teardown(reason: TeardownReason, state: TcpState) {
    COUNTERS.conns_freed.bump();
    match reason {
        TeardownReason::RtxGiveup => COUNTERS.rtx_giveups.bump(),
        TeardownReason::FinGiveup => COUNTERS.fin_giveups.bump(),
        TeardownReason::PersistGiveup => COUNTERS.persist_giveups.bump(),
        TeardownReason::PoolReclaim => COUNTERS.pool_reclaimed.bump(),
        TeardownReason::RxRingOom => COUNTERS.rx_ring_oom.bump(),
        TeardownReason::PeerReset
        | TeardownReason::PassiveClose
        | TeardownReason::TimeWaitExpiry => {}
    }
    LAST_TEARDOWN.record(TeardownRecord {
        reason,
        state,
        at_ms: kernel_core::clock::now_ms(),
    });
}

/// Counter `(name, value)` pairs in declaration order — the flat
/// half of the `/obs` `"tcp"` block.
pub fn snapshot() -> [(&'static str, u64); 26] {
    let c = &COUNTERS;
    [
        ("syn_rx", c.syn_rx.get()),
        ("synack_tx", c.synack_tx.get()),
        ("conns_established", c.conns_established.get()),
        ("ack_unsent", c.ack_unsent.get()),
        ("conns_freed", c.conns_freed.get()),
        ("rst_received", c.rst_received.get()),
        ("rst_sent", c.rst_sent.get()),
        ("rtx_giveups", c.rtx_giveups.get()),
        ("fin_giveups", c.fin_giveups.get()),
        ("persist_giveups", c.persist_giveups.get()),
        ("pool_exhausted", c.pool_exhausted.get()),
        ("pool_reclaimed", c.pool_reclaimed.get()),
        ("rx_ring_oom", c.rx_ring_oom.get()),
        ("rtx_buf_oom", c.rtx_buf_oom.get()),
        ("data_retransmits", c.data_retransmits.get()),
        ("fin_retransmits", c.fin_retransmits.get()),
        ("persist_probes", c.persist_probes.get()),
        ("rx_chunk_stash_hits", c.rx_chunk_stash_hits.get()),
        ("rx_chunk_ring_drain", c.rx_chunk_ring_drain.get()),
        ("accept_calls", c.accept_calls.get()),
        ("accept_iterations", c.accept_iterations.get()),
        ("linear_find_calls", c.linear_find_calls.get()),
        ("linear_find_iterations", c.linear_find_iterations.get()),
        ("hash_find_probes", c.hash_find_probes.get()),
        ("syn_scan_calls", c.syn_scan_calls.get()),
        ("syn_scan_iterations", c.syn_scan_iterations.get()),
    ]
}

/// Render the TCP observability block as a JSON object — every
/// counter flat, then the `LastEvent` snapshots nested. This is
/// TCP's contribution to `/obs`; `waitless_backend::tcp_obs_json`
/// forwards it across the `os:none` → app boundary.
pub fn write_obs_json(w: &mut dyn fmt::Write) -> fmt::Result {
    w.write_str("{")?;
    for (name, value) in snapshot() {
        write!(w, "\"{name}\":{value},")?;
    }
    LAST_RST.write_json(w, "last_rst")?;
    w.write_str(",")?;
    LAST_TEARDOWN.write_json(w, "last_teardown")?;
    w.write_str(",")?;
    LAST_ACK_UNSENT.write_json(w, "last_ack_unsent")?;
    w.write_str("}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn rst_record_renders() {
        let mut s = String::new();
        RstRecord {
            peer_port: 51000,
            local_port: 443,
            seg_seq: 1000,
            rcv_nxt: 1000,
            in_window: true,
            conn_state: TcpState::Established,
            at_ms: 42,
        }
        .write_fields(&mut s)
        .unwrap();
        assert_eq!(
            s,
            "\"peer_port\":51000,\"local_port\":443,\"seg_seq\":1000,\
             \"rcv_nxt\":1000,\"in_window\":true,\
             \"conn_state\":\"established\",\"at_ms\":42"
        );
    }

    #[test]
    fn ack_unsent_record_renders() {
        let mut s = String::new();
        AckUnsentRecord {
            peer_port: 51000,
            local_port: 443,
            seg_ack: 5000,
            snd_una: 1000,
            snd_nxt: 1500,
            conn_state: TcpState::Established,
            at_ms: 42,
        }
        .write_fields(&mut s)
        .unwrap();
        assert_eq!(
            s,
            "\"peer_port\":51000,\"local_port\":443,\"seg_ack\":5000,\
             \"snd_una\":1000,\"snd_nxt\":1500,\
             \"conn_state\":\"established\",\"at_ms\":42"
        );
    }

    #[test]
    fn record_teardown_bumps_total_and_reason() {
        let total = COUNTERS.conns_freed.get();
        let giveups = COUNTERS.rtx_giveups.get();
        record_teardown(TeardownReason::RtxGiveup, TcpState::Established);
        assert_eq!(COUNTERS.conns_freed.get(), total + 1);
        assert_eq!(COUNTERS.rtx_giveups.get(), giveups + 1);
        let (_, last) = LAST_TEARDOWN.snapshot();
        assert_eq!(last.expect("recorded").reason, TeardownReason::RtxGiveup);
    }

    #[test]
    fn write_obs_json_is_one_object() {
        let mut s = String::new();
        write_obs_json(&mut s).unwrap();
        assert!(s.starts_with('{') && s.ends_with('}'));
        assert!(s.contains("\"syn_rx\":"));
        assert!(s.contains("\"ack_unsent\":"));
        assert!(s.contains("\"persist_probes\":"));
        assert!(s.contains("\"last_teardown\":{\"count\":"));
        assert!(s.contains("\"last_ack_unsent\":{\"count\":"));
    }
}
