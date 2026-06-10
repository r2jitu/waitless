// Active open (client connect) — the engine half of `tcp_connect`.
//
// `connect_on_core` allocates a slot on the **calling core**, picks a
// core-affine ephemeral port (`ephemeral` — the port's 4-tuple hashes
// back to this core under the SAME flow hash Tier-2 RX classify
// uses), sends the SYN, and arms the SYN-retransmit timer. The
// SYN-ACK then lands in `receive::handle_syn_sent`, which drives the
// `SynSent → Established` transition and wakes the connect future
// parked on the send-waker slot. `connect_status` is the poll the
// reactor's `TcpConnect` future loops on.
//
// Failure model: a refused (RST) or timed-out (SYN retry cap) connect
// does NOT free the slot — `fail_connect` flags it
// (`ConnectFailure`), removes the 4-tuple from the hash, goes
// wire-inert (`Closed`), and wakes the waiter. The slot is released
// when the future observes the failure (its held `TcpStream` drops →
// `close` → `free_connection`), so `Refused` and `TimedOut` stay
// distinguishable across the wakeup.

use crate::ephemeral::alloc_ephemeral_port;
use crate::pool::{
    alloc_connection, conn_ptr, decode_handle, encode_handle, free_connection, next_seq,
    tcp_hash_insert, tcp_hash_key, tcp_hash_remove,
};
use crate::send::{SYN_OPTS_MAX, SegmentMeta, send_segment_opts, syn_option_blob};
use crate::state::{
    ConnectFailure, RX_RING_BYTES, TCP_SYN, TcpConnection, TcpState, mss_for,
};
use types::IpAddr;

/// Open an active connection from `local_ip` to `remote_ip:remote_port`
/// on the **current core** — the entry point behind the reactor's
/// `connect` backend hook (mirroring `listen_on_core`'s shape). Picks
/// a core-affine ephemeral port, sends the SYN (with the same MSS /
/// Window-Scale / SACK-Permitted options the SYN-ACK builder emits),
/// and arms the SYN-retransmit timer.
///
/// Returns the slot handle + generation for the embryo `SynSent`
/// conn, or `None` when no ephemeral port / pool slot / RX ring could
/// be had. Completion (or failure) is observed via [`connect_status`].
pub fn connect_on_core(
    local_ip: IpAddr,
    remote_ip: IpAddr,
    remote_port: u16,
) -> Option<(*mut (), u16)> {
    let core = kernel_core::cpu_id();
    let local_port = alloc_ephemeral_port(core, local_ip, remote_ip, remote_port)?;
    let slot = alloc_connection(core)?;
    // SAFETY: per-core ownership; this is the owning core (slot was
    // just allocated from its own pool) and the slot was popped off
    // the free list, so no other code holds a reference.
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Allocate the per-conn RX ring up front — OOM refuses the
    // connect rather than proceeding with a ring that would silently
    // drop every inbound payload byte (same admission gate as the
    // passive SYN path).
    if !c.ensure_rx_ring() {
        free_connection(core, slot);
        return None;
    }
    c.state = TcpState::SynSent;
    c.remote_ip = remote_ip;
    c.local_ip = local_ip;
    c.local_port = local_port;
    c.remote_port = remote_port;
    // The SYN occupies one sequence number: SND.UNA = ISS,
    // SND.NXT = ISS+1 once the SYN below is on the wire.
    let iss = next_seq();
    c.snd_una = iss;
    c.snd_nxt = iss.wrapping_add(1);
    // Not a listener child — never visible to `accept_on_port`.
    c.listener_port = 0;
    c.accepted = true;
    // Anchor an RTT sample on the SYN round trip (RFC 6298 §3) —
    // the SYN-ACK's arrival seeds the estimator unless a SYN
    // retransmit invalidated the sample (Karn's rule, see
    // `retransmit_syn`).
    let now = kernel_core::clock::now_ms();
    c.rtt_anchor_ms = now;
    c.rtt_anchor_seq = iss.wrapping_add(1);
    c.rtt_anchor_active = true;
    let generation = c.generation;
    // Publish the 4-tuple so the SYN-ACK (and everything after)
    // lands in `tcp_hash_find` — the same index the passive path
    // inserts into at SYN time. The key is keyed by the REMOTE end
    // (ip, port) + our local port, which for a client conn is the
    // ephemeral port chosen above — full-4-tuple unique either way.
    tcp_hash_insert(core, tcp_hash_key(remote_ip, remote_port, local_port), slot);
    c.send_syn();
    crate::diag::COUNTERS.connect_attempts.bump();
    // Arm the SYN retransmit: the lifecycle timer doubles as the
    // SYN-retransmit timer in `SynSent` (see `on_tcp_tick`), with
    // the same exponential backoff the FIN retransmit uses.
    c.arm_fin_timer(now);
    Some((encode_handle(core, slot), generation))
}

/// What the reactor's `TcpConnect` future observes when it polls.
/// Thin pass-through to the executor-level enum so the backend fn
/// pointer and this engine query share one type.
pub fn connect_status(handle: *mut (), generation: u16) -> executor::reactor::TcpConnectStatus {
    use executor::reactor::TcpConnectStatus;
    let Some((core, slot)) = decode_handle(handle) else {
        return TcpConnectStatus::TimedOut;
    };
    // SAFETY: per-core ownership; the worker polling its connect
    // future is the one that called `connect_on_core`.
    let c = unsafe { &*conn_ptr(core, slot) };
    if c.generation != generation {
        // Slot reused under us. Unreachable pre-completion (a failed
        // embryo is held un-freed until the future observes it; only
        // `shutdown_all` can free it earlier) — report timed out.
        return TcpConnectStatus::TimedOut;
    }
    match c.state {
        TcpState::SynSent => TcpConnectStatus::InProgress,
        TcpState::Closed => match c.connect_failure {
            ConnectFailure::Refused => TcpConnectStatus::Refused,
            _ => TcpConnectStatus::TimedOut,
        },
        // Established — or any later state the peer raced the conn
        // into (data/FIN arriving before the future re-polled). The
        // handshake completed either way.
        _ => TcpConnectStatus::Established,
    }
}

/// Fail an in-progress active open: record the reason, take the conn
/// wire-inert, and wake the parked connect waiter. The slot is NOT
/// freed — see the module doc; `free_connection` runs when the future
/// observes the failure and drops its embryo `TcpStream`.
pub(crate) fn fail_connect(core: u32, slot: usize, failure: ConnectFailure) {
    // SAFETY: per-core ownership — called from this core's RX path
    // (RST in SynSent) or timer tick (SYN retry cap).
    let c = unsafe { &mut *conn_ptr(core, slot) };
    // Remove the 4-tuple from the hash index so later segments can't
    // find the dead embryo. Done here (not left to `free_connection`)
    // because the state goes `Closed` below, which `free_connection`'s
    // hash-remove is gated against.
    tcp_hash_remove(core, tcp_hash_key(c.remote_ip, c.remote_port, c.local_port));
    crate::diag::record_teardown(
        match failure {
            ConnectFailure::Refused => crate::diag::TeardownReason::ConnectRefused,
            _ => crate::diag::TeardownReason::ConnectTimeout,
        },
        c.state,
    );
    c.connect_failure = failure;
    c.state = TcpState::Closed;
    c.lifecycle_deadline_ms = 0;
    c.fin_retx_count = 0;
    c.rtt_anchor_active = false;
    if let Some(w) = c.send_waker.take() {
        w.wake();
    }
    if let Some(w) = c.recv_waker.take() {
        w.wake();
    }
}

impl TcpConnection {
    /// Emit this connection's SYN — initial transmission and every
    /// retransmit (same ISS, same options, byte-identical). Always
    /// offers MSS + Window-Scale (shift 0) + SACK-Permitted via the
    /// shared [`syn_option_blob`] builder, so the active SYN and the
    /// passive SYN-ACK can never drift; the peer's echo (or absence)
    /// in the SYN-ACK decides what's in effect
    /// (`receive::handle_syn_sent`).
    pub(crate) fn send_syn(&self) {
        let mut opts = [0u8; SYN_OPTS_MAX];
        let n = syn_option_blob(mss_for(self.local_ip) as u16, true, true, &mut opts);
        send_segment_opts(
            &SegmentMeta {
                local_ip: self.local_ip,
                dst_ip: self.remote_ip,
                src_port: self.local_port,
                dst_port: self.remote_port,
                // The SYN sits at ISS == snd_una; snd_nxt is already
                // past it (the SYN's phantom byte).
                seq: self.snd_una,
                ack: 0,
                flags: TCP_SYN,
                // Same fixed advertisement as the SYN-ACK path — the
                // ring is empty pre-handshake.
                window: RX_RING_BYTES as u16,
            },
            &[],
            &opts[..n],
        );
    }

    /// Retransmit the SYN (`SynSent`) and re-arm the lifecycle timer
    /// with one more step of backoff — the active-open analogue of
    /// `retransmit_fin`. Called by `on_tcp_tick` once the deadline
    /// has passed and the `SYN_RETX_MAX` budget remains.
    pub(crate) fn retransmit_syn(&mut self, now: u64) {
        crate::diag::COUNTERS.syn_retransmits.bump();
        self.send_syn();
        // Karn's algorithm: a retransmitted SYN makes the SYN-RTT
        // sample ambiguous — drop the anchor.
        self.rtt_anchor_active = false;
        self.fin_retx_count = self.fin_retx_count.saturating_add(1);
        self.arm_fin_timer(now);
    }
}
