//! Cross-core control lane — the net-stack side.
//!
//! `kernel_core` owns the mechanism: a per-core `ctrl_inbox` (the same
//! lock-free MPSC the Tier-2 RX lane uses) over the shared
//! `ctrl_node_pool`, carrying `CtrlMsg` values. This module owns the
//! policy — who sends what, and what a drained message does.
//!
//! First consumer: wrong-core PMTUD reports. A multi-queue NIC
//! RSS-hashes an ICMP error by its own header (a 2-tuple), not by the
//! TCP 4-tuple it quotes, so Fragmentation-Needed / Packet-Too-Big
//! usually lands on a core that doesn't own the flow and the MSS hint
//! used to be dropped on the floor (`pmtu_dropped`). The flow→core map
//! is the NIC's RSS indirection, which we don't model — so the origin
//! core *broadcasts* the report to every other core and the owner
//! (whichever it is) applies it; everyone else's lookup misses and
//! ignores it. Broadcast is the right shape here: reports are rare,
//! idempotent (apply-only-lower, re-gated on the owning core), and
//! ownership-blind delivery avoids inventing a flow-steering table for
//! a hint. A future consumer with real fan-out volume should add an
//! ownership map instead of copying the broadcast.

use kernel_bare::percpu::{self, CtrlMsg, PerCore};
use net_types::IpAddr;

use crate::{sched, tcp};

/// Broadcast a Path-MTU report that missed this core's connection
/// table to every other core. No-op on a single-core system (the miss
/// then just means a stale or forged report).
pub(crate) fn broadcast_path_mtu(
    remote_ip: IpAddr,
    remote_port: u16,
    local_port: u16,
    seq: u32,
    candidate_mss: u16,
) {
    let cores = percpu::num_cores();
    if cores <= 1 {
        return;
    }
    let me = kernel_bare::cpu_id();
    crate::diag::COUNTERS.pmtu_routed.bump();
    for id in 0..cores {
        if id == me {
            continue;
        }
        let msg = CtrlMsg::PathMtu {
            remote_ip,
            remote_port,
            local_port,
            seq,
            candidate_mss,
        };
        // SAFETY: `percpu::init()` ran before any AP started; `id` is
        // bounded by `num_cores()`.
        let core = unsafe { percpu::get(id) };
        if percpu::ctrl_node_pool().distribute(&core.ctrl_inbox, msg).is_err() {
            // Pool momentarily exhausted — drop the rest of the
            // fan-out. Every control message is an advisory hint whose
            // trigger re-fires (here: the next too-big retransmit
            // elicits a fresh ICMP error).
            crate::diag::COUNTERS.ctrl_dropped.bump();
            return;
        }
        sched::WAKEUP
            .at(id)
            .store(true, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Drain this core's control inbox, dispatching each message. Called
/// from the event loop's drain stage alongside the RX inbox; returns
/// whether any message was processed.
pub(crate) fn drain(core: &PerCore) -> bool {
    core.ctrl_inbox.drain_each(percpu::ctrl_node_pool(), |msg| match msg {
        CtrlMsg::PathMtu {
            remote_ip,
            remote_port,
            local_port,
            seq,
            candidate_mss,
        } => {
            // Re-runs every RFC 5927 gate on this core. `Applied` /
            // `Rejected` bump the tcp counters; `NoConn` is the
            // expected outcome on every recipient that doesn't own the
            // flow (ownership-blind broadcast) — deliberately silent.
            let _ = tcp::note_path_mtu(remote_ip, remote_port, local_port, seq, candidate_mss);
        }
    }) > 0
}
