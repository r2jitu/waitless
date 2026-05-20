// RFC 6298 retransmission tick — walks every connection on the
// current core looking for armed RTO deadlines. The per-conn
// estimator + ring lives on `TcpConnection` (see `state.rs`); this
// module just drives the per-core poll cadence.

use crate::pool::{conn_ptr, free_connection, pool_capacity};
use crate::state::RTX_MAX_RETRIES;

/// Drive the RFC 6298 retransmission timers for the current core's
/// connection pool. Called from the net poll loop (`sched::poll`) at
/// a coarse cadence: every connection whose RTO deadline has passed
/// gets its oldest unacked segment retransmitted, or is torn down
/// once it has been retransmitted `RTX_MAX_RETRIES` times with no
/// intervening progress (RFC 9293 §3.8.3 — give up on a dead peer).
pub fn on_rtx_tick() {
    let core = kernel_core::cpu_id();
    let now = kernel_core::clock::now_ms();
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership — only this core touches its pool.
        let c = unsafe { &mut *conn_ptr(core, i) };
        if c.rtx_deadline_ms == 0 || now < c.rtx_deadline_ms {
            continue;
        }
        if c.rtx_backoff >= RTX_MAX_RETRIES {
            free_connection(core, i);
            continue;
        }
        c.retransmit_oldest(now);
    }
}

/// True if any connection on the current core has an armed RTO timer.
/// The event loop consults this before going fully idle so a core
/// with a pending retransmission does not sleep past the deadline.
pub fn has_armed_rtx_timers() -> bool {
    let core = kernel_core::cpu_id();
    let cap = pool_capacity(core);
    for i in 0..cap {
        // SAFETY: per-core ownership.
        let c = unsafe { &*conn_ptr(core, i) };
        if c.rtx_deadline_ms != 0 {
            return true;
        }
    }
    false
}
