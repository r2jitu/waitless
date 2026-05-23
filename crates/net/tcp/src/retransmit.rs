// Per-core TCP timer tick. Walks every connection on the current core
// and services the per-conn timers: RFC 6298 data retransmission, the
// RFC 9293 §3.8.6.1 zero-window persist probe, and the connection-
// lifecycle timers (the FIN retransmit in `FinWait1` / `LastAck`, and
// the `TimeWait` 2×MSL drop). The per-conn estimator, retransmit ring,
// persist, and lifecycle-timer methods live on `TcpConnection` (see
// `state.rs`); this module just drives the per-core poll cadence.

use crate::pool::{TICK_HEAD, conn_ptr, free_connection};
use crate::state::{FIN_RETX_MAX, NULL_SLOT, PERSIST_MAX_PROBES, RTX_MAX_RETRIES, TcpState};

/// Drive the per-core TCP timers for the current core's connection
/// pool. Called from the net poll loop (`sched::poll`) at a coarse
/// cadence:
///
///   * RFC 6298 data retransmission — a connection whose RTO deadline
///     has passed gets its oldest unacked segment retransmitted, or is
///     torn down once it has been retransmitted `RTX_MAX_RETRIES`
///     times with no intervening progress (RFC 9293 §3.8.3).
///   * Zero-window persist — a connection whose peer has kept its
///     receive window shut gets a probe (RFC 9293 §3.8.6.1), or is
///     aborted after `PERSIST_MAX_PROBES` unanswered probes.
///   * FIN retransmission — a `FinWait1` (active close) or `LastAck`
///     (passive close) connection whose FIN went unacknowledged gets
///     it retransmitted with exponential backoff, or is forced shut
///     after `FIN_RETX_MAX` attempts.
///   * `TimeWait` expiry — a connection that completed its active
///     close is freed once the 2×MSL hold has elapsed.
pub fn on_tcp_tick() {
    let core = kernel_core::cpu_id();
    let now = kernel_core::clock::now_ms();
    crate::diag::COUNTERS.tick_calls.bump();
    let mut iters: u64 = 0;
    let mut armed: u64 = 0;

    // Walk the per-core armed-timer list, rebuilding it as we go.
    // Slots whose timers fired and re-armed (the common case for
    // long-lived flows) get re-linked at the head of the new list;
    // slots whose timers all cleared (peer ACK'd everything, conn
    // closed cleanly, …) drop off via `tick_in_list = false`. Same-
    // core, no atomics — TICK_HEAD is just an UnsafeCell<u16>.
    //
    // SAFETY: per-core ownership for both the head cell and every
    // slot pointer; nothing else runs concurrently on this core.
    let head_cell = TICK_HEAD.at(core);
    let old_head = unsafe { *head_cell.get() };
    unsafe { *head_cell.get() = NULL_SLOT };

    let mut new_head: u16 = NULL_SLOT;
    let mut walker = old_head;
    while walker != NULL_SLOT {
        iters += 1;
        let i = walker as usize;
        // Snapshot `next` BEFORE any mutation — the timer handlers
        // below may call `free_connection`, which resets the slot
        // (including `tick_next`). The snapshot keeps the walk safe.
        let next = unsafe { (*conn_ptr(core, i)).tick_next };
        let c = unsafe { &mut *conn_ptr(core, i) };
        armed += 1;

        // RFC 6298 data retransmission.
        if c.rtx_deadline_ms != 0 && now >= c.rtx_deadline_ms {
            if c.rtx_backoff >= RTX_MAX_RETRIES {
                crate::diag::record_teardown(crate::diag::TeardownReason::RtxGiveup, c.state);
                free_connection(core, i);
                continue;
            }
            crate::diag::COUNTERS.data_retransmits.bump();
            c.retransmit_oldest(now);
        }

        // RFC 9293 §3.8.6.1 zero-window persist. Probe a peer that
        // has kept its receive window shut; abort the connection once
        // `PERSIST_MAX_PROBES` probes go unanswered.
        if c.persist_deadline_ms != 0 && now >= c.persist_deadline_ms {
            if c.state == TcpState::Established {
                if c.persist_backoff >= PERSIST_MAX_PROBES {
                    crate::diag::record_teardown(
                        crate::diag::TeardownReason::PersistGiveup,
                        c.state,
                    );
                    free_connection(core, i);
                    continue;
                }
                c.send_window_probe(now);
            } else {
                // The timer outlived `Established` (the sending task
                // was cancelled) — disarm it rather than probe.
                c.persist_deadline_ms = 0;
            }
        }

        // Connection-lifecycle timers — the FIN retransmit and the
        // TimeWait 2×MSL drop.
        if c.lifecycle_deadline_ms != 0 && now >= c.lifecycle_deadline_ms {
            match c.state {
                TcpState::FinWait1 | TcpState::LastAck => {
                    if c.fin_retx_count >= FIN_RETX_MAX {
                        // The peer never acknowledged our FIN — give
                        // up rather than leak the half-closed slot.
                        crate::diag::record_teardown(
                            crate::diag::TeardownReason::FinGiveup,
                            c.state,
                        );
                        free_connection(core, i);
                    } else {
                        crate::diag::COUNTERS.fin_retransmits.bump();
                        c.retransmit_fin(now);
                    }
                }
                TcpState::TimeWait => {
                    // 2×MSL elapsed — the window for a delayed
                    // duplicate or a retransmitted peer FIN is over.
                    crate::diag::record_teardown(
                        crate::diag::TeardownReason::TimeWaitExpiry,
                        TcpState::TimeWait,
                    );
                    free_connection(core, i);
                }
                // A lifecycle deadline armed on a state that no longer
                // owns one — disarm defensively.
                _ => c.lifecycle_deadline_ms = 0,
            }
        }

        // Lazy unlink: re-link the slot into the new list only if
        // any timer is still armed after processing. Calls to
        // `arm_for_tick` from within the handlers above are no-ops
        // (`tick_in_list` is still true), so the in_list flag stays
        // accurate for the steady-state re-arm case.
        let still_armed = c.rtx_deadline_ms != 0
            || c.persist_deadline_ms != 0
            || c.lifecycle_deadline_ms != 0;
        if still_armed {
            c.tick_next = new_head;
            new_head = walker;
        } else {
            c.tick_in_list = false;
            // tick_next is left as junk; the next arm_for_tick
            // overwrites it before linking back into the list.
        }

        walker = next;
    }
    unsafe { *head_cell.get() = new_head };

    crate::diag::COUNTERS.tick_iterations.add(iters);
    crate::diag::COUNTERS.tick_armed_seen.add(armed);
}

/// True if any connection on the current core has an armed timer — an
/// RFC 6298 retransmission deadline, a zero-window persist deadline,
/// or a connection-lifecycle deadline. The event loop consults this
/// before going fully idle so a core with a pending timer does not
/// sleep past its deadline.
pub fn has_armed_timers() -> bool {
    let core = kernel_core::cpu_id();
    // O(1): the armed-timer list head is non-`NULL_SLOT` iff some
    // slot has at least one deadline set. Previously this scanned
    // the per-core pool until finding the first armed slot —
    // bounded by the open-conn density, which collapsed when the
    // event loop tried to go idle on a sparse pool.
    let head_cell = TICK_HEAD.at(core);
    // SAFETY: per-core ownership; only the owning core reads/writes.
    let head = unsafe { *head_cell.get() };
    head != NULL_SLOT
}
