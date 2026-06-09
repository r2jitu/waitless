//! Progress-aware TX-ring stall circuit breaker — the single home for
//! the full-pool acquire-spin policy shared by virtio-net and gve-GQI.
//!
//! ## The problem
//!
//! When a driver's TX pool is full, the acquire path spin-drains:
//! kick the device, drain completions, re-scan for a freed slot. Under
//! normal saturation a slot frees within microseconds and the spin
//! beats the drop+retransmit cost. But the spin MUST be bounded: if
//! the device stops draining the ring entirely, an unbounded spin
//! hard-hangs the whole core synchronously — no executor yield, no RX,
//! no timers. That is the Apple-HVF h3-`/stream` wedge (the guest's
//! view of the TX `used->idx` went stale, completions were never
//! observed, and the old unbounded loop pegged the core forever).
//!
//! ## The predicate (and why it must be progress-based)
//!
//! "Stalled" means **no forward progress** — the queue's completion
//! counter frozen for the whole budget window — NOT "this call didn't
//! get a slot". At NIC line rate the pool is legitimately full
//! essentially always while the device drains continuously (an n2/GQI
//! A/B measured 498M full-pool laps at ~15 Gbps with the ring
//! perfectly healthy), and spot-host scheduling produces routine
//! 1-3 ms gaps between completion write-backs. A claim-based 1 ms
//! budget + blind cooldown misfired 69,941 times on that suite; this
//! progress-based version fired zero times on the identical load.
//!
//! So: the spin budget restarts every time the progress counter
//! advances — saturation-with-progress spins losslessly (ordinary
//! back-pressure) — and only a queue with ZERO completions for
//! [`STALL_BUDGET_US`] trips. A trip arms a fast-fail cooldown stamped
//! with the frozen counter value, so the cooldown self-clears the
//! instant completions resume: a recovered ring drops at most the
//! sends attempted while it was actually frozen.

use core::sync::atomic::{AtomicU64, Ordering};

/// gve-GQI's budget: microseconds of ZERO completions before the queue
/// is declared stalled. The budget is a `spin` PARAMETER, not policy —
/// it encodes the host's completion-latency distribution. GQI on GCE
/// spot rides out routine 1-3 ms completion-write-back gaps, so 5 ms
/// (validated: 0 trips at line rate). virtio on nested-KVM/HVF hosts
/// passes a tighter budget instead: vhost threads pause for multiple
/// ms ROUTINELY under host oversubscription, and spinning through
/// every pause blocks the event loop (measured ~4% static64k rps),
/// while bailing early is cheap (chain sends requeue; the cooldown
/// self-clears on the first completion).
pub const STALL_BUDGET_US: u64 = 5_000;

/// Fast-fail window after a trip: while armed (and the queue still
/// frozen), full-pool acquires fail after one cheap drain+claim
/// attempt instead of spinning, keeping each call O(µs) so
/// retransmission/PTO timers firing into the dead path drain as a
/// brief burst and the event loop stays live.
pub const STALL_COOLDOWN_US: u64 = 10_000;

/// Per-queue breaker state. Embed one per TX queue (gve-GQI puts it on
/// `TxQueue`); a driver whose pools can't stall independently may
/// share one static (virtio-net: a real stall only ever arises on the
/// single contended/coherence-starved ring).
pub struct TxStallBreaker {
    /// Fast-fail deadline in the caller's clock units; 0 = not stalled.
    until: AtomicU64,
    /// Progress-counter value stamped when the cooldown was armed; the
    /// cooldown self-clears the moment the live value differs.
    progress_snap: AtomicU64,
}

impl TxStallBreaker {
    pub const fn new() -> Self {
        Self {
            until: AtomicU64::new(0),
            progress_snap: AtomicU64::new(0),
        }
    }

    /// Run the bounded, progress-aware spin for a full TX pool. Call
    /// AFTER one failed fast-path claim, so the healthy hot path never
    /// touches the clock or this cell.
    ///
    /// * `budget_us` — µs of zero progress before declaring a stall;
    ///   driver-chosen for its host's completion-latency tail (see
    ///   [`STALL_BUDGET_US`]).
    /// * `cycles_per_us` / `now` — the caller's monotonic cycle clock.
    /// * `progress` — a monotonic per-queue completion counter that
    ///   advances iff the device completed work (gve-GQI: `done_cnt`;
    ///   virtio: the device-written `used->idx`, zero-extended). Only
    ///   equality is tested, so narrow counters that wrap are fine.
    /// * `lap` — one kick + drain + claim attempt; `Some` = got a slot.
    ///
    /// Returns `None` when the queue is stalled — frozen for
    /// [`STALL_BUDGET_US`], or a previously-armed cooldown is still in
    /// force. The caller translates `None` into ring-full back-pressure
    /// (chain senders requeue their unsent tail; control/rtx segments
    /// RTO-recover) and bumps its own stall-drop diagnostics.
    pub fn spin<T>(
        &self,
        budget_us: u64,
        cycles_per_us: u64,
        mut now: impl FnMut() -> u64,
        mut progress: impl FnMut() -> u64,
        mut lap: impl FnMut() -> Option<T>,
    ) -> Option<T> {
        let t0 = now();

        // Cooldown: a prior call found the queue frozen. If the device
        // has produced even one completion since (counter moved off the
        // stamped value), the queue is alive — clear and spin normally.
        // Otherwise fast-fail; the caller's failed fast-path claim was
        // the one cheap attempt.
        let until = self.until.load(Ordering::Relaxed);
        if until != 0 {
            let frozen = progress() == self.progress_snap.load(Ordering::Relaxed);
            if frozen && t0 < until {
                return None;
            }
            self.until.store(0, Ordering::Relaxed);
        }

        // Spin, bounded by lack of PROGRESS: the budget window restarts
        // every time the completion counter advances.
        let budget = cycles_per_us.saturating_mul(budget_us);
        let mut window_start = t0;
        let mut seen = progress();
        loop {
            if let Some(t) = lap() {
                return Some(t);
            }
            let p = progress();
            let t = now();
            if p != seen {
                // Forward progress — the device is draining (the claim
                // can still fail when e.g. only another pool's slots
                // completed). Re-arm the budget and keep spinning: this
                // is ordinary line-rate back-pressure, not a stall.
                seen = p;
                window_start = t;
                continue;
            }
            if t.wrapping_sub(window_start) > budget {
                // Zero completions for the whole window: the queue is
                // dead. Arm the fast-fail cooldown, stamped with the
                // frozen counter so it self-clears on recovery.
                self.progress_snap.store(seen, Ordering::Relaxed);
                self.until.store(
                    t.wrapping_add(cycles_per_us.saturating_mul(STALL_COOLDOWN_US)),
                    Ordering::Relaxed,
                );
                return None;
            }
        }
    }
}

impl Default for TxStallBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// Harness: a scripted clock (1 cycle == 1 µs ⇒ `cycles_per_us`=1)
    /// and progress counter. Each `lap` advances the clock by `lap_us`.
    struct Sim {
        clock: Cell<u64>,
        progress: Cell<u64>,
        laps: Cell<u64>,
    }
    impl Sim {
        fn new() -> Self {
            Self {
                clock: Cell::new(1000),
                progress: Cell::new(7),
                laps: Cell::new(0),
            }
        }
    }

    /// Saturated-but-draining queue: claims keep failing but progress
    /// advances every lap — must spin losslessly (no trip) until the
    /// claim finally succeeds, and must leave no cooldown armed.
    #[test]
    fn progress_resets_budget_and_never_trips() {
        let b = TxStallBreaker::new();
        let s = Sim::new();
        // Each lap takes 4ms (just under the 5ms budget) but advances
        // progress, so the window restarts; succeed on lap 10 — total
        // elapsed 40ms, far past a naive from-entry budget.
        let got = b.spin(
            5_000,
            1,
            || s.clock.get(),
            || s.progress.get(),
            || {
                s.laps.set(s.laps.get() + 1);
                s.clock.set(s.clock.get() + 4_000);
                s.progress.set(s.progress.get() + 32);
                if s.laps.get() == 10 { Some(s.laps.get()) } else { None }
            },
        );
        assert_eq!(got, Some(10));
        assert_eq!(b.until.load(Ordering::Relaxed), 0, "no cooldown armed");
    }

    /// Frozen queue: progress never moves — trips once the budget
    /// elapses and arms the cooldown; the next call fast-fails with
    /// zero laps.
    #[test]
    fn frozen_queue_trips_then_fast_fails() {
        let b = TxStallBreaker::new();
        let s = Sim::new();
        let got: Option<()> = b.spin(
            5_000,
            1,
            || s.clock.get(),
            || s.progress.get(),
            || {
                s.laps.set(s.laps.get() + 1);
                s.clock.set(s.clock.get() + 1_000); // 1ms/lap, frozen
                None
            },
        );
        assert_eq!(got, None);
        let trip_laps = s.laps.get();
        assert!(trip_laps >= 5, "spun the full 5ms budget, got {trip_laps}");
        assert_ne!(b.until.load(Ordering::Relaxed), 0, "cooldown armed");

        // Still frozen, still inside the cooldown window: zero laps.
        let got: Option<()> =
            b.spin(5_000, 1, || s.clock.get(), || s.progress.get(), || {
                s.laps.set(s.laps.get() + 1);
                None
            });
        assert_eq!(got, None);
        assert_eq!(s.laps.get(), trip_laps, "fast-fail does no laps");
    }

    /// Cooldown self-clears the moment completions resume — even well
    /// before the deadline — and the spin then proceeds normally.
    #[test]
    fn cooldown_self_clears_on_progress() {
        let b = TxStallBreaker::new();
        let s = Sim::new();
        // Trip it.
        let _: Option<()> = b.spin(
            5_000,
            1,
            || s.clock.get(),
            || s.progress.get(),
            || {
                s.clock.set(s.clock.get() + 6_000);
                None
            },
        );
        assert_ne!(b.until.load(Ordering::Relaxed), 0);
        // Device recovers: one completion. Next spin clears the
        // cooldown (no waiting out the deadline) and claims.
        s.progress.set(s.progress.get() + 1);
        let got = b.spin(5_000, 1, || s.clock.get(), || s.progress.get(), || Some(42));
        assert_eq!(got, Some(42));
        assert_eq!(b.until.load(Ordering::Relaxed), 0, "cooldown cleared");
    }

    /// A frozen queue past the cooldown deadline re-probes: the spin
    /// runs again (laps happen) and re-arms on the still-dead queue.
    #[test]
    fn cooldown_expiry_reprobes_and_rearms() {
        let b = TxStallBreaker::new();
        let s = Sim::new();
        let _: Option<()> = b.spin(
            5_000,
            1,
            || s.clock.get(),
            || s.progress.get(),
            || {
                s.clock.set(s.clock.get() + 6_000);
                None
            },
        );
        let first_until = b.until.load(Ordering::Relaxed);
        assert_ne!(first_until, 0);
        // Jump past the deadline; queue still frozen.
        s.clock.set(first_until + 1);
        let _: Option<()> = b.spin(
            5_000,
            1,
            || s.clock.get(),
            || s.progress.get(),
            || {
                s.laps.set(s.laps.get() + 1);
                s.clock.set(s.clock.get() + 6_000);
                None
            },
        );
        assert!(s.laps.get() > 0, "expired cooldown re-probes with real laps");
        let second_until = b.until.load(Ordering::Relaxed);
        assert!(second_until > first_until, "re-armed with a later deadline");
    }
}
