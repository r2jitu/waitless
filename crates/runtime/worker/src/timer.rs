// crates/runtime/worker/src/timer.rs — Per-worker timer wheel.
//
// Simple single-level timer wheel with fixed tick granularity.
// Each worker has its own wheel (a fixed `[Slot; WHEEL_SIZE]` array) —
// no synchronization needed for insert/fire on the owning worker.
//
// There is no cross-worker submission queue: a timer is only ever
// inserted by its owning worker. (An earlier draft of this header
// described a `PendingTimers` MPSC queue + intrusive free-list — neither
// exists; kept simple until a concrete cross-worker consumer shows up.)

// When compiled as the `timer_test` crate root (std), `alloc` isn't
// in the extern prelude the way it is via lib.rs's declaration.
extern crate alloc;
use alloc::vec::Vec;

/// Number of slots in the wheel. Must be a power of 2.
const WHEEL_SIZE: usize = 256;
const WHEEL_MASK: usize = WHEEL_SIZE - 1;

/// A timer entry: fires at a specific tick, calls a function.
#[derive(Clone, Copy)]
pub struct Timer {
    pub deadline: u64,
    pub func: fn(usize),
    pub arg: usize,
}

/// Inline timers per slot before spilling to the heap. Sized so
/// every light/typical load runs with zero timer-wheel heap use.
const INLINE_PER_SLOT: usize = 8;

/// Slot in the wheel — a bag of timers whose deadlines share a
/// residue mod WHEEL_SIZE. The first `INLINE_PER_SLOT` live inline;
/// beyond that they spill to a heap `Vec`. Unbounded capacity
/// matters: the previous hard 8-per-slot cap made `insert` fail
/// under same-µs deadline bursts (thousands of keep-alive conns
/// re-arming 30 s recv timeouts in one event-loop batch), and the
/// `Sleep` fallback for a failed insert fires the timeout
/// immediately — which closed *live* HTTP connections en masse and
/// collapsed throughput above ~4 K concurrent conns (GCE,
/// 2026-06-11). Spill storage is dropped once the spill drains, so
/// the heap returns to its baseline after a burst (the shutdown
/// leak gate checks exactly that).
struct Slot {
    inline: [Option<Timer>; INLINE_PER_SLOT],
    /// `inline[..inline_len]` are `Some`; no holes.
    inline_len: usize,
    spill: Vec<Timer>,
    /// Lower bound on the earliest deadline in this slot;
    /// `u64::MAX` when empty. May go stale-low after a cancel
    /// (never stale-high), costing at most one wasted scan.
    /// Lets `advance` skip far-future slots in O(1) — with tens of
    /// thousands of long (30 s) timers resident, scanning every
    /// slot's contents each µs-tick would dwarf the real work.
    min_deadline: u64,
}

impl Slot {
    const fn new() -> Self {
        Slot {
            inline: [None; INLINE_PER_SLOT],
            inline_len: 0,
            spill: Vec::new(),
            min_deadline: u64::MAX,
        }
    }

    #[must_use = "an ignored `false` silently drops the timer"]
    fn insert(&mut self, timer: Timer) -> bool {
        if self.inline_len < INLINE_PER_SLOT {
            self.inline[self.inline_len] = Some(timer);
            self.inline_len += 1;
        } else {
            // try_reserve keeps the no-panic-on-OOM admission
            // discipline: a full heap degrades to "timer refused"
            // (the caller's documented fallback) instead of aborting.
            if self.spill.len() == self.spill.capacity() && self.spill.try_reserve(8).is_err() {
                return false;
            }
            self.spill.push(timer);
        }
        self.min_deadline = self.min_deadline.min(timer.deadline);
        true
    }

    fn is_empty(&self) -> bool {
        self.inline_len == 0 && self.spill.is_empty()
    }

    /// Drop spill storage once drained (heap back to baseline).
    fn release_spill_if_empty(&mut self) {
        if self.spill.is_empty() && self.spill.capacity() != 0 {
            self.spill = Vec::new();
        }
    }
}

/// Per-core timer wheel.
///
/// The slot array lives on the heap (`Vec`), not inline: an inline
/// `[Slot; 256]` is a ~60 KB by-value temporary at construction,
/// which is boot-stack-hazard territory on aarch64 (see
/// `reference_const_fn_boot_stack`). `new()` is therefore not
/// `const` — wheels are only ever built at `executor::init` time,
/// after the heap is up.
pub struct TimerWheel {
    slots: Vec<Slot>,
    current_tick: u64,
    /// Running count of live timers. Maintained by `insert`/`cancel`/
    /// `advance` so `count()` is O(1) — and so `advance` can fast-path
    /// an empty wheel without walking every tick from 0 on first call.
    total: usize,
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerWheel {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(WHEEL_SIZE);
        slots.resize_with(WHEEL_SIZE, Slot::new);
        TimerWheel {
            slots,
            current_tick: 0,
            total: 0,
        }
    }

    /// Insert a timer that fires at the given deadline tick.
    ///
    /// Returns `false` only if the slot's spill allocation failed
    /// (heap exhausted). Callers MUST check and handle the drop — a
    /// silent `false` on the timer path will hang network
    /// retransmit logic.
    #[must_use = "an ignored `false` silently drops the timer"]
    pub fn insert(&mut self, timer: Timer) -> bool {
        let slot_idx = (timer.deadline as usize) & WHEEL_MASK;
        if self.slots[slot_idx].insert(timer) {
            self.total += 1;
            true
        } else {
            false
        }
    }

    /// Cancel a timer by arg value. Returns true if found and removed.
    ///
    /// O(WHEEL_SIZE × MAX_PER_SLOT). Prefer `cancel_at` when the
    /// caller knows the deadline — at one cancel per `timeout_us`-
    /// wrapped recv on a busy listener that's millions of slot-
    /// scans per second.
    pub fn cancel(&mut self, arg: usize) -> bool {
        for slot in self.slots.iter_mut() {
            if Self::cancel_in_slot(slot, arg) {
                self.total -= 1;
                return true;
            }
        }
        false
    }

    /// Cancel a timer whose `(deadline, arg)` pair matches. The
    /// wheel hashes timers by `deadline & WHEEL_MASK`, so providing
    /// the deadline turns cancel into an O(MAX_PER_SLOT) lookup
    /// instead of an O(WHEEL_SIZE × MAX_PER_SLOT) scan. Hot-path
    /// callers (`Sleep::drop`, the per-recv timeout in keep-alive
    /// HTTP) all carry the deadline already.
    pub fn cancel_at(&mut self, deadline: u64, arg: usize) -> bool {
        let slot_idx = (deadline as usize) & WHEEL_MASK;
        if Self::cancel_in_slot(&mut self.slots[slot_idx], arg) {
            self.total -= 1;
            return true;
        }
        false
    }

    fn cancel_in_slot(slot: &mut Slot, arg: usize) -> bool {
        let mut found = false;
        for i in 0..slot.inline_len {
            if slot.inline[i].is_some_and(|t| t.arg == arg) {
                // Swap-remove within the inline region.
                slot.inline_len -= 1;
                slot.inline[i] = slot.inline[slot.inline_len].take();
                found = true;
                break;
            }
        }
        if !found {
            for i in 0..slot.spill.len() {
                if slot.spill[i].arg == arg {
                    slot.spill.swap_remove(i);
                    slot.release_spill_if_empty();
                    found = true;
                    break;
                }
            }
        }
        if found {
            // `min_deadline` may now be stale-low (if the removed
            // timer was the min) — safe: advance over-scans once
            // and recomputes. Reset only the known-empty case.
            if slot.is_empty() {
                slot.min_deadline = u64::MAX;
            }
        }
        found
    }

    /// Advance to `now` and fire all expired timers.
    /// Calls each timer's function inline. Returns number of timers fired.
    pub fn advance(&mut self, now: u64) -> usize {
        // Fast path: empty wheel, jump current_tick forward instead of
        // walking every slot from the last advance (could be millions
        // of ticks on first call after boot — `now` is "µs since boot").
        if self.total == 0 {
            self.current_tick = now.saturating_add(1);
            return 0;
        }
        let mut fired = 0;
        while self.current_tick <= now {
            let slot_idx = (self.current_tick as usize) & WHEEL_MASK;
            let slot = &mut self.slots[slot_idx];

            // O(1) skip for slots holding only far-future timers —
            // the common case when long recv timeouts dominate the
            // wheel. `min_deadline` is a lower bound, so a skip is
            // never wrong; a stale-low bound just means one scan
            // that fires nothing and tightens it back up.
            if !slot.is_empty() && slot.min_deadline <= now {
                let mut new_min = u64::MAX;
                let mut i = 0;
                while i < slot.inline_len {
                    let Some(timer) = slot.inline[i] else {
                        i += 1;
                        continue;
                    };
                    if timer.deadline <= now {
                        // Swap-remove within the inline region.
                        slot.inline_len -= 1;
                        slot.inline[i] = slot.inline[slot.inline_len].take();
                        self.total -= 1;
                        (timer.func)(timer.arg);
                        fired += 1;
                        // Don't increment i — swapped element needs checking
                    } else {
                        new_min = new_min.min(timer.deadline);
                        i += 1;
                    }
                }
                let mut i = 0;
                while i < slot.spill.len() {
                    let timer = slot.spill[i];
                    if timer.deadline <= now {
                        slot.spill.swap_remove(i);
                        self.total -= 1;
                        (timer.func)(timer.arg);
                        fired += 1;
                    } else {
                        new_min = new_min.min(timer.deadline);
                        i += 1;
                    }
                }
                slot.release_spill_if_empty();
                slot.min_deadline = new_min;
            }
            self.current_tick += 1;
        }
        fired
    }

    /// Number of timers currently scheduled.
    pub fn count(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    // Test handlers count fires through a per-test `Counters` struct
    // whose address is passed as the Timer's `arg`. Each test owns its
    // own Counters, so cargo test's parallel runner won't race on a
    // global counter the way the previous `static FIRE_COUNT` did.

    struct Counters {
        fired: AtomicU32,
        last_arg: AtomicU32,
    }

    impl Counters {
        fn new() -> Box<Self> {
            Box::new(Counters {
                fired: AtomicU32::new(0),
                last_arg: AtomicU32::new(0),
            })
        }
    }

    fn mk_timer(deadline: u64, user_arg: u32, c: &Counters) -> Timer {
        // `user_arg` is passed to the handler via Counters.last_arg so
        // tests can verify which timer fired; Timer.arg is reserved
        // for the Counters pointer.
        c.last_arg.store(user_arg, Ordering::Relaxed);
        Timer {
            deadline,
            func: bump,
            arg: c as *const Counters as usize,
        }
    }

    fn bump(arg: usize) {
        let c = unsafe { &*(arg as *const Counters) };
        c.fired.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn insert_and_fire() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(mk_timer(5, 42, &c)));
        assert_eq!(wheel.count(), 1);

        // Advance to tick 4 — timer shouldn't fire
        wheel.advance(4);
        assert_eq!(c.fired.load(Ordering::Relaxed), 0);

        // Advance to tick 5 — timer fires
        wheel.advance(5);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1);
        assert_eq!(c.last_arg.load(Ordering::Relaxed), 42);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn multiple_timers_same_slot() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        // Deadlines 256 apart map to the same slot (WHEEL_SIZE=256)
        assert!(wheel.insert(mk_timer(10, 1, &c)));
        assert!(wheel.insert(mk_timer(10, 2, &c)));
        assert_eq!(wheel.count(), 2);
        wheel.advance(10);
        assert_eq!(c.fired.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cancel_timer() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        let timer = mk_timer(100, 99, &c);
        let arg = timer.arg;
        assert!(wheel.insert(timer));
        assert_eq!(wheel.count(), 1);
        assert!(wheel.cancel(arg));
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn cancel_nonexistent() {
        let mut wheel = TimerWheel::new();
        assert!(!wheel.cancel(42));
    }

    #[test]
    fn fire_order() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(mk_timer(1, 10, &c)));
        assert!(wheel.insert(mk_timer(3, 30, &c)));
        assert!(wheel.insert(mk_timer(2, 20, &c)));

        wheel.advance(3);
        // All three should have fired
        assert_eq!(c.fired.load(Ordering::Relaxed), 3);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn same_slot_burst_all_fire() {
        // Regression: the old fixed [Timer; 8] slots dropped the 9th
        // same-residue insert, which `Sleep` turned into an instant
        // (spurious) timeout — closing live keep-alive connections
        // under load. Slots now grow; a same-µs burst must all land
        // and all fire on time, not early.
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        for _ in 0..1000 {
            assert!(wheel.insert(mk_timer(300, 7, &c)));
        }
        assert_eq!(wheel.count(), 1000);
        wheel.advance(299);
        assert_eq!(c.fired.load(Ordering::Relaxed), 0, "must not fire early");
        wheel.advance(300);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1000);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn far_future_same_slot_not_fired_early() {
        // A near timer and a far timer sharing a slot (deadlines 256
        // apart): advancing past the near one fires it alone, and the
        // recomputed slot min must still let the far one fire later.
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(mk_timer(10, 1, &c)));
        assert!(wheel.insert(mk_timer(10 + 256, 2, &c)));
        wheel.advance(20);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1);
        assert_eq!(wheel.count(), 1);
        wheel.advance(10 + 256);
        assert_eq!(c.fired.load(Ordering::Relaxed), 2);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn cancel_min_then_fire_rest() {
        // Cancelling the slot's earliest timer leaves min_deadline
        // stale-low; the next advance must tolerate that (one wasted
        // scan) and still fire the remaining timer at its deadline.
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        let near = mk_timer(50, 1, &c);
        let near_arg_marker = near.arg;
        assert!(wheel.insert(near));
        assert!(wheel.insert(Timer { deadline: 50 + 512, ..near }));
        assert!(wheel.cancel_at(50, near_arg_marker));
        // Both timers share `arg` (the Counters ptr); cancel_at removed
        // one of them. Advance through the near deadline: nothing due.
        wheel.advance(100);
        assert_eq!(wheel.count(), 1);
        wheel.advance(50 + 512);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn advance_past_deadline() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(mk_timer(5, 55, &c)));
        // Advance far past the deadline
        wheel.advance(100);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1);
    }
}
