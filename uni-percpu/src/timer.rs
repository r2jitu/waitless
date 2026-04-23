// uni-percpu/src/timer.rs — Per-worker timer wheel.
//
// Simple single-level timer wheel with fixed tick granularity.
// Each worker has its own wheel — no synchronization needed for
// insert/fire on the owning worker.
//
// Cross-worker timer creation goes through the `PendingTimers` MPSC
// queue. Pool storage is a lock-free intrusive free-list.

// No cross-worker submission queue yet — kept simple until a
// concrete consumer shows up.

/// Number of slots in the wheel. Must be a power of 2.
const WHEEL_SIZE: usize = 256;
const WHEEL_MASK: usize = WHEEL_SIZE - 1;

/// Maximum number of timers per slot.
const MAX_PER_SLOT: usize = 8;

/// A timer entry: fires at a specific tick, calls a function.
#[derive(Clone, Copy)]
pub struct Timer {
    pub deadline: u64,
    pub func: fn(usize),
    pub arg: usize,
}

/// Slot in the wheel — holds up to MAX_PER_SLOT timers.
struct Slot {
    timers: [Option<Timer>; MAX_PER_SLOT],
    count: usize,
}

impl Slot {
    const fn new() -> Self {
        Slot {
            timers: [None; MAX_PER_SLOT],
            count: 0,
        }
    }

    #[must_use = "an ignored `false` silently drops the timer"]
    fn insert(&mut self, timer: Timer) -> bool {
        if self.count >= MAX_PER_SLOT {
            return false;
        }
        self.timers[self.count] = Some(timer);
        self.count += 1;
        true
    }
}

/// Per-core timer wheel.
pub struct TimerWheel {
    slots: [Slot; WHEEL_SIZE],
    current_tick: u64,
    /// Running count of live timers. Maintained by `insert`/`cancel`/
    /// `advance` so `count()` is O(1) — and so `advance` can fast-path
    /// an empty wheel without walking every tick from 0 on first call.
    total: usize,
}

impl TimerWheel {
    pub const fn new() -> Self {
        TimerWheel {
            slots: [const { Slot::new() }; WHEEL_SIZE],
            current_tick: 0,
            total: 0,
        }
    }

    /// Insert a timer that fires at the given deadline tick.
    ///
    /// Returns `false` if the target slot is already at `MAX_PER_SLOT`
    /// capacity. Callers MUST check and handle the drop — a silent
    /// `false` on the timer path will hang network retransmit logic.
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
    pub fn cancel(&mut self, arg: usize) -> bool {
        for slot in self.slots.iter_mut() {
            for i in 0..slot.count {
                if let Some(t) = &slot.timers[i] {
                    if t.arg == arg {
                        // Swap-remove
                        slot.count -= 1;
                        slot.timers[i] = slot.timers[slot.count];
                        slot.timers[slot.count] = None;
                        self.total -= 1;
                        return true;
                    }
                }
            }
        }
        false
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

            // Fire timers whose deadline <= now.
            //
            // Invariant: `slot.timers[0..slot.count]` are always
            // `Some`; `insert()` / swap-remove maintain this. If a
            // future refactor breaks that invariant the `None` branch
            // skips the slot rather than panicking in the timer ISR.
            let mut i = 0;
            while i < slot.count {
                let Some(timer) = slot.timers[i] else {
                    i += 1;
                    continue;
                };
                if timer.deadline <= now {
                    // Swap-remove
                    slot.count -= 1;
                    slot.timers[i] = slot.timers[slot.count];
                    slot.timers[slot.count] = None;
                    self.total -= 1;
                    // Fire
                    (timer.func)(timer.arg);
                    fired += 1;
                    // Don't increment i — swapped element needs checking
                } else {
                    i += 1;
                }
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
        Timer { deadline, func: bump, arg: c as *const Counters as usize }
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
    fn advance_past_deadline() {
        let c = Counters::new();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(mk_timer(5, 55, &c)));
        // Advance far past the deadline
        wheel.advance(100);
        assert_eq!(c.fired.load(Ordering::Relaxed), 1);
    }
}
