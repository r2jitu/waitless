// kernel/timer.rs — Per-core timer wheel.
//
// Simple single-level timer wheel with fixed tick granularity.
// Each core has its own wheel — no synchronization needed for
// insert/fire on the owning core.
//
// Cross-core timer creation goes through pending_timers MPSC queue
// (see ROADMAP Phase 2a design).

use core::sync::atomic::{AtomicUsize, Ordering};

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
}

impl TimerWheel {
    pub const fn new() -> Self {
        TimerWheel {
            slots: [const { Slot::new() }; WHEEL_SIZE],
            current_tick: 0,
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
        self.slots[slot_idx].insert(timer)
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
        let mut total = 0;
        for slot in self.slots.iter() {
            total += slot.count;
        }
        total
    }
}

/// MPSC queue for cross-core timer submission.
/// Any core can push; only the owning core pops.
/// Lock-free via atomic linked-list head.
pub struct PendingTimers {
    head: AtomicUsize, // pointer to first TimerNode, or 0
}

/// Node in the pending timers linked list.
/// Allocated from a fixed pool (no heap needed).
struct TimerNode {
    timer: Timer,
    next: usize, // pointer to next node, or 0
}

const PENDING_POOL_SIZE: usize = 64;

static mut PENDING_POOL: [TimerNode; PENDING_POOL_SIZE] = [const {
    TimerNode {
        timer: Timer { deadline: 0, func: noop, arg: 0 },
        next: 0,
    }
}; PENDING_POOL_SIZE];

static PENDING_POOL_HEAD: AtomicUsize = AtomicUsize::new(0);
static PENDING_POOL_INIT: AtomicUsize = AtomicUsize::new(0);

fn noop(_: usize) {}

fn init_pool() {
    if PENDING_POOL_INIT.compare_exchange(0, 1, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        return;
    }
    unsafe {
        // Build free list
        for i in 0..PENDING_POOL_SIZE - 1 {
            PENDING_POOL[i].next = &PENDING_POOL[i + 1] as *const _ as usize;
        }
        PENDING_POOL[PENDING_POOL_SIZE - 1].next = 0;
        PENDING_POOL_HEAD.store(&PENDING_POOL[0] as *const _ as usize, Ordering::Release);
    }
}

fn alloc_node() -> Option<*mut TimerNode> {
    init_pool();
    loop {
        let head = PENDING_POOL_HEAD.load(Ordering::Acquire);
        if head == 0 {
            return None;
        }
        let node = head as *mut TimerNode;
        let next = unsafe { (*node).next };
        if PENDING_POOL_HEAD.compare_exchange(head, next, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return Some(node);
        }
    }
}

fn free_node(node: *mut TimerNode) {
    loop {
        let head = PENDING_POOL_HEAD.load(Ordering::Acquire);
        unsafe { (*node).next = head; }
        if PENDING_POOL_HEAD.compare_exchange(head, node as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return;
        }
    }
}

impl PendingTimers {
    pub const fn new() -> Self {
        PendingTimers {
            head: AtomicUsize::new(0),
        }
    }

    /// Push a timer (any core can call). Lock-free.
    ///
    /// Returns `false` if the global pending pool is exhausted —
    /// callers must propagate that up rather than assume success.
    #[must_use = "an ignored `false` silently drops the timer"]
    pub fn push(&self, timer: Timer) -> bool {
        let node = match alloc_node() {
            Some(n) => n,
            None => return false,
        };
        unsafe { (*node).timer = timer; }
        loop {
            let head = self.head.load(Ordering::Acquire);
            unsafe { (*node).next = head; }
            if self.head.compare_exchange(head, node as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return true;
            }
        }
    }

    /// Drain all pending timers into the given wheel (owning core only).
    /// Returns `(inserted, dropped)` — `dropped` counts timers whose
    /// target wheel slot was full at drain time.
    pub fn drain_into(&self, wheel: &mut TimerWheel) -> (usize, usize) {
        // Atomically take the entire list
        let head = self.head.swap(0, Ordering::AcqRel);
        let mut inserted = 0;
        let mut dropped = 0;
        let mut node_ptr = head;
        while node_ptr != 0 {
            let node = node_ptr as *mut TimerNode;
            let next = unsafe { (*node).next };
            let timer = unsafe { (*node).timer };
            if wheel.insert(timer) { inserted += 1; } else { dropped += 1; }
            free_node(node);
            node_ptr = next;
        }
        (inserted, dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    static FIRE_COUNT: AtomicU32 = AtomicU32::new(0);
    static LAST_ARG: AtomicU32 = AtomicU32::new(0);

    fn test_handler(arg: usize) {
        FIRE_COUNT.fetch_add(1, Ordering::Relaxed);
        LAST_ARG.store(arg as u32, Ordering::Relaxed);
    }

    fn reset_counters() {
        FIRE_COUNT.store(0, Ordering::Relaxed);
        LAST_ARG.store(0, Ordering::Relaxed);
    }

    #[test]
    fn insert_and_fire() {
        reset_counters();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(Timer { deadline: 5, func: test_handler, arg: 42 }));
        assert_eq!(wheel.count(), 1);

        // Advance to tick 4 — timer shouldn't fire
        wheel.advance(4);
        assert_eq!(FIRE_COUNT.load(Ordering::Relaxed), 0);

        // Advance to tick 5 — timer fires
        wheel.advance(5);
        assert_eq!(FIRE_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_ARG.load(Ordering::Relaxed), 42);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn multiple_timers_same_slot() {
        reset_counters();
        let mut wheel = TimerWheel::new();
        // Deadlines 256 apart map to the same slot (WHEEL_SIZE=256)
        assert!(wheel.insert(Timer { deadline: 10, func: test_handler, arg: 1 }));
        assert!(wheel.insert(Timer { deadline: 10, func: test_handler, arg: 2 }));
        assert_eq!(wheel.count(), 2);
        wheel.advance(10);
        assert_eq!(FIRE_COUNT.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cancel_timer() {
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(Timer { deadline: 100, func: test_handler, arg: 99 }));
        assert_eq!(wheel.count(), 1);
        assert!(wheel.cancel(99));
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn cancel_nonexistent() {
        let mut wheel = TimerWheel::new();
        assert!(!wheel.cancel(42));
    }

    #[test]
    fn fire_order() {
        reset_counters();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(Timer { deadline: 1, func: test_handler, arg: 10 }));
        assert!(wheel.insert(Timer { deadline: 3, func: test_handler, arg: 30 }));
        assert!(wheel.insert(Timer { deadline: 2, func: test_handler, arg: 20 }));

        wheel.advance(3);
        // All three should have fired
        assert_eq!(FIRE_COUNT.load(Ordering::Relaxed), 3);
        assert_eq!(wheel.count(), 0);
    }

    #[test]
    fn advance_past_deadline() {
        reset_counters();
        let mut wheel = TimerWheel::new();
        assert!(wheel.insert(Timer { deadline: 5, func: test_handler, arg: 55 }));
        // Advance far past the deadline
        wheel.advance(100);
        assert_eq!(FIRE_COUNT.load(Ordering::Relaxed), 1);
    }
}
