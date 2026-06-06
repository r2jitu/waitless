// net/egress — per-core egress scheduler (the second back-pressure source
// from docs/tx-backpressure.md: many flows saturating ONE NIC TX queue).
//
// Where `net_cc`'s `CongestionControl` bounds a *single* flow against a slow
// path/peer, this arbitrates *between* flows competing for one shared egress.
// It's a Deficit Round Robin (Shreedhar & Varghese) fair queue: each active
// flow earns `quantum` bytes of send credit per round, so over time flows
// share the link in proportion to their weights and no flow can starve the
// others — the thing a first-caller-wins `acquire_tx_buf` race cannot give.
//
// Pull-based and lossless: the scheduler holds no packets. It only answers
// "whose turn is it, and for how many bytes?"; the caller pulls that many
// bytes from the flow's (separately bounded) send buffer and places them in
// the ring. When the ring fills, the caller simply stops calling
// `next_flow` — active flows keep their place and accumulated deficit, and
// resume next event-loop pass once the ring drains. No drops, no spinning.
//
// Fixed capacity `N` (max concurrent flows on this core's queue), no alloc,
// O(1) per operation — host-unit-testable.

#![cfg_attr(not(test), no_std)]

/// A Deficit-Round-Robin fair-queue scheduler over up to `N` flows, each
/// identified by an index in `0..N` (e.g. a per-core connection slot). A
/// flow is *active* when it has data ready to send (and, in the integrated
/// design, is congestion-window eligible); the caller toggles that with
/// [`activate`](Self::activate) / [`deactivate`](Self::deactivate).
pub struct DeficitRoundRobin<const N: usize> {
    /// Bytes of send credit granted per round when the flow reaches the
    /// head — its weight. Larger quantum ⇒ larger share of the link.
    quantum: [u32; N],
    /// Accumulated, not-yet-spent send credit (bytes).
    deficit: [u32; N],
    /// Flow wants service (has data + is eligible).
    active: [bool; N],
    /// Flow currently has a slot in `ring` (may be a stale slot left by a
    /// `deactivate`, cleared lazily on pop). Guards against double-insert so
    /// each flow occupies the ring at most once and `len <= N` always holds.
    scheduled: [bool; N],
    /// FIFO ring of scheduled flow ids (round-robin order).
    ring: [u16; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Default for DeficitRoundRobin<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DeficitRoundRobin<N> {
    pub const fn new() -> Self {
        assert!(N <= u16::MAX as usize + 1, "flow ids must fit in u16");
        DeficitRoundRobin {
            quantum: [0; N],
            deficit: [0; N],
            active: [false; N],
            scheduled: [false; N],
            ring: [0; N],
            head: 0,
            len: 0,
        }
    }

    fn push_tail(&mut self, flow: u16) {
        // len < N is an invariant here (`scheduled` guards double-insert and
        // there are at most N distinct flows), so this never overwrites.
        let tail = (self.head + self.len) % N;
        self.ring[tail] = flow;
        self.len += 1;
    }

    fn pop_head(&mut self) -> u16 {
        let f = self.ring[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        f
    }

    /// Mark `flow` ready to send with the given `quantum` (its weight in
    /// bytes/round). Idempotent: re-activating an already-active flow just
    /// updates its weight and keeps its position — new data arriving never
    /// jumps the queue. A flow re-activated after draining starts a fresh
    /// round with zero deficit (no credit hoarded while idle).
    pub fn activate(&mut self, flow: usize, quantum: u32) {
        debug_assert!(flow < N);
        if flow >= N {
            return;
        }
        self.active[flow] = true;
        self.quantum[flow] = quantum.max(1);
        if !self.scheduled[flow] {
            self.scheduled[flow] = true;
            self.deficit[flow] = 0;
            self.push_tail(flow as u16);
        }
    }

    /// Mark `flow` idle (drained, or no longer eligible). Its deficit is
    /// dropped so it can't hoard credit while idle; its ring slot is removed
    /// lazily the next time it surfaces at the head.
    pub fn deactivate(&mut self, flow: usize) {
        debug_assert!(flow < N);
        if flow >= N {
            return;
        }
        self.active[flow] = false;
        self.deficit[flow] = 0;
    }

    /// Select the next flow to serve and credit it one quantum. Returns its
    /// id; the caller then reads [`grant`](Self::grant) for the byte budget,
    /// sends up to that, and calls [`charge`](Self::charge). The flow is
    /// rotated to the back of the line, so it stays scheduled until
    /// explicitly deactivated. Returns `None` when no flow is active (the
    /// natural "nothing to send" idle signal).
    pub fn next_flow(&mut self) -> Option<usize> {
        loop {
            if self.len == 0 {
                return None;
            }
            let f = self.pop_head();
            let fi = f as usize;
            if !self.active[fi] {
                // Stale slot from a deactivate — drop it and continue.
                self.scheduled[fi] = false;
                continue;
            }
            self.deficit[fi] = self.deficit[fi].saturating_add(self.quantum[fi]);
            self.push_tail(f); // round-robin; stays scheduled
            return Some(fi);
        }
    }

    /// Bytes `flow` may send this turn (its accumulated deficit).
    pub fn grant(&self, flow: usize) -> u32 {
        debug_assert!(flow < N);
        if flow >= N {
            return 0;
        }
        self.deficit[flow]
    }

    /// Record that `flow` sent `bytes` this turn, debiting its deficit.
    /// Unspent credit carries to the flow's next turn (so a flow whose
    /// packets are smaller than its quantum still gets its fair share over
    /// rounds — the point of the *deficit* in DRR).
    pub fn charge(&mut self, flow: usize, bytes: u32) {
        debug_assert!(flow < N);
        if flow >= N {
            return;
        }
        self.deficit[flow] = self.deficit[flow].saturating_sub(bytes);
    }

    /// Is `flow` currently active?
    pub fn is_active(&self, flow: usize) -> bool {
        flow < N && self.active[flow]
    }

    /// Whether any flow is active (cheap "is there work?" check).
    pub fn has_work(&self) -> bool {
        self.len != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yields_nothing() {
        let mut s = DeficitRoundRobin::<8>::new();
        assert_eq!(s.next_flow(), None);
        assert!(!s.has_work());
    }

    #[test]
    fn single_flow_accumulates_deficit_across_turns() {
        let mut s = DeficitRoundRobin::<8>::new();
        s.activate(3, 1000);
        // First turn: credited one quantum.
        assert_eq!(s.next_flow(), Some(3));
        assert_eq!(s.grant(3), 1000);
        // Send less than the grant → unspent credit carries.
        s.charge(3, 600);
        assert_eq!(s.grant(3), 400);
        // Next turn adds another quantum on top of the carried 400.
        assert_eq!(s.next_flow(), Some(3));
        assert_eq!(s.grant(3), 1400);
    }

    #[test]
    fn equal_weights_share_equally() {
        let mut s = DeficitRoundRobin::<8>::new();
        s.activate(0, 1500);
        s.activate(1, 1500);
        let mut bytes = [0u64; 2];
        // Infinite-demand flows that spend their whole grant each turn.
        for _ in 0..1000 {
            let f = s.next_flow().unwrap();
            let g = s.grant(f);
            bytes[f] += g as u64;
            s.charge(f, g);
        }
        // Within a quantum of each other.
        let diff = bytes[0].abs_diff(bytes[1]);
        assert!(diff <= 1500, "unequal: {bytes:?}");
    }

    #[test]
    fn weights_set_the_ratio() {
        let mut s = DeficitRoundRobin::<8>::new();
        s.activate(0, 1000); // weight 1
        s.activate(1, 3000); // weight 3
        let mut bytes = [0u64; 2];
        for _ in 0..2000 {
            let f = s.next_flow().unwrap();
            let g = s.grant(f);
            bytes[f] += g as u64;
            s.charge(f, g);
        }
        // flow 1 should get ~3x flow 0.
        let ratio = bytes[1] as f64 / bytes[0] as f64;
        assert!((2.7..=3.3).contains(&ratio), "ratio={ratio} bytes={bytes:?}");
    }

    #[test]
    fn drained_flow_is_skipped_then_others_continue() {
        let mut s = DeficitRoundRobin::<8>::new();
        s.activate(0, 1000);
        s.activate(1, 1000);
        // Serve 0 once, then it drains.
        assert_eq!(s.next_flow(), Some(0));
        s.deactivate(0);
        // From here only flow 1 is served, repeatedly.
        for _ in 0..10 {
            assert_eq!(s.next_flow(), Some(1));
            let g = s.grant(1);
            s.charge(1, g);
        }
        // Flow 0's stale slot is gone; flow 0 inactive.
        assert!(!s.is_active(0));
    }

    #[test]
    fn reactivate_does_not_double_schedule() {
        let mut s = DeficitRoundRobin::<8>::new();
        s.activate(0, 1000);
        s.activate(1, 1000);
        // Drain 0 then immediately re-activate before its stale slot is
        // popped — must NOT create a second ring slot (which would give it
        // a double turn / could overflow the ring).
        s.deactivate(0);
        s.activate(0, 1000);
        // Over a full sweep each flow appears once per round: count turns.
        let mut turns = [0u32; 2];
        for _ in 0..100 {
            let f = s.next_flow().unwrap();
            turns[f] += 1;
            let g = s.grant(f);
            s.charge(f, g);
        }
        // Balanced (no flow getting ~2x turns from a duplicate slot).
        assert!(turns[0].abs_diff(turns[1]) <= 1, "turns={turns:?}");
    }

    #[test]
    fn deficit_is_retained_when_caller_pauses_for_backpressure() {
        // Simulate "ring full → caller stops calling next_flow": the flow's
        // deficit and position survive untouched, so it resumes exactly
        // where it left off (lossless back-pressure).
        let mut s = DeficitRoundRobin::<4>::new();
        s.activate(2, 800);
        let f = s.next_flow().unwrap();
        assert_eq!(f, 2);
        s.charge(2, 300); // sent 300 of 800 before the ring filled
        let saved = s.grant(2);
        assert_eq!(saved, 500);
        // ... caller does nothing else this pass (back-pressure) ...
        // Next pass: still active, still scheduled, deficit intact + credited.
        assert_eq!(s.next_flow(), Some(2));
        assert_eq!(s.grant(2), saved + 800);
    }

    #[test]
    fn ring_never_overflows_under_full_churn() {
        // Activate all N flows, churn deactivate/reactivate, ensure the ring
        // stays consistent (no panic, len bounded) and still schedules.
        let mut s = DeficitRoundRobin::<4>::new();
        for f in 0..4 {
            s.activate(f, 1000);
        }
        for round in 0..50 {
            let f = s.next_flow().unwrap();
            let g = s.grant(f);
            s.charge(f, g);
            // Periodically drain + immediately refill a flow.
            if round % 3 == 0 {
                s.deactivate(f);
                s.activate(f, 1000);
            }
        }
        assert!(s.has_work());
    }
}
