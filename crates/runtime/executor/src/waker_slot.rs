// crates/runtime/executor/src/waker_slot.rs — the shared parked-waker
// slot, and the RAII registration that makes parking cancel-safe by
// construction (architecture-audit #7).
//
// Three hand-rolled copies of this discipline existed: `AsyncEvent`'s
// spinlocked cell, the UDP `WorkerInbox`'s gate + cell, and the TCP
// per-conn slots reached through the backend vtable. The first two now
// embed this type; new park-points should too, holding the [`Parked`]
// guard as a future field so a `select!`-losing branch or task abort
// deregisters its waker structurally instead of by convention.
//
// Shape: a spinlocked `Option<Waker>` plus a `present` gate producers
// can read without touching the lock's cache line (the UDP hot-path
// property: at ~700k pps the lock round-trip per packet halved
// throughput). All writes — park, clear, take — flip the gate inside
// the critical section, so the gate never disagrees with the slot for
// longer than one in-flight section.

use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use crate::reactor::SpinLock;

pub struct WakerSlot {
    /// `false` ⇒ nothing parked ⇒ [`wake_gated`](Self::wake_gated)
    /// returns without locking.
    present: AtomicBool,
    waker: SpinLock<Option<Waker>>,
}

impl Default for WakerSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl WakerSlot {
    pub const fn new() -> Self {
        WakerSlot {
            present: AtomicBool::new(false),
            waker: SpinLock::new(None),
        }
    }

    /// Consumer side: park `w` for a producer to wake. Skips the clone
    /// when the slot already holds a waker for the same task
    /// (`Waker::will_wake`) — the common repoll-in-a-loop case.
    pub fn park(&self, w: &Waker) {
        let mut slot = self.waker.lock();
        let need_store = match &*slot {
            Some(existing) => !existing.will_wake(w),
            None => true,
        };
        if need_store {
            *slot = Some(w.clone());
        }
        self.present.store(true, Ordering::Release);
    }

    /// [`park`](Self::park), returning the RAII registration. Hold it
    /// as a future field: dropping the future deregisters exactly its
    /// own waker (see [`Parked`]).
    pub fn park_guard(&self, w: &Waker) -> Parked<'_> {
        self.park(w);
        Parked {
            slot: self,
            waker: w.clone(),
        }
    }

    /// Consumer side: drop whatever is parked. For the slow-path
    /// re-check that finds its own data (we parked, but the producer's
    /// store landed before our re-read), so the producer can
    /// short-circuit the next event.
    pub fn unpark(&self) {
        let mut slot = self.waker.lock();
        *slot = None;
        self.present.store(false, Ordering::Release);
    }

    /// Producer side: take and wake the parked task, if any. Always
    /// takes the lock — paired with the consumer's park-then-re-check
    /// protocol this cannot lose a wakeup (the lock orders the two
    /// critical sections; whichever ran second sees the other's
    /// effect). Use this when no later event would re-trigger the
    /// consumer (one-shot signals like `AsyncEvent::set`).
    pub fn wake(&self) {
        let taken = {
            let mut slot = self.waker.lock();
            let t = slot.take();
            if t.is_some() {
                self.present.store(false, Ordering::Release);
            }
            t
        };
        if let Some(w) = taken {
            w.wake();
        }
    }

    /// Producer side, gated: return without locking when nothing is
    /// parked. The gate read and the consumer's park are not ordered
    /// by a common lock, so a park racing this call can be missed
    /// (store-buffer interleaving) — use only where the producer's
    /// data flow re-triggers the consumer anyway (a stream of events,
    /// e.g. per-datagram wakes: the consumer's post-park re-check or
    /// the next event covers the race). One-shot producers must use
    /// [`wake`](Self::wake).
    pub fn wake_gated(&self) {
        if !self.present.load(Ordering::Acquire) {
            return;
        }
        self.wake();
    }

    /// Cancel-safety: clear the parked waker iff it is `w`'s
    /// (`will_wake`-precise). A canceled future removes exactly its
    /// own registration — a successor that legitimately re-parked is
    /// left intact, and a registration already consumed by
    /// [`wake`](Self::wake) is a no-op.
    pub fn clear_if(&self, w: &Waker) {
        let mut slot = self.waker.lock();
        if slot.as_ref().is_some_and(|s| s.will_wake(w)) {
            *slot = None;
            self.present.store(false, Ordering::Release);
        }
    }
}

/// A live waker registration in a [`WakerSlot`] — the RAII resource
/// the audit's #7 calls for. Futures hold one as a field; the field's
/// drop (future completed, canceled by `select!`, or task aborted)
/// removes the registration precisely, so no stale waker outlives the
/// future that parked it.
pub struct Parked<'a> {
    slot: &'a WakerSlot,
    waker: Waker,
}

impl Parked<'_> {
    /// Re-park on a later poll (the executor may hand the future a
    /// different waker). Updates both the slot and the waker this
    /// guard will deregister on drop.
    pub fn repark(&mut self, w: &Waker) {
        if !self.waker.will_wake(w) {
            self.waker = w.clone();
        }
        self.slot.park(w);
    }
}

impl Drop for Parked<'_> {
    fn drop(&mut self) {
        self.slot.clear_if(&self.waker);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    struct CountingWake(AtomicUsize);
    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn waker() -> (Waker, Arc<CountingWake>) {
        let cw = Arc::new(CountingWake(AtomicUsize::new(0)));
        (Waker::from(Arc::clone(&cw)), cw)
    }

    #[test]
    fn park_wake_roundtrip_and_empty_wake() {
        let slot = WakerSlot::new();
        slot.wake(); // empty: no-op
        let (w, cw) = waker();
        slot.park(&w);
        slot.wake();
        assert_eq!(cw.0.load(Ordering::Relaxed), 1);
        slot.wake(); // consumed: no-op
        assert_eq!(cw.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn gated_wake_skips_when_nothing_parked_and_fires_when_parked() {
        let slot = WakerSlot::new();
        slot.wake_gated();
        let (w, cw) = waker();
        slot.park(&w);
        slot.wake_gated();
        assert_eq!(cw.0.load(Ordering::Relaxed), 1);
        // Gate dropped with the take: a second gated wake is a pure load.
        slot.wake_gated();
        assert_eq!(cw.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn guard_drop_clears_own_registration_only() {
        let slot = WakerSlot::new();
        let (w1, cw1) = waker();
        let guard = slot.park_guard(&w1);
        drop(guard);
        slot.wake();
        assert_eq!(cw1.0.load(Ordering::Relaxed), 0, "canceled waiter not woken");

        // A successor that re-parked survives the predecessor's drop.
        let (w1, cw1) = waker();
        let guard1 = slot.park_guard(&w1);
        let (w2, cw2) = waker();
        let _guard2 = slot.park_guard(&w2); // overwrites (single-waiter contract)
        drop(guard1); // will_wake fails against w2 → leaves it
        slot.wake();
        assert_eq!(cw1.0.load(Ordering::Relaxed), 0);
        assert_eq!(cw2.0.load(Ordering::Relaxed), 1, "successor still woken");
    }

    #[test]
    fn repark_tracks_the_new_waker() {
        let slot = WakerSlot::new();
        let (w1, _cw1) = waker();
        let mut guard = slot.park_guard(&w1);
        let (w2, cw2) = waker();
        guard.repark(&w2);
        drop(guard); // deregisters w2, the waker it last parked
        slot.wake();
        assert_eq!(cw2.0.load(Ordering::Relaxed), 0, "drop cleared the re-parked waker");
    }
}
