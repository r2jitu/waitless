// crates/runtime/executor/src/event.rs — waker-driven async event flag.
//
// Shape: a manual-reset one-bit flag plus a single parked waker.
// Producer calls `set()` to flip the bit and wake the waiter (on
// whichever worker it's running — the executor's cross-worker
// waker dispatch handles it); consumer `.wait().await`s until the
// bit is set. `reset()` clears the bit for the next cycle.
//
// Single waiter. If a second task awaits the same event while the
// first is parked, the second one's waker overwrites the first's —
// which is fine for the use cases this primitive exists for
// (request/reply state machines like DHCP where one task owns the
// await side). Broader multi-waiter semantics would want something
// closer to a Notify / CondVar and should be added as a separate
// primitive rather than complicating this one.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use crate::waker_slot::{Parked, WakerSlot};

pub struct AsyncEvent {
    set: AtomicBool,
    /// The parked waiter. Producer takes-and-wakes on `set()`;
    /// consumer parks on poll. See `waker_slot` for the discipline.
    waker: WakerSlot,
}

impl Default for AsyncEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncEvent {
    pub const fn new() -> Self {
        AsyncEvent {
            set: AtomicBool::new(false),
            waker: WakerSlot::new(),
        }
    }

    /// True if `set()` has been called (and `reset()` hasn't).
    #[inline]
    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// Flip the flag and wake any parked waiter. Cheap on the
    /// already-set path (swap returns true → the earlier setter
    /// already woke whoever was parked). Uses the ungated
    /// `WakerSlot::wake` — a one-shot signal must not race a
    /// just-parking waiter past the gate.
    pub fn set(&self) {
        if self.set.swap(true, Ordering::AcqRel) {
            return;
        }
        self.waker.wake();
    }

    /// Clear the flag so the next `wait()` re-arms. Usually called
    /// by the consumer between cycles (e.g. between a DHCP OFFER and
    /// the subsequent REQUEST/ACK exchange).
    pub fn reset(&self) {
        self.set.store(false, Ordering::Release);
    }

    /// Await until the flag is set. Does NOT auto-reset; caller
    /// owns the lifecycle so they can observe multiple sets without
    /// a race losing one.
    pub fn wait(&self) -> WaitEvent<'_> {
        WaitEvent {
            event: self,
            parked: None,
        }
    }
}

pub struct WaitEvent<'a> {
    event: &'a AsyncEvent,
    /// The live registration. Its drop — future completed, canceled
    /// by `select!`, or task aborted — deregisters exactly the waker
    /// this future parked (structural cancel-safety, `will_wake`-
    /// precise): a successor waiter that legitimately overwrote the
    /// slot (the documented sequential-waiter pattern) is untouched,
    /// and a wait resolved by `set()` finds the slot already taken —
    /// both no-ops. `None` until the first `Pending`-bound poll.
    parked: Option<Parked<'a>>,
}

impl<'a> Future for WaitEvent<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.event.is_set() {
            return Poll::Ready(());
        }
        // Register waker then re-check — closes the race where
        // `set()` lands between our fast-path load and the store.
        match &mut this.parked {
            Some(p) => p.repark(cx.waker()),
            None => this.parked = Some(this.event.waker.park_guard(cx.waker())),
        }
        if this.event.is_set() {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}
