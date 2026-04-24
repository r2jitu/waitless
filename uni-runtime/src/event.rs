// uni-runtime/src/event.rs — waker-driven async event flag.
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

use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

pub struct AsyncEvent {
    set: AtomicBool,
    /// `waker_locked` guards `waker` as a spinlock — producer and
    /// consumer can both touch it (producer clears + wakes on set,
    /// consumer writes on poll). Held briefly; no async work under
    /// the lock.
    waker_locked: AtomicBool,
    waker: UnsafeCell<Option<Waker>>,
}

// SAFETY: `waker` is only accessed under the `waker_locked`
// spinlock; `set` is atomic.
unsafe impl Sync for AsyncEvent {}

impl AsyncEvent {
    pub const fn new() -> Self {
        AsyncEvent {
            set: AtomicBool::new(false),
            waker_locked: AtomicBool::new(false),
            waker: UnsafeCell::new(None),
        }
    }

    /// True if `set()` has been called (and `reset()` hasn't).
    #[inline]
    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }

    /// Flip the flag and wake any parked waiter. Cheap on the happy
    /// path (already set → fetch_or short-circuits, no waker touch).
    pub fn set(&self) {
        if self.set.swap(true, Ordering::AcqRel) {
            return; // already set; waiter (if any) was already scheduled
        }
        let w = self.take_waker();
        if let Some(w) = w {
            w.wake();
        }
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
        WaitEvent { event: self }
    }

    fn lock(&self) {
        while self
            .waker_locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    fn unlock(&self) {
        self.waker_locked.store(false, Ordering::Release);
    }

    fn take_waker(&self) -> Option<Waker> {
        self.lock();
        // SAFETY: lock held → exclusive access to `waker`.
        let out = unsafe { (*self.waker.get()).take() };
        self.unlock();
        out
    }

    fn store_waker(&self, w: &Waker) {
        self.lock();
        // SAFETY: lock held → exclusive access.
        unsafe {
            let slot = &mut *self.waker.get();
            match slot {
                Some(existing) if existing.will_wake(w) => {}
                _ => *slot = Some(w.clone()),
            }
        }
        self.unlock();
    }
}

pub struct WaitEvent<'a> {
    event: &'a AsyncEvent,
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
        this.event.store_waker(cx.waker());
        if this.event.is_set() {
            return Poll::Ready(());
        }
        Poll::Pending
    }
}
