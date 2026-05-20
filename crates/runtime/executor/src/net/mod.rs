// uni-runtime/src/net.rs — UDP reactor with per-worker inboxes.
//
// ## Model
//
// `UdpSocket::bind(port)` claims one of `MAX_UDP_SOCKETS` static
// slots. Each slot owns `MAX_WORKERS` independent SPSC inboxes —
// one per worker. Inbound datagrams are pushed into the inbox of
// the worker that received them (bare-metal Tier 1: the core whose
// RX queue fired; Tier 2: the distributor; native: the worker whose
// kqueue/epoll fired for the sibling fd). `recv_from` pulls from
// the calling worker's inbox.
//
// Packets delivered to worker N stay on worker N — no cross-core
// push, no cross-core pop, no cross-core waker walk. The NIC's flow
// hash already distributes traffic across workers; the reactor
// preserves that fan-out all the way to the async handler.
//
// ## User API
//
// The common pattern — "run a per-worker handler loop" — is the
// `run` method:
//
// ```rust
// let echo = UdpSocket::bind(7)?.run(|sock| async move {
//     let mut buf = [0u8; 1500];
//     loop {
//         let (ip, port, n) = sock.recv_from(&mut buf).await;
//         let _ = sock.send_to(ip, port, &buf[..n]);
//     }
// });
// // store `echo` (a `UdpHandle`) on a long-lived owner so it
// // tears down cleanly when the owner drops.
// ```
//
// `run` consumes the socket, wraps it in an `Arc`, and arranges
// the same async body to be spawned on every worker on that
// worker's next tick. Forgetting to spawn-per-worker is
// impossible — bind+spawn happen together.
//
// The lower-level `bind` + `recv_from` / `send_to` is still
// exposed for short-lived request/reply patterns (DHCP client,
// DNS query, fire-and-forget emit) that don't need fan-out.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use uni_worker::{CurrentWorker, PerWorker};

pub mod tcp;
pub mod udp;

pub use tcp::*;
pub use udp::*;

// ---- SpinLock (waker cell) --------------------------------------------------

pub(crate) struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

pub(crate) struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    pub(crate) const fn new(v: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(v),
        }
    }

    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        SpinGuard { lock: self }
    }
}

impl<'a, T> core::ops::Deref for SpinGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the lock gives us exclusive access.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

// ---- Waker helper -----------------------------------------------------------

/// Store `w` into `slot` unless it already holds a waker that
/// would wake the same task (`Waker::will_wake`). Used on the
/// slow path of every `poll` that parks on a per-port waker slot
/// to keep the clone off the hot path when the same task repolls
/// in a tight loop.
pub(crate) fn store_waker_if_needed(slot: &SpinLock<Option<Waker>>, w: &Waker) {
    let mut slot = slot.lock();
    let need_store = match &*slot {
        Some(existing) => !existing.will_wake(w),
        None => true,
    };
    if need_store {
        *slot = Some(w.clone());
    }
}

// ---- Launcher helper --------------------------------------------------------

/// Install a freshly-spawned worker task into its per-worker slot,
/// handling the drop-race with `*Handle::Drop`: if `stopping` was
/// set between the launcher's first check and now, abort the task
/// we just spawned instead of stashing it (its abort flag would
/// otherwise go unseen until the next drop, leaking the task for
/// the rest of the process). Taking the lock once keeps the common
/// case to a single acquire/release.
pub(crate) fn install_worker_task(
    stopping: &AtomicBool,
    handles: &PerWorker<SpinLock<Option<crate::TaskHandle>>>,
    h: crate::TaskHandle,
) {
    let cc = CurrentWorker::enter();
    let mut slot = handles.current(&cc).lock();
    if stopping.load(Ordering::Acquire) {
        drop(slot);
        h.abort();
    } else {
        *slot = Some(h);
    }
}

// ---- Shared launcher table (UDP + TCP + future reactors) --------------------
//
// Any reactor's `run`-style method registers a type-erased launcher
// closure in `NET_LAUNCHERS` (a `LaunchTable`) via
// `register_net_launcher`. `fire_pending_net_launchers` — called
// from `uni_runtime::tick` on every worker every iteration — walks
// the table from that worker's cursor to the global count and
// invokes each live launcher. Each launcher typically calls
// `spawn(body(...))` on the calling worker.
//
// `LaunchTable` uses chunked lazy allocation, so the upfront cost
// is just the outer pointer array (8 KiB) regardless of how many
// listeners the app eventually creates. See
// `uni-runtime/src/launcher.rs` for the ownership / tombstone /
// monotonic-counter invariants that back the table.

static NET_LAUNCHERS: crate::launcher::LaunchTable = crate::launcher::LaunchTable::new();

#[inline]
pub(crate) fn register_net_launcher(launcher: crate::launcher::Launcher) -> usize {
    NET_LAUNCHERS.register(launcher)
}

#[inline]
pub(crate) fn release_launcher_slot(idx: usize) {
    NET_LAUNCHERS.release(idx);
}

/// Fire every net launcher added since `worker_id` last called
/// here. Thin wrapper over `NET_LAUNCHERS.fire_pending` so
/// `uni_runtime::tick` has a named entry point.
#[inline]
pub fn fire_pending_net_launchers(worker_id: u32) {
    NET_LAUNCHERS.fire_pending(worker_id);
}
