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
// UdpSocket::bind(7)?.run(|sock| async move {
//     let mut buf = [0u8; 1500];
//     loop {
//         let (ip, port, n) = sock.recv_from(&mut buf).await;
//         uni::udp_send(ip, 7, port, &buf[..n]);
//     }
// });
// ```
//
// `run` consumes the socket, leaks it to `&'static`, and arranges
// the same async body to be spawned on every worker when that
// worker's event loop starts. Forgetting to spawn-per-worker is
// impossible — bind+spawn happen together.
//
// The lower-level `bind` + `recv_from` is still exposed for cases
// that want custom lifecycle or multiple concurrent tasks sharing
// the socket (one per worker, via `spawn_on_each_worker`).

use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use atomic_fn::AtomicFn;
use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

// ---- Sizing -----------------------------------------------------------------

pub const MAX_UDP_SOCKETS: usize = 8;
const INBOX_CAPACITY: usize = 4;
const MAX_PAYLOAD: usize = 1500;

// ---- SpinLock (waker cell) --------------------------------------------------

struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    const fn new(v: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(v),
        }
    }

    fn lock(&self) -> SpinGuard<'_, T> {
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

// ---- Datagram + worker inbox ------------------------------------------------

#[repr(C)]
struct Datagram {
    src_ip: [u8; 4],
    src_port: u16,
    len: u16,
    payload: [u8; MAX_PAYLOAD],
}

impl Datagram {
    const ZERO: Self = Datagram {
        src_ip: [0; 4],
        src_port: 0,
        len: 0,
        payload: [0; MAX_PAYLOAD],
    };
}

/// One worker's view of a socket. Producer and consumer are the
/// same worker in the common case: the delivery path runs on the
/// core that received the packet, and the `recv_from` task awaits
/// on that same worker.
struct WorkerInbox {
    head: AtomicU32,
    tail: AtomicU32,
    slots: UnsafeCell<[Datagram; INBOX_CAPACITY]>,
    waker: SpinLock<Option<Waker>>,
}

unsafe impl Sync for WorkerInbox {}
unsafe impl Send for WorkerInbox {}

impl WorkerInbox {
    const fn new() -> Self {
        WorkerInbox {
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            slots: UnsafeCell::new([const { Datagram::ZERO }; INBOX_CAPACITY]),
            waker: SpinLock::new(None),
        }
    }

    fn try_push(&self, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let next = tail.wrapping_add(1) % INBOX_CAPACITY as u32;
        if next == head {
            return false;
        }
        // SAFETY: SPSC — producer owns the tail slot until Release store below.
        let slots = unsafe { &mut *self.slots.get() };
        let slot = &mut slots[tail as usize];
        slot.src_ip = src_ip;
        slot.src_port = src_port;
        let n = payload.len().min(MAX_PAYLOAD);
        slot.len = n as u16;
        slot.payload[..n].copy_from_slice(&payload[..n]);
        self.tail.store(next, Ordering::Release);
        true
    }

    fn pop_into(&self, buf: &mut [u8]) -> Option<([u8; 4], u16, usize)> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        // SAFETY: SPSC — consumer owns the head slot until Release store below.
        let slots = unsafe { &*self.slots.get() };
        let slot = &slots[head as usize];
        let n = (slot.len as usize).min(buf.len());
        buf[..n].copy_from_slice(&slot.payload[..n]);
        let r = (slot.src_ip, slot.src_port, n);
        let next = head.wrapping_add(1) % INBOX_CAPACITY as u32;
        self.head.store(next, Ordering::Release);
        Some(r)
    }

    fn reset(&self) {
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Relaxed);
        *self.waker.lock() = None;
    }
}

// ---- Per-port state ---------------------------------------------------------

struct SocketState {
    port: AtomicU16,
    inboxes: PerCpu<WorkerInbox, MAX_WORKERS>,
}

const fn fresh_inboxes() -> [WorkerInbox; MAX_WORKERS] {
    [const { WorkerInbox::new() }; MAX_WORKERS]
}

impl SocketState {
    const fn new() -> Self {
        SocketState {
            port: AtomicU16::new(0),
            inboxes: PerCpu::new(fresh_inboxes()),
        }
    }
}

static REGISTRY: [SocketState; MAX_UDP_SOCKETS] =
    [const { SocketState::new() }; MAX_UDP_SOCKETS];

// ---- Backend plug-in for bind-time setup ------------------------------------

static BACKEND_BIND: AtomicFn<fn(port: u16) -> Result<(), ()>> = AtomicFn::null();

/// Register the backend-side bind hook. On bare-metal this stays
/// unset — the NIC RX path unconditionally delivers to
/// `deliver_udp`. On native, the POSIX backend registers a hook
/// that opens SO_REUSEPORT sibling fds for each `UdpSocket::bind`.
pub fn register_backend_bind(hook: fn(port: u16) -> Result<(), ()>) {
    BACKEND_BIND.store(hook);
}

// ---- Public API -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpBindError {
    AllSlotsBusy,
    PortInUse,
    InvalidPort,
    /// Backend-side bind step failed (native OS refused to open the
    /// SO_REUSEPORT sibling sockets for this port).
    BackendFailed,
}

/// A UDP socket bound to one port. Created with `bind`; the typical
/// pattern is to call `.run(|sock| async move { ... })` on it
/// immediately, which consumes the socket and spawns a per-worker
/// handler task.
///
/// For custom lifecycle, use `bind` + manual `spawn_on_each_worker`
/// with `&'static UdpSocket`, holding onto the socket explicitly.
pub struct UdpSocket {
    port: u16,
    idx: usize,
}

impl UdpSocket {
    pub fn bind(port: u16) -> Result<UdpSocket, UdpBindError> {
        if port == 0 {
            return Err(UdpBindError::InvalidPort);
        }
        for state in REGISTRY.iter() {
            if state.port.load(Ordering::Acquire) == port {
                return Err(UdpBindError::PortInUse);
            }
        }
        for (idx, state) in REGISTRY.iter().enumerate() {
            if state
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                for w in 0..MAX_WORKERS as u32 {
                    state.inboxes.at(w).reset();
                }
                if let Some(hook) = BACKEND_BIND.load() {
                    if hook(port).is_err() {
                        state.port.store(0, Ordering::Release);
                        return Err(UdpBindError::BackendFailed);
                    }
                }
                return Ok(UdpSocket { port, idx });
            }
        }
        Err(UdpBindError::AllSlotsBusy)
    }

    /// Port this socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Await one datagram on the **calling worker's** inbox. The
    /// copy into `buf` happens on the single poll that returns
    /// `Ready`. Oversized payloads truncate to `buf.len()`.
    pub fn recv_from<'a>(&'a self, buf: &'a mut [u8]) -> UdpRecv<'a> {
        UdpRecv {
            sock: self,
            buf,
            _not_send: PhantomData,
        }
    }

    /// Convenience: per-datagram sync handler. The framework owns
    /// the receive loop; `handler` is called once per inbound
    /// datagram on the worker that received it. For async
    /// per-datagram work (e.g. DB lookups), use `run_loop` instead.
    ///
    /// `handler` is `Fn`, called concurrently across workers. State
    /// across calls should live in `PerCpu<T, MAX_WORKERS>` or use
    /// interior mutability.
    pub fn run_each<H>(self, handler: H)
    where
        H: Fn([u8; 4], u16, &[u8]) + Send + Sync + 'static,
    {
        // Leak the handler to `&'static` so each worker's spawn
        // can move a copy of the reference into its async block —
        // the outer closure we hand to `run_loop` is `Fn`, which
        // can't yield a borrow to its inner async state.
        let handler: &'static H = Box::leak(Box::new(handler));
        self.run_loop(move |sock| async move {
            let mut buf = [0u8; MAX_PAYLOAD];
            loop {
                let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
                handler(src_ip, src_port, &buf[..n]);
            }
        })
    }

    /// Escape hatch: custom async body, spawned once per worker.
    /// The body receives `&'static UdpSocket` and typically loops on
    /// `recv_from` to drive the per-worker inbox. Use this when the
    /// sync `run_each` doesn't fit (async per-datagram work, batched
    /// reads, cross-message state not expressible via `PerCpu`).
    pub fn run_loop<H, F>(self, body: H)
    where
        H: Fn(&'static UdpSocket) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let idx = self.idx;
        let leaked: &'static UdpSocket = Box::leak(Box::new(self));
        // Launcher: captures the leaked socket, produces one future
        // per call, hands it to `spawn` which puts it in the calling
        // worker's arena.
        let launcher: BoxedLauncher = Box::new(move || {
            let fut = body(leaked);
            let _ = crate::spawn(fut);
        });
        // Outer box: `AtomicPtr<T>` needs `T: Sized`, so we store a
        // thin pointer to the heap-alloc'd fat pointer.
        let outer: Box<BoxedLauncher> = Box::new(launcher);
        LAUNCHERS[idx].store(Box::into_raw(outer), Ordering::Release);
        ensure_launcher_hook_registered();
    }
}

// `UdpSocket` deliberately does NOT implement `Drop`. `bind` +
// `run` is the intended lifecycle; `run` consumes self. The lower-
// level `bind` without `run` also leaks — port slots are intended
// to be permanent allocations. If explicit release becomes needed
// later, add a dedicated `release()` method rather than repurposing
// `Drop`.

/// The UdpRecv future holds a mutable borrow of the caller's buffer
/// plus a shared ref to the socket. `!Send + !Sync` via
/// `PhantomData<*mut ()>` so the future can't migrate across workers
/// mid-await — the per-worker inbox semantics depend on staying on
/// the worker where we first polled.
pub struct UdpRecv<'a> {
    sock: &'a UdpSocket,
    buf: &'a mut [u8],
    _not_send: PhantomData<*mut ()>,
}

impl<'a> Future for UdpRecv<'a> {
    type Output = ([u8; 4], u16, usize);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let cc = CurrentCore::enter();
        let inbox = REGISTRY[this.sock.idx].inboxes.current(&cc);

        // Fast path: data already in this worker's inbox.
        if let Some(r) = inbox.pop_into(this.buf) {
            return Poll::Ready(r);
        }
        // Slow path: register the waker, then re-check — closes the
        // race where `deliver_udp` pushed between the fast-path pop
        // and the waker registration.
        *inbox.waker.lock() = Some(cx.waker().clone());
        if let Some(r) = inbox.pop_into(this.buf) {
            *inbox.waker.lock() = None;
            return Poll::Ready(r);
        }
        Poll::Pending
    }
}

// ---- Backend entry point ----------------------------------------------------

/// Deliver one inbound UDP datagram on the **calling worker**'s
/// view of whichever `UdpSocket` is bound to `dst_port`. Must be
/// called from the network RX path on the core that received the
/// packet. Returns `true` if a socket was found.
pub fn deliver_udp(dst_port: u16, src_ip: [u8; 4], src_port: u16, payload: &[u8]) -> bool {
    let cc = CurrentCore::enter();
    for state in REGISTRY.iter() {
        if state.port.load(Ordering::Acquire) == dst_port {
            let inbox = state.inboxes.current(&cc);
            let _ = inbox.try_push(src_ip, src_port, payload);
            let taken = inbox.waker.lock().take();
            if let Some(waker) = taken {
                waker.wake();
            }
            return true;
        }
    }
    false
}

// ---- Per-worker launcher table ----------------------------------------------
//
// `UdpSocket::run(body)` stores a type-erased launcher closure in
// `LAUNCHERS[idx]`. A single `spawn_on_each_worker` hook, registered
// lazily on the first `run` call, walks the table on each worker's
// first tick and fires every live launcher — each launcher calls
// `spawn(body(sock))` on the calling worker.
//
// Storage is `AtomicPtr<Box<dyn Fn...>>`: the atomic holds a thin
// pointer to a heap-allocated `Box` (which in turn is the fat
// pointer to the closure). `AtomicPtr<T>` requires `T: Sized`;
// `Box<dyn Fn>` is sized (a fat pointer is still `Sized`). Leaking
// the `Box` keeps the launcher heap-alive for the process lifetime
// — matches `run`'s consume-the-socket contract.

type BoxedLauncher = Box<dyn Fn() + Send + Sync + 'static>;

static LAUNCHERS: [AtomicPtr<BoxedLauncher>; MAX_UDP_SOCKETS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_UDP_SOCKETS];

static LAUNCHER_HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

fn ensure_launcher_hook_registered() {
    if LAUNCHER_HOOK_REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        crate::spawn_on_each_worker(fire_launchers);
    }
}

fn fire_launchers() {
    for slot in LAUNCHERS.iter() {
        let p = slot.load(Ordering::Acquire);
        if p.is_null() {
            continue;
        }
        // SAFETY: `p` was obtained from `Box::into_raw(Box::new(
        // BoxedLauncher{..}))` in `UdpSocket::run`. The outer box is
        // leaked (never freed). Release/Acquire pairs the store and
        // load.
        let launcher: &BoxedLauncher = unsafe { &*p };
        launcher();
    }
}
