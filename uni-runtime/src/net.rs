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
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

use uni_percpu::{CurrentCore, PerCpu, MAX_WORKERS};

// ---- Sizing -----------------------------------------------------------------

pub const MAX_UDP_SOCKETS: usize = 8;
/// Per-worker inbox depth. The hot path (same-core producer + same-
/// core consumer) drains one entry per task poll, so this is purely
/// burst tolerance for when delivery outpaces task scheduling (NIC
/// RX interrupt coalescing, slow handler work, cross-core delivery
/// on Tier 2). 16 absorbs typical interrupt bursts without ballooning
/// static BSS — total footprint is MAX_UDP_SOCKETS × MAX_WORKERS ×
/// INBOX_CAPACITY × MAX_PAYLOAD ≈ 1.5 MB.
const INBOX_CAPACITY: usize = 16;
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

// ---- Launcher helper --------------------------------------------------------

/// Install a freshly-spawned worker task into its per-worker slot,
/// handling the drop-race with `*Handle::Drop`: if `stopping` was
/// set between the launcher's first check and now, abort the task
/// we just spawned instead of stashing it (its abort flag would
/// otherwise go unseen until the next drop, leaking the task for
/// the rest of the process). Taking the lock once keeps the common
/// case to a single acquire/release.
fn install_worker_task(
    stopping: &AtomicBool,
    handles: &[SpinLock<Option<crate::TaskHandle>>; MAX_WORKERS],
    h: crate::TaskHandle,
) {
    let cc = CurrentCore::enter();
    let mut slot = handles[cc.id() as usize].lock();
    if stopping.load(Ordering::Acquire) {
        drop(slot);
        h.abort();
    } else {
        *slot = Some(h);
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

struct UdpState {
    port: AtomicU16,
    inboxes: PerCpu<WorkerInbox, MAX_WORKERS>,
}

const fn fresh_inboxes() -> [WorkerInbox; MAX_WORKERS] {
    [const { WorkerInbox::new() }; MAX_WORKERS]
}

impl UdpState {
    const fn new() -> Self {
        UdpState {
            port: AtomicU16::new(0),
            inboxes: PerCpu::new(fresh_inboxes()),
        }
    }
}

static UDP_REGISTRY: [UdpState; MAX_UDP_SOCKETS] =
    [const { UdpState::new() }; MAX_UDP_SOCKETS];

// ---- Backend vtable (UDP) ---------------------------------------------------

/// All UDP backend hooks. Installed once at boot by the platform
/// backend — native (POSIX sockets) or bare-metal (integrated NIC
/// driver + protocol stack). `UdpSocket::bind` / `send_to` /
/// `Drop` dispatch through a single atomic load instead of one
/// per hook.
pub struct UdpBackend {
    /// Called after `UdpSocket::bind` claims a UDP_REGISTRY slot.
    /// `None` on bare-metal (routing is REGISTRY-only); `Some` on
    /// native (opens SO_REUSEPORT sibling fds).
    pub bind: Option<fn(port: u16) -> Result<(), ()>>,
    /// Mirror of `bind` — called on port release to let the
    /// backend tear down per-bind state. Same optional-on-bare-
    /// metal rationale.
    pub unbind: Option<fn(port: u16)>,
    /// Datagram send transport. Mandatory: `UdpSocket::send_to`
    /// returns `Err(())` if the backend isn't installed yet.
    pub send: fn(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]),
}

static UDP_BACKEND: AtomicPtr<UdpBackend> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the UDP backend. Call once at boot, before any
/// `UdpSocket::bind` / `send_to`. Safe to call more than once —
/// last writer wins — but that's not a supported runtime pattern.
pub fn register_udp_backend(b: &'static UdpBackend) {
    UDP_BACKEND.store(b as *const _ as *mut _, Ordering::Release);
}

#[inline]
fn udp_backend() -> Option<&'static UdpBackend> {
    let p = UDP_BACKEND.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `register_udp_backend` stores `&'static` references;
        // the pointer is either null or a valid `&'static UdpBackend`.
        Some(unsafe { &*p })
    }
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

/// A UDP socket bound to one port.
///
/// Two lifecycles:
///   * **Short-lived request/reply** (DHCP bring-up, DNS client,
///     NTP query): `bind(port)?` → `send_to` / `recv_from` → drop.
///     `Drop` releases the port slot.
///   * **Long-lived listener / fan-out reactor** (UDP echo,
///     QUIC): `bind(port)?.run_each(handler)` returns a
///     [`UdpHandle`]. Drop it to stop the per-worker receivers
///     and release the port; call `.leak()` when the listener
///     should live for the whole process.
#[must_use = "UdpSocket releases its port on drop; bind without \
              using the socket immediately releases it again"]
pub struct UdpSocket {
    port: u16,
    idx: usize,
    /// `UdpHandle::Drop` releases the port slot and calls the
    /// backend's unbind hook eagerly so a subsequent
    /// `bind(same_port)` works without waiting for aborted tasks
    /// to actually drop their `Arc<UdpSocket>` clones. This flag
    /// makes the later `UdpSocket::Drop` (on the last Arc drop) a
    /// no-op. Plain `bind + drop` paths leave it clear and get
    /// the release here.
    released: AtomicBool,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            // Already released by `UdpHandle::Drop`.
            return;
        }
        // Order matters: clear the registry slot first (so the
        // port is immediately available for a new bind on this
        // thread) and only then notify the backend. Native's
        // unbind hook closes POSIX fds, which is much slower and
        // doesn't need to happen before the slot is reusable.
        UDP_REGISTRY[self.idx].port.store(0, Ordering::Release);
        if let Some(unbind) = udp_backend().and_then(|b| b.unbind) {
            unbind(self.port);
        }
        // The inbox's unconsumed entries (if any) stay — the next
        // bind that lands on this slot calls `reset()` on every
        // worker's inbox before use.
    }
}

impl UdpSocket {
    pub fn bind(port: u16) -> Result<UdpSocket, UdpBindError> {
        if port == 0 {
            return Err(UdpBindError::InvalidPort);
        }
        for state in UDP_REGISTRY.iter() {
            if state.port.load(Ordering::Acquire) == port {
                return Err(UdpBindError::PortInUse);
            }
        }
        for (idx, state) in UDP_REGISTRY.iter().enumerate() {
            if state
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                for w in 0..MAX_WORKERS as u32 {
                    state.inboxes.at(w).reset();
                }
                if let Some(bind) = udp_backend().and_then(|b| b.bind) {
                    if bind(port).is_err() {
                        state.port.store(0, Ordering::Release);
                        return Err(UdpBindError::BackendFailed);
                    }
                }
                return Ok(UdpSocket {
                    port,
                    idx,
                    released: AtomicBool::new(false),
                });
            }
        }
        Err(UdpBindError::AllSlotsBusy)
    }

    /// Port this socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Send a datagram from this socket to `(dst_ip, dst_port)`.
    /// Returns `Err(())` if the backend isn't wired (should only
    /// happen pre-init) — backend failures themselves (full TX
    /// ring on bare-metal, `sendto` EAGAIN on native) are swallowed
    /// today since they're harmless for UDP; add a proper error
    /// enum when QUIC needs to observe them.
    pub fn send_to(&self, dst_ip: [u8; 4], dst_port: u16, data: &[u8]) -> Result<(), ()> {
        let b = udp_backend().ok_or(())?;
        (b.send)(dst_ip, self.port, dst_port, data);
        Ok(())
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
    /// Returns a [`UdpHandle`] whose `Drop` aborts the per-worker
    /// recv tasks and releases the port. Long-lived listeners
    /// should call `.leak()` on the handle.
    pub fn run_each<H>(self, handler: H) -> UdpHandle
    where
        H: Fn([u8; 4], u16, &[u8]) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        self.run_loop_boxed(Box::new(move |sock: Arc<UdpSocket>| {
            let handler = Arc::clone(&handler);
            Box::pin(async move {
                let mut buf = [0u8; MAX_PAYLOAD];
                loop {
                    let (src_ip, src_port, n) = sock.recv_from(&mut buf).await;
                    handler(src_ip, src_port, &buf[..n]);
                }
            })
        }))
    }

    /// Escape hatch: custom async body, spawned once per worker.
    /// The body receives `Arc<UdpSocket>` (owned ref — the task's
    /// future owns its clone, so lifetime is `'static`) and
    /// typically loops on `recv_from` to drive the per-worker
    /// inbox. Use this when the sync `run_each` doesn't fit
    /// (async per-datagram work, batched reads, cross-message
    /// state not expressible via `PerCpu`).
    ///
    /// Returns a [`UdpHandle`] whose `Drop` aborts the per-worker
    /// recv tasks and releases the port.
    pub fn run_loop<H, F>(self, body: H) -> UdpHandle
    where
        H: Fn(Arc<UdpSocket>) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        self.run_loop_boxed(Box::new(move |sock| Box::pin(body(sock))))
    }

    fn run_loop_boxed(self, body: BoxedBody) -> UdpHandle {
        let ctx = Arc::new(UdpFanoutCtx {
            sock: Arc::new(self),
            body,
            stopping: AtomicBool::new(false),
            handles: [const { SpinLock::new(None) }; MAX_WORKERS],
        });
        // Launcher captures a strong `Arc<ctx>` clone. When
        // `UdpHandle::drop` frees the launcher slot, the captured
        // clone drops; if it was the last one, `Arc<ctx>` drops
        // (cascading `sock` Arc drop and thus `UdpSocket::Drop`),
        // so there's no permanent leak.
        let ctx_for_launcher = Arc::clone(&ctx);
        let launcher_slot = register_net_launcher(Box::new(move || {
            if ctx_for_launcher.stopping.load(Ordering::Acquire) {
                return;
            }
            let sock = Arc::clone(&ctx_for_launcher.sock);
            let fut = (ctx_for_launcher.body)(sock);
            if let Ok(h) = crate::spawn(fut) {
                install_worker_task(
                    &ctx_for_launcher.stopping,
                    &ctx_for_launcher.handles,
                    h,
                );
            }
        }));
        UdpHandle { ctx, launcher_slot }
    }
}

// ---- UdpHandle: owning reference returned by run_each / run_loop --

type BoxedBody = Box<
    dyn Fn(Arc<UdpSocket>) -> Pin<Box<dyn Future<Output = ()>>>
        + Send + Sync + 'static,
>;

/// Per-fanout shared state: the socket, the user's body closure,
/// a stop flag, and one `TaskHandle` slot per worker. Owned by
/// `UdpHandle` (strong `Arc`) and by the launcher closure inside
/// `NET_LAUNCHERS` (strong `Arc`). When `UdpHandle::drop` frees
/// the launcher slot, the only strong ref left is the handle's
/// own clone; dropping it drops `UdpFanoutCtx`, which drops
/// `Arc<UdpSocket>`, which (on the last worker's per-task Arc
/// release) runs `UdpSocket::Drop`.
struct UdpFanoutCtx {
    sock: Arc<UdpSocket>,
    body: BoxedBody,
    stopping: AtomicBool,
    handles: [SpinLock<Option<crate::TaskHandle>>; MAX_WORKERS],
}

/// Owning handle to a running `UdpSocket` fanout. Use via `Deref`
/// for `send_to` / `recv_from` / `port`; `Drop` aborts the
/// per-worker recv tasks and releases the port slot. Call
/// `.leak()` for process-lifetime listeners.
#[must_use = "UdpHandle stops the recv tasks and releases the port \
              on drop; for a long-lived listener call .leak()"]
pub struct UdpHandle {
    ctx: Arc<UdpFanoutCtx>,
    launcher_slot: usize,
}

impl UdpHandle {
    /// Relinquish ownership — the socket + recv tasks live for
    /// the rest of the process. Idiomatic for app-lifetime UDP
    /// listeners (UDP echo, QUIC endpoints).
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl core::ops::Deref for UdpHandle {
    type Target = UdpSocket;
    fn deref(&self) -> &UdpSocket {
        &self.ctx.sock
    }
}

impl Drop for UdpHandle {
    fn drop(&mut self) {
        // 1. Block any launcher that hasn't fired yet. Store
        //    first so any worker that proceeds past the `stopping`
        //    check after `handles` is iterated still sees `true`
        //    on its re-check in the launcher closure.
        self.ctx.stopping.store(true, Ordering::Release);
        // 2. Abort tasks already spawned. `TaskHandle::abort` is
        //    cross-worker-safe: sets the abort flag + forces a
        //    tick on the owning worker so the future is dropped
        //    promptly.
        for slot in self.ctx.handles.iter() {
            if let Some(h) = slot.lock().take() {
                h.abort();
            }
        }
        // 3. Eager port release so a subsequent `bind(same_port)`
        //    succeeds without waiting for aborted tasks to
        //    actually drop their `Arc<UdpSocket>` clones.
        //    `UdpSocket::Drop` will see `released = true` on the
        //    last Arc drop and no-op.
        let sock = &*self.ctx.sock;
        if !sock.released.swap(true, Ordering::AcqRel) {
            UDP_REGISTRY[sock.idx].port.store(0, Ordering::Release);
            if let Some(unbind) = udp_backend().and_then(|b| b.unbind) {
                unbind(sock.port);
            }
        }
        // 4. Free the launcher Box — this drops the launcher's
        //    strong `Arc<ctx>` clone. Combined with our own Arc
        //    dropping at end of scope, the ctx refcount falls to
        //    zero once all per-worker tasks have actually dropped
        //    (on their next tick after abort). At that point the
        //    Arc<UdpSocket> inside also drops and the backing
        //    heap memory is reclaimed.
        release_launcher_slot(self.launcher_slot);
    }
}

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
        let inbox = UDP_REGISTRY[this.sock.idx].inboxes.current(&cc);

        // Fast path: data already in this worker's inbox.
        if let Some(r) = inbox.pop_into(this.buf) {
            return Poll::Ready(r);
        }
        // Slow path: register the waker, then re-check — closes the
        // race where `deliver_udp` pushed between the fast-path pop
        // and the waker registration. Dedup via `will_wake` keeps the
        // loop case (same task polling in a tight recv loop) off the
        // clone path.
        {
            let mut slot = inbox.waker.lock();
            let need_store = match &*slot {
                Some(w) => !w.will_wake(cx.waker()),
                None => true,
            };
            if need_store {
                *slot = Some(cx.waker().clone());
            }
        }
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
    for state in UDP_REGISTRY.iter() {
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

// ============================================================================
// TCP accept reactor
// ============================================================================
//
// `TcpListener::bind(port)` claims a slot in a parallel registry.
// The backend (bare-metal `net::tcp` / native `drain_tcp_listener`)
// calls `deliver_tcp_ready(port)` on the core that observed a new
// accept-able connection; `accept()` await-loops
// `tcp_backend_accept` (the backend's non-blocking accept fn) under
// the familiar "try → register waker → re-check" pattern.
//
// Unlike the UDP reactor, the TCP reactor does NOT buffer accepted
// connections itself — the backend's own accept queue is the source
// of truth. `TcpAccept::poll` simply calls the backend's accept
// hook; the reactor layer is purely "notify when there's something
// to accept".
//
// Accepted connections are returned as `RawTcpStream(*mut ())` —
// the same opaque handle `uni_backend::tcp_accept` returns today.
// Higher layers wrap it into `uni::TcpStream` for the typed API.

pub const MAX_TCP_LISTENERS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpBindError {
    AllSlotsBusy,
    PortInUse,
    InvalidPort,
    /// Backend refused to open the listener (port already in use
    /// by another process on native, etc.).
    BackendFailed,
}

/// Opaque handle to a backend TCP connection. Higher layers
/// (`uni::TcpStream`) wrap it into a typed API.
///
/// `generation` is the backend-assigned generation for this conn
/// slot; every subsequent async hook call verifies it matches the
/// conn's current generation, so a stale handle that survived a
/// connection close + slot reuse is detected and short-circuits to
/// the "closed" path (recv returns 0, waker registration
/// immediately wakes to let the task observe closure).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawTcpStream {
    pub handle: *mut (),
    pub generation: u16,
}

/// `!Send` — backends return pointers into per-worker state; moving
/// a stream across workers is wrong. The task system already keeps
/// futures pinned to their spawning worker.
impl RawTcpStream {
    pub const NULL: Self = RawTcpStream {
        handle: core::ptr::null_mut(),
        generation: 0,
    };

    #[inline]
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }
}

struct TcpState {
    port: AtomicU16,
    /// Per-worker waker slot. Backend `deliver_tcp_ready` fires on
    /// the core that has the newly-accept-able conn; the waker
    /// wakes a task on that same core.
    wakers: PerCpu<SpinLock<Option<Waker>>, MAX_WORKERS>,
}

const fn fresh_waker_slots() -> [SpinLock<Option<Waker>>; MAX_WORKERS] {
    [const { SpinLock::new(None) }; MAX_WORKERS]
}

impl TcpState {
    const fn new() -> Self {
        TcpState {
            port: AtomicU16::new(0),
            wakers: PerCpu::new(fresh_waker_slots()),
        }
    }
}

static TCP_REGISTRY: [TcpState; MAX_TCP_LISTENERS] =
    [const { TcpState::new() }; MAX_TCP_LISTENERS];

// ---- Backend vtable (TCP) ---------------------------------------------------

/// All TCP backend hooks. Installed once at boot by the platform
/// backend — native (kqueue/epoll over POSIX sockets) or bare-
/// metal (integrated NIC driver + handshake stack). Every TCP
/// reactor dispatch — listen/accept/unlisten plus per-stream
/// recv/send readiness and transport — goes through a single
/// atomic load of this pointer instead of one load per hook.
///
/// Generation discipline: every per-stream hook receives the
/// `generation` stamped into the `RawTcpStream` when it was handed
/// out via `TcpAccept`. A mismatch against the conn's current
/// generation means the slot was reused, and the backend short-
/// circuits to the "closed" path — recv returns 0, try_send
/// returns -1, waker registration fires immediately so the task
/// observes closure on its next poll.
pub struct TcpBackend {
    /// Claim the listener for `port`. Bare-metal opens one TCB per
    /// core; native opens a single listen fd shared across workers.
    pub listen: fn(port: u16) -> Result<(), ()>,
    /// Non-blocking accept. Returns `RawTcpStream::NULL` when
    /// nothing is ready; otherwise returns a handle paired with
    /// the accepted conn's current generation.
    pub accept: fn(port: u16) -> RawTcpStream,
    /// Optional release hook — native closes its listen fd,
    /// bare-metal frees its per-core Listen TCB slots. Backends
    /// without per-listener state can leave this `None`.
    pub unlisten: Option<fn(port: u16)>,

    // Per-stream recv hooks (hot path — TcpRecv::poll).
    /// Cheap non-blocking probe. Returns `true` also on close or
    /// stale `gen` so the caller's `recv` resolves to `0` in those
    /// cases.
    pub has_data: fn(handle: *mut (), generation: u16) -> bool,
    /// Sync read into `buf`; `0` = EOF / close / stale `gen`.
    pub do_recv: fn(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize,
    /// Store this waker. Called before the final has-data re-check;
    /// the backend de-dupes with `Waker::will_wake`. A stale `gen`
    /// fires `waker` immediately.
    pub register_recv_waker:
        fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored recv waker. Called after Ready. Stale `gen`
    /// is a no-op.
    pub clear_recv_waker: fn(handle: *mut (), generation: u16),

    // Per-stream send hooks (hot path — TcpSend::poll).
    /// Non-blocking write. Returns bytes-queued on success (may be
    /// partial), `0` if the backend is full (caller should park a
    /// waker and re-poll), or negative on fatal conn error /
    /// stale `gen`.
    pub try_send: fn(handle: *mut (), generation: u16, buf: &[u8]) -> isize,
    /// Park `waker` on the conn's send slot; a subsequent writable
    /// event fires it. Stale `gen` fires immediately.
    pub register_send_waker:
        fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored send waker.
    pub clear_send_waker: fn(handle: *mut (), generation: u16),
}

static TCP_BACKEND: AtomicPtr<TcpBackend> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the TCP backend. Call once at boot.
pub fn register_tcp_backend(b: &'static TcpBackend) {
    TCP_BACKEND.store(b as *const _ as *mut _, Ordering::Release);
}

#[inline]
fn tcp_backend() -> Option<&'static TcpBackend> {
    let p = TCP_BACKEND.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: `register_tcp_backend` stores `&'static` references;
        // the pointer is either null or a valid `&'static TcpBackend`.
        Some(unsafe { &*p })
    }
}

/// A TCP listener bound to one port.
///
/// Two lifecycles, same shape as [`UdpSocket`]: drop directly for
/// a short-lived bind (releases the port); call
/// `bound.run(handler)` for the fan-out pattern and drop / leak
/// the returned [`TcpHandle`].
#[must_use = "TcpListener releases its port on drop"]
pub struct TcpListener {
    port: u16,
    idx: usize,
    /// Same pattern as `UdpSocket::released` — set by
    /// `TcpHandle::Drop` so the later `TcpListener::Drop` on the
    /// last `Arc` release no-ops instead of double-invoking the
    /// backend unlisten hook.
    released: AtomicBool,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        TCP_REGISTRY[self.idx].port.store(0, Ordering::Release);
        if let Some(unlisten) = tcp_backend().and_then(|b| b.unlisten) {
            unlisten(self.port);
        }
    }
}

impl TcpListener {
    pub fn bind(port: u16) -> Result<TcpListener, TcpBindError> {
        if port == 0 {
            return Err(TcpBindError::InvalidPort);
        }
        for state in TCP_REGISTRY.iter() {
            if state.port.load(Ordering::Acquire) == port {
                return Err(TcpBindError::PortInUse);
            }
        }
        for (idx, state) in TCP_REGISTRY.iter().enumerate() {
            if state
                .port
                .compare_exchange(0, port, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                for w in 0..MAX_WORKERS as u32 {
                    *state.wakers.at(w).lock() = None;
                }
                let b = tcp_backend().ok_or(TcpBindError::BackendFailed)?;
                if (b.listen)(port).is_err() {
                    state.port.store(0, Ordering::Release);
                    return Err(TcpBindError::BackendFailed);
                }
                return Ok(TcpListener {
                    port,
                    idx,
                    released: AtomicBool::new(false),
                });
            }
        }
        Err(TcpBindError::AllSlotsBusy)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Await the next accepted connection on the **calling worker**.
    /// Resolves with a `RawTcpStream`. The stream pointer is
    /// non-null by construction of the `accept` hook contract — a
    /// null return from the hook means "not ready yet" and keeps
    /// the future Pending.
    pub fn accept<'a>(&'a self) -> TcpAccept<'a> {
        TcpAccept {
            listener: self,
            _not_send: PhantomData,
        }
    }

    /// Spawn `body` once per accepted connection. The framework
    /// owns the accept loop; each `body(stream)` invocation runs
    /// as its own task on the worker that accepted the connection.
    ///
    /// Returns a [`TcpHandle`] whose `Drop` aborts the per-worker
    /// accept tasks and releases the port. In-flight per-connection
    /// tasks already spawned keep running until they return
    /// normally (the handle drop doesn't force-close live conns).
    /// Long-lived listeners should call `.leak()` on the handle.
    pub fn run<H, F>(self, body: H) -> TcpHandle
    where
        H: Fn(RawTcpStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let body = Arc::new(body);
        let ctx = Arc::new(TcpFanoutCtx {
            listener: Arc::new(self),
            accept_body: Box::new(move |stream| {
                let body = Arc::clone(&body);
                Box::pin(async move { body(stream).await })
            }),
            stopping: AtomicBool::new(false),
            handles: [const { SpinLock::new(None) }; MAX_WORKERS],
        });
        let ctx_for_launcher = Arc::clone(&ctx);
        let launcher_slot = register_net_launcher(Box::new(move || {
            if ctx_for_launcher.stopping.load(Ordering::Acquire) {
                return;
            }
            // Clone the listener Arc for the accept task — the
            // task's future owns it for as long as it runs.
            let listener = Arc::clone(&ctx_for_launcher.listener);
            let ctx_inner = Arc::clone(&ctx_for_launcher);
            if let Ok(h) = crate::spawn(async move {
                loop {
                    let stream = listener.accept().await;
                    // `accept_body` wraps the user's body in a
                    // factory that itself clones its captured
                    // Arc<body> for the per-conn task.
                    let fut = (ctx_inner.accept_body)(stream);
                    let _ = crate::spawn(fut);
                }
            }) {
                install_worker_task(
                    &ctx_for_launcher.stopping,
                    &ctx_for_launcher.handles,
                    h,
                );
            }
        }));
        TcpHandle { ctx, launcher_slot }
    }
}

type BoxedAcceptBody = Box<
    dyn Fn(RawTcpStream) -> Pin<Box<dyn Future<Output = ()>>>
        + Send + Sync + 'static,
>;

/// Per-fanout shared state for `TcpListener::run`. Shape mirrors
/// `UdpFanoutCtx`; separated because the two reactors register
/// different body signatures. Owned by `TcpHandle` + the launcher
/// closure (both strong `Arc`s); the launcher's ref drops when
/// `TcpHandle::Drop` frees the launcher slot.
struct TcpFanoutCtx {
    listener: Arc<TcpListener>,
    accept_body: BoxedAcceptBody,
    stopping: AtomicBool,
    handles: [SpinLock<Option<crate::TaskHandle>>; MAX_WORKERS],
}

/// Owning handle to a running `TcpListener` fanout. Use via
/// `Deref` for `port` / `accept`; `Drop` aborts the per-worker
/// accept tasks and releases the port slot. Call `.leak()` for
/// process-lifetime listeners.
#[must_use = "TcpHandle stops the accept tasks and releases the \
              port on drop; for a long-lived listener call .leak()"]
pub struct TcpHandle {
    ctx: Arc<TcpFanoutCtx>,
    launcher_slot: usize,
}

impl TcpHandle {
    pub fn leak(self) {
        core::mem::forget(self);
    }
}

impl core::ops::Deref for TcpHandle {
    type Target = TcpListener;
    fn deref(&self) -> &TcpListener {
        &self.ctx.listener
    }
}

impl Drop for TcpHandle {
    fn drop(&mut self) {
        self.ctx.stopping.store(true, Ordering::Release);
        for slot in self.ctx.handles.iter() {
            if let Some(h) = slot.lock().take() {
                h.abort();
            }
        }
        // Eager port release — mirror `TcpListener::Drop` so a
        // rebind works without waiting for aborted accept tasks
        // to drop their `Arc<TcpListener>` clones.
        let l = &*self.ctx.listener;
        if !l.released.swap(true, Ordering::AcqRel) {
            TCP_REGISTRY[l.idx].port.store(0, Ordering::Release);
            if let Some(unlisten) = tcp_backend().and_then(|b| b.unlisten) {
                unlisten(l.port);
            }
        }
        release_launcher_slot(self.launcher_slot);
    }
}

pub struct TcpAccept<'a> {
    listener: &'a TcpListener,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> Future for TcpAccept<'a> {
    type Output = RawTcpStream;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let port = this.listener.port;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending, // backend not wired yet
        };

        // Fast path
        let stream = (b.accept)(port);
        if !stream.is_null() {
            return Poll::Ready(stream);
        }

        // Register waker on this worker's slot, then re-check.
        // `will_wake` dedup keeps long-lived accept loops off the
        // clone path when the same task re-polls.
        let cc = CurrentCore::enter();
        let state = &TCP_REGISTRY[this.listener.idx];
        {
            let mut slot = state.wakers.current(&cc).lock();
            let need_store = match &*slot {
                Some(w) => !w.will_wake(cx.waker()),
                None => true,
            };
            if need_store {
                *slot = Some(cx.waker().clone());
            }
        }

        let stream = (b.accept)(port);
        if !stream.is_null() {
            *state.wakers.current(&cc).lock() = None;
            return Poll::Ready(stream);
        }

        Poll::Pending
    }
}

// ---- Per-stream async recv -------------------------------------------------
//
// `TcpStream::recv(buf).await` resolves with the byte count once the
// backend has data available on the underlying conn (or zero on peer
// close). The backend owns the readiness signal (kqueue/epoll on
// native, rx-ring enqueue on bare-metal) and parks / wakes a single
// per-stream `Waker` via the `register_recv_waker` / `has_data` /
// `do_recv` / `clear_recv_waker` fields of `TcpBackend`. The stream
// handle is an opaque `*mut ()` — identical to the `RawTcpStream`
// the accept reactor returns.

/// Future returned by `TcpStream::recv`. Holds a mutable borrow of
/// the caller's buffer plus the conn handle + generation. `!Send`
/// because the underlying handle points into per-worker state.
pub struct TcpRecv<'a> {
    handle: *mut (),
    generation: u16,
    buf: &'a mut [u8],
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpRecv<'a> {
    #[inline]
    pub fn new(handle: *mut (), generation: u16, buf: &'a mut [u8]) -> Self {
        TcpRecv { handle, generation, buf, _not_send: PhantomData }
    }
}

impl<'a> Future for TcpRecv<'a> {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };
        // Fast path — probe, read, clear any stale waker.
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        // Register waker, then re-check — closes the wake-before-park
        // race with the backend's wake site.
        (b.register_recv_waker)(h, g, cx.waker());
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        Poll::Pending
    }
}

// ---- Per-stream async send ------------------------------------------------
//
// `TcpStream::send(data).await` resolves when every byte in `data`
// has been queued to the backend (kernel send buffer on native, NIC
// TX ring on bare-metal) or the connection is dead. Same waker
// protocol as recv but parked on a separate slot so reads and
// writes can pend concurrently on the same conn. Hook semantics
// live on `TcpBackend::{try_send, register_send_waker,
// clear_send_waker}`.

/// Future returned by `TcpStream::send`. Resolves `Ok(())` when
/// every byte in `data` has been queued, or `Err(())` if the
/// connection breaks. `!Send`.
pub struct TcpSend<'a> {
    handle: *mut (),
    generation: u16,
    buf: &'a [u8],
    sent: usize,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpSend<'a> {
    #[inline]
    pub fn new(handle: *mut (), generation: u16, buf: &'a [u8]) -> Self {
        TcpSend { handle, generation, buf, sent: 0, _not_send: PhantomData }
    }
}

impl<'a> Future for TcpSend<'a> {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };

        // Drain as much as the backend will take this tick.
        loop {
            if this.sent == this.buf.len() {
                (b.clear_send_waker)(h, g);
                return Poll::Ready(Ok(()));
            }
            let remaining = &this.buf[this.sent..];
            let n = (b.try_send)(h, g, remaining);
            if n < 0 {
                (b.clear_send_waker)(h, g);
                return Poll::Ready(Err(()));
            }
            if n == 0 {
                // Backend is full. Park waker, then re-probe once —
                // closes the wake-before-park race with the writable
                // event site. If the second try also returns 0, pend.
                (b.register_send_waker)(h, g, cx.waker());
                let n2 = (b.try_send)(h, g, remaining);
                if n2 < 0 {
                    (b.clear_send_waker)(h, g);
                    return Poll::Ready(Err(()));
                }
                if n2 == 0 {
                    return Poll::Pending;
                }
                this.sent += n2 as usize;
                continue;
            }
            this.sent += n as usize;
        }
    }
}

/// Notify the reactor that the backend has a newly accept-able
/// connection for `dst_port`. Must be called from the core that
/// owns the new connection (bare-metal: core whose RX queue
/// observed the handshake completion; native: worker whose
/// kqueue/epoll fired for the listen fd). Returns `true` if a
/// matching listener was found.
pub fn deliver_tcp_ready(dst_port: u16) -> bool {
    let cc = CurrentCore::enter();
    for state in TCP_REGISTRY.iter() {
        if state.port.load(Ordering::Acquire) == dst_port {
            let taken = state.wakers.current(&cc).lock().take();
            if let Some(waker) = taken {
                waker.wake();
            }
            return true;
        }
    }
    false
}

// ---- Shared launcher table (UDP + TCP + future reactors) --------------------
//
// Any reactor's `run`-style method registers a type-erased launcher
// closure here via `register_net_launcher`. A single
// `spawn_on_each_worker` hook — registered lazily on the first
// launcher — walks the table on each worker's first tick and fires
// every live launcher. Each launcher calls `spawn(body(...))` on
// the calling worker.
//
// Slot states (stored in `AtomicPtr<BoxedLauncher>`):
//   * `null`      — not yet stored (`register_net_launcher` did
//                   fetch_add but hasn't published; readers stop
//                   and re-try on the next tick).
//   * `TOMBSTONE` — previously live, released via
//                   `release_launcher_slot` (from a `*Handle::Drop`).
//                   Readers skip it; cursor advances past.
//   * any other   — `Box::into_raw(Box::new(BoxedLauncher { .. }))`,
//                   live launcher. The reader dereferences and
//                   calls it.
//
// Slots are NOT reused after release: rewriting a slot whose cursor
// has already passed on some worker would leak the new launcher on
// that worker forever. Bumping `NET_LAUNCHER_COUNT` monotonically
// keeps the cursor invariant simple. `MAX_NET_LAUNCHERS = 256`
// covers typical apps — bump it if a legitimate long-running app
// legitimately creates more listeners than that over its lifetime.

type BoxedLauncher = Box<dyn Fn() + Send + Sync + 'static>;

/// Bounded cap on launchers ever allocated, not live at once.
/// Each `UdpSocket::run_each` / `TcpListener::run` / etc. costs
/// one slot; handle drop marks the slot as a tombstone but doesn't
/// free it for reuse. 256 covers a realistic long-running app.
const MAX_NET_LAUNCHERS: usize = 256;

/// Sentinel for a released slot. Must be a non-null, non-Box pointer;
/// we use `1` which cannot collide with any real `Box::into_raw`
/// result (all real heap pointers are aligned to at least 8).
#[inline]
fn tombstone() -> *mut BoxedLauncher {
    1 as *mut BoxedLauncher
}

#[inline]
fn is_tombstone(p: *mut BoxedLauncher) -> bool {
    p as usize == 1
}

static NET_LAUNCHERS: [AtomicPtr<BoxedLauncher>; MAX_NET_LAUNCHERS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_NET_LAUNCHERS];
static NET_LAUNCHER_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
/// Per-worker cursor into `NET_LAUNCHERS` — each tick fires only
/// the launchers added since this worker's last fire. Mirrors
/// `STARTUP_FIRED_COUNT` in `uni-runtime/src/lib.rs`; needed
/// because launchers can be registered from inside a task running
/// on a worker that's already ticked (e.g. `TcpListener::bind(80)`
/// called from the `#[uni::boot]` async body after DHCP's
/// `UdpSocket::bind(68)` already ran).
static NET_LAUNCHER_FIRED: [core::sync::atomic::AtomicUsize; MAX_WORKERS] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_WORKERS];

/// Register a launcher. Returns the slot index so the owning
/// handle can call `release_launcher_slot` on drop, freeing the
/// captured `Arc`s. `usize::MAX` means "table full; launcher
/// dropped" — the caller still gets a valid handle, but no task
/// ever fires. Practically this only happens if an app creates
/// more than `MAX_NET_LAUNCHERS` listeners over its entire
/// lifetime.
fn register_net_launcher(launcher: BoxedLauncher) -> usize {
    let i = NET_LAUNCHER_COUNT
        .fetch_add(1, Ordering::AcqRel);
    if i >= MAX_NET_LAUNCHERS {
        return usize::MAX;
    }
    let outer: Box<BoxedLauncher> = Box::new(launcher);
    NET_LAUNCHERS[i].store(Box::into_raw(outer), Ordering::Release);
    i
}

/// Release a launcher slot on handle drop: swap a tombstone into
/// the slot and free the `Box`. The tombstone ensures
/// `fire_pending_net_launchers` skips the slot instead of
/// stalling on it.
fn release_launcher_slot(idx: usize) {
    if idx >= MAX_NET_LAUNCHERS {
        return;
    }
    let prev = NET_LAUNCHERS[idx].swap(tombstone(), Ordering::AcqRel);
    if prev.is_null() || is_tombstone(prev) {
        return;
    }
    // SAFETY: every non-null non-tombstone pointer in this table
    // came from `Box::into_raw(Box::new(BoxedLauncher{..}))` in
    // `register_net_launcher`. We hold exclusive access to it now
    // (the swap removed it from the shared table; only this call
    // site consumes it).
    unsafe {
        let _ = Box::from_raw(prev);
    }
}

/// Spawn every net launcher added since `worker_id` last called
/// here. Runs once per `uni_runtime::tick()` — a no-op when the
/// cursor is already caught up, which is the common case.
///
/// `register_net_launcher` does `fetch_add(count)` and then
/// `store(slot)` as two separate ops, so a reader can observe the
/// incremented count before the matching slot is published. We stop
/// at the first null slot rather than skipping it, so the next
/// tick re-tries; skipping + advancing the cursor would drop the
/// registration permanently.
pub fn fire_pending_net_launchers(worker_id: u32) {
    if (worker_id as usize) >= MAX_WORKERS {
        return;
    }
    let total = NET_LAUNCHER_COUNT
        .load(Ordering::Acquire)
        .min(MAX_NET_LAUNCHERS);
    let fired = NET_LAUNCHER_FIRED[worker_id as usize].load(Ordering::Relaxed);
    if fired >= total {
        return;
    }
    let mut new_fired = fired;
    for i in fired..total {
        let p = NET_LAUNCHERS[i].load(Ordering::Acquire);
        if p.is_null() {
            // Registration mid-flight (fetch_add done, store not
            // yet visible). Stop here; the next tick catches up.
            break;
        }
        if is_tombstone(p) {
            // Slot was live and has been released. Skip and
            // advance — never re-touch.
            new_fired = i + 1;
            continue;
        }
        // SAFETY: `p` was obtained from `Box::into_raw(Box::new(
        // BoxedLauncher{..}))` in `register_net_launcher`. The
        // pointer's validity is guaranteed until
        // `release_launcher_slot` swaps in a tombstone (detected
        // above), and the swap is AcqRel so we see a consistent
        // snapshot.
        let launcher: &BoxedLauncher = unsafe { &*p };
        launcher();
        new_fired = i + 1;
    }
    if new_fired > fired {
        NET_LAUNCHER_FIRED[worker_id as usize]
            .store(new_fired, Ordering::Relaxed);
    }
}
