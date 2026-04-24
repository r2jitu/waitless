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
static BACKEND_UDP_SEND: AtomicFn<
    fn(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]),
> = AtomicFn::null();

/// Register the backend-side bind hook. On bare-metal this stays
/// unset — the NIC RX path unconditionally delivers to
/// `deliver_udp`. On native, the POSIX backend registers a hook
/// that opens SO_REUSEPORT sibling fds for each `UdpSocket::bind`.
pub fn register_backend_bind(hook: fn(port: u16) -> Result<(), ()>) {
    BACKEND_BIND.store(hook);
}

/// Register the backend-side UDP send hook. Both bare-metal and
/// native wire this; it's the transport for `UdpSocket::send_to`.
pub fn register_backend_udp_send(
    hook: fn(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]),
) {
    BACKEND_UDP_SEND.store(hook);
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

    /// Send a datagram from this socket to `(dst_ip, dst_port)`.
    /// Returns `Err(())` if the backend isn't wired (should only
    /// happen pre-init) — backend failures themselves (full TX
    /// ring on bare-metal, `sendto` EAGAIN on native) are swallowed
    /// today since they're harmless for UDP; add a proper error
    /// enum when QUIC needs to observe them.
    pub fn send_to(&self, dst_ip: [u8; 4], dst_port: u16, data: &[u8]) -> Result<(), ()> {
        let send = BACKEND_UDP_SEND.load().ok_or(())?;
        send(dst_ip, self.port, dst_port, data);
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
    /// `handler` is `Fn`, called concurrently across workers. State
    /// across calls should live in `PerCpu<T, MAX_WORKERS>` or use
    /// interior mutability.
    pub fn run_each<H>(self, handler: H) -> &'static UdpSocket
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
    ///
    /// Returns the leaked `&'static UdpSocket` so request/reply
    /// protocols (DHCP, DNS client, etc.) can keep sending on it
    /// while receivers fan out across workers. Pure-receiver callers
    /// can drop the returned reference.
    pub fn run_loop<H, F>(self, body: H) -> &'static UdpSocket
    where
        H: Fn(&'static UdpSocket) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let leaked: &'static UdpSocket = Box::leak(Box::new(self));
        register_net_launcher(Box::new(move || {
            let fut = body(leaked);
            let _ = crate::spawn(fut);
        }));
        leaked
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

// Backend hooks. On bare-metal + native both are registered at
// init; pre-registration calls of `TcpListener::bind` / `accept`
// return `BackendFailed` / `Pending` respectively.

static TCP_BACKEND_LISTEN: AtomicFn<fn(port: u16) -> Result<(), ()>> =
    AtomicFn::null();
static TCP_BACKEND_ACCEPT: AtomicFn<fn(port: u16) -> RawTcpStream> =
    AtomicFn::null();

/// Register the TCP backend hooks. Called once at boot by the
/// backend that owns the actual listen sockets / handshake state.
/// `accept` returns `RawTcpStream::NULL` when nothing is ready;
/// otherwise it returns the handle paired with the accepted conn's
/// current generation.
pub fn register_tcp_backend(
    listen: fn(port: u16) -> Result<(), ()>,
    accept: fn(port: u16) -> RawTcpStream,
) {
    TCP_BACKEND_LISTEN.store(listen);
    TCP_BACKEND_ACCEPT.store(accept);
}

pub struct TcpListener {
    port: u16,
    idx: usize,
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
                let listen = TCP_BACKEND_LISTEN
                    .load()
                    .ok_or(TcpBindError::BackendFailed)?;
                if listen(port).is_err() {
                    state.port.store(0, Ordering::Release);
                    return Err(TcpBindError::BackendFailed);
                }
                return Ok(TcpListener { port, idx });
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
    /// Consumes the listener — the port stays claimed for the
    /// process lifetime.
    pub fn run<H, F>(self, body: H)
    where
        H: Fn(RawTcpStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let leaked: &'static TcpListener = Box::leak(Box::new(self));
        let body: &'static H = Box::leak(Box::new(body));
        register_net_launcher(Box::new(move || {
            let _ = crate::spawn(async move {
                loop {
                    let stream = leaked.accept().await;
                    let fut = body(stream);
                    let _ = crate::spawn(fut);
                }
            });
        }));
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
        let accept = match TCP_BACKEND_ACCEPT.load() {
            Some(f) => f,
            None => return Poll::Pending, // backend not wired yet
        };

        // Fast path
        let stream = accept(port);
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

        let stream = accept(port);
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
// per-stream `Waker` registered via the hooks below. The stream
// handle is an opaque `*mut ()` — identical to the `RawTcpStream`
// the accept reactor returns.
//
// Hook contract (every hook receives `generation` — the value the
// backend stamped when the handle was handed out via `TcpAccept`;
// a mismatch against the conn's current generation means the slot
// was reused, and the backend short-circuits to the "closed" path):
// - `TCP_HAS_DATA(h, gen)` — cheap non-blocking probe. `true` also
//   on close or stale `gen` so the caller's `recv` returns `0`.
// - `TCP_DO_RECV(h, gen, buf)` — sync read into `buf`; `0` = EOF /
//   close / stale `gen`.
// - `TCP_REGISTER_RECV_WAKER(h, gen, waker)` — store this waker.
//   Called before the final has-data re-check; the backend de-dupes
//   with `Waker::will_wake`. A stale `gen` fires `waker` immediately
//   so the task observes closure on its next poll.
// - `TCP_CLEAR_RECV_WAKER(h, gen)` — drop the stored waker. Called
//   after Ready. A stale `gen` is a no-op.

static TCP_HAS_DATA: AtomicFn<fn(handle: *mut (), generation: u16) -> bool> =
    AtomicFn::null();
static TCP_DO_RECV: AtomicFn<
    fn(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize,
> = AtomicFn::null();
static TCP_REGISTER_RECV_WAKER: AtomicFn<
    fn(handle: *mut (), generation: u16, waker: &Waker),
> = AtomicFn::null();
static TCP_CLEAR_RECV_WAKER: AtomicFn<fn(handle: *mut (), generation: u16)> =
    AtomicFn::null();

/// Register backend hooks for the async recv primitive. Called once
/// at boot alongside `register_tcp_backend`. Both native and bare-
/// metal wire up all four.
pub fn register_tcp_recv_hooks(
    has_data: fn(handle: *mut (), generation: u16) -> bool,
    do_recv: fn(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize,
    register_waker: fn(handle: *mut (), generation: u16, waker: &Waker),
    clear_waker: fn(handle: *mut (), generation: u16),
) {
    TCP_HAS_DATA.store(has_data);
    TCP_DO_RECV.store(do_recv);
    TCP_REGISTER_RECV_WAKER.store(register_waker);
    TCP_CLEAR_RECV_WAKER.store(clear_waker);
}

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
        let has = match TCP_HAS_DATA.load() {
            Some(f) => f,
            None => return Poll::Pending,
        };
        let do_recv = match TCP_DO_RECV.load() {
            Some(f) => f,
            None => return Poll::Pending,
        };
        // Fast path — probe, read, clear any stale waker.
        if has(h, g) {
            if let Some(clear) = TCP_CLEAR_RECV_WAKER.load() {
                clear(h, g);
            }
            return Poll::Ready(do_recv(h, g, this.buf));
        }
        // Register waker, then re-check — closes the wake-before-park
        // race with the backend's wake site.
        if let Some(reg) = TCP_REGISTER_RECV_WAKER.load() {
            reg(h, g, cx.waker());
        }
        if has(h, g) {
            if let Some(clear) = TCP_CLEAR_RECV_WAKER.load() {
                clear(h, g);
            }
            return Poll::Ready(do_recv(h, g, this.buf));
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
// writes can pend concurrently on the same conn.
//
// Hook contract (all generation-checked; mismatch → treat as closed):
// - `TCP_TRY_SEND(h, gen, buf)` returns
//     > 0  : bytes queued (may be partial);
//     == 0 : would block (caller should register a waker and pend);
//     < 0  : fatal — conn broken / stale generation.
// - `TCP_REGISTER_SEND_WAKER(h, gen, waker)` parks `waker` on the
//   conn's send slot; a subsequent writable event (native:
//   EVFILT_WRITE / EPOLLOUT; bare-metal: NIC-TX drain + stack
//   advance) fires it. Stale `gen` fires immediately so the task
//   observes closure.
// - `TCP_CLEAR_SEND_WAKER(h, gen)` drops the stored waker.

static TCP_TRY_SEND: AtomicFn<
    fn(handle: *mut (), generation: u16, buf: &[u8]) -> isize,
> = AtomicFn::null();
static TCP_REGISTER_SEND_WAKER: AtomicFn<
    fn(handle: *mut (), generation: u16, waker: &Waker),
> = AtomicFn::null();
static TCP_CLEAR_SEND_WAKER: AtomicFn<fn(handle: *mut (), generation: u16)> =
    AtomicFn::null();

/// Register backend hooks for the async send primitive. Called once
/// at boot alongside `register_tcp_backend`.
pub fn register_tcp_send_hooks(
    try_send: fn(handle: *mut (), generation: u16, buf: &[u8]) -> isize,
    register_waker: fn(handle: *mut (), generation: u16, waker: &Waker),
    clear_waker: fn(handle: *mut (), generation: u16),
) {
    TCP_TRY_SEND.store(try_send);
    TCP_REGISTER_SEND_WAKER.store(register_waker);
    TCP_CLEAR_SEND_WAKER.store(clear_waker);
}

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
        let try_send = match TCP_TRY_SEND.load() {
            Some(f) => f,
            None => return Poll::Pending,
        };

        // Drain as much as the backend will take this tick.
        loop {
            if this.sent == this.buf.len() {
                if let Some(clear) = TCP_CLEAR_SEND_WAKER.load() {
                    clear(h, g);
                }
                return Poll::Ready(Ok(()));
            }
            let remaining = &this.buf[this.sent..];
            let n = try_send(h, g, remaining);
            if n < 0 {
                if let Some(clear) = TCP_CLEAR_SEND_WAKER.load() {
                    clear(h, g);
                }
                return Poll::Ready(Err(()));
            }
            if n == 0 {
                // Backend is full. Park waker, then re-probe once —
                // closes the wake-before-park race with the writable
                // event site. If the second try also returns 0, pend.
                if let Some(reg) = TCP_REGISTER_SEND_WAKER.load() {
                    reg(h, g, cx.waker());
                }
                let n2 = try_send(h, g, remaining);
                if n2 < 0 {
                    if let Some(clear) = TCP_CLEAR_SEND_WAKER.load() {
                        clear(h, g);
                    }
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
// Storage is `AtomicPtr<Box<dyn Fn...>>`: the atomic holds a thin
// pointer to a heap-allocated `Box` (which in turn is the fat
// pointer to the closure). `AtomicPtr<T>` requires `T: Sized`;
// `Box<dyn Fn>` is sized. Leaking the outer box keeps the launcher
// heap-alive for the process lifetime — matches the consume-the-
// socket contract of `run`/`run_loop`/`run_each`.

type BoxedLauncher = Box<dyn Fn() + Send + Sync + 'static>;

/// Bounded cap; UDP and TCP each consume up to `MAX_UDP_SOCKETS`
/// slots at current sizing. Total also accommodates any future
/// protocol reactors.
const MAX_NET_LAUNCHERS: usize = 16;

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

/// Register a launcher. Each protocol's `run`/`run_each` method
/// wraps its body-spawn logic in a `BoxedLauncher` and hands it
/// here. Each worker's `tick()` calls `fire_pending_net_launchers`
/// to spawn anything newly added since its last tick.
fn register_net_launcher(launcher: BoxedLauncher) {
    let i = NET_LAUNCHER_COUNT
        .fetch_add(1, Ordering::AcqRel);
    if i >= MAX_NET_LAUNCHERS {
        // Table full — drop. 16 slots is beyond any realistic
        // per-binary reactor count.
        return;
    }
    let outer: Box<BoxedLauncher> = Box::new(launcher);
    NET_LAUNCHERS[i].store(Box::into_raw(outer), Ordering::Release);
}

/// Spawn every net launcher added since `worker_id` last called
/// here. Runs once per `uni_runtime::tick()` — a no-op when the
/// cursor is already caught up, which is the common case.
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
    for slot in NET_LAUNCHERS.iter().take(total).skip(fired) {
        let p = slot.load(Ordering::Acquire);
        if p.is_null() {
            continue;
        }
        // SAFETY: `p` was obtained from `Box::into_raw(Box::new(
        // BoxedLauncher{..}))` in `register_net_launcher`. Outer
        // box is leaked (never freed). Release/Acquire pairs the
        // store and load.
        let launcher: &BoxedLauncher = unsafe { &*p };
        launcher();
    }
    NET_LAUNCHER_FIRED[worker_id as usize].store(total, Ordering::Relaxed);
}
