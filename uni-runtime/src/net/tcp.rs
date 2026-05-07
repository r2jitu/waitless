// uni-runtime/src/net/tcp.rs — TCP listener / accept reactor +
// per-stream send/recv futures.
//
// See `super` (`net/mod.rs`) for the shared primitives (`SpinLock`,
// waker helpers, the launcher table) consumed here and by the UDP
// module.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, Ordering};
use core::task::{Context, Poll, Waker};

use uni_worker::{CurrentWorker, PerWorker, num_workers};

use super::{
    SpinLock, install_worker_task, register_net_launcher, release_launcher_slot,
    store_waker_if_needed,
};

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
// Accepted connections are returned as `TcpStream(*mut ())` —
// the same opaque handle `uni_backend::tcp_accept` returns today.
// Higher layers wrap it into `uni::TcpStream` for the typed API.

/// Static cap on concurrently bound TCP listening ports. Sized to
/// match `MAX_UDP_SOCKETS` so the two registries scale together.
/// In practice apps bind a handful of well-known ports (HTTP /
/// HTTPS / a couple of services); 256 is generous headroom.
///
/// Each slot is ~80 bytes (port + per-worker waker array), so the
/// table is ~20 KB at the upper bound — affordable for the
/// process-lifetime allocation.
pub const MAX_TCP_LISTENERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpBindError {
    AllSlotsBusy,
    PortInUse,
    InvalidPort,
    /// Backend refused to open the listener (port already in use
    /// by another process on native, etc.).
    BackendFailed,
}

/// Owned handle to an accepted TCP connection.
///
/// `generation` is the backend-assigned generation for this conn
/// slot. Every per-stream hook (`recv`, `send`, `close`) verifies
/// it matches the conn's current generation; a stale handle that
/// survived a close + slot reuse is detected and short-circuits
/// to the "closed" path (recv returns 0, waker registration
/// immediately wakes, close no-ops).
///
/// `!Send + !Copy + !Clone + Drop`:
/// - `!Send` because backends return pointers into per-worker
///   state; moving a stream across workers is wrong. The task
///   system already keeps futures pinned to their spawning worker.
/// - `!Copy + !Clone` because the stream owns the conn — at most
///   one `Drop` per accepted conn keeps the close path
///   single-shot.
/// - `Drop` sends FIN and releases the backend's per-stream state
///   via `TcpBackend::close`. Apps don't need an explicit
///   `close()` call on every exit path; `return` from a `run`
///   body drops the stream and tears down cleanly.
pub struct TcpStream {
    handle: *mut (),
    generation: u16,
    _not_send: PhantomData<*mut ()>,
}

impl TcpStream {
    /// Sentinel returned by `TcpBackend::accept` when no
    /// connection is ready. Carries a null pointer; `is_null` is
    /// the way for the reactor to detect this without ever
    /// constructing a real `TcpStream` for "nothing yet".
    ///
    /// SAFETY (for Drop): a null pointer never reaches user code —
    /// the `TcpAccept` future filters it out before the stream is
    /// moved into a body. `TcpStream::Drop` (and `TcpBackend::close`)
    /// no-op on a null handle.
    pub const NULL: Self = TcpStream {
        handle: core::ptr::null_mut(),
        generation: 0,
        _not_send: PhantomData,
    };

    /// Construct directly from a backend handle + generation.
    /// Backends call this from their `accept` hook when a fresh
    /// conn is ready.
    #[inline]
    pub const fn from_raw(handle: *mut (), generation: u16) -> Self {
        TcpStream { handle, generation, _not_send: PhantomData }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }

    /// Async read. Resolves with the byte count when data is
    /// available (or `0` on peer close / stale generation).
    #[inline]
    pub fn recv<'a>(&'a self, buf: &'a mut [u8]) -> TcpRecv<'a> {
        TcpRecv::new(self.handle, self.generation, buf)
    }

    /// Drain exactly `buf.len()` bytes into `buf`. Returns `Ok(())`
    /// when full, `Err(n_filled)` if the peer closed before all
    /// bytes arrived (the partial prefix is left in `buf`).
    ///
    /// Saves the manual `while got < N { ... }` loop every TCP
    /// server otherwise writes for fixed-size frames; for streamed
    /// protocols use `recv` directly.
    pub async fn recv_exact(&self, buf: &mut [u8]) -> Result<(), usize> {
        let total = buf.len();
        let mut got = 0;
        while got < total {
            let n = self.recv(&mut buf[got..]).await;
            if n == 0 {
                return Err(got);
            }
            got += n;
        }
        Ok(())
    }

    /// Async chain write. Hands `chain` to the backend so the
    /// transport decides chunking — bare-metal packs bytes
    /// directly into MSS-sized TCP segments via cursor walk (no
    /// intermediate user-space coalesce buffer); native drains
    /// the chain through `writev(2)` so a multi-part response
    /// shape ships in a single syscall + kernel-side coalesce.
    /// The backend drains `chain` as bytes hit the wire;
    /// resolves `Ok(())` when the chain is empty (every byte
    /// queued), `Err(())` on fatal transport error.
    ///
    /// Chain is the standard send surface — apps that already
    /// have a contiguous slice and don't want to wrap it use
    /// [`Self::send_bytes`] instead.
    #[inline]
    pub fn send<'a>(
        &'a self,
        chain: &'a mut uni_iobuf::IOBufChain,
    ) -> TcpSendChain<'a> {
        TcpSendChain::new(self.handle, self.generation, chain)
    }

    /// Async byte-slice write — convenience wrapper that builds
    /// a 1-element `IOBufChain` borrowing `data` and hands it to
    /// [`Self::send`]. Resolves `Ok(())` when every byte is on
    /// the wire, `Err(())` if the conn breaks.
    ///
    /// Lives at the runtime layer rather than the backend: the
    /// transport sees only chains, the byte-slice case is a
    /// trivial wrap on the way down. Per-call cost is one
    /// `VecDeque` allocation for the chain buffer plus an
    /// `IOBuf::External` struct init — negligible at the call
    /// rates we hit in benchmarks.
    pub async fn send_bytes(&self, data: &[u8]) -> Result<(), ()> {
        // SAFETY: `chain` is dropped before this future returns;
        // the `IOBuf::External` wrapping `data` therefore can't
        // outlive `data`'s borrow. `drop_fn = None` because the
        // bytes are borrowed, not owned.
        let mut chain = uni_iobuf::IOBufChain::new();
        let iobuf = unsafe {
            uni_iobuf::IOBuf::from_external(
                core::ptr::NonNull::new_unchecked(data.as_ptr() as *mut u8),
                data.len() as u32,
                0,
                data.len() as u32,
                None,
                core::ptr::null_mut(),
            )
        };
        chain.push_back(iobuf);
        self.send(&mut chain).await
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if self.handle.is_null() {
            // The NULL sentinel produced by `accept` when nothing
            // was ready. Filtered out before reaching user code,
            // but Drop runs on every value in scope — guard here.
            return;
        }
        if let Some(b) = tcp_backend() {
            (b.close)(self.handle, self.generation);
        }
    }
}

struct TcpState {
    port: AtomicU16,
    /// Per-worker waker slot. Backend `deliver_tcp_ready` fires on
    /// the core that has the newly-accept-able conn; the waker
    /// wakes a task on that same core.
    wakers: PerWorker<SpinLock<Option<Waker>>>,
}

impl TcpState {
    const fn new() -> Self {
        TcpState {
            port: AtomicU16::new(0),
            wakers: PerWorker::new(),
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
/// `generation` stamped into the `TcpStream` when it was handed
/// out via `TcpAccept`. A mismatch against the conn's current
/// generation means the slot was reused, and the backend short-
/// circuits to the "closed" path — recv returns 0, try_send
/// returns -1, waker registration fires immediately so the task
/// observes closure on its next poll.
pub struct TcpBackend {
    /// Claim the listener for `port`. Bare-metal opens one TCB per
    /// core; native opens a single listen fd shared across workers.
    pub listen: fn(port: u16) -> Result<(), ()>,
    /// Non-blocking accept. Returns `TcpStream::NULL` when
    /// nothing is ready; otherwise returns a handle paired with
    /// the accepted conn's current generation.
    pub accept: fn(port: u16) -> TcpStream,
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

    /// Send FIN on the conn and release the backend's per-stream
    /// state. Idempotent: a stale `gen` (slot already reused) or
    /// already-closed conn is a no-op. Called from
    /// `TcpStream::Drop` so apps don't have to track close
    /// explicitly.
    pub close: fn(handle: *mut (), generation: u16),

    // Per-stream send hooks (hot path).
    /// Non-blocking gather-write. Drains as much of `chain` as
    /// the backend can accept this call — the backend decides
    /// the actual chunking. Bare-metal walks the chain via cursor
    /// and packs bytes directly into MSS-sized TCP segments;
    /// native uses `writev(2)` so a multi-part shape
    /// (`[headers, body0, body1, ...]`) becomes one syscall +
    /// kernel-side coalesce.
    ///
    /// Drain semantics: each call pops fully-sent parts off the
    /// front and (on partial native `writev`) advances the front
    /// part's visible payload past the bytes that were committed.
    /// On return the chain holds only what the caller still has
    /// to send. The wrapping `TcpSendChain` future loops until
    /// `chain.is_empty()`. This lets `External` IOBufs return
    /// their backing storage (NIC RX descriptors, etc.) to the
    /// driver pool as bytes hit the wire rather than all at the
    /// end.
    ///
    /// Returns:
    ///   * `Ok(n)` where `n > 0`: drained `n` bytes (chain shrunk).
    ///   * `Ok(0)`: backend queue is full — caller parks a waker
    ///     and re-polls.
    ///   * `Err(())`: fatal conn error / stale `gen` — caller
    ///     drops the conn.
    pub try_send: fn(
        handle: *mut (),
        generation: u16,
        chain: &mut uni_iobuf::IOBufChain,
    ) -> Result<usize, ()>,
    /// Park `waker` on the conn's send slot; a subsequent writable
    /// event fires it. Stale `gen` fires immediately.
    pub register_send_waker:
        fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored send waker.
    pub clear_send_waker: fn(handle: *mut (), generation: u16),

    /// Optional. RST every connection currently in the backend's
    /// pool — called once at shutdown so peers see an immediate
    /// close instead of timing out via TCP keepalive after the VM
    /// powers off. Native leaves this `None`: the kernel FINs every
    /// open fd at process exit.
    pub shutdown_all: Option<fn()>,
}

static TCP_BACKEND: AtomicPtr<TcpBackend> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the TCP backend. Call once at boot.
pub fn register_tcp_backend(b: &'static TcpBackend) {
    TCP_BACKEND.store(b as *const _ as *mut _, Ordering::Release);
}

/// Trigger the backend's `shutdown_all` hook if it has one. No-op
/// on native (the kernel handles fd cleanup at process exit) and
/// before any backend has registered.
pub fn shutdown_all_tcp() {
    if let Some(b) = tcp_backend() {
        if let Some(f) = b.shutdown_all {
            f();
        }
    }
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

/// `bind(port).map(|l| l.run(body))` in one call. The 80%-case
/// shortcut for "open a TCP server on port N and run this loop on
/// every accepted conn." Use [`TcpListener::bind`] +
/// [`TcpListener::run`] directly when you need to inspect /
/// configure the listener between bind and run.
pub fn tcp_listen<H, F>(port: u16, body: H) -> Result<TcpHandle, TcpBindError>
where
    H: Fn(TcpStream) -> F + Send + Sync + 'static,
    F: Future<Output = ()> + 'static,
{
    TcpListener::bind(port).map(|l| l.run(body))
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
                state.wakers.ensure_init(num_workers(), |_| SpinLock::new(None));
                for w in 0..num_workers() {
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
    /// Resolves with a `TcpStream`. The stream pointer is
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
        H: Fn(TcpStream) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + 'static,
    {
        let body = Arc::new(body);
        let handles = PerWorker::new();
        handles.init(num_workers(), |_| SpinLock::new(None));
        let ctx = Arc::new(TcpFanoutCtx {
            listener: Arc::new(self),
            accept_body: Box::new(move |stream| {
                let body = Arc::clone(&body);
                Box::pin(async move { body(stream).await })
            }),
            stopping: AtomicBool::new(false),
            handles,
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
                    // Arc<body> for the per-conn task. It returns
                    // a `BoxedFuture`, so route through
                    // `spawn_boxed` to skip a redundant `Box::pin`
                    // per accepted conn.
                    let fut = (ctx_inner.accept_body)(stream);
                    let _ = crate::spawn_boxed(fut);
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
    dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()>>>
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
    handles: PerWorker<SpinLock<Option<crate::TaskHandle>>>,
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
        for w in 0..self.ctx.handles.len() {
            if let Some(h) = self.ctx.handles.at(w).lock().take() {
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
    type Output = TcpStream;

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
        let cc = CurrentWorker::enter();
        let state = &TCP_REGISTRY[this.listener.idx];
        store_waker_if_needed(state.wakers.current(&cc), cx.waker());

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
// handle is an opaque `*mut ()` — identical to the `TcpStream`
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

/// Future returned by [`TcpStream::send`]. Drives
/// the backend's `try_send` hook to completion: the backend
/// drains `chain` as bytes hit the wire (pop_front fully-sent
/// parts, advance the head buf's visible payload past partial-
/// committed bytes), and the future loops until `chain.is_empty()`.
///
/// `External` IOBufs (NIC RX descriptors, etc.) return their
/// backing storage to the driver pool as they leave the chain,
/// so the descriptor-recycle latency tracks the wire-commit time
/// rather than the whole-response completion.
pub struct TcpSendChain<'a> {
    handle: *mut (),
    generation: u16,
    chain: &'a mut uni_iobuf::IOBufChain,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpSendChain<'a> {
    #[inline]
    pub fn new(
        handle: *mut (),
        generation: u16,
        chain: &'a mut uni_iobuf::IOBufChain,
    ) -> Self {
        TcpSendChain {
            handle,
            generation,
            chain,
            _not_send: PhantomData,
        }
    }
}

impl<'a> Future for TcpSendChain<'a> {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };

        loop {
            if this.chain.is_empty() {
                // Backend drained everything. Done.
                return Poll::Ready(Ok(()));
            }
            match (b.try_send)(h, g, this.chain) {
                Err(()) => {
                    // Drop the unsent remainder — caller can't reuse
                    // a chain whose underlying conn just died.
                    this.chain.clear();
                    return Poll::Ready(Err(()));
                }
                Ok(0) => {
                    // Backend pushed back. Park waker, then re-probe
                    // once — closes the wake-before-park race with
                    // the writable event site.
                    (b.register_send_waker)(h, g, cx.waker());
                    match (b.try_send)(h, g, this.chain) {
                        Err(()) => {
                            this.chain.clear();
                            return Poll::Ready(Err(()));
                        }
                        Ok(0) => return Poll::Pending,
                        Ok(_) => continue,
                    }
                }
                Ok(_) => {
                    // Backend drained some bytes off the chain's
                    // front. Loop and try the next batch.
                }
            }
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
    let cc = CurrentWorker::enter();
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
