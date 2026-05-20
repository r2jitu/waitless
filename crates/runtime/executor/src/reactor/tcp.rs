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

use worker::{CurrentWorker, PerWorker, num_workers};

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
// the same opaque handle `backend::tcp_accept` returns today.
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
        TcpStream {
            handle,
            generation,
            _not_send: PhantomData,
        }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        self.handle.is_null()
    }

    /// Async read. Resolves with the byte count once data is
    /// available (or `0` on peer close / stale generation).
    ///
    /// Takes `&mut self`. `TcpStream` is a thin handle over an
    /// *opaque backend pointer* — the borrow checker cannot see the
    /// per-connection state aliased through that raw handle, so the
    /// `&mut self` exclusivity is the *only* lever that enforces
    /// "at most one read outstanding per stream." `recv` registers
    /// `buf`'s pointer with the connection for the direct-copy fast
    /// path; two overlapping reads would have the second silently
    /// steal the first's slot. `&mut self` makes that a compile
    /// error instead — the same discipline [`Self::recv_chunk`]
    /// already used, now applied uniformly across the API.
    ///
    /// ```compile_fail
    /// # async fn two_reads(s: &mut executor::reactor::TcpStream) {
    /// let mut a = [0u8; 16];
    /// let mut b = [0u8; 16];
    /// let r1 = s.recv(&mut a);
    /// let r2 = s.recv(&mut b); // ERROR: `*s` already borrowed
    /// let _ = (r1.await, r2.await);
    /// # }
    /// ```
    #[inline]
    pub fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> TcpRecv<'a> {
        TcpRecv::new(self.handle, self.generation, buf)
    }

    /// Async zero-copy read. Resolves with a [`RecvChunkGuard`]
    /// over the next inbound chunk of data, or `None` on peer close
    /// / stale generation / a backend with no chunk path.
    ///
    /// Where [`Self::recv`] copies bytes into a caller-supplied
    /// buffer, `recv_chunk` surfaces the transport's own buffer:
    /// `guard.data()` reads it in place (zero copy), and
    /// `guard.into_owned()` lifts it to an owned `IOBuf` — zero
    /// copy when the buffer is already owned (the bare-metal NIC
    /// RX case), one memcpy when it is a borrowed view.
    ///
    /// `recv_chunk` takes `&mut self` and the returned guard
    /// borrows it for the guard's whole lifetime. That is
    /// deliberate: at most one chunk is outstanding per stream, so
    /// the transport may reuse the surfaced buffer the moment the
    /// guard drops. Two simultaneously-live guards are therefore a
    /// borrow-check error:
    ///
    /// ```compile_fail
    /// # async fn two_guards(s: &mut executor::reactor::TcpStream) {
    /// let g1 = s.recv_chunk().await;
    /// let g2 = s.recv_chunk().await; // ERROR: `*s` already borrowed
    /// let _ = (g1, g2);
    /// # }
    /// ```
    ///
    /// The same calls with one guard live at a time compile fine:
    ///
    /// ```no_run
    /// # async fn sequential(s: &mut executor::reactor::TcpStream) {
    /// { let _g = s.recv_chunk().await; }
    /// { let _g = s.recv_chunk().await; }
    /// # }
    /// ```
    #[inline]
    pub fn recv_chunk(&mut self) -> RecvChunk<'_> {
        RecvChunk::new(self.handle, self.generation)
    }

    /// Drain exactly `buf.len()` bytes into `buf`. Returns `Ok(())`
    /// when full, `Err(n_filled)` if the peer closed before all
    /// bytes arrived (the partial prefix is left in `buf`).
    ///
    /// Saves the manual `while got < N { ... }` loop every TCP
    /// server otherwise writes for fixed-size frames; for streamed
    /// protocols use `recv` directly.
    ///
    /// `&mut self` for the same reason as [`Self::recv`] — it loops
    /// `recv`, so it inherits the one-read-at-a-time exclusivity.
    pub async fn recv_exact(&mut self, buf: &mut [u8]) -> Result<(), usize> {
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
    ///
    /// `&mut self` for the same reason as [`Self::recv`]: a send
    /// registers a waker on the connection's send slot, and the
    /// opaque-handle aliasing is invisible to the borrow checker —
    /// the exclusive borrow is what serialises sends per stream.
    #[inline]
    pub fn send<'a>(&'a mut self, chain: &'a mut iobuf::IOBufChain) -> TcpSendChain<'a> {
        TcpSendChain::new(self.handle, self.generation, chain)
    }

    /// Try to send a single TSO super-segment whose payload is
    /// produced by `fill`. The closure receives a mutable byte
    /// slice into the driver's TX-pool big-slot's payload region
    /// (after L2/L3/L4 headers); on success it returns the
    /// payload byte count and the TCP layer fills the headers
    /// around it and submits. On `Err(())` the slot is returned
    /// to the pool without enqueue and the error propagates.
    ///
    /// Three outcomes:
    ///   * `Some(Ok(n))` — submitted, `n` bytes in flight.
    ///   * `Some(Err(()))` — closure failed; caller treats as
    ///     fatal (typically TLS seal error).
    ///   * `None` — no TSO slot available (TSO not negotiated,
    ///     big pool full, conn not Established, dst MAC
    ///     unresolved, native backend). Caller falls back to the
    ///     regular `send()` path. The closure is NOT called.
    ///
    /// `min_payload` is a lower bound on the TCP-payload bytes
    /// the closure will produce; passing the exact size when
    /// known is fine. The backend short-circuits to `None`
    /// (without acquiring a slot or running the closure) when
    /// `min_payload <= mss` — see [`TcpBackend::try_send_tso`].
    pub fn try_send_tso<F>(&mut self, min_payload: usize, mut fill: F) -> Option<Result<usize, ()>>
    where
        F: FnMut(&mut [u8]) -> Result<usize, ()>,
    {
        if self.handle.is_null() {
            return None;
        }
        let backend = tcp_backend()?;
        let f = backend.try_send_tso?;
        f(self.handle, self.generation, min_payload, &mut fill)
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
    /// `IOBuf::Borrowed` struct init — negligible at the call
    /// rates we hit in benchmarks.
    pub async fn send_bytes(&mut self, data: &[u8]) -> Result<(), ()> {
        // SAFETY: `chain` is dropped before this future returns;
        // the `IOBuf::Borrowed` wrapping `data` therefore can't
        // outlive `data`'s borrow. No drop callback — the bytes
        // are borrowed, not owned.
        let mut chain = iobuf::IOBufChain::new();
        let iobuf = unsafe {
            iobuf::IOBuf::borrow(
                core::ptr::NonNull::new_unchecked(data.as_ptr() as *mut u8),
                data.len() as u32,
                0,
                data.len() as u32,
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

static TCP_REGISTRY: [TcpState; MAX_TCP_LISTENERS] = [const { TcpState::new() }; MAX_TCP_LISTENERS];

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
    pub register_recv_waker: fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored recv waker. Called after Ready. Stale `gen`
    /// is a no-op.
    pub clear_recv_waker: fn(handle: *mut (), generation: u16),

    /// Optional direct-copy fast path. When set, `TcpRecv::poll`
    /// registers its `&mut buf` (pointer + capacity) on the conn
    /// before parking; the next inbound TCP payload writes bytes
    /// straight into that buffer, skipping the per-conn ring. The
    /// future's next poll claims the byte count from the conn
    /// (`do_recv` returns it) without copying again.
    ///
    /// Cancel-safety: `TcpRecv::Drop` calls `clear_recv_buf_slot`
    /// so a future dropped before the waker fires never leaves a
    /// dangling pointer that the next `tcp_receive` would write
    /// into. Native backends leave both `None` — POSIX `recv()`
    /// already copies in one shot at the syscall boundary.
    pub set_recv_buf_slot: Option<fn(handle: *mut (), generation: u16, ptr: *mut u8, cap: u16)>,
    pub clear_recv_buf_slot: Option<fn(handle: *mut (), generation: u16)>,

    /// Optional zero-copy chunk-recv path — the backing for
    /// [`TcpStream::recv_chunk`]. When set, `RecvChunk::poll`
    /// flags the conn with `set_chunk_buf_slot` before parking; the
    /// next inbound payload is surfaced as an owned `IOBuf` (the
    /// transport's own buffer, not a copy) and claimed via
    /// `do_recv_chunk`.
    ///
    /// `do_recv_chunk` returns `None` on EOF / peer close / stale
    /// `generation` — the caller observes the end of the stream.
    /// A backend that leaves these `None` (native POSIX, which
    /// copies at the `recv()` syscall anyway) makes `recv_chunk`
    /// resolve to `None` on its first poll.
    ///
    /// Cancel-safety mirrors `set_recv_buf_slot`: `RecvChunk::Drop`
    /// calls `clear_chunk_buf_slot` so a future dropped before the
    /// waker fires leaves no stale "deliver-as-IOBuf" request. The
    /// recv-side waker hooks (`register_recv_waker` /
    /// `clear_recv_waker`) are reused — readiness is a conn-level
    /// signal, and a conn never has both a `recv` and a
    /// `recv_chunk` future parked at once.
    pub do_recv_chunk: Option<fn(handle: *mut (), generation: u16) -> Option<iobuf::IOBuf>>,
    pub set_chunk_buf_slot: Option<fn(handle: *mut (), generation: u16)>,
    pub clear_chunk_buf_slot: Option<fn(handle: *mut (), generation: u16)>,

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
    pub try_send:
        fn(handle: *mut (), generation: u16, chain: &mut iobuf::IOBufChain) -> Result<usize, ()>,
    /// Park `waker` on the conn's send slot; a subsequent writable
    /// event fires it. Stale `gen` fires immediately.
    pub register_send_waker: fn(handle: *mut (), generation: u16, waker: &Waker),
    /// Drop the stored send waker.
    pub clear_send_waker: fn(handle: *mut (), generation: u16),

    /// Optional fast path: try to send a single TSO super-segment
    /// (TCP-level payload up to ~16 KiB) whose payload bytes are
    /// produced by the `fill` closure into a driver TX-pool
    /// big-slot. The closure is called with a mutable byte slice
    /// into the slot's payload region (after L2/L3/L4 headers);
    /// it writes payload bytes and returns the count.
    ///
    /// Returns:
    ///   * `Some(n)` on successful submission (n = bytes written).
    ///   * `None` when TSO isn't supported, no slot is available,
    ///     conn isn't Established, dst MAC isn't resolved, or the
    ///     backend doesn't expose this surface (`None` outer).
    ///
    /// Used by the TLS-over-TCP fast path to encrypt ciphertext
    /// directly into the driver's TX-pool slot — eliminating the
    /// stack-scratch → TX-slot memcpy that `try_send` would do
    /// after a separate encrypt-into-scratch pass.
    /// `min_payload` is a lower bound the caller can pre-compute on
    /// the TCP-payload bytes the closure will write. The backend
    /// short-circuits to `None` without acquiring a slot or running
    /// the closure when `min_payload <= mss`, so single-segment
    /// sends don't waste a big-slot acquire + encrypt pass on a
    /// frame the device would emit as one wire packet anyway. (And
    /// some hardware TSO — gve in particular — silently drops
    /// payloads at or below MSS, so the gate is correctness-load-
    /// bearing in those backends.)
    pub try_send_tso: Option<
        fn(
            handle: *mut (),
            generation: u16,
            min_payload: usize,
            fill: &mut dyn FnMut(&mut [u8]) -> Result<usize, ()>,
        ) -> Option<Result<usize, ()>>,
    >,

    /// Optional. RST every connection currently in the backend's
    /// pool — called once at shutdown so peers see an immediate
    /// close instead of timing out via TCP keepalive after the VM
    /// powers off. Native leaves this `None`: the kernel FINs every
    /// open fd at process exit.
    pub shutdown_all: Option<fn()>,
}

static TCP_BACKEND: AtomicPtr<TcpBackend> = AtomicPtr::new(core::ptr::null_mut());

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
                state
                    .wakers
                    .ensure_init(num_workers(), |_| SpinLock::new(None));
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
                install_worker_task(&ctx_for_launcher.stopping, &ctx_for_launcher.handles, h);
            }
        }));
        TcpHandle { ctx, launcher_slot }
    }
}

type BoxedAcceptBody =
    Box<dyn Fn(TcpStream) -> Pin<Box<dyn Future<Output = ()>>> + Send + Sync + 'static>;

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
        TcpRecv {
            handle,
            generation,
            buf,
            _not_send: PhantomData,
        }
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
            if let Some(clear) = b.clear_recv_buf_slot {
                clear(h, g);
            }
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        // Register waker AND (optionally) the direct-copy slot.
        // The slot lets `tcp_receive` write payload bytes straight
        // into `this.buf` when the next packet lands, bypassing
        // the per-conn ring. Bare-metal sets `set_recv_buf_slot`;
        // native leaves it `None` and copies via `do_recv` as
        // before.
        if let Some(set) = b.set_recv_buf_slot {
            // Cap at u16 to match the conn-side field width — TCP
            // recv buffers larger than 64 KiB would just truncate
            // the registered slot but the ring would absorb the
            // remainder on the next call.
            let cap = this.buf.len().min(u16::MAX as usize) as u16;
            set(h, g, this.buf.as_mut_ptr(), cap);
        }
        (b.register_recv_waker)(h, g, cx.waker());
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            if let Some(clear) = b.clear_recv_buf_slot {
                clear(h, g);
            }
            return Poll::Ready((b.do_recv)(h, g, this.buf));
        }
        Poll::Pending
    }
}

impl<'a> Drop for TcpRecv<'a> {
    fn drop(&mut self) {
        // Cancel-safety: if the future is dropped before its waker
        // fires (parent task aborted, select! losing branch, etc.),
        // clear the recv_buf_slot pointer we registered above so a
        // subsequent `tcp_receive` doesn't write into freed user
        // memory.
        if let Some(b) = tcp_backend() {
            if let Some(clear) = b.clear_recv_buf_slot {
                clear(self.handle, self.generation);
            }
        }
    }
}

// ---- Per-stream zero-copy chunk recv ---------------------------------------
//
// `TcpStream::recv_chunk().await` resolves with a `RecvChunkGuard`
// over the next inbound `IOBuf` — the transport's own buffer,
// surfaced without the copy-into-caller-buffer that `recv` does.
// The guard borrows `&mut TcpStream`, so the borrow checker permits
// at most one outstanding chunk per stream; the transport is free
// to reuse / repost the buffer once the guard drops.
//
// Backed by the optional `do_recv_chunk` / `set_chunk_buf_slot` /
// `clear_chunk_buf_slot` hooks; the recv-side waker hooks are
// reused. A backend without `do_recv_chunk` (native POSIX) makes
// `recv_chunk` resolve to `None` on its first poll.

/// RAII guard returned by [`TcpStream::recv_chunk`]. Owns the
/// surfaced [`IOBuf`](iobuf::IOBuf) and carries the `&'a mut`
/// borrow of the stream it came from.
///
/// The borrow is the load-bearing part: it makes "at most one
/// outstanding IOBuf per stream" a compile-time fact rather than a
/// runtime invariant, and — for transports that surface a
/// `Borrowed` view (TLS plaintext, a later RX-path item) — it
/// prevents the stream from being re-read, and those bytes
/// overwritten, while the guard is live.
pub struct RecvChunkGuard<'a> {
    iobuf: iobuf::IOBuf,
    /// Ties the guard to the `&'a mut self` of `recv_chunk`. The
    /// inner type is opaque (`()`) so one guard type can serve
    /// every stream — `TcpStream` here, `TlsStream` later.
    _borrow: PhantomData<&'a mut ()>,
}

impl<'a> RecvChunkGuard<'a> {
    /// Wrap a transport-surfaced [`IOBuf`](iobuf::IOBuf) in a
    /// guard. The guard's `'a` is inferred at the call site — a
    /// `recv_chunk` binds it to the `&'a mut self` it took, so the
    /// borrow checker keeps that stream mutably borrowed (hence
    /// un-re-readable) for the guard's whole life.
    ///
    /// `pub` because the guard is the *one* type shared across
    /// every `recv_chunk` surface, and the constructions live in
    /// different crates: the `TcpStream` backend builds it from the
    /// `do_recv_chunk` hook here in `uni-runtime` (an owned
    /// `External`/`Heap` IOBuf), and `TlsStream::recv_chunk` in
    /// `uni-tls` builds it from a `Borrowed` view of decrypted
    /// plaintext (RX item G). A single guard type — not a parallel
    /// `TlsRecvChunkGuard` — is what lets item H's `BodyReader`
    /// stay generic over the stream.
    #[inline]
    pub fn new(iobuf: iobuf::IOBuf) -> Self {
        RecvChunkGuard {
            iobuf,
            _borrow: PhantomData,
        }
    }

    /// The chunk's bytes, read in place. Zero copy. Callers that
    /// need the length use `data().len()`.
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.iobuf.data()
    }

    /// Take owned possession of the chunk. Zero copy when the
    /// surfaced `IOBuf` already owns its storage (`Heap`, or the
    /// NIC-RX `ExternalOwned` device buffer); one memcpy into a
    /// fresh heap buffer when it is a `Borrowed` view (TLS
    /// plaintext). The escape hatch for holding the bytes past the
    /// guard's borrow — e.g. a proxy forwarding the chunk into an
    /// outbound `send`.
    #[inline]
    pub fn into_owned(self) -> iobuf::IOBuf {
        self.iobuf.into_owned()
    }
}

/// Future returned by [`TcpStream::recv_chunk`]. Resolves to
/// `Some(guard)` once the backend has a chunk, or `None` on peer
/// close / stale generation / a backend with no chunk path. `!Send`
/// — the conn handle points into per-worker state.
pub struct RecvChunk<'a> {
    handle: *mut (),
    generation: u16,
    _not_send: PhantomData<*mut ()>,
    /// The `&'a mut TcpStream` borrow `recv_chunk` took — held by
    /// the future, then carried into the resolved guard via the
    /// shared `'a`.
    _borrow: PhantomData<&'a mut TcpStream>,
}

impl<'a> RecvChunk<'a> {
    #[inline]
    fn new(handle: *mut (), generation: u16) -> Self {
        RecvChunk {
            handle,
            generation,
            _not_send: PhantomData,
            _borrow: PhantomData,
        }
    }
}

impl<'a> Future for RecvChunk<'a> {
    type Output = Option<RecvChunkGuard<'a>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let h = this.handle;
        let g = this.generation;
        let b = match tcp_backend() {
            Some(b) => b,
            None => return Poll::Pending,
        };
        // A backend with no chunk path (native POSIX, which copies
        // at the `recv()` syscall anyway) — resolve `None` so a
        // caller can fall back to `recv`.
        let do_chunk = match b.do_recv_chunk {
            Some(f) => f,
            None => return Poll::Ready(None),
        };
        // Fast path — a chunk is already available (or the conn is
        // closed, in which case `do_recv_chunk` returns `None`).
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            if let Some(clear) = b.clear_chunk_buf_slot {
                clear(h, g);
            }
            return Poll::Ready(do_chunk(h, g).map(RecvChunkGuard::new));
        }
        // Flag the conn for zero-copy delivery, park the waker, then
        // re-probe once — closes the wake-before-park race with the
        // `tcp_receive` data-arrival site.
        if let Some(set) = b.set_chunk_buf_slot {
            set(h, g);
        }
        (b.register_recv_waker)(h, g, cx.waker());
        if (b.has_data)(h, g) {
            (b.clear_recv_waker)(h, g);
            if let Some(clear) = b.clear_chunk_buf_slot {
                clear(h, g);
            }
            return Poll::Ready(do_chunk(h, g).map(RecvChunkGuard::new));
        }
        Poll::Pending
    }
}

impl<'a> Drop for RecvChunk<'a> {
    fn drop(&mut self) {
        // Cancel-safety: a future dropped before its waker fires
        // (parent task aborted, `select!` losing branch) must not
        // leave a stale "deliver-as-IOBuf" request — the next
        // segment would otherwise be stashed for a consumer that no
        // longer exists. An already-stashed chunk is left intact;
        // it's still owed to the conn slot and is released on slot
        // reset.
        if let Some(b) = tcp_backend() {
            if let Some(clear) = b.clear_chunk_buf_slot {
                clear(self.handle, self.generation);
            }
        }
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
    chain: &'a mut iobuf::IOBufChain,
    _not_send: PhantomData<*mut ()>,
}

impl<'a> TcpSendChain<'a> {
    #[inline]
    pub fn new(handle: *mut (), generation: u16, chain: &'a mut iobuf::IOBufChain) -> Self {
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

#[cfg(test)]
mod tests {
    use super::RecvChunkGuard;
    use iobuf::IOBuf;

    /// `RecvChunkGuard::into_owned` round-trips bytes for an
    /// already-owned (`Heap`) IOBuf — the bare-metal NIC-RX shape,
    /// where `into_owned` is a zero-copy no-op. `data()` reads the
    /// same bytes in place beforehand.
    #[test]
    fn recv_chunk_guard_into_owned_owned_roundtrip() {
        let bytes: &[u8] = b"item-F chunk payload";
        let guard = RecvChunkGuard::new(IOBuf::from(bytes.to_vec()));
        assert_eq!(guard.data(), bytes, "data() reads the chunk in place");
        let owned = guard.into_owned();
        assert_eq!(owned.data(), bytes, "owned IOBuf preserves the bytes");
    }

    /// `into_owned` on a guard wrapping a `Borrowed` view copies
    /// the bytes into a fresh heap buffer — the TLS-plaintext shape
    /// (the one memcpy case) — and the copy preserves the payload.
    #[test]
    fn recv_chunk_guard_into_owned_borrowed_roundtrip() {
        let backing: alloc::vec::Vec<u8> = b"borrowed view -> heap".to_vec();
        let len = backing.len() as u32;
        // SAFETY: `backing` outlives `guard` (and `owned`, which
        // copies out of it). The borrowed window spans the whole
        // buffer; nothing else mutates it for the borrow's life.
        let guard = RecvChunkGuard::new(unsafe {
            IOBuf::borrow(
                core::ptr::NonNull::new(backing.as_ptr() as *mut u8).unwrap(),
                len,
                0,
                len,
            )
        });
        assert_eq!(guard.data(), backing.as_slice());
        let owned = guard.into_owned();
        assert_eq!(
            owned.data(),
            backing.as_slice(),
            "Borrowed -> Heap copy preserves the bytes",
        );
        drop(backing);
    }
}
