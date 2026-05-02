// uni-backend/src/native/tcp.rs — POSIX TCP backend.
//
// One nonblocking listen fd per port, registered in every worker's
// kqueue/epoll. When a SYN arrives, whichever worker's event queue
// fires first calls `accept(2)` and owns the resulting connection;
// losers see EAGAIN and re-poll. No dedicated acceptor, no pipes —
// mirrors the unikernel's per-core model.
//
// Why shared-fd and not per-worker SO_REUSEPORT siblings:
// macOS's TCP SO_REUSEPORT does NOT distribute SYNs across sibling
// listeners (unlike UDP, and unlike Linux's TCP 4-tuple hash).
// `sample` under tls_handshake_max showed worker 0 doing all TLS
// crypto while worker 1 sat 95% idle in kevent — all accepts
// funnelled to thread 0 via the siblings layout. The shared-fd
// "first-to-accept-wins" pattern is what `uni_http`'s sync path
// used to get 5.9 k hs/s on 2 t; siblings-plus-async was capping
// at 3.7 k.
//
// On Linux this shape also works — EPOLLIN on the same fd from N
// epolls will wake one per event; kernel SO_REUSEPORT-style load
// balancing is lost but is not needed for correctness.

use std::cell::UnsafeCell;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;

use super::*;

// ============================================================================
// Async TCP listener table
// ============================================================================

const MAX_ASYNC_TCP_LISTENERS: usize = 4;

struct AsyncTcpListener {
    app_port: u16,
    /// Single shared listen fd; same `fd` is registered in every
    /// worker's kqueue/epoll.
    fd: i32,
}

struct AsyncTcpListenersSlot(UnsafeCell<[Option<AsyncTcpListener>; MAX_ASYNC_TCP_LISTENERS]>);
// SAFETY: populated only on the main thread during `uni_boot`
// (via `async_tcp_listen_hook` from `uni::runtime::TcpListener::bind`);
// read from workers afterwards without further mutation.
unsafe impl Sync for AsyncTcpListenersSlot {}
static ASYNC_TCP_LISTENERS: AsyncTcpListenersSlot =
    AsyncTcpListenersSlot(UnsafeCell::new([const { None }; MAX_ASYNC_TCP_LISTENERS]));
static ASYNC_TCP_COUNT: AtomicUsize = AtomicUsize::new(0);

fn make_listener(port: u16) -> i32 {
    unsafe {
        let fd = socket(AF_INET, SOCK_STREAM, 0);
        if fd < 0 { return -1; }

        let opt: i32 = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
        // SO_REUSEPORT intentionally omitted: on macOS it doesn't
        // distribute connections across sockets; the shared-fd
        // first-to-accept-wins pattern handles that.
        set_nonblocking(fd);

        let addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, std::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd); return -1;
        }
        if listen(fd, 128) < 0 {
            close(fd); return -1;
        }
        fd
    }
}

fn async_tcp_listen_hook(app_port: u16) -> Result<(), ()> {
    unsafe {
        let count = ASYNC_TCP_COUNT.load(Ordering::Acquire);
        if count >= MAX_ASYNC_TCP_LISTENERS {
            return Err(());
        }
        let host_port = read_port_env("TCP", app_port).unwrap_or(app_port);
        let fd = make_listener(host_port);
        if fd < 0 {
            return Err(());
        }
        let idx = count;
        (*ASYNC_TCP_LISTENERS.0.get())[idx] = Some(AsyncTcpListener {
            app_port,
            fd,
        });
        ASYNC_TCP_COUNT.store(idx + 1, Ordering::Release);

        // Register the shared fd in every worker's event queue.
        let want = NUM_THREADS.load(Ordering::Acquire).max(1);
        let threads = &mut *THREADS.0.get();
        for worker_id in 0..want {
            threads[worker_id].register_fd(fd);
        }
        Ok(())
    }
}

/// Counterpart to `async_tcp_listen_hook`. Called from
/// `TcpListener::Drop` via `TCP_BACKEND_UNLISTEN`. Closes the
/// shared listen fd (kqueue/epoll auto-remove the fd from every
/// worker's event queue) and clears the slot so a subsequent
/// `bind(app_port)` can allocate fresh. `ASYNC_TCP_COUNT` isn't
/// decremented — the table is small (cap 4) and we tolerate
/// `None` holes rather than compacting on teardown.
fn async_tcp_unlisten_hook(app_port: u16) {
    unsafe {
        let count = ASYNC_TCP_COUNT.load(Ordering::Acquire);
        let listeners = &mut *ASYNC_TCP_LISTENERS.0.get();
        for entry in listeners.iter_mut().take(count) {
            if let Some(l) = entry {
                if l.app_port == app_port {
                    close(l.fd);
                    *entry = None;
                    return;
                }
            }
        }
    }
}

fn async_tcp_accept_hook(app_port: u16) -> uni_runtime::net::TcpStream {
    use uni_runtime::net::TcpStream;
    unsafe {
        let tid = uni_platform::current_worker();
        let count = ASYNC_TCP_COUNT.load(Ordering::Acquire);
        let listeners = &*ASYNC_TCP_LISTENERS.0.get();
        for entry in listeners.iter().take(count) {
            let l = match entry {
                Some(l) => l,
                None => continue,
            };
            if l.app_port != app_port || l.fd < 0 {
                continue;
            }
            // `accept` races across workers on the shared fd. The
            // kernel hands each SYN to exactly one waiter; losers
            // see EAGAIN and re-poll on the next kqueue fire.
            let fd = accept(l.fd, ptr::null_mut(), ptr::null_mut());
            if fd < 0 {
                return TcpStream::NULL;
            }
            set_nonblocking(fd);
            // Disable Nagle on the accepted client socket. The TLS
            // handshake server flight is 5 small consecutive
            // `send()` calls, and with Nagle + Linux delayed-ACK
            // the client ends up waiting ~40ms for each segment's
            // ACK before sending its Finished — a ~150x regression
            // in `tls_handshake_max` on GCP.
            let opt: i32 = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, 4);
            let ts = thread_state(tid);
            let c = ts.alloc_conn();
            if c.is_null() {
                close(fd);
                return TcpStream::NULL;
            }
            (*c).fd = fd;
            ts.register_fd(fd);
            return TcpStream::from_raw(c as *mut (), (*c).generation);
        }
        TcpStream::NULL
    }
}

/// Called from `dispatch_ready_fd` (in `super`). Returns `true` iff
/// `fd` matched an async-TCP listener (and the reactor notification
/// was issued).
pub(super) fn async_tcp_dispatch(fd: i32) -> bool {
    unsafe {
        let count = ASYNC_TCP_COUNT.load(Ordering::Acquire);
        let listeners = &*ASYNC_TCP_LISTENERS.0.get();
        for entry in listeners.iter().take(count) {
            let l = match entry {
                Some(l) => l,
                None => continue,
            };
            if l.fd == fd {
                uni_runtime::net::deliver_tcp_ready(l.app_port);
                return true;
            }
        }
        false
    }
}

// ============================================================================
// Async TCP recv / send hooks
// ============================================================================
//
// Called from `uni_runtime::net::TcpRecv::poll` / `TcpSend::poll` via
// the function pointers in `NATIVE_TCP_BACKEND`. Each operates on a
// `NativeConn *` obtained from `async_tcp_accept_hook` and lives in
// the owning worker's `ThreadState.conns`. No locking — the conn's
// worker thread is the only writer of `recv_waker`/`send_waker`; the
// poll site runs on that same worker (TcpStream is `!Send`).
//
// `generation` is stamped at accept time and checked on every hook
// call — a mismatch means the slot got reused by a newer connection
// after a close, so we behave as if the conn is closed for the
// stale caller (recv returns 0, waker registration wakes
// immediately so the task observes closure).

/// Returns `true` iff the slot's generation matches and it's still
/// live. Stale handles return `(c, false)` — the caller should
/// treat them as closed. Null `handle` also returns `(ptr::null, false)`.
#[inline]
unsafe fn check_gen(handle: *mut (), generation: u16) -> (*mut NativeConn, bool) {
    let c = handle as *mut NativeConn;
    if c.is_null() {
        return (c, false);
    }
    let matches = unsafe { (*c).generation == generation && !(*c).closed };
    (c, matches)
}

fn native_tcp_has_data(handle: *mut (), generation: u16) -> bool {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            // Closed or stale → TcpRecv resolves so the caller sees
            // `recv() == 0`.
            return !c.is_null();
        }
        (*c).has_pending_data
    }
}

fn native_tcp_do_recv(handle: *mut (), generation: u16, buf: &mut [u8]) -> usize {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            return 0;
        }
        let fd = (*c).fd;
        if fd < 0 {
            return 0;
        }
        let n = recv(fd, buf.as_mut_ptr(), buf.len(), 0);
        if n < 0 { (*c).has_pending_data = false; return 0; }
        if n == 0 { (*c).closed = true; (*c).has_pending_data = false; return 0; }
        (*c).has_pending_data = false;
        n as usize
    }
}

fn native_tcp_register_recv_waker(handle: *mut (), generation: u16, waker: &Waker) {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            waker.wake_by_ref();
            return;
        }
        // Dedup — avoid the clone if the stored waker will already
        // fire the same task.
        match &(*c).recv_waker {
            Some(w) if w.will_wake(waker) => {}
            _ => (*c).recv_waker = Some(waker.clone()),
        }
    }
}

fn native_tcp_clear_recv_waker(handle: *mut (), generation: u16) {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            return;
        }
        (*c).recv_waker = None;
    }
}

fn native_tcp_try_send(handle: *mut (), generation: u16, buf: &[u8]) -> isize {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            return -1;
        }
        let fd = (*c).fd;
        if fd < 0 {
            return -1;
        }
        let n = send(fd, buf.as_ptr(), buf.len(), MSG_NOSIGNAL);
        if n >= 0 {
            return n;
        }
        // `send` returned -1. EAGAIN means "try again" — report 0 so
        // the future parks a waker. Any other errno is fatal.
        if get_errno() == EAGAIN {
            0
        } else {
            -1
        }
    }
}

fn native_tcp_register_send_waker(handle: *mut (), generation: u16, waker: &Waker) {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            waker.wake_by_ref();
            return;
        }
        // Lazily arm EVFILT_WRITE / EPOLLOUT. Arming/disarming is a
        // real syscall on every pending-send cycle — defer to
        // `clear_send_waker` so sends that finish in one try_send
        // round never touch the event queue.
        if !(*c).send_registered {
            let tid = uni_platform::current_worker();
            thread_state(tid).arm_write_fd((*c).fd);
            (*c).send_registered = true;
        }
        match &(*c).send_waker {
            Some(w) if w.will_wake(waker) => {}
            _ => (*c).send_waker = Some(waker.clone()),
        }
    }
}

fn native_tcp_clear_send_waker(handle: *mut (), generation: u16) {
    unsafe {
        let (c, live) = check_gen(handle, generation);
        if !live {
            return;
        }
        (*c).send_waker = None;
        if (*c).send_registered {
            let tid = uni_platform::current_worker();
            thread_state(tid).disarm_write_fd((*c).fd);
            (*c).send_registered = false;
        }
    }
}

fn tcp_close(handle: *mut (), generation: u16) {
    let c = handle as *mut NativeConn;
    if c.is_null() { return; }
    // SAFETY: stream handles point into per-worker `NativeConn`
    // pools — the `!Send` marker on `TcpStream` keeps cross-worker
    // closes out, and the generation check rejects a stale stream
    // whose slot was already reused by a fresh accept.
    unsafe {
        if (*c).generation != generation {
            return;
        }
    }
    let tid = uni_platform::current_worker();
    thread_state(tid).release_conn(c);
}

/// Native TCP backend vtable. Wired into the runtime by
/// `init_native`.
pub(super) static NATIVE_TCP_BACKEND: uni_runtime::net::TcpBackend =
    uni_runtime::net::TcpBackend {
        listen: async_tcp_listen_hook,
        accept: async_tcp_accept_hook,
        unlisten: Some(async_tcp_unlisten_hook),
        has_data: native_tcp_has_data,
        do_recv: native_tcp_do_recv,
        register_recv_waker: native_tcp_register_recv_waker,
        clear_recv_waker: native_tcp_clear_recv_waker,
        close: tcp_close,
        try_send: native_tcp_try_send,
        register_send_waker: native_tcp_register_send_waker,
        clear_send_waker: native_tcp_clear_send_waker,
    };

/// Pump the worker's event queue non-blockingly. Flips
/// `has_pending_data` on any TCP conn that became readable and
/// drains any UDP sibling that fired (dispatching the app handler
/// inline). Returns `true` iff a UDP sibling was drained — tells
/// the event loop to skip its idle sleep and run another iteration.
pub(super) fn tcp_poll() -> bool {
    thread_state(uni_platform::current_worker()).poll_events()
}
