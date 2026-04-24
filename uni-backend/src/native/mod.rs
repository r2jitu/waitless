// Host POSIX backend for `uni`. libc-FFI sockets, kqueue/epoll,
// pthread workers, cross-worker event loop.
//
// Listener distribution: one nonblocking listen fd registered in every
// worker's kqueue/epoll. First worker whose kqueue fires calls
// accept() and owns the connection; others see EAGAIN and sleep. No
// dedicated acceptor, no pipes — mirrors the unikernel's per-core
// model.

use std::cell::UnsafeCell;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use atomic_fn::AtomicFn;

/// Re-export of the shared runtime's executor surface — apps
/// reach these via `uni::runtime::{spawn,sleep_us,Sleep,…}`.
pub mod runtime {
    pub use uni_runtime::{
        has_pending, sleep_us, spawn, spawn_on_each_worker, tick, Sleep,
    };
}

// ============================================================================
// libc FFI declarations
// ============================================================================

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SHUT_RDWR: i32 = 2;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
const SIGPIPE: i32 = 13;
const SIG_IGN: usize = 1;

#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0x800;

#[cfg(target_os = "macos")]
const SOL_SOCKET: i32 = 0xFFFF;
#[cfg(target_os = "linux")]
const SOL_SOCKET: i32 = 1;

#[cfg(target_os = "macos")]
const SO_REUSEADDR: i32 = 0x0004;
#[cfg(target_os = "linux")]
const SO_REUSEADDR: i32 = 2;

#[cfg(target_os = "macos")]
const SO_REUSEPORT: i32 = 0x0200;
#[cfg(target_os = "linux")]
const SO_REUSEPORT: i32 = 15;

// TCP_NODELAY lives at the `IPPROTO_TCP` socket level on both
// Linux (6) and macOS (6). Disabling Nagle on every accepted
// client socket matters a *lot* on the TLS handshake path:
// the server writes the flight as 5 consecutive `send()` calls
// (ServerHello, CCS, EE, Certificate, CertVerify, Finished),
// each of which is a small buffer, and with Nagle on the kernel
// batches them waiting for the previous segment to be ACKed.
// Combined with Linux's delayed-ACK on the client side this
// produces the classic ~40ms-per-round-trip deadlock, which
// showed up as tls_handshake_max at ~20 hs/s on GCP KVM (a
// hundredfold regression versus macOS HVF on the same binary).
const IPPROTO_TCP: i32 = 6;
#[cfg(target_os = "macos")]
const TCP_NODELAY: i32 = 0x01;
#[cfg(target_os = "linux")]
const TCP_NODELAY: i32 = 1;


#[cfg(target_os = "linux")]
const MSG_NOSIGNAL: i32 = 0x4000;
#[cfg(target_os = "macos")]
const MSG_NOSIGNAL: i32 = 0;


#[cfg(target_os = "macos")]
const EAGAIN: i32 = 35;
#[cfg(target_os = "linux")]
const EAGAIN: i32 = 11;

#[repr(C)]
struct SockAddrIn {
    #[cfg(target_os = "macos")]
    sin_len: u8,
    #[cfg(target_os = "macos")]
    sin_family: u8,
    #[cfg(target_os = "linux")]
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// kqueue (macOS)
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Kevent {
    ident: usize,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: isize,
    udata: *mut u8,
}

#[cfg(target_os = "macos")]
const EVFILT_READ: i16 = -1;
#[cfg(target_os = "macos")]
const EVFILT_WRITE: i16 = -2;
#[cfg(target_os = "macos")]
const EV_ADD: u16 = 0x0001;
#[cfg(target_os = "macos")]
const EV_DELETE: u16 = 0x0002;
#[cfg(target_os = "macos")]
const EV_CLEAR: u16 = 0x0020;

// epoll (Linux)
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[cfg(target_os = "linux")]
const EPOLLIN: u32 = 0x001;
#[cfg(target_os = "linux")]
const EPOLLOUT: u32 = 0x004;
#[cfg(target_os = "linux")]
const EPOLL_CTL_ADD: i32 = 1;
#[cfg(target_os = "linux")]
const EPOLL_CTL_MOD: i32 = 3;
#[cfg(target_os = "linux")]
const EPOLL_CTL_DEL: i32 = 2;

type PthreadT = usize;

unsafe extern "C" {
    fn socket(domain: i32, sock_type: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    fn recvfrom(fd: i32, buf: *mut u8, len: usize, flags: i32,
                addr: *mut SockAddrIn, addrlen: *mut u32) -> isize;
    fn sendto(fd: i32, buf: *const u8, len: usize, flags: i32,
              addr: *const SockAddrIn, addrlen: u32) -> isize;
    fn close(fd: i32) -> i32;
    fn shutdown(fd: i32, how: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const i32, len: u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    #[cfg(target_os = "macos")]
    fn kqueue() -> i32;
    #[cfg(target_os = "macos")]
    fn kevent(kq: i32, changelist: *const Kevent, nchanges: i32,
              eventlist: *mut Kevent, nevents: i32, timeout: *const Timespec) -> i32;

    #[cfg(target_os = "linux")]
    fn epoll_create1(flags: i32) -> i32;
    #[cfg(target_os = "linux")]
    fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    #[cfg(target_os = "linux")]
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;

    fn pthread_create(thread: *mut PthreadT, attr: *const u8,
                      start: extern "C" fn(*mut u8) -> *mut u8, arg: *mut u8) -> i32;
    fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32;
    fn sysconf(name: i32) -> i64;

    #[cfg(target_os = "macos")]
    fn sysctlbyname(name: *const u8, oldp: *mut u8, oldlenp: *mut usize,
                    newp: *const u8, newlen: usize) -> i32;

    #[cfg(target_os = "macos")]
    fn __error() -> *mut i32;
    #[cfg(target_os = "linux")]
    fn __errno_location() -> *mut i32;
}

fn get_errno() -> i32 {
    unsafe {
        #[cfg(target_os = "macos")]
        { *__error() }
        #[cfg(target_os = "linux")]
        { *__errno_location() }
    }
}

/// Read `UNIKERNEL_<PROTO>_<GUEST>` (e.g. `UNIKERNEL_TCP_80`) and
/// parse as a u16. Matches the name derivation baked into the VM
/// launchers by `variants.bzl`, so `UNIKERNEL_TCP_80=18080
/// :<app>_native` and `… :<app>_hvf` both bind to the same host port.
fn read_port_env(proto: &str, guest_port: u16) -> Option<u16> {
    std::env::var(format!("UNIKERNEL_{proto}_{guest_port}")).ok()?.parse().ok()
}

fn set_nonblocking(fd: i32) {
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0i32);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

pub fn num_cpus() -> usize {
    #[cfg(target_os = "macos")]
    const SC_NPROCESSORS_ONLN: i32 = 58;
    #[cfg(target_os = "linux")]
    const SC_NPROCESSORS_ONLN: i32 = 84;
    let n = unsafe { sysconf(SC_NPROCESSORS_ONLN) };
    if n > 0 { n as usize } else { 1 }
}

/// Total physical RAM, in bytes, as reported by the host. Zero means
/// "unknown" (portability fallback). macOS reads `hw.memsize`;
/// Linux multiplies `_SC_PHYS_PAGES` by `_SC_PAGESIZE`.
pub fn host_ram_bytes() -> usize {
    #[cfg(target_os = "macos")]
    unsafe {
        let mut val: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        let name = b"hw.memsize\0".as_ptr();
        if sysctlbyname(name, &mut val as *mut u64 as *mut u8, &mut len,
                        std::ptr::null(), 0) == 0 {
            return val as usize;
        }
        0
    }
    #[cfg(target_os = "linux")]
    unsafe {
        const SC_PAGESIZE: i32 = 30;
        const SC_PHYS_PAGES: i32 = 85;
        let pages = sysconf(SC_PHYS_PAGES);
        let page = sysconf(SC_PAGESIZE);
        if pages > 0 && page > 0 {
            (pages as usize).saturating_mul(page as usize)
        } else {
            0
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    { 0 }
}

// ============================================================================
// Per-thread connection pool
// ============================================================================

const CONNS_PER_THREAD: usize = 64;
const MAX_THREADS: usize = 16;

struct NativeConn {
    fd: i32,
    is_listener: bool,
    /// True when this listener's fd is shared across workers (multi-thread mode).
    /// release_conn must NOT close the fd — other workers are still using it.
    is_shared_listener: bool,
    closed: bool,
    has_pending_data: bool,
    /// Incremented every time this slot is released. Async handles
    /// (RawTcpStream) carry the generation at accept time; hook
    /// callers pass it on every op so we can detect a stale handle
    /// whose slot got reused by a newer connection. u16 wraps after
    /// 65k reuses per slot — collision window one-in-65k, low enough
    /// for the aliasing bug we're guarding against.
    generation: u16,
    /// Waker parked by `TcpRecv` / `register_tcp_recv_hooks`.
    /// Set on Pend, taken by `dispatch_ready_fd` when the fd fires,
    /// cleared explicitly on Ready or on close.
    recv_waker: Option<Waker>,
    /// Waker parked by `TcpSend` / `register_tcp_send_hooks`. Uses
    /// `EVFILT_WRITE` / `EPOLLOUT` on the same fd; taken when the
    /// event queue fires write-readiness, cleared on Ready or close.
    send_waker: Option<Waker>,
    /// `true` while `EVFILT_WRITE` / `EPOLLOUT` is registered on the
    /// fd. The filter is expensive to add for every pending-send
    /// poll so we leave it armed across partial-send cycles and
    /// drop it on clear_send_waker / close.
    send_registered: bool,
}

impl NativeConn {
    const fn empty() -> Self {
        NativeConn {
            fd: -1,
            is_listener: false,
            is_shared_listener: false,
            closed: true,
            has_pending_data: false,
            generation: 0,
            recv_waker: None,
            send_waker: None,
            send_registered: false,
        }
    }
}

/// One UDP sibling fd owned by a worker thread. Populated at
/// `udp_bind` time, one entry per `-p udp:...` relay. Drained
/// inline from `collect_events` when the kqueue/epoll reports the fd
/// ready — no dedicated RX thread, matches HVF's inline-poll design.
#[derive(Clone, Copy)]
struct UdpSibling {
    fd: i32,
    binding_idx: usize,
}

struct ThreadState {
    conns: [NativeConn; CONNS_PER_THREAD],
    eq_fd: i32,  // kqueue (macOS) or epoll (Linux) fd
    thread_id: u32,
    udp_sibs: [UdpSibling; MAX_UDP_BINDINGS],
    udp_sib_count: usize,
}

impl ThreadState {
    const fn new(id: u32) -> Self {
        ThreadState {
            conns: [const { NativeConn::empty() }; CONNS_PER_THREAD],
            eq_fd: -1,
            thread_id: id,
            udp_sibs: [UdpSibling { fd: -1, binding_idx: 0 }; MAX_UDP_BINDINGS],
            udp_sib_count: 0,
        }
    }

    fn add_udp_sibling(&mut self, fd: i32, binding_idx: usize) {
        if self.udp_sib_count >= MAX_UDP_BINDINGS { return; }
        self.udp_sibs[self.udp_sib_count] = UdpSibling { fd, binding_idx };
        self.udp_sib_count += 1;
        self.register_fd(fd);
    }

    fn init_event_queue(&mut self) {
        unsafe {
            #[cfg(target_os = "macos")]
            { self.eq_fd = kqueue(); }
            #[cfg(target_os = "linux")]
            { self.eq_fd = epoll_create1(0); }
        }
    }

    fn register_fd(&self, fd: i32) {
        unsafe {
            #[cfg(target_os = "macos")]
            {
                let ev = Kevent {
                    ident: fd as usize, filter: EVFILT_READ,
                    flags: EV_ADD, fflags: 0, data: 0,
                    udata: fd as *mut u8,
                };
                kevent(self.eq_fd, &ev, 1, ptr::null_mut(), 0, ptr::null());
            }
            #[cfg(target_os = "linux")]
            {
                let mut ev = EpollEvent { events: EPOLLIN, data: fd as u64 };
                epoll_ctl(self.eq_fd, EPOLL_CTL_ADD, fd, &mut ev);
            }
        }
    }

    fn unregister_fd(&self, fd: i32) {
        unsafe {
            #[cfg(target_os = "macos")]
            {
                let ev = Kevent {
                    ident: fd as usize, filter: EVFILT_READ,
                    flags: EV_DELETE, fflags: 0, data: 0, udata: ptr::null_mut(),
                };
                kevent(self.eq_fd, &ev, 1, ptr::null_mut(), 0, ptr::null());
            }
            #[cfg(target_os = "linux")]
            {
                epoll_ctl(self.eq_fd, EPOLL_CTL_DEL, fd, ptr::null_mut());
            }
        }
    }

    /// Arm write-readiness notifications on `fd`. On kqueue the
    /// read and write filters are independent kevents; we add
    /// `EVFILT_WRITE` alongside the existing `EVFILT_READ`. On
    /// epoll they're flags on the same event; we MOD the
    /// subscription to include `EPOLLOUT`. `EV_CLEAR` / default
    /// epoll level-triggered behaviour — we leave the filter armed
    /// across partial sends and explicitly `disarm_write_fd` once
    /// the async send completes.
    fn arm_write_fd(&self, fd: i32) {
        unsafe {
            #[cfg(target_os = "macos")]
            {
                let ev = Kevent {
                    ident: fd as usize, filter: EVFILT_WRITE,
                    flags: EV_ADD | EV_CLEAR, fflags: 0, data: 0,
                    udata: fd as *mut u8,
                };
                kevent(self.eq_fd, &ev, 1, ptr::null_mut(), 0, ptr::null());
            }
            #[cfg(target_os = "linux")]
            {
                let mut ev = EpollEvent {
                    events: EPOLLIN | EPOLLOUT,
                    data: fd as u64,
                };
                epoll_ctl(self.eq_fd, EPOLL_CTL_MOD, fd, &mut ev);
            }
        }
    }

    fn disarm_write_fd(&self, fd: i32) {
        unsafe {
            #[cfg(target_os = "macos")]
            {
                let ev = Kevent {
                    ident: fd as usize, filter: EVFILT_WRITE,
                    flags: EV_DELETE, fflags: 0, data: 0, udata: ptr::null_mut(),
                };
                kevent(self.eq_fd, &ev, 1, ptr::null_mut(), 0, ptr::null());
            }
            #[cfg(target_os = "linux")]
            {
                let mut ev = EpollEvent { events: EPOLLIN, data: fd as u64 };
                epoll_ctl(self.eq_fd, EPOLL_CTL_MOD, fd, &mut ev);
            }
        }
    }

    fn alloc_conn(&mut self) -> *mut NativeConn {
        for c in self.conns.iter_mut() {
            if c.closed && c.fd < 0 {
                c.fd = -1;
                c.is_listener = false;
                c.is_shared_listener = false;
                c.closed = false;
                c.has_pending_data = false;
                c.recv_waker = None;
                c.send_waker = None;
                c.send_registered = false;
                // Generation is preserved across reuse — `release_conn`
                // bumps it.
                return c as *mut NativeConn;
            }
        }
        ptr::null_mut()
    }

    fn release_conn(&mut self, c: *mut NativeConn) {
        unsafe {
            if (*c).fd >= 0 {
                // Disarm write-readiness if still armed; `unregister_fd`
                // removes the read filter / the whole epoll entry, so
                // kqueue needs explicit EV_DELETE on EVFILT_WRITE.
                if (*c).send_registered {
                    self.disarm_write_fd((*c).fd);
                }
                self.unregister_fd((*c).fd);
                if !(*c).is_shared_listener {
                    shutdown((*c).fd, SHUT_RDWR);
                    close((*c).fd);
                }
                (*c).fd = -1;
            }
            (*c).closed = true;
            (*c).has_pending_data = false;
            (*c).is_listener = false;
            (*c).is_shared_listener = false;
            (*c).send_registered = false;
            // Bump generation so any still-outstanding async handle
            // sees a mismatch on its next hook call.
            (*c).generation = (*c).generation.wrapping_add(1);
            // Wake any parked recv_waker so its next poll sees
            // `closed` and resolves with `recv() == 0`.
            if let Some(w) = (*c).recv_waker.take() {
                w.wake();
            }
            if let Some(w) = (*c).send_waker.take() {
                w.wake();
            }
        }
    }

    /// Non-blocking poll: check for ready fds without waiting. Returns
    /// `true` if any UDP sibling was drained (inline-dispatched to its
    /// handler) so the event loop can keep itself busy instead of
    /// sleeping after UDP work.
    fn poll_events(&mut self) -> bool {
        self.collect_events(0)
    }

    /// Blocking wait: sleep until at least one fd is ready (up to 10ms).
    fn wait_for_events(&mut self) {
        let _ = self.collect_events(10);
    }

    fn collect_events(&mut self, timeout_ms: i32) -> bool {
        const MAX_EVENTS: usize = 64;
        let mut udp_work = false;
        unsafe {
            #[cfg(target_os = "macos")]
            {
                let mut events = [std::mem::zeroed::<Kevent>(); MAX_EVENTS];
                let ts = if timeout_ms > 0 {
                    Timespec { tv_sec: 0, tv_nsec: timeout_ms as i64 * 1_000_000 }
                } else {
                    Timespec { tv_sec: 0, tv_nsec: 0 }
                };
                let n = kevent(self.eq_fd, ptr::null(), 0,
                               events.as_mut_ptr(), MAX_EVENTS as i32, &ts);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].udata as i32;
                    let is_write = events[i].filter == EVFILT_WRITE;
                    if self.dispatch_ready_fd(fd, is_write) { udp_work = true; }
                }
            }
            #[cfg(target_os = "linux")]
            {
                let mut events = [std::mem::zeroed::<EpollEvent>(); MAX_EVENTS];
                let n = epoll_wait(self.eq_fd, events.as_mut_ptr(), MAX_EVENTS as i32, timeout_ms);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].data as i32;
                    let flags = events[i].events;
                    // epoll may signal both read and write in one event;
                    // dispatch once per direction.
                    if flags & EPOLLIN != 0 {
                        if self.dispatch_ready_fd(fd, false) { udp_work = true; }
                    }
                    if flags & EPOLLOUT != 0 {
                        self.dispatch_ready_fd(fd, true);
                    }
                }
            }
        }
        udp_work
    }

    /// Handle a single ready fd. `is_write == true` → write-readiness
    /// event (EVFILT_WRITE / EPOLLOUT): wake the conn's send_waker.
    /// Otherwise read-readiness: UDP siblings get drained inline, the
    /// async-TCP accept reactor is notified, and TCP conn fds flip
    /// `has_pending_data` + wake any parked recv_waker. Returns `true`
    /// iff a UDP sibling was drained.
    fn dispatch_ready_fd(&mut self, fd: i32, is_write: bool) -> bool {
        if is_write {
            for c in self.conns.iter_mut() {
                if c.fd == fd {
                    if let Some(w) = c.send_waker.take() {
                        w.wake();
                    }
                    break;
                }
            }
            return false;
        }
        for i in 0..self.udp_sib_count {
            if self.udp_sibs[i].fd == fd {
                drain_udp_sibling(fd, self.udp_sibs[i].binding_idx);
                return true;
            }
        }
        // Async TCP listener fd fired → wake the reactor's accept
        // future on this worker; the task's next poll drains accept.
        if async_tcp_dispatch(self.thread_id, fd) {
            return false;
        }
        for c in self.conns.iter_mut() {
            if c.fd == fd {
                c.has_pending_data = true;
                // Wake any task parked on `TcpRecv` for this conn.
                // Take() avoids re-waking if the event queue fires
                // again before the task re-registers.
                if let Some(w) = c.recv_waker.take() {
                    w.wake();
                }
                break;
            }
        }
        false
    }
}

/// Drain a UDP sibling non-blockingly until `recvfrom` returns EAGAIN,
/// dispatching the app handler for each datagram. Called from the
/// worker thread's `collect_events` when its kqueue/epoll reports the
/// sibling ready.
fn drain_udp_sibling(fd: i32, binding_idx: usize) {
    let (app_port, handler) = unsafe {
        match (*UDP_BINDINGS.0.get())[binding_idx] {
            Some(ref b) => (b.app_port, b.handler),
            None => return,
        }
    };
    let mut buf = [0u8; 65536];
    loop {
        let mut src_addr: SockAddrIn = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<SockAddrIn>() as u32;
        let n = unsafe {
            recvfrom(fd, buf.as_mut_ptr(), buf.len(), 0,
                     &mut src_addr, &mut addr_len)
        };
        if n <= 0 { break; }
        let src_ip = src_addr.sin_addr.to_be_bytes();
        let src_port = u16::from_be(src_addr.sin_port);
        let payload = &buf[..n as usize];

        // Try the async reactor first; fall back to the legacy
        // callback only if no `UdpSocket` is bound for this port.
        if !uni_runtime::net::deliver_udp(app_port, src_ip, src_port, payload) {
            if let Some(h) = handler {
                h(src_ip, src_port, payload);
            }
        }
    }
}

// ============================================================================
// Global state
// ============================================================================

// Per-thread state. Written exclusively during init_native (BSP) and
// then by each worker's own slot afterwards — no cross-thread
// mutation. UnsafeCell + unsafe impl Sync encodes the contract.
struct ThreadsSlot(UnsafeCell<[ThreadState; MAX_THREADS]>);
// SAFETY: each worker mutates only its own slot; BSP-only init
// populates all slots before workers start.
unsafe impl Sync for ThreadsSlot {}
static THREADS: ThreadsSlot = ThreadsSlot(
    UnsafeCell::new([const { ThreadState::new(0) }; MAX_THREADS])
);

/// Populated once by `init_native` from UNIKERNEL_CPUS / num_cpus;
/// then read by all worker paths. Atomic so cross-thread reads are
/// race-free without the `&static mut` dance.
static NUM_THREADS: AtomicUsize = AtomicUsize::new(1);

/// Set by the SIGINT/SIGTERM handler on any thread; polled by every
/// worker. AtomicBool is the natural fit.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

// ── Shared listen sockets ─────────────────────────────────────────────────────
// macOS SO_REUSEPORT does not distribute connections across sockets. Instead,
// all workers share a single nonblocking listen socket per port. Each worker
// registers it with its own kqueue/epoll. The worker whose kqueue fires first
// calls accept(); others see EAGAIN and go back to sleep. No dedicated thread,
// no pipes — mirrors the unikernel's per-core polling model.
//
// Multiple ports (e.g. HTTP on 8080 + HTTPS on 8443) are supported via a
// small fixed table: each `tcp_listen(port)` call is deduplicated by port,
// and all workers register every current fd with their kqueue/epoll so any
// of them can accept either flavour of connection.

const MAX_SHARED_LISTENERS: usize = 4;

/// `(port, fd)` pairs for every listener currently active. Indexed up to
/// `SHARED_LISTEN_COUNT`. Entries are never removed during a normal run;
/// the process exits on shutdown.
// Shared-listener table. Filled exclusively on the main thread
// before any worker starts (HTTP `Server::listen{,_tls}` runs on
// thread 0 during `uni_main`). After that, workers only read via
// `tcp_register_shared_listener`.
struct SharedListenSlot(UnsafeCell<SharedListenTable>);
struct SharedListenTable {
    ports: [u16; MAX_SHARED_LISTENERS],
    fds: [i32; MAX_SHARED_LISTENERS],
}
// SAFETY: table is frozen after init (see contract above).
unsafe impl Sync for SharedListenSlot {}

static SHARED_LISTEN: SharedListenSlot = SharedListenSlot(UnsafeCell::new(SharedListenTable {
    ports: [0; MAX_SHARED_LISTENERS],
    fds: [-1; MAX_SHARED_LISTENERS],
}));
static SHARED_LISTEN_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Look up (or create) a shared listener for `port`. Returns the fd, or
/// -1 if bind/listen failed. Must only be called with the shared-listener
/// table guarded by the init sequence (no concurrent callers at this
/// point: `Server::listen_tls` runs on the main thread before any worker
/// has entered its event loop).
unsafe fn shared_listen_get_or_create(port: u16) -> i32 {
    unsafe {
        let table = &mut *SHARED_LISTEN.0.get();
        let count = SHARED_LISTEN_COUNT.load(Ordering::Acquire);
        for i in 0..count {
            if table.ports[i] == port {
                return table.fds[i];
            }
        }
        if count >= MAX_SHARED_LISTENERS {
            return -1;
        }
        let fd = make_listener(port, true);
        if fd < 0 { return -1; }
        let idx = count;
        table.ports[idx] = port;
        table.fds[idx] = fd;
        SHARED_LISTEN_COUNT.store(idx + 1, Ordering::Release);
        fd
    }
}

/// Get the current thread's state. Thread ID is stored in a thread-local-like
/// fashion by passing it through the worker function argument.
/// For the main thread (thread 0), we access THREADS[0] directly.
fn thread_state(id: u32) -> &'static mut ThreadState {
    // SAFETY: each worker only ever mutates its own slot; BSP-only
    // init writes across all slots before workers start.
    unsafe { &mut (*THREADS.0.get())[id as usize] }
}

unsafe extern "C" fn sigint_handler(_sig: i32) {
    SHUTDOWN.store(true, Ordering::Release);
}

fn init_native() {
    unsafe {
        // Per-port overrides (`UNIKERNEL_<PROTO>_<GUEST>`) are read
        // lazily from `config_port` / `config_tls_port` /
        // `udp_bind`, keyed by the caller-supplied default port —
        // same derivation as `variants.bzl` bakes into the VM
        // launcher templates. Callers use the same spelling
        // regardless of which runner LAUNCHER points at.

        // Determine thread count from environment or CPU count.
        let num_threads = std::env::var("UNIKERNEL_CPUS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| num_cpus().min(MAX_THREADS));
        NUM_THREADS.store(num_threads, Ordering::Release);

        let threads = &mut *THREADS.0.get();
        for i in 0..num_threads {
            threads[i].thread_id = i as u32;
            threads[i].init_event_queue();
        }

        // Cast through a function pointer first; rust 1.93+ rejects
        // casting a function item directly to an integer.
        let h = sigint_handler as unsafe extern "C" fn(i32) as usize;
        signal(SIGINT, h);
        signal(SIGTERM, h);
        signal(SIGPIPE, SIG_IGN);
    }

    // Wire `UdpSocket::bind` in uni-runtime to our SO_REUSEPORT
    // sibling opener. On bare-metal the hook stays unset because
    // the NIC RX path unconditionally delivers to the reactor.
    uni_runtime::net::register_backend_bind(udp_backend_bind);
    uni_runtime::net::register_backend_udp_send(udp_send);

    // TCP reactor hooks. `listen` is a no-op stub (returns `Ok`) so
    // `TcpListener::bind` succeeds on native; `accept` returns null
    // so the async accept future stays Pending. Full native wiring —
    // opening per-worker listen fds and routing kqueue fires to
    // `deliver_tcp_ready` — is a follow-up; until then apps needing
    // TCP accept on native should stay on `uni_http::Server`.
    uni_runtime::net::register_tcp_backend(
        async_tcp_listen_hook,
        async_tcp_accept_hook,
    );
    uni_runtime::net::register_tcp_recv_hooks(
        native_tcp_has_data,
        native_tcp_do_recv,
        native_tcp_register_recv_waker,
        native_tcp_clear_recv_waker,
    );
    uni_runtime::net::register_tcp_send_hooks(
        native_tcp_try_send,
        native_tcp_register_send_waker,
        native_tcp_clear_send_waker,
    );

    // Register TCP/UDP polling as the first IO poll callback.
    // Runs on every worker's event-loop tick and drains the worker's
    // kqueue/epoll: TCP fd readiness flips `has_pending_data` on
    // matching conns, and UDP sibling readiness triggers inline
    // `recvfrom` + handler dispatch. No dedicated RX threads — same
    // inline-poll pattern as the HVF runner's vCPU loop.
    register_io_poll(|_worker_id| tcp_poll());
}

// ---- Async TCP reactor backend (native side) ------------------------------
//
// One listen fd per port, shared across every worker. Each worker
// registers it in its own kqueue/epoll; when a SYN arrives the
// kernel wakes one waiter (or, on macOS, multiple — thundering
// herd), whose `async_tcp_accept_hook` calls `accept(2)` and owns
// the resulting connection. Losers see EAGAIN and re-poll.
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

const MAX_ASYNC_TCP_LISTENERS: usize = 4;

struct AsyncTcpListener {
    app_port: u16,
    /// Single shared listen fd; same `fd` is registered in every
    /// worker's kqueue/epoll.
    fd: i32,
}

struct AsyncTcpListenersSlot(UnsafeCell<[Option<AsyncTcpListener>; MAX_ASYNC_TCP_LISTENERS]>);
// SAFETY: populated only on the main thread during `uni_main`
// (via `async_tcp_listen_hook` from `uni::runtime::TcpListener::bind`);
// read from workers afterwards without further mutation.
unsafe impl Sync for AsyncTcpListenersSlot {}
static ASYNC_TCP_LISTENERS: AsyncTcpListenersSlot =
    AsyncTcpListenersSlot(UnsafeCell::new([const { None }; MAX_ASYNC_TCP_LISTENERS]));
static ASYNC_TCP_COUNT: AtomicUsize = AtomicUsize::new(0);

fn async_tcp_listen_hook(app_port: u16) -> Result<(), ()> {
    unsafe {
        let count = ASYNC_TCP_COUNT.load(Ordering::Acquire);
        if count >= MAX_ASYNC_TCP_LISTENERS {
            return Err(());
        }
        let host_port = read_port_env("TCP", app_port).unwrap_or(app_port);
        let fd = make_listener(host_port, true);
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

fn async_tcp_accept_hook(app_port: u16) -> uni_runtime::net::RawTcpStream {
    use uni_runtime::net::RawTcpStream;
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
                return RawTcpStream::NULL;
            }
            set_nonblocking(fd);
            let opt: i32 = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, 4);
            let ts = thread_state(tid);
            let c = ts.alloc_conn();
            if c.is_null() {
                close(fd);
                return RawTcpStream::NULL;
            }
            (*c).fd = fd;
            ts.register_fd(fd);
            return RawTcpStream {
                handle: c as *mut (),
                generation: (*c).generation,
            };
        }
        RawTcpStream::NULL
    }
}

// ---- Async TCP recv hooks ------------------------------------------------
//
// Called from `uni_runtime::net::TcpRecv::poll` via the four function
// pointers registered in `init_native`. Each operates on a
// `NativeConn *` obtained from `async_tcp_accept_hook` and lives in
// the owning worker's `ThreadState.conns`. No locking — the conn's
// worker thread is the only writer of `recv_waker`; the poll site
// runs on that same worker (TcpRecv is `!Send`).
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
        let (_c, live) = check_gen(handle, generation);
        if !live {
            return 0;
        }
        // Live + matching generation → forward to the sync recv path.
        tcp_recv(handle, buf)
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

// ---- Async TCP send hooks ------------------------------------------------

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

/// Called from `dispatch_ready_fd`. Returns `true` iff `fd` matched
/// an async-TCP listener (and the reactor notification was issued).
fn async_tcp_dispatch(_thread_id: u32, fd: i32) -> bool {
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
// Platform API — called from uni/lib.rs backend dispatch
// ============================================================================

pub fn log(msg: &[u8]) {
    unsafe { write(2, msg.as_ptr(), msg.len()); }
}

pub fn config_port(default_port: u16) -> u16 {
    read_port_env("TCP", default_port).unwrap_or(default_port)
}

/// TLS port override. Reads `UNIKERNEL_TCP_<default_port>` — TLS runs
/// over TCP, so the namespace is shared with plain HTTP. bench.py /
/// tests set this to a high port to avoid the privileged-port bind
/// on Linux (macOS lets non-root bind anywhere, but we can't rely
/// on that cross-platform).
pub fn config_tls_port(default_port: u16) -> u16 {
    read_port_env("TCP", default_port).unwrap_or(default_port)
}

pub fn check_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Acquire)
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Release);
}

pub fn wait_for_events() {
    thread_state(uni_platform::current_worker()).wait_for_events();
}

pub fn poll_events() -> bool {
    thread_state(uni_platform::current_worker()).poll_events()
}

pub fn num_workers() -> u32 {
    // NUM_THREADS is set by init_native() from UNIKERNEL_CPUS or
    // num_cpus() as default. Use it directly — don't override with
    // num_cpus().
    NUM_THREADS.load(Ordering::Acquire) as u32
}

// ---- TCP (per-thread) -------------------------------------------------------

fn make_listener(port: u16, nonblocking: bool) -> i32 {
    unsafe {
        let fd = socket(AF_INET, SOCK_STREAM, 0);
        if fd < 0 { return -1; }

        let opt: i32 = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
        // SO_REUSEPORT intentionally omitted: on macOS it doesn't distribute
        // connections across sockets; the centralized acceptor handles this.
        if nonblocking { set_nonblocking(fd); }

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

pub fn tcp_listen(port: u16) -> *mut () {
    tcp_listen_for(port, uni_platform::current_worker())
}

pub fn tcp_listen_on(worker_id: u32, port: u16) -> *mut () {
    tcp_listen_for(port, worker_id)
}

pub fn tcp_listen_for(port: u16, worker_id: u32) -> *mut () {
    let tid = worker_id;
    let ts = thread_state(tid);

    unsafe {
        if NUM_THREADS.load(Ordering::Acquire) > 1 {
            // Multi-thread: one shared nonblocking listen socket per port
            // (so HTTP on 8080 and HTTPS on 8443 each get their own fd,
            // but the fd is shared across all workers). All workers'
            // kqueue/epoll instances end up watching both fds and any of
            // them can accept either flavour of connection.
            let fd = shared_listen_get_or_create(port);
            if fd < 0 { return ptr::null_mut(); }
            let c = ts.alloc_conn();
            if c.is_null() { return ptr::null_mut(); }
            (*c).fd = fd;
            (*c).is_listener = true;
            (*c).is_shared_listener = true;
            c as *mut ()
        } else {
            // Single-thread: direct accept(), nonblocking (polled via kqueue/epoll).
            let fd = make_listener(port, true);
            if fd < 0 { return ptr::null_mut(); }
            let c = ts.alloc_conn();
            if c.is_null() { close(fd); return ptr::null_mut(); }
            (*c).fd = fd;
            (*c).is_listener = true;
            ts.register_fd(fd);
            c as *mut ()
        }
    }
}

pub fn tcp_accept(handle: *mut ()) -> *mut () {
    let listener = handle as *mut NativeConn;
    let tid = uni_platform::current_worker();
    let ts = thread_state(tid);
    unsafe {
        if listener.is_null() || (*listener).fd < 0 || (*listener).closed {
            return ptr::null_mut();
        }
        let fd = accept((*listener).fd, ptr::null_mut(), ptr::null_mut());
        if fd < 0 {
            if get_errno() == EAGAIN { (*listener).has_pending_data = false; }
            return ptr::null_mut();
        }
        set_nonblocking(fd);
        // Disable Nagle on the accepted client socket. See the
        // comment on `TCP_NODELAY` above for the full story — short
        // version: the TLS handshake server flight is 5 small
        // consecutive `send()` calls, and with Nagle + Linux
        // delayed-ACK in play the client ends up waiting ~40ms for
        // each segment's ACK before sending its Finished. That
        // alone accounted for a ~150x regression in
        // `tls_handshake_max` on GCP.
        let opt: i32 = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, 4);
        let c = ts.alloc_conn();
        if c.is_null() { close(fd); return ptr::null_mut(); }
        (*c).fd = fd;
        ts.register_fd(fd);
        c as *mut ()
    }
}

pub fn tcp_has_data(handle: *mut ()) -> bool {
    let c = handle as *mut NativeConn;
    unsafe {
        if c.is_null() || (*c).closed { return false; }
        (*c).has_pending_data
    }
}

pub fn tcp_recv(handle: *mut (), buf: &mut [u8]) -> usize {
    let c = handle as *mut NativeConn;
    unsafe {
        if c.is_null() || (*c).fd < 0 || (*c).closed { return 0; }
        let n = recv((*c).fd, buf.as_mut_ptr(), buf.len(), 0);
        if n < 0 { (*c).has_pending_data = false; return 0; }
        if n == 0 { (*c).closed = true; (*c).has_pending_data = false; return 0; }
        (*c).has_pending_data = false;
        n as usize
    }
}

pub fn tcp_send(handle: *mut (), data: &[u8]) -> i32 {
    let c = handle as *mut NativeConn;
    unsafe {
        if c.is_null() || (*c).fd < 0 || (*c).closed { return -1; }
        let sent = send((*c).fd, data.as_ptr(), data.len(), MSG_NOSIGNAL);
        if sent < 0 { -1 } else { sent as i32 }
    }
}

pub fn tcp_close(handle: *mut ()) {
    let c = handle as *mut NativeConn;
    if c.is_null() { return; }
    // Find which thread owns this connection and release it
    let tid = uni_platform::current_worker();
    thread_state(tid).release_conn(c);
}

pub fn tcp_is_closed(handle: *mut ()) -> bool {
    let c = handle as *mut NativeConn;
    unsafe { c.is_null() || (*c).closed }
}

/// Pump the worker's event queue non-blockingly. Flips
/// `has_pending_data` on any TCP conn that became readable and drains
/// any UDP sibling that fired (dispatching the app handler inline).
/// Returns `true` iff a UDP sibling was drained — tells the event
/// loop to skip its idle sleep and run another iteration.
pub fn tcp_poll() -> bool {
    thread_state(uni_platform::current_worker()).poll_events()
}

/// Register every shared listen socket with this worker's kqueue/epoll.
/// Called once per worker thread once it's running. In multi-thread mode
/// the shared fds are watched by all workers simultaneously; whichever
/// kqueue fires first calls accept() and the rest see EAGAIN. We iterate
/// the full `SHARED_LISTEN_FDS` table so that workers pick up both the
/// HTTP listener and (if configured) the HTTPS listener — missing either
/// one silently drops accept events for that port.
fn tcp_register_shared_listener() {
    let tid = uni_platform::current_worker();
    unsafe {
        let table = &*SHARED_LISTEN.0.get();
        let count = SHARED_LISTEN_COUNT.load(Ordering::Acquire);
        for i in 0..count {
            let fd = table.fds[i];
            if fd >= 0 {
                thread_state(tid).register_fd(fd);
            }
        }
    }
}

// ============================================================================
// UDP support
// ============================================================================

const MAX_UDP_BINDINGS: usize = 8;

/// One UDP relay. Holds `NUM_THREADS` SO_REUSEPORT sibling sockets all
/// bound to the same host port. Incoming datagrams are distributed
/// across the siblings by the kernel (4-tuple hash) so each UDP worker
/// thread blocks on its own fd's `recvfrom` and runs the app handler
/// inline. Replies use the receiving thread's sibling fd, which keeps
/// the reply source port equal to the relay port (NAT-correct) and
/// avoids cross-thread contention on a single kernel socket lock.
struct UdpBinding {
    fds: [i32; MAX_THREADS],
    sibling_count: usize,
    app_port: u16,  // port as requested by app (used for send-side lookup)
    /// Callback path: `Some` for legacy `udp_bind(port, handler)`.
    /// `None` when the async reactor (`UdpSocket::bind`) set this
    /// binding up — drain dispatches to `uni_runtime::net::deliver_udp`
    /// in that case.
    handler: Option<fn([u8; 4], u16, &[u8])>,
}

// UDP relay table. Entries written by `udp_bind` on the main thread
// (before workers start); workers read their owned sibling fd from
// the entry.
struct UdpBindingsSlot(UnsafeCell<[Option<UdpBinding>; MAX_UDP_BINDINGS]>);
// SAFETY: populated only on the main thread during `uni_main`; read
// from workers afterwards without further mutation.
unsafe impl Sync for UdpBindingsSlot {}
static UDP_BINDINGS: UdpBindingsSlot =
    UdpBindingsSlot(UnsafeCell::new([const { None }; MAX_UDP_BINDINGS]));
static UDP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Open one non-blocking SO_REUSEPORT-bound UDP sibling socket on
/// `bind_port`. All siblings of a relay share the same port — kernel
/// distributes incoming datagrams across them by 4-tuple hash.
fn open_udp_sibling(bind_port: u16) -> i32 {
    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 { return -1; }

        let opt: i32 = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, 4);

        let addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: bind_port.to_be(),
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, std::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd);
            return -1;
        }

        set_nonblocking(fd);
        fd
    }
}

pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    let _ = open_udp_relay(port, Some(handler));
}

/// Hook registered with `uni_runtime::net::register_backend_bind`.
/// Invoked when a `UdpSocket` is created; opens the SO_REUSEPORT
/// siblings with no sync handler so the `drain_udp_sibling` path
/// routes inbound datagrams through the async reactor.
fn udp_backend_bind(port: u16) -> Result<(), ()> {
    open_udp_relay(port, None)
}

/// Open SO_REUSEPORT siblings for `app_port` and register each in
/// its worker's kqueue/epoll. Shared by the legacy sync `udp_bind`
/// and the async `UdpSocket::bind` hook (`handler = None`). Returns
/// `Err(())` if the OS refused the first sibling bind — higher
/// layers surface that as `UdpBindError::BackendFailed`.
fn open_udp_relay(
    app_port: u16,
    handler: Option<fn([u8; 4], u16, &[u8])>,
) -> Result<(), ()> {
    unsafe {
        let count = UDP_COUNT.load(Ordering::Acquire);
        if count >= MAX_UDP_BINDINGS { return Err(()); }

        // Per-port override keyed on the app's requested port:
        // `UNIKERNEL_UDP_<port>` swaps in a different host-bind
        // port. Each app-requested UDP port has its own knob — no
        // shared base + offset remapping.
        let bind_port = read_port_env("UDP", app_port).unwrap_or(app_port);

        // Open NUM_THREADS SO_REUSEPORT siblings so the kernel
        // distributes incoming datagrams across the group by 4-tuple
        // hash. Each worker thread owns sibling `i` and polls it
        // inline via its own kqueue/epoll — no dedicated RX thread.
        let want = NUM_THREADS.load(Ordering::Acquire).max(1);
        let mut fds = [-1i32; MAX_THREADS];
        let mut got = 0usize;
        for i in 0..want {
            let fd = open_udp_sibling(bind_port);
            if fd < 0 {
                if i == 0 { return Err(()); }
                break;
            }
            fds[i] = fd;
            got += 1;
        }

        let binding_idx = count;
        (*UDP_BINDINGS.0.get())[binding_idx] = Some(UdpBinding {
            fds,
            sibling_count: got,
            app_port,
            handler,
        });
        UDP_COUNT.store(binding_idx + 1, Ordering::Release);

        // Register each sibling in its owning worker's event queue.
        // `udp_bind` runs on the main thread before workers start,
        // but each worker's kqueue/epoll fd is already live (set up
        // in `init_native`), so we can push registrations from here.
        let threads = &mut *THREADS.0.get();
        for worker_id in 0..got {
            threads[worker_id].add_udp_sibling(fds[worker_id], binding_idx);
        }
        Ok(())
    }
}

pub fn udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    unsafe {
        // Handler runs inline on a worker thread after its kqueue
        // reported the sibling ready. Reply on that worker's own
        // sibling — same kernel socket lock as the recv, and the
        // source port is already equal to the relay port, which keeps
        // NAT path-correct.
        let tid = uni_platform::current_worker() as usize;
        let mut send_fd = -1;
        let bindings = &*UDP_BINDINGS.0.get();
        let count = UDP_COUNT.load(Ordering::Acquire);
        for i in 0..count {
            if let Some(ref b) = bindings[i] {
                if b.app_port == src_port && b.sibling_count > 0 {
                    send_fd = if tid < b.sibling_count && b.fds[tid] >= 0 {
                        b.fds[tid]
                    } else {
                        b.fds[0]
                    };
                    break;
                }
            }
        }
        if send_fd < 0 {
            // No binding — create ephemeral socket
            send_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if send_fd < 0 { return; }
        }

        let dst_addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: dst_port.to_be(),
            sin_addr: u32::from_be_bytes(dst_ip),
            sin_zero: [0; 8],
        };

        sendto(send_fd, data.as_ptr(), data.len(), 0,
               &dst_addr, std::mem::size_of::<SockAddrIn>() as u32);
    }
}

// ============================================================================
// Callback-driven event loop (mirrors uni_kernel::eventloop)
// ============================================================================
//
// Same pattern as the unikernel: register callbacks, all workers run
// the same loop. On native, "worker" = OS thread. IO_POLL callbacks
// are called every tick; SERVICE is the app's per-tick service step.

type PollFn = fn(u32) -> bool;

/// Up to 4 IO poll callbacks (network + future storage). Each slot is
/// an `AtomicFn<PollFn>` — null = empty, published value = callback.
/// `IO_POLL_COUNT` tracks how many slots have been claimed. Slots
/// are filled in order during init by `register_io_poll`, then read
/// by all worker threads. `AtomicFn`'s Release/Acquire pair gives us
/// cross-thread happens-before without a volatile *mut ().
const IO_POLL_MAX: usize = 4;
static IO_POLL: [AtomicFn<PollFn>; IO_POLL_MAX] = [
    AtomicFn::null(),
    AtomicFn::null(),
    AtomicFn::null(),
    AtomicFn::null(),
];
static IO_POLL_COUNT: AtomicUsize = AtomicUsize::new(0);
static SERVICE: AtomicFn<PollFn> = AtomicFn::null();
static READY: AtomicBool = AtomicBool::new(false);

/// Optional per-worker pre-spawn hook. HTTP-like crates that need
/// per-worker TCP listeners (SO_REUSEPORT siblings) register here;
/// `run()` invokes it for workers 1..NUM_THREADS after `uni_main`
/// and before `pthread_create`. Apps without per-worker setup
/// leave it null.
static ADD_WORKER_LISTENER: AtomicFn<fn(u32)> = AtomicFn::null();

/// Install a per-worker pre-spawn hook — see `ADD_WORKER_LISTENER`.
pub fn set_add_worker_listener(f: fn(u32)) {
    ADD_WORKER_LISTENER.store(f);
}

/// Register an IO poll callback (network, storage, etc). Multiple
/// sources can be registered; all are called each iteration. Designed
/// to be called from a single init thread; the atomic fetch_add
/// reserves the slot index race-free even if that contract is ever
/// violated.
pub fn register_io_poll(f: PollFn) {
    let idx = IO_POLL_COUNT.fetch_add(1, Ordering::AcqRel);
    if idx < IO_POLL_MAX {
        IO_POLL[idx].store(f);
    } else {
        // Roll back to keep IO_POLL_COUNT bounded.
        IO_POLL_COUNT.store(IO_POLL_MAX, Ordering::Release);
    }
}

pub fn set_service(f: PollFn) {
    SERVICE.store(f);
}

fn get_service() -> Option<PollFn> {
    SERVICE.load()
}

pub fn set_ready() {
    READY.store(true, Ordering::Release);
}

fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Run the worker event loop on this thread. Same structure as the
/// unikernel's. Called by `native_worker_loop` after thread setup.
pub fn run_worker(worker_id: u32) {
    // Worker 0 skips the READY wait: `uni_main` now only spawns the
    // app's boot body as an async task; worker 0 is what polls it,
    // and the task's `uni::run(app)` is what eventually calls
    // `set_ready` to release the other workers. Blocking here would
    // deadlock because nothing else drives the runtime.
    if worker_id != 0 {
        while !is_ready() && !check_shutdown() {
            wait_for_events();
        }
    }

    loop {
        if check_shutdown() { break; }

        let mut did_work = false;

        // 1. IO poll callbacks (network, future storage, etc)
        let n = IO_POLL_COUNT.load(Ordering::Acquire).min(IO_POLL_MAX);
        for i in 0..n {
            if let Some(f) = IO_POLL[i].load() {
                if f(worker_id) { did_work = true; }
            }
        }

        // 2. App service callback
        if let Some(f) = get_service() {
            if f(worker_id) { did_work = true; }
        }

        // 2a. Async runtime: every worker advances its own timer
        // list and polls its own arena — same per-core pattern as
        // the unikernel, driven by `//uni-runtime` under the hood.
        if uni_runtime::tick(worker_id) { did_work = true; }

        // 3. Idle if no work
        if !did_work {
            wait_for_events();
        }
    }
}

// ============================================================================
// Native entry point
// ============================================================================

unsafe extern "C" {
    fn uni_main();
}

extern "C" fn worker_thread(arg: *mut u8) -> *mut u8 {
    let tid = arg as u32;
    uni_platform::set_current_worker(tid);

    // Workers call the same service_core() as the unikernel APs.
    // The Server is set up by the main thread before workers start.
    unsafe extern "C" { fn native_worker_loop(thread_id: u32); }
    unsafe { native_worker_loop(tid); }
    ptr::null_mut()
}

/// Config for `run()`. Holds the two uni-side hooks we'd otherwise
/// need to call across the crate boundary:
///
///   * `boot_info_fn` — fills `uni::boot_info` with the native host's
///     CPU count / RAM bytes right after thread-pool init.
///   * `shutdown_fn` — called after all workers join, to drop the app
///     box and clear the net slot (`uni::shutdown_and_drop`).
///
/// HTTP-like per-worker pre-spawn hooks (SO_REUSEPORT listeners) are
/// registered separately via `set_add_worker_listener` — they're
/// optional and only set by `uni-http`, so carrying them here would
/// force every native app to know about them.
pub struct RunConfig {
    pub boot_info_fn: fn(num_cpus: u32, ram_bytes: usize),
    pub shutdown_fn: fn(),
}

/// Native-binary entry point — called from `uni::native::run` (which
/// in turn is called from `bazel/rules/native_main.rs`'s `fn main()`).
/// Returns the process exit code.
pub fn run(config: RunConfig) -> i32 {
    init_native();

    // Publish the boot-time snapshot via the uni-side callback. The
    // native backend has no NIC driver (POSIX sockets go through the
    // host stack), so nic info is filled in by the callback as empty.
    (config.boot_info_fn)(num_cpus() as u32, host_ram_bytes());

    unsafe {
        uni_main();
        // uni_main called server.run() → tcp_listen() on thread 0.
        // In multi-thread mode, tcp_listen() created the shared listen
        // socket and per-worker handles. If `uni-http` (or similar)
        // registered a per-worker hook, call it now to create the
        // remaining worker handles before their threads start.
        let num_threads = NUM_THREADS.load(Ordering::Acquire);
        if let Some(f) = ADD_WORKER_LISTENER.load() {
            for i in 1..num_threads {
                uni_platform::set_current_worker(i as u32);
                f(i as u32);
            }
        }
        uni_platform::set_current_worker(0);

        // Start worker threads
        let mut thread_handles = [0usize; MAX_THREADS];
        for i in 1..num_threads {
            pthread_create(
                &mut thread_handles[i],
                ptr::null(),
                worker_thread,
                i as *mut u8,
            );
        }

        // Main thread is worker 0
        uni_platform::set_current_worker(0);
        native_worker_loop(0);

        // Join workers
        for i in 1..num_threads {
            if thread_handles[i] != 0 {
                pthread_join(thread_handles[i], ptr::null_mut());
            }
        }

        // App teardown — drops whatever the user handed to `uni::run`
        // (firing its `Drop` impl). Idempotent; ordered after workers
        // have stopped touching app state.
        (config.shutdown_fn)();
    }
    0
}

/// Called by each worker thread (including main).
#[unsafe(no_mangle)]
pub extern "C" fn native_worker_loop(thread_id: u32) {
    uni_platform::set_current_worker(thread_id);
    // Register the shared listen socket with this worker's kqueue/epoll so it
    // wakes up when a new connection arrives.
    tcp_register_shared_listener();
    run_worker(thread_id);
}

// ---- Driver diagnostics stubs (native has no NIC driver) -------------------
//
// Parallel the unikernel side's `uni_drivers::net::{rx_counts, num_queue_pairs,
// rx_used_cursors}` so cross-platform callers see the same names and return
// zeros here.

pub fn net_rx_counts() -> [u64; 8] { [0; 8] }
pub fn net_num_queue_pairs() -> u16 { 1 }
pub fn net_rx_used_cursors() -> [(u16, u16); 8] { [(0, 0); 8] }

// ---- Heap stats ------------------------------------------------------------

pub fn heap_stats() -> super::HeapStats { super::HeapStats::default() }
