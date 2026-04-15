// uni/native.rs — Native (POSIX) backend: multi-threaded sockets + stdio.
//
// Each worker thread has its own:
//   - Shared listen socket registered in its own kqueue/epoll
//   - Connection pool
//   - poll() loop
//
// Multi-thread distribution: a single nonblocking listen socket is registered
// in every worker's kqueue/epoll. When a connection arrives, the first worker
// whose kqueue fires calls accept() and owns the connection; others see EAGAIN
// and go back to sleep. No dedicated acceptor thread, no pipes — mirrors the
// unikernel's per-core event loop model where each core polls the accept queue.
//
// NOTE: this file is the host POSIX dev backend, not the unikernel itself.
// It still uses several `static mut` globals for thread/UDP/listener state.
// They're sound by current convention (init from a single thread before
// workers start, then mutated only by their owning worker), but the
// migration to atomics/locks here is lower priority than the unikernel
// side and is left as future work. The lint allow is local to this file
// rather than crate-wide.
#![allow(static_mut_refs)]

use core::ptr;

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
const EV_ADD: u16 = 0x0001;
#[cfg(target_os = "macos")]
const EV_DELETE: u16 = 0x0002;

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
const EPOLL_CTL_ADD: i32 = 1;
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
    fn getenv(name: *const u8) -> *const u8;
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
    fn pthread_key_create(key: *mut usize, destructor: usize) -> i32;
    fn pthread_setspecific(key: usize, value: *const u8) -> i32;
    fn pthread_getspecific(key: usize) -> *const u8;
    fn sysconf(name: i32) -> i64;

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

fn parse_u16(s: *const u8) -> u16 {
    let mut n: u32 = 0;
    let mut i = 0;
    unsafe {
        loop {
            let c = *s.add(i);
            if c < b'0' || c > b'9' { break; }
            n = n * 10 + (c - b'0') as u32;
            i += 1;
        }
    }
    n as u16
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

// ============================================================================
// Per-thread connection pool
// ============================================================================

const CONNS_PER_THREAD: usize = 64;
const MAX_THREADS: usize = 16;

#[derive(Clone, Copy)]
struct NativeConn {
    fd: i32,
    is_listener: bool,
    /// True when this listener's fd is shared across workers (multi-thread mode).
    /// release_conn must NOT close the fd — other workers are still using it.
    is_shared_listener: bool,
    closed: bool,
    has_pending_data: bool,
}

impl NativeConn {
    const fn empty() -> Self {
        NativeConn { fd: -1, is_listener: false, is_shared_listener: false, closed: true, has_pending_data: false }
    }
}

/// One UDP sibling fd owned by a worker thread. Populated at
/// `native_udp_bind` time, one entry per `-p udp:...` relay. Drained
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
            conns: [NativeConn::empty(); CONNS_PER_THREAD],
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

    fn alloc_conn(&mut self) -> *mut NativeConn {
        for c in self.conns.iter_mut() {
            if c.closed && c.fd < 0 {
                *c = NativeConn { fd: -1, is_listener: false, is_shared_listener: false, closed: false, has_pending_data: false };
                return c as *mut NativeConn;
            }
        }
        ptr::null_mut()
    }

    fn release_conn(&mut self, c: *mut NativeConn) {
        unsafe {
            if (*c).fd >= 0 {
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
                let mut events = [core::mem::zeroed::<Kevent>(); MAX_EVENTS];
                let ts = if timeout_ms > 0 {
                    Timespec { tv_sec: 0, tv_nsec: timeout_ms as i64 * 1_000_000 }
                } else {
                    Timespec { tv_sec: 0, tv_nsec: 0 }
                };
                let n = kevent(self.eq_fd, ptr::null(), 0,
                               events.as_mut_ptr(), MAX_EVENTS as i32, &ts);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].udata as i32;
                    if self.dispatch_ready_fd(fd) { udp_work = true; }
                }
            }
            #[cfg(target_os = "linux")]
            {
                let mut events = [core::mem::zeroed::<EpollEvent>(); MAX_EVENTS];
                let n = epoll_wait(self.eq_fd, events.as_mut_ptr(), MAX_EVENTS as i32, timeout_ms);
                for i in 0..n.max(0) as usize {
                    let fd = events[i].data as i32;
                    if self.dispatch_ready_fd(fd) { udp_work = true; }
                }
            }
        }
        udp_work
    }

    /// Handle a single ready fd: UDP siblings get drained and dispatched
    /// inline (matches HVF's inline-poll design); TCP fds just get
    /// `has_pending_data = true` so the app's recv path picks them up.
    /// Returns `true` iff a UDP sibling was drained — TCP flagging
    /// alone isn't "work" for the event loop because the app's service
    /// step is what actually consumes it.
    fn dispatch_ready_fd(&mut self, fd: i32) -> bool {
        for i in 0..self.udp_sib_count {
            if self.udp_sibs[i].fd == fd {
                drain_udp_sibling(fd, self.udp_sibs[i].binding_idx);
                return true;
            }
        }
        for c in self.conns.iter_mut() {
            if c.fd == fd { c.has_pending_data = true; break; }
        }
        false
    }
}

/// Drain a UDP sibling non-blockingly until `recvfrom` returns EAGAIN,
/// dispatching the app handler for each datagram. Called from the
/// worker thread's `collect_events` when its kqueue/epoll reports the
/// sibling ready.
fn drain_udp_sibling(fd: i32, binding_idx: usize) {
    let handler = unsafe {
        match UDP_BINDINGS[binding_idx] {
            Some(ref b) => b.handler,
            None => return,
        }
    };
    let mut buf = [0u8; 65536];
    loop {
        let mut src_addr: SockAddrIn = unsafe { core::mem::zeroed() };
        let mut addr_len = core::mem::size_of::<SockAddrIn>() as u32;
        let n = unsafe {
            recvfrom(fd, buf.as_mut_ptr(), buf.len(), 0,
                     &mut src_addr, &mut addr_len)
        };
        if n <= 0 { break; }
        let src_ip = src_addr.sin_addr.to_be_bytes();
        let src_port = u16::from_be(src_addr.sin_port);
        handler(src_ip, src_port, &buf[..n as usize]);
    }
}

// ============================================================================
// Global state
// ============================================================================

static mut THREADS: [ThreadState; MAX_THREADS] = [const { ThreadState::new(0) }; MAX_THREADS];
pub static mut NUM_THREADS: usize = 1;
static mut CONFIG_PORT: u16 = 0;
static mut CONFIG_TLS_PORT: u16 = 0;
pub static mut SHUTDOWN: bool = false;

// ── Shared listen socket ──────────────────────────────────────────────────────
// macOS SO_REUSEPORT does not distribute connections across sockets. Instead,
// all workers share a single nonblocking listen socket. Each worker registers
// it with its own kqueue/epoll. The worker whose kqueue fires first calls
// accept(); others see EAGAIN and go back to sleep. No dedicated thread, no
// pipes — mirrors the unikernel's per-core polling model.

static mut SHARED_LISTEN_FD: i32 = -1;

/// Get the current thread's state. Thread ID is stored in a thread-local-like
/// fashion by passing it through the worker function argument.
/// For the main thread (thread 0), we access THREADS[0] directly.
fn thread_state(id: u32) -> &'static mut ThreadState {
    unsafe { &mut THREADS[id as usize] }
}

// ============================================================================
// Helpers for the uni API (dispatched by thread_id)
// ============================================================================

// Thread-local thread ID via pthread TLS.
// Must be per-thread so concurrent workers don't clobber each other's
// identity — wrong thread ID means wrong connection pool and wrong
// kqueue/epoll fd.
//
// pthread_key_t: usize on both macOS and Linux (unsigned long / unsigned int).
static mut TLS_KEY: usize = 0;

fn set_current_thread_id(id: u32) {
    unsafe { pthread_setspecific(TLS_KEY, id as usize as *const u8); }
}

fn current_thread_id() -> u32 {
    unsafe { pthread_getspecific(TLS_KEY) as u32 }
}

unsafe extern "C" fn sigint_handler(_sig: i32) {
    unsafe { SHUTDOWN = true; }
}

fn init_native() {
    unsafe {
        pthread_key_create(&mut TLS_KEY, 0);

        let p = getenv(b"PORT\0".as_ptr());
        if !p.is_null() && *p != 0 {
            CONFIG_PORT = parse_u16(p);
        }

        // TLS listener port override. bench.py / tests set this to
        // a high port to avoid the privileged-port bind on Linux
        // (macOS lets non-root bind anywhere, but we can't rely on
        // that cross-platform).
        let tp = getenv(b"TLS_PORT\0".as_ptr());
        if !tp.is_null() && *tp != 0 {
            CONFIG_TLS_PORT = parse_u16(tp);
        }

        let u = getenv(b"UDP_PORT\0".as_ptr());
        if !u.is_null() && *u != 0 {
            UDP_PORT_BASE = parse_u16(u);
        }

        // Determine thread count from environment or CPU count
        let t = getenv(b"THREADS\0".as_ptr());
        if !t.is_null() && *t != 0 {
            NUM_THREADS = parse_u16(t) as usize;
        } else {
            NUM_THREADS = num_cpus().min(MAX_THREADS);
        }

        for i in 0..NUM_THREADS {
            THREADS[i].thread_id = i as u32;
            THREADS[i].init_event_queue();
        }

        // Cast through a function pointer first; rust 1.93+ rejects
        // casting a function item directly to an integer.
        let h = sigint_handler as unsafe extern "C" fn(i32) as usize;
        signal(SIGINT, h);
        signal(SIGTERM, h);
        signal(SIGPIPE, SIG_IGN);
    }

    // Register the IO poll callback. This runs on every worker's
    // event-loop tick and drains the worker's kqueue/epoll: TCP fd
    // readiness flips `has_pending_data` on matching conns, and UDP
    // sibling readiness triggers inline `recvfrom`+handler dispatch.
    // No dedicated RX threads — same inline-poll pattern as the HVF
    // runner's vCPU loop.
    crate::register_io_poll(|_worker_id| tcp_poll());
}

// ============================================================================
// Platform API — called from uni/lib.rs backend dispatch
// ============================================================================

pub fn log(msg: &[u8]) {
    unsafe { write(2, msg.as_ptr(), msg.len()); }
}

pub fn config_port(default_port: u16) -> u16 {
    let port = unsafe { CONFIG_PORT };
    if port != 0 { port } else { default_port }
}

/// TLS port override, populated from the `TLS_PORT` environment
/// variable at `init_native()` time. Returns the override when
/// set, otherwise the caller-supplied default (typically 443).
/// Mirrors `config_port` but for the HTTPS listener.
pub fn config_tls_port(default_port: u16) -> u16 {
    let port = unsafe { CONFIG_TLS_PORT };
    if port != 0 { port } else { default_port }
}

pub fn check_shutdown() -> bool {
    unsafe { SHUTDOWN }
}

pub fn wait_for_events() {
    thread_state(current_thread_id()).wait_for_events();
}

pub fn poll_events() -> bool {
    thread_state(current_thread_id()).poll_events()
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
            sin_len: core::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, core::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd); return -1;
        }
        if listen(fd, 128) < 0 {
            close(fd); return -1;
        }
        fd
    }
}

pub fn tcp_listen(port: u16) -> *mut () {
    tcp_listen_for(port, current_thread_id())
}

pub fn tcp_listen_for(port: u16, worker_id: u32) -> *mut () {
    let tid = worker_id;
    let ts = thread_state(tid);

    unsafe {
        if NUM_THREADS > 1 {
            // Multi-thread: single shared nonblocking listen socket.
            // Create it once on the first call, then hand each worker a handle
            // pointing at the same fd. Registration with each worker's
            // kqueue/epoll happens in tcp_register_shared_listener() once the
            // worker thread is actually running.
            if SHARED_LISTEN_FD < 0 {
                let fd = make_listener(port, true);  // nonblocking
                if fd < 0 { return ptr::null_mut(); }
                SHARED_LISTEN_FD = fd;
            }
            let c = ts.alloc_conn();
            if c.is_null() { return ptr::null_mut(); }
            (*c).fd = SHARED_LISTEN_FD;
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
    let tid = current_thread_id();
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
    let tid = current_thread_id();
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
    thread_state(current_thread_id()).poll_events()
}

/// Register the shared listen socket with this worker's kqueue/epoll.
/// Called once per worker thread once it's running. In multi-thread mode the
/// shared fd is watched by all workers simultaneously; whichever kqueue fires
/// first calls accept() and the rest see EAGAIN.
pub fn tcp_register_shared_listener() {
    let tid = current_thread_id();
    unsafe {
        if SHARED_LISTEN_FD >= 0 {
            thread_state(tid).register_fd(SHARED_LISTEN_FD);
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
/// inline. Replies use the receiving thread's sibling fd (set in the
/// `CURRENT_UDP_FD` TLS slot before the handler call), which keeps the
/// reply source port equal to the relay port (NAT-correct) and avoids
/// cross-thread contention on a single kernel socket lock.
struct UdpBinding {
    fds: [i32; MAX_THREADS],
    sibling_count: usize,
    app_port: u16,  // port as requested by app (used for send-side lookup)
    handler: fn([u8; 4], u16, &[u8]),
}

static mut UDP_BINDINGS: [Option<UdpBinding>; MAX_UDP_BINDINGS] =
    [const { None }; MAX_UDP_BINDINGS];
static mut UDP_COUNT: usize = 0;
/// Base UDP port override from UDP_PORT env var (0 = use app-requested port).
static mut UDP_PORT_BASE: u16 = 0;
/// Default UDP port used by the app (first bound port, set on first bind call).
static mut UDP_DEFAULT_PORT: u16 = 0;

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
            sin_len: core::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: bind_port.to_be(),
            sin_addr: 0,
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, core::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd);
            return -1;
        }

        set_nonblocking(fd);
        fd
    }
}

pub fn native_udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    unsafe {
        if UDP_COUNT >= MAX_UDP_BINDINGS { return; }

        // If UDP_PORT env var is set, remap ports: the first app UDP port maps
        // to UDP_PORT, subsequent ports offset from there.
        let bind_port = if UDP_PORT_BASE != 0 {
            if UDP_DEFAULT_PORT == 0 { UDP_DEFAULT_PORT = port; }
            UDP_PORT_BASE + (port - UDP_DEFAULT_PORT)
        } else {
            port
        };

        // Open NUM_THREADS SO_REUSEPORT siblings so the kernel
        // distributes incoming datagrams across the group by 4-tuple
        // hash. Each worker thread owns sibling `i` and polls it
        // inline via its own kqueue/epoll — no dedicated RX thread.
        let want = NUM_THREADS.max(1);
        let mut fds = [-1i32; MAX_THREADS];
        let mut got = 0usize;
        for i in 0..want {
            let fd = open_udp_sibling(bind_port);
            if fd < 0 {
                if i == 0 { return; }
                break;
            }
            fds[i] = fd;
            got += 1;
        }

        let binding_idx = UDP_COUNT;
        UDP_BINDINGS[binding_idx] = Some(UdpBinding {
            fds,
            sibling_count: got,
            app_port: port,
            handler,
        });
        UDP_COUNT += 1;

        // Register each sibling in its owning worker's event queue.
        // `native_udp_bind` runs on the main thread before workers
        // start, but each worker's kqueue/epoll fd is already live
        // (set up in `init_native`), so we can push registrations
        // from here.
        for worker_id in 0..got {
            THREADS[worker_id].add_udp_sibling(fds[worker_id], binding_idx);
        }
    }
}

pub fn native_udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    unsafe {
        // Handler runs inline on a worker thread after its kqueue
        // reported the sibling ready. Reply on that worker's own
        // sibling — same kernel socket lock as the recv, and the
        // source port is already equal to the relay port, which keeps
        // NAT path-correct.
        let tid = current_thread_id() as usize;
        let mut send_fd = -1;
        for i in 0..UDP_COUNT {
            if let Some(ref b) = UDP_BINDINGS[i] {
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
            sin_len: core::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: dst_port.to_be(),
            sin_addr: u32::from_be_bytes(dst_ip),
            sin_zero: [0; 8],
        };

        sendto(send_fd, data.as_ptr(), data.len(), 0,
               &dst_addr, core::mem::size_of::<SockAddrIn>() as u32);
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
    set_current_thread_id(tid);

    // Import the Server pointer from http.rs
    // Workers call the same service_core() as the unikernel APs.
    // The Server is set up by the main thread before workers start.
    unsafe extern "C" { fn native_worker_loop(thread_id: u32); }
    unsafe { native_worker_loop(tid); }
    ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    init_native();
    unsafe {
        uni_main();
        // uni_main called server.run() → tcp_listen() on thread 0.
        // In multi-thread mode, tcp_listen() created the shared listen socket
        // and per-worker handles. add_worker_listener creates the remaining
        // worker handles before their threads start.

        for i in 1..NUM_THREADS {
            set_current_thread_id(i as u32);
            crate::http::add_worker_listener(i as u32);
        }
        set_current_thread_id(0);

        // Start worker threads
        let mut thread_handles = [0usize; MAX_THREADS];
        for i in 1..NUM_THREADS {
            pthread_create(
                &mut thread_handles[i],
                ptr::null(),
                worker_thread,
                i as *mut u8,
            );
        }

        // Main thread is worker 0
        set_current_thread_id(0);
        native_worker_loop(0);

        // Join workers
        for i in 1..NUM_THREADS {
            if thread_handles[i] != 0 {
                pthread_join(thread_handles[i], ptr::null_mut());
            }
        }
    }
    0
}

/// Called by each worker thread (including main).
#[unsafe(no_mangle)]
pub extern "C" fn native_worker_loop(thread_id: u32) {
    set_current_thread_id(thread_id);
    // Register the shared listen socket with this worker's kqueue/epoll so it
    // wakes up when a new connection arrives.
    tcp_register_shared_listener();
    crate::backend::run_worker(thread_id);
}
