// Host POSIX backend for `uni`. libc-FFI sockets, kqueue/epoll,
// pthread workers, cross-worker event loop.
//
// Listener distribution: one nonblocking listen fd registered in every
// worker's kqueue/epoll. First worker whose kqueue fires calls
// accept() and owns the connection; others see EAGAIN and sleep. No
// dedicated acceptor, no pipes — mirrors the unikernel's per-core
// model.

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::task::Waker;
use atomic_fn::AtomicFn;

/// Re-export of the shared runtime's executor surface — apps
/// reach these via `uni::runtime::{spawn,sleep_us,Sleep,…}`.
pub mod runtime {
    pub use uni_runtime::{
        has_pending, sleep_us, spawn, tick, Sleep,
    };
}

mod udp;
mod tcp;

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
#[derive(Clone, Copy)]
pub(crate) struct IoVec {
    /// `*const u8` rather than `*mut u8` because we only use
    /// `IoVec` for `writev` (gather-write), which takes
    /// `const struct iovec*` semantically. Casting to `*mut`
    /// at the boundary is fine — the kernel only reads.
    pub iov_base: *const u8,
    pub iov_len: usize,
}

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
    fn writev(fd: i32, iov: *const IoVec, iovcnt: i32) -> isize;
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

fn errno() -> i32 {
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
    closed: bool,
    has_pending_data: bool,
    /// Incremented every time this slot is released. Async handles
    /// (TcpStream) carry the generation at accept time; hook
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
struct ThreadState {
    conns: [NativeConn; CONNS_PER_THREAD],
    eq_fd: i32,  // kqueue (macOS) or epoll (Linux) fd
    thread_id: u32,
    /// Sparse port → fd table for `udp_send`. 65536 `AtomicI32`
    /// entries (-1 means "no fd for this port on this thread"),
    /// allocated once at thread setup. Cross-thread bind sets the
    /// entry via Release; same-thread send loads it via Relaxed.
    /// Eliminates the linear scan that the old fixed-size
    /// `UDP_BINDINGS` table required, so `udp_send` stays O(1)
    /// even at thousands of concurrent ephemeral binds.
    udp_send_fd: AtomicPtr<AtomicI32>,
    /// fd → app_port map used by `try_dispatch_fd_event` to learn
    /// which UDP port a kqueue/epoll-fired fd belongs to. Single-
    /// writer (only this thread mutates) — server-fanout binds
    /// run before workers start, ephemeral binds run on the
    /// owning worker.
    udp_dispatch: UnsafeCell<Option<HashMap<i32, u16>>>,
}

impl ThreadState {
    const fn new(id: u32) -> Self {
        ThreadState {
            conns: [const { NativeConn::empty() }; CONNS_PER_THREAD],
            eq_fd: -1,
            thread_id: id,
            udp_send_fd: AtomicPtr::new(ptr::null_mut()),
            udp_dispatch: UnsafeCell::new(None),
        }
    }

    /// Heap-allocate the per-thread UDP fast-path tables. Called
    /// from thread setup before workers start. Idempotent.
    fn init_udp_tables(&self) {
        if !self.udp_send_fd.load(Ordering::Relaxed).is_null() {
            return;
        }
        let mut v: Vec<AtomicI32> = Vec::with_capacity(65536);
        for _ in 0..65536 {
            v.push(AtomicI32::new(-1));
        }
        let boxed: Box<[AtomicI32]> = v.into_boxed_slice();
        let raw = Box::leak(boxed).as_mut_ptr();
        self.udp_send_fd.store(raw, Ordering::Release);
        // SAFETY: single-writer at boot before workers spawn, then
        // single-writer on this thread for runtime updates.
        unsafe { *self.udp_dispatch.get() = Some(HashMap::new()); }
    }

    /// Register `(fd, app_port)` on this thread's UDP fast-path
    /// tables and arm the event queue for read-readiness. Used by
    /// both the server-fanout bind path (cross-thread, boot-only)
    /// and the ephemeral bind path (same-thread, runtime).
    fn add_udp_binding(&self, fd: i32, app_port: u16) {
        // Send-side: O(1) port → fd lookup.
        let table = self.udp_send_fd.load(Ordering::Acquire);
        if !table.is_null() {
            // SAFETY: table points to a leaked 65536-entry slice;
            // app_port is a u16, so the index is in bounds.
            unsafe {
                (*table.add(app_port as usize)).store(fd, Ordering::Release);
            }
        }
        // Drain-side: O(1) fd → port lookup.
        // SAFETY: server-fanout binds run on the main thread before
        // workers start; ephemeral binds run on the owning worker.
        // Either way, no concurrent access.
        unsafe {
            if let Some(map) = &mut *self.udp_dispatch.get() {
                map.insert(fd, app_port);
            }
        }
        self.register_fd(fd);
    }

    /// Tear down the entries `add_udp_binding` published. Called
    /// from `udp_backend_unbind` for every thread that owned a
    /// sibling fd for this port.
    fn remove_udp_binding(&self, fd: i32, app_port: u16) {
        let table = self.udp_send_fd.load(Ordering::Acquire);
        if !table.is_null() {
            unsafe {
                // Compare-exchange so we only clear if this thread's
                // entry is still our fd (a concurrent rebind may
                // have replaced it).
                let entry = &*table.add(app_port as usize);
                let _ = entry.compare_exchange(
                    fd, -1, Ordering::AcqRel, Ordering::Acquire,
                );
            }
        }
        // SAFETY: same single-writer invariant as `add_udp_binding`.
        unsafe {
            if let Some(map) = &mut *self.udp_dispatch.get() {
                map.remove(&fd);
            }
        }
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
                shutdown((*c).fd, SHUT_RDWR);
                close((*c).fd);
                (*c).fd = -1;
            }
            (*c).closed = true;
            (*c).has_pending_data = false;
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
        // O(1) UDP fd → app_port lookup (was a linear scan over a
        // 256-entry sibling array). Only this thread mutates the
        // dispatch map, so the UnsafeCell read is safe.
        let app_port = unsafe {
            (*self.udp_dispatch.get())
                .as_ref()
                .and_then(|m| m.get(&fd).copied())
        };
        if let Some(port) = app_port {
            drain_udp_sibling(fd, port);
            return true;
        }
        // Async TCP listener fd fired → wake the reactor's accept
        // future on this worker; the task's next poll drains accept.
        if tcp::async_tcp_dispatch(fd) {
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
///
/// Allocates a Heap `IOBuf` per datagram, recvs into it directly, and
/// hands ownership to `deliver_udp`. This is the same one-copy
/// shape the legacy `recvfrom` + memcpy path had — but it routes
/// through the unified IOBuf delivery surface, so the runtime's UDP
/// inbox doesn't need a parallel `&[u8]` push path. Native is dev-
/// only, so the per-packet alloc is acceptable; production goes
/// through the bare-metal NIC drivers' `iobuf_rx` instead.
fn drain_udp_sibling(fd: i32, app_port: u16) {
    // 64 KiB matches the maximum UDP datagram size; the previous
    // stack buffer was the same size, just dropped on EAGAIN.
    const RECV_CAP: usize = 65536;
    loop {
        // `new_with_reserved(0, RECV_CAP, 0)` allocates RECV_CAP
        // bytes of storage but leaves the visible payload empty —
        // the `payload_capacity` arg is reserve, not initial len.
        // `extend_uninit(RECV_CAP)` claims the whole region as
        // visible payload so `recvfrom` can write into it; we trim
        // back to the actual recv size below.
        let mut iobuf = uni_iobuf::IOBuf::new_with_reserved(0, RECV_CAP, 0);
        let buf_ptr = match iobuf.extend_uninit(RECV_CAP) {
            Ok(s) => s.as_mut_ptr(),
            Err(_) => break, // alloc failed / shape mismatch; bail
        };
        let mut src_addr: SockAddrIn = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of::<SockAddrIn>() as u32;
        let n = unsafe {
            recvfrom(fd, buf_ptr, RECV_CAP, 0,
                     &mut src_addr, &mut addr_len)
        };
        if n <= 0 {
            // No more datagrams — `iobuf` drops here, freeing its
            // backing buffer. One wasted alloc per drain pass on
            // EAGAIN. Acceptable for the native-dev path.
            break;
        }
        let n = n as usize;
        // Trim the IOBuf's visible payload to the actual recv'd
        // size. The remaining `RECV_CAP - n` bytes hang as
        // tailroom, freed when the IOBuf drops.
        if n < RECV_CAP {
            let _ = iobuf.trim_end(RECV_CAP - n);
        }
        // Mirror of `from_ne_bytes` in udp_send. sin_addr is stored
        // in memory in network byte order; `to_ne_bytes` extracts
        // those four bytes intact regardless of host endianness.
        let src_octets = src_addr.sin_addr.to_ne_bytes();
        let src_ip = uni_runtime::ip::IpAddr::V4(uni_runtime::ip::Ipv4Addr {
            addr: u32::from_ne_bytes(src_octets),
        });
        let src_port = u16::from_be(src_addr.sin_port);
        let _ = uni_runtime::net::deliver_udp(app_port, src_ip, src_port, iobuf);
    }
}

// ============================================================================
// Global state
// ============================================================================

// Per-thread state. Written exclusively during init_native (BSP) and
// then by each worker's own slot afterwards — no cross-thread
// mutation. UnsafeCell + unsafe impl Sync encodes the contract.
struct ThreadsCell(UnsafeCell<[ThreadState; MAX_THREADS]>);
// SAFETY: each worker mutates only its own slot; BSP-only init
// populates all slots before workers start.
unsafe impl Sync for ThreadsCell {}
static THREADS: ThreadsCell = ThreadsCell(
    UnsafeCell::new([const { ThreadState::new(0) }; MAX_THREADS])
);

/// Populated once by `init_native` from UNIKERNEL_CPUS / num_cpus;
/// then read by all worker paths. Atomic so cross-thread reads are
/// race-free without the `&static mut` dance.
static NUM_THREADS: AtomicUsize = AtomicUsize::new(1);

/// Set by the SIGINT/SIGTERM handler on any thread; polled by every
/// worker. AtomicBool is the natural fit.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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

/// Native UDP backend vtable. `bind`/`unbind` open and close the
/// per-port SO_REUSEPORT sibling fds; `send` is the `sendto` path.
static NATIVE_UDP_BACKEND: uni_runtime::net::UdpBackend =
    uni_runtime::net::UdpBackend {
        bind: Some(udp::udp_backend_bind),
        unbind: Some(udp::udp_backend_unbind),
        send: udp::udp_send,
        // Native uses the OS sendto(); no L2/L3/L4 headers to fill.
        // Caller's `send_to_with_l2_headroom` falls back to send()
        // over `frame[headroom..]` automatically.
        send_with_l2_headroom: None,
    };

fn init_native() {
    unsafe {
        // Per-port overrides (`UNIKERNEL_<PROTO>_<GUEST>`) are read
        // lazily inside `tcp::async_tcp_listen_hook` / `udp::udp_backend_bind`,
        // keyed by the caller-supplied app port — same derivation
        // as `variants.bzl` bakes into the VM launcher templates.
        // Callers use the same spelling regardless of which runner
        // LAUNCHER points at.

        // Determine thread count from environment or CPU count.
        let num_threads = std::env::var("UNIKERNEL_CPUS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| num_cpus().min(MAX_THREADS));
        NUM_THREADS.store(num_threads, Ordering::Release);

        // Publish to `uni-worker` so all `PerWorker<T>` users size
        // themselves correctly, then init the shared runtime's
        // per-worker tables (timer wheels + task arenas).
        uni_worker::set_num_workers(num_threads as u32);
        uni_runtime::init(num_threads as u32);

        let threads = &mut *THREADS.0.get();
        for i in 0..num_threads {
            threads[i].thread_id = i as u32;
            threads[i].init_event_queue();
            threads[i].init_udp_tables();
        }

        // Cast through a function pointer first; rust 1.93+ rejects
        // casting a function item directly to an integer.
        let h = sigint_handler as unsafe extern "C" fn(i32) as usize;
        signal(SIGINT, h);
        signal(SIGTERM, h);
        signal(SIGPIPE, SIG_IGN);
    }

    // Wire the UDP + TCP reactors. Each module owns its vtable.
    uni_runtime::net::register_udp_backend(&NATIVE_UDP_BACKEND);
    uni_runtime::net::register_tcp_backend(&tcp::NATIVE_TCP_BACKEND);

    // Register TCP/UDP polling as the first IO poll callback.
    // Runs on every worker's event-loop tick and drains the worker's
    // kqueue/epoll: TCP fd readiness flips `has_pending_data` on
    // matching conns, and UDP sibling readiness triggers inline
    // `recvfrom` + handler dispatch. No dedicated RX threads — same
    // inline-poll pattern as the HVF runner's vCPU loop.
    register_io_poll(|_worker_id| tcp::tcp_poll());
}

// ============================================================================
// Platform API — called from uni/lib.rs backend dispatch
// ============================================================================

pub fn log(msg: &[u8]) {
    use std::sync::Mutex;
    use std::time::Instant;
    // Boot-start timestamp + line-start tracker — same shape as the
    // kernel-side `[N.NNN]` prefix in `kernel/serial.rs`. Captured
    // lazily on first call (before any code in this binary's boot
    // path emits stderr). Mutex coordinates multi-threaded native
    // workers writing concurrently; per-line atomic for AT_LINE_START
    // so we only emit a timestamp once at the start of each line.
    static BOOT_START: Mutex<Option<Instant>> = Mutex::new(None);
    static AT_LINE_START: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(true);
    static LOCK: Mutex<()> = Mutex::new(());

    let _g = LOCK.lock().unwrap();
    let start = {
        let mut s = BOOT_START.lock().unwrap();
        *s.get_or_insert_with(Instant::now)
    };
    let mut out: Vec<u8> = Vec::with_capacity(msg.len() + 16);
    use std::sync::atomic::Ordering;
    for &b in msg {
        if AT_LINE_START.load(Ordering::Relaxed) {
            // Microsecond resolution to match the kernel-side
            // `[S.uuuuuu]` format. With HVF boot down to ~1 ms,
            // ms-only timestamps lump every line into a single tick.
            let elapsed = start.elapsed();
            let us = elapsed.as_micros() as u64;
            let secs = us / 1_000_000;
            let us_part = (us % 1_000_000) as u32;
            out.push(b'[');
            if secs == 0 {
                out.push(b'0');
            } else {
                let mut tmp = [0u8; 10];
                let mut len = 0;
                let mut s = secs;
                while s > 0 { tmp[len] = b'0' + (s % 10) as u8; s /= 10; len += 1; }
                for i in 0..len { out.push(tmp[len - 1 - i]); }
            }
            out.push(b'.');
            out.push(b'0' + (us_part / 100_000) as u8);
            out.push(b'0' + ((us_part / 10_000) % 10) as u8);
            out.push(b'0' + ((us_part / 1_000) % 10) as u8);
            out.push(b'0' + ((us_part / 100) % 10) as u8);
            out.push(b'0' + ((us_part / 10) % 10) as u8);
            out.push(b'0' + (us_part % 10) as u8);
            out.push(b']');
            out.push(b' ');
            AT_LINE_START.store(false, Ordering::Relaxed);
        }
        out.push(b);
        if b == b'\n' {
            AT_LINE_START.store(true, Ordering::Relaxed);
        }
    }
    unsafe { write(2, out.as_ptr(), out.len()); }
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

/// Register an IO poll callback (network, storage, etc). Multiple
/// sources can be registered; all are called each iteration. Designed
/// to be called from a single init thread; the atomic fetch_add
/// reserves the slot index race-free even if that contract is ever
/// violated.
fn register_io_poll(f: PollFn) {
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
    // Worker 0 skips the READY wait: `uni_init` now only spawns the
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

// Rust ABI — both sides are Rust and the function takes no args /
// returns nothing. `#[no_mangle]` on the emitting `#[uni::init]`
// macro gives the symbol a stable link-time name.
unsafe extern "Rust" {
    fn uni_init();
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
pub struct RunConfig {
    pub boot_info_fn: fn(num_cpus: u32, ram_bytes: usize),
    pub shutdown_fn: fn(),
}

/// Native-binary entry point — called from `uni::native::run` (which
/// in turn is called from `bazel/rules/native_main.rs`'s `fn main()`).
/// Returns the process exit code.
pub fn run(config: RunConfig) -> i32 {
    init_native();

    // Boot banner — same shape as the bare-metal kernel's so users
    // can `grep '^cpu:'` etc. across runners. POSIX has no equivalent
    // of `[N.NNN]` timestamps because there's no kernel-controlled
    // serial line we route everything through; standard write(2) to
    // stderr is fine, untagged.
    let host_cpus = num_cpus();
    let ram_mb = host_ram_bytes() / (1024 * 1024);
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" }
               else if cfg!(target_arch = "x86_64") { "x86_64" }
               else { "unknown" };
    let os = if cfg!(target_os = "macos") { "darwin" }
             else if cfg!(target_os = "linux") { "linux" }
             else { "posix" };
    log(b"UniKernel v0.1.0 (native)\n");
    log(format!("platform: {} ({})\n", os, arch).as_bytes());
    log(format!("cpu: {} \u{00d7} host\n", host_cpus).as_bytes());
    log(format!("mem: {} MB (host)\n", ram_mb).as_bytes());

    // Publish the boot-time snapshot via the uni-side callback. The
    // native backend has no NIC driver (POSIX sockets go through the
    // host stack), so nic info is filled in by the callback as empty.
    (config.boot_info_fn)(host_cpus as u32, host_ram_bytes());

    unsafe {
        uni_init();
        let num_threads = NUM_THREADS.load(Ordering::Acquire);

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
