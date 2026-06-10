// libc FFI surface for the native (POSIX) backend.
//
// Consts, repr(C) structs, the `unsafe extern "C"` block and the
// per-OS cfg branches that paper over macOS vs Linux differences in
// socket / signal / fcntl flag values and in the readiness-API
// (kqueue vs epoll). Everything is `pub(super)`: the parent
// `native::mod` re-exports them via `use ffi::*;` and the
// `native::tcp` / `native::udp` submodules pick them up through
// `use super::*`.

pub(super) const AF_INET: i32 = 2;
pub(super) const SOCK_STREAM: i32 = 1;
pub(super) const SOCK_DGRAM: i32 = 2;
pub(super) const SHUT_RDWR: i32 = 2;
pub(super) const F_GETFL: i32 = 3;
pub(super) const F_SETFL: i32 = 4;
pub(super) const SIGINT: i32 = 2;
pub(super) const SIGTERM: i32 = 15;
pub(super) const SIGPIPE: i32 = 13;
pub(super) const SIG_IGN: usize = 1;

#[cfg(target_os = "macos")]
pub(super) const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
pub(super) const O_NONBLOCK: i32 = 0x800;

#[cfg(target_os = "macos")]
pub(super) const SOL_SOCKET: i32 = 0xFFFF;
#[cfg(target_os = "linux")]
pub(super) const SOL_SOCKET: i32 = 1;

#[cfg(target_os = "macos")]
pub(super) const SO_REUSEADDR: i32 = 0x0004;
#[cfg(target_os = "linux")]
pub(super) const SO_REUSEADDR: i32 = 2;

#[cfg(target_os = "macos")]
pub(super) const SO_REUSEPORT: i32 = 0x0200;
#[cfg(target_os = "linux")]
pub(super) const SO_REUSEPORT: i32 = 15;

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
pub(super) const IPPROTO_TCP: i32 = 6;
#[cfg(target_os = "macos")]
pub(super) const TCP_NODELAY: i32 = 0x01;
#[cfg(target_os = "linux")]
pub(super) const TCP_NODELAY: i32 = 1;

#[cfg(target_os = "linux")]
pub(super) const MSG_NOSIGNAL: i32 = 0x4000;
#[cfg(target_os = "macos")]
pub(super) const MSG_NOSIGNAL: i32 = 0;

#[cfg(target_os = "macos")]
pub(super) const EAGAIN: i32 = 35;
#[cfg(target_os = "linux")]
pub(super) const EAGAIN: i32 = 11;

// Nonblocking `connect(2)` progress / verdict codes. The async
// connect path issues the connect once (expecting EINPROGRESS),
// then re-issues it from `connect_status` to read the verdict:
// EALREADY/EINPROGRESS = still going, EISCONN = established,
// ECONNREFUSED/ECONNRESET = refused, ETIMEDOUT = timed out.
#[cfg(target_os = "macos")]
pub(super) const EINPROGRESS: i32 = 36;
#[cfg(target_os = "linux")]
pub(super) const EINPROGRESS: i32 = 115;
#[cfg(target_os = "macos")]
pub(super) const EALREADY: i32 = 37;
#[cfg(target_os = "linux")]
pub(super) const EALREADY: i32 = 114;
#[cfg(target_os = "macos")]
pub(super) const EISCONN: i32 = 56;
#[cfg(target_os = "linux")]
pub(super) const EISCONN: i32 = 106;
#[cfg(target_os = "macos")]
pub(super) const ECONNREFUSED: i32 = 61;
#[cfg(target_os = "linux")]
pub(super) const ECONNREFUSED: i32 = 111;
#[cfg(target_os = "macos")]
pub(super) const ECONNRESET: i32 = 54;
#[cfg(target_os = "linux")]
pub(super) const ECONNRESET: i32 = 104;
#[cfg(target_os = "macos")]
pub(super) const ETIMEDOUT: i32 = 60;
#[cfg(target_os = "linux")]
pub(super) const ETIMEDOUT: i32 = 110;

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
#[derive(Clone, Copy)]
pub(super) struct SockAddrIn {
    #[cfg(target_os = "macos")]
    pub sin_len: u8,
    #[cfg(target_os = "macos")]
    pub sin_family: u8,
    #[cfg(target_os = "linux")]
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

#[cfg(target_os = "macos")]
#[repr(C)]
pub(super) struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// kqueue (macOS)
#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Kevent {
    pub ident: usize,
    pub filter: i16,
    pub flags: u16,
    pub fflags: u32,
    pub data: isize,
    pub udata: *mut u8,
}

#[cfg(target_os = "macos")]
pub(super) const EVFILT_READ: i16 = -1;
#[cfg(target_os = "macos")]
pub(super) const EVFILT_WRITE: i16 = -2;
#[cfg(target_os = "macos")]
pub(super) const EV_ADD: u16 = 0x0001;
#[cfg(target_os = "macos")]
pub(super) const EV_DELETE: u16 = 0x0002;
#[cfg(target_os = "macos")]
pub(super) const EV_CLEAR: u16 = 0x0020;

// epoll (Linux)
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

#[cfg(target_os = "linux")]
pub(super) const EPOLLIN: u32 = 0x001;
#[cfg(target_os = "linux")]
pub(super) const EPOLLOUT: u32 = 0x004;
#[cfg(target_os = "linux")]
pub(super) const EPOLL_CTL_ADD: i32 = 1;
#[cfg(target_os = "linux")]
pub(super) const EPOLL_CTL_MOD: i32 = 3;
#[cfg(target_os = "linux")]
pub(super) const EPOLL_CTL_DEL: i32 = 2;

pub(super) type PthreadT = usize;

unsafe extern "C" {
    pub(super) fn socket(domain: i32, sock_type: i32, protocol: i32) -> i32;
    pub(super) fn bind(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    pub(super) fn listen(fd: i32, backlog: i32) -> i32;
    pub(super) fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    pub(super) fn connect(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    pub(super) fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    pub(super) fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    pub(super) fn writev(fd: i32, iov: *const IoVec, iovcnt: i32) -> isize;
    pub(super) fn recvfrom(
        fd: i32,
        buf: *mut u8,
        len: usize,
        flags: i32,
        addr: *mut SockAddrIn,
        addrlen: *mut u32,
    ) -> isize;
    pub(super) fn sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const SockAddrIn,
        addrlen: u32,
    ) -> isize;
    pub(super) fn close(fd: i32) -> i32;
    pub(super) fn shutdown(fd: i32, how: i32) -> i32;
    pub(super) fn setsockopt(fd: i32, level: i32, name: i32, val: *const i32, len: u32) -> i32;
    pub(super) fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    pub(super) fn signal(sig: i32, handler: usize) -> usize;
    pub(super) fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    #[cfg(target_os = "macos")]
    pub(super) fn kqueue() -> i32;
    #[cfg(target_os = "macos")]
    pub(super) fn kevent(
        kq: i32,
        changelist: *const Kevent,
        nchanges: i32,
        eventlist: *mut Kevent,
        nevents: i32,
        timeout: *const Timespec,
    ) -> i32;

    #[cfg(target_os = "linux")]
    pub(super) fn epoll_create1(flags: i32) -> i32;
    #[cfg(target_os = "linux")]
    pub(super) fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: *mut EpollEvent) -> i32;
    #[cfg(target_os = "linux")]
    pub(super) fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32)
    -> i32;

    pub(super) fn pthread_create(
        thread: *mut PthreadT,
        attr: *const u8,
        start: extern "C" fn(*mut u8) -> *mut u8,
        arg: *mut u8,
    ) -> i32;
    pub(super) fn pthread_join(thread: PthreadT, retval: *mut *mut u8) -> i32;
    pub(super) fn sysconf(name: i32) -> i64;

    #[cfg(target_os = "macos")]
    pub(super) fn sysctlbyname(
        name: *const u8,
        oldp: *mut u8,
        oldlenp: *mut usize,
        newp: *const u8,
        newlen: usize,
    ) -> i32;

    #[cfg(target_os = "macos")]
    fn __error() -> *mut i32;
    #[cfg(target_os = "linux")]
    fn __errno_location() -> *mut i32;
}

pub(super) fn errno() -> i32 {
    unsafe {
        #[cfg(target_os = "macos")]
        {
            *__error()
        }
        #[cfg(target_os = "linux")]
        {
            *__errno_location()
        }
    }
}
