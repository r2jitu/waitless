// uni/native.rs — Native (POSIX) backend: sockets + stdio.
// Also provides main() for the native entry point.

use core::ptr;

// ============================================================================
// libc FFI declarations
// ============================================================================

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
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

#[cfg(target_os = "linux")]
const MSG_NOSIGNAL: i32 = 0x4000;
#[cfg(target_os = "macos")]
const MSG_NOSIGNAL: i32 = 0; // SIGPIPE is ignored globally via signal()

const POLLIN: i16 = 0x0001;
const POLLHUP: i16 = 0x0010;
const POLLERR: i16 = 0x0008;

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

#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(target_os = "macos")]
type NfdsT = u32;
#[cfg(target_os = "linux")]
type NfdsT = u64;

unsafe extern "C" {
    fn socket(domain: i32, sock_type: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, addr: *mut u8, len: *mut u32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn send(fd: i32, buf: *const u8, len: usize, flags: i32) -> isize;
    fn close(fd: i32) -> i32;
    fn shutdown(fd: i32, how: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const i32, len: u32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: i32) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
    fn getenv(name: *const u8) -> *const u8;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn nanosleep(req: *const Timespec, rem: *mut Timespec) -> i32;

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

// ============================================================================
// Connection pool
// ============================================================================

#[derive(Clone, Copy)]
struct NativeConn {
    fd: i32,
    is_listener: bool,
    closed: bool,
    has_pending_data: bool,
}

impl NativeConn {
    const fn empty() -> Self {
        NativeConn { fd: -1, is_listener: false, closed: true, has_pending_data: false }
    }
}

const CONN_POOL_SIZE: usize = 256;
static mut POOL: [NativeConn; CONN_POOL_SIZE] = [NativeConn::empty(); CONN_POOL_SIZE];

unsafe fn alloc_conn() -> *mut NativeConn {
    for c in POOL.iter_mut() {
        if c.closed && c.fd < 0 {
            *c = NativeConn { fd: -1, is_listener: false, closed: false, has_pending_data: false };
            return c as *mut NativeConn;
        }
    }
    ptr::null_mut()
}

unsafe fn release_conn(c: *mut NativeConn) {
    if (*c).fd >= 0 {
        shutdown((*c).fd, SHUT_RDWR);
        close((*c).fd);
        (*c).fd = -1;
    }
    (*c).closed = true;
    (*c).has_pending_data = false;
    (*c).is_listener = false;
}

// ============================================================================
// State
// ============================================================================

static mut CONFIG_PORT: u16 = 0;
static mut SHUTDOWN: bool = false;

unsafe extern "C" fn sigint_handler(_sig: i32) {
    SHUTDOWN = true;
}

fn init_native() {
    unsafe {
        // Parse $PORT
        let p = getenv(b"PORT\0".as_ptr());
        if !p.is_null() && *p != 0 {
            CONFIG_PORT = parse_u16(p);
        }

        // Signal handlers
        signal(SIGINT, sigint_handler as usize);
        signal(SIGTERM, sigint_handler as usize);
        signal(SIGPIPE, SIG_IGN);
    }
}

// ============================================================================
// Platform API — same interface as ffi.rs + stack.rs (called from api.rs)
// ============================================================================

pub fn log(msg: &[u8]) {
    unsafe { write(2, msg.as_ptr(), msg.len()); }
}

pub fn config_port(default_port: u16) -> u16 {
    let port = unsafe { CONFIG_PORT };
    if port != 0 { port } else { default_port }
}

pub fn check_shutdown() -> bool {
    unsafe { SHUTDOWN }
}

pub fn wait_for_events() {
    unsafe {
        let mut fds = [PollFd { fd: 0, events: 0, revents: 0 }; CONN_POOL_SIZE];
        let mut n: usize = 0;
        for c in POOL.iter() {
            if !c.closed && c.fd >= 0 {
                fds[n] = PollFd { fd: c.fd, events: POLLIN, revents: 0 };
                n += 1;
            }
        }
        if n == 0 {
            let ts = Timespec { tv_sec: 0, tv_nsec: 1_000_000 }; // 1 ms
            nanosleep(&ts, ptr::null_mut());
            return;
        }
        poll(fds.as_mut_ptr(), n as NfdsT, 10);
        for i in 0..n {
            if fds[i].revents & (POLLIN | POLLHUP | POLLERR) != 0 {
                for c in POOL.iter_mut() {
                    if c.fd == fds[i].fd {
                        c.has_pending_data = true;
                        break;
                    }
                }
            }
        }
    }
}

// ---- TCP --------------------------------------------------------------------

pub fn tcp_listen(port: u16) -> *mut () {
    unsafe {
        let fd = socket(AF_INET, SOCK_STREAM, 0);
        if fd < 0 { return ptr::null_mut(); }

        let opt: i32 = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
        set_nonblocking(fd);

        let addr = SockAddrIn {
            #[cfg(target_os = "macos")]
            sin_len: core::mem::size_of::<SockAddrIn>() as u8,
            #[cfg(target_os = "macos")]
            sin_family: AF_INET as u8,
            #[cfg(target_os = "linux")]
            sin_family: AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: 0, // INADDR_ANY
            sin_zero: [0; 8],
        };

        if bind(fd, &addr, core::mem::size_of::<SockAddrIn>() as u32) < 0 {
            close(fd);
            return ptr::null_mut();
        }
        if listen(fd, 128) < 0 {
            close(fd);
            return ptr::null_mut();
        }

        let c = alloc_conn();
        if c.is_null() {
            close(fd);
            return ptr::null_mut();
        }
        (*c).fd = fd;
        (*c).is_listener = true;
        c as *mut ()
    }
}

pub fn tcp_accept(handle: *mut ()) -> *mut () {
    let listener = handle as *mut NativeConn;
    unsafe {
        if listener.is_null() || (*listener).fd < 0 || (*listener).closed {
            return ptr::null_mut();
        }

        let fd = accept((*listener).fd, ptr::null_mut(), ptr::null_mut());
        if fd < 0 {
            if get_errno() == EAGAIN {
                (*listener).has_pending_data = false;
            }
            return ptr::null_mut();
        }

        set_nonblocking(fd);

        let c = alloc_conn();
        if c.is_null() {
            close(fd);
            return ptr::null_mut();
        }
        (*c).fd = fd;
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
        if n < 0 {
            (*c).has_pending_data = false;
            return 0;
        }
        if n == 0 {
            (*c).closed = true;
            (*c).has_pending_data = false;
            return 0;
        }
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
    unsafe {
        if c.is_null() { return; }
        release_conn(c);
    }
}

pub fn tcp_is_closed(handle: *mut ()) -> bool {
    let c = handle as *mut NativeConn;
    unsafe { c.is_null() || (*c).closed }
}

pub fn tcp_poll() {
    unsafe {
        let mut fds = [PollFd { fd: 0, events: 0, revents: 0 }; CONN_POOL_SIZE];
        let mut map = [ptr::null_mut::<NativeConn>(); CONN_POOL_SIZE];
        let mut n: usize = 0;
        for c in POOL.iter_mut() {
            if !c.closed && c.fd >= 0 {
                fds[n] = PollFd { fd: c.fd, events: POLLIN, revents: 0 };
                map[n] = c as *mut NativeConn;
                n += 1;
            }
        }
        if n == 0 { return; }
        poll(fds.as_mut_ptr(), n as NfdsT, 0);
        for i in 0..n {
            if fds[i].revents & (POLLIN | POLLHUP | POLLERR) != 0 {
                (*map[i]).has_pending_data = true;
            }
        }
    }
}

// ============================================================================
// Native entry point — replaces native_main.cc
// ============================================================================

unsafe extern "C" {
    fn uni_main();
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    init_native();
    unsafe { uni_main() };
    0
}
