// uni/api.rs — Rust-friendly platform abstraction API
//
// Provides safe Rust types for the uni:: platform interface:
//   - TcpListener / TcpStream (instead of *mut () opaque pointers)
//   - log(), config_port(), check_shutdown(), wait_for_events()
//
// Symbols are resolved at link time from one of two backends:
//   - Unikernel: net/stack.rs (TCP) + uni/ffi.rs (lifecycle)
//   - Native:    uni/native.rs (POSIX sockets + stdio)

#![no_std]

// ---- FFI declarations (resolved at link time) --------------------------------

unsafe extern "C" {
    fn uni_log(msg: *const u8);
    fn uni_check_shutdown() -> bool;
    fn uni_wait_for_events();
    fn uni_config_port(default_port: u16) -> u16;
    fn uni_tcp_listen(port: u16) -> *mut ();
    fn uni_tcp_accept(conn: *mut ()) -> *mut ();
    fn uni_tcp_has_data(conn: *mut ()) -> bool;
    fn uni_tcp_recv(conn: *mut (), buf: *mut u8, max_len: usize) -> usize;
    fn uni_tcp_send(conn: *mut (), data: *const u8, len: usize) -> i32;
    fn uni_tcp_close(conn: *mut ());
    fn uni_tcp_is_closed(conn: *mut ()) -> bool;
    fn uni_tcp_poll();
}

// ---- Platform functions (safe wrappers) --------------------------------------

/// Write a null-terminated message to the platform log (serial or stderr).
pub fn log(msg: &[u8]) {
    unsafe { uni_log(msg.as_ptr()) }
}

/// Check whether a shutdown has been requested (Ctrl-C / SIGINT).
pub fn check_shutdown() -> bool {
    unsafe { uni_check_shutdown() }
}

/// Block until network events are available (WFI/poll).
pub fn wait_for_events() {
    unsafe { uni_wait_for_events() }
}

/// Read the configured port (from $PORT env var or kernel config),
/// falling back to `default` if unset.
pub fn config_port(default: u16) -> u16 {
    unsafe { uni_config_port(default) }
}

/// Poll the network stack for pending events.
pub fn tcp_poll() {
    unsafe { uni_tcp_poll() }
}

// ---- TcpListener ------------------------------------------------------------

/// A TCP listener socket, bound to a port and accepting connections.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpListener(*mut ());

impl TcpListener {
    /// Bind and listen on the given port. Returns `None` on failure.
    pub fn bind(port: u16) -> Option<Self> {
        let p = unsafe { uni_tcp_listen(port) };
        if p.is_null() { None } else { Some(TcpListener(p)) }
    }

    /// Accept a pending connection. Returns `None` if no connection is waiting.
    pub fn accept(&self) -> Option<TcpStream> {
        let p = unsafe { uni_tcp_accept(self.0) };
        if p.is_null() { None } else { Some(TcpStream(p)) }
    }

    /// Close the listener socket.
    pub fn close(&self) {
        unsafe { uni_tcp_close(self.0) }
    }
}

// ---- TcpStream --------------------------------------------------------------

/// An accepted TCP connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpStream(*mut ());

impl TcpStream {
    /// Check whether data is available to read without blocking.
    pub fn has_data(&self) -> bool {
        unsafe { uni_tcp_has_data(self.0) }
    }

    /// Read available data into `buf`. Returns the number of bytes read (0 if none).
    pub fn recv(&self, buf: &mut [u8]) -> usize {
        unsafe { uni_tcp_recv(self.0, buf.as_mut_ptr(), buf.len()) }
    }

    /// Send data. Returns bytes sent, or -1 on error.
    pub fn send(&self, data: &[u8]) -> i32 {
        unsafe { uni_tcp_send(self.0, data.as_ptr(), data.len()) }
    }

    /// Close the connection.
    pub fn close(&self) {
        unsafe { uni_tcp_close(self.0) }
    }

    /// Check whether the remote end has closed the connection.
    pub fn is_closed(&self) -> bool {
        unsafe { uni_tcp_is_closed(self.0) }
    }
}
