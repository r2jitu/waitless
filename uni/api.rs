// uni/api.rs — Rust-friendly platform abstraction API
//
// Provides safe Rust types for the uni:: platform interface:
//   - TcpListener / TcpStream (instead of *mut () opaque pointers)
//   - log(), config_port(), check_shutdown(), wait_for_events()
//
// The backend is selected at compile time via #[cfg]:
//   - platform_unikernel: calls net_stack (TCP) + uni_ffi (lifecycle) directly
//   - platform_native:    calls uni_native (POSIX sockets + stdio) directly
//
// No C FFI boundary — all calls are direct Rust crate function calls.

#![no_std]

#[cfg(platform_unikernel)]
extern crate uni_ffi;
#[cfg(platform_unikernel)]
extern crate net_stack;

#[cfg(platform_native)]
extern crate uni_native;

// ---- Backend dispatch --------------------------------------------------------
// Unify the two backends behind a single module so the public API has no
// #[cfg] duplication. Both backends export the same `pub extern "C" fn`
// symbols — they're safe to call directly from Rust.

#[cfg(platform_unikernel)]
mod backend {
    pub use uni_ffi::{uni_log, uni_config_port, uni_check_shutdown, uni_wait_for_events};
    pub use net_stack::{uni_tcp_listen, uni_tcp_accept, uni_tcp_has_data,
                        uni_tcp_recv, uni_tcp_send, uni_tcp_close, uni_tcp_is_closed, uni_tcp_poll};
}

#[cfg(platform_native)]
mod backend {
    pub use uni_native::{uni_log, uni_config_port, uni_check_shutdown, uni_wait_for_events,
                         uni_tcp_listen, uni_tcp_accept, uni_tcp_has_data,
                         uni_tcp_recv, uni_tcp_send, uni_tcp_close, uni_tcp_is_closed, uni_tcp_poll};
}

// ---- Platform functions (safe wrappers) --------------------------------------

/// Write a null-terminated message to the platform log (serial or stderr).
pub fn log(msg: &[u8]) {
    backend::uni_log(msg.as_ptr());
}

/// Check whether a shutdown has been requested (Ctrl-C / SIGINT).
pub fn check_shutdown() -> bool {
    backend::uni_check_shutdown()
}

/// Block until network events are available (WFI/poll).
pub fn wait_for_events() {
    backend::uni_wait_for_events();
}

/// Read the configured port (from $PORT env var or kernel config),
/// falling back to `default` if unset.
pub fn config_port(default: u16) -> u16 {
    backend::uni_config_port(default)
}

/// Poll the network stack for pending events.
pub fn tcp_poll() {
    backend::uni_tcp_poll();
}

// ---- TcpListener ------------------------------------------------------------

/// A TCP listener socket, bound to a port and accepting connections.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpListener(*mut ());

impl TcpListener {
    /// Bind and listen on the given port. Returns `None` on failure.
    pub fn bind(port: u16) -> Option<Self> {
        let p = backend::uni_tcp_listen(port);
        if p.is_null() { None } else { Some(TcpListener(p)) }
    }

    /// Accept a pending connection. Returns `None` if no connection is waiting.
    pub fn accept(&self) -> Option<TcpStream> {
        let p = backend::uni_tcp_accept(self.0);
        if p.is_null() { None } else { Some(TcpStream(p)) }
    }

    /// Close the listener socket.
    pub fn close(&self) {
        backend::uni_tcp_close(self.0);
    }
}

// ---- TcpStream --------------------------------------------------------------

/// An accepted TCP connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpStream(*mut ());

impl TcpStream {
    /// Check whether data is available to read without blocking.
    pub fn has_data(&self) -> bool {
        backend::uni_tcp_has_data(self.0)
    }

    /// Read available data into `buf`. Returns the number of bytes read (0 if none).
    pub fn recv(&self, buf: &mut [u8]) -> usize {
        backend::uni_tcp_recv(self.0, buf.as_mut_ptr(), buf.len())
    }

    /// Send data. Returns bytes sent, or -1 on error.
    pub fn send(&self, data: &[u8]) -> i32 {
        backend::uni_tcp_send(self.0, data.as_ptr(), data.len())
    }

    /// Close the connection.
    pub fn close(&self) {
        backend::uni_tcp_close(self.0);
    }

    /// Check whether the remote end has closed the connection.
    pub fn is_closed(&self) -> bool {
        backend::uni_tcp_is_closed(self.0)
    }
}
