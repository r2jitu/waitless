// uni/api.rs — Platform abstraction API
//
// Provides safe Rust types for the uni:: platform interface:
//   - TcpListener / TcpStream
//   - log(), config_port(), check_shutdown(), wait_for_events(), tcp_poll()
//
// Backend selected at compile time via #[cfg]:
//   - platform_unikernel: net_stack (TCP) + uni_unikernel (lifecycle)
//   - platform_native:    uni_native (POSIX sockets + stdio)

#![no_std]

#[cfg(platform_unikernel)]
extern crate uni_unikernel;
#[cfg(platform_unikernel)]
extern crate net_stack;

#[cfg(platform_native)]
extern crate uni_native;

// ---- Backend dispatch --------------------------------------------------------

#[cfg(platform_unikernel)]
mod backend {
    pub use uni_unikernel::{log, config_port, check_shutdown, wait_for_events};
    pub use net_stack::{tcp_listen, tcp_accept, tcp_has_data,
                        tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};
}

#[cfg(platform_native)]
mod backend {
    pub use uni_native::{log, config_port, check_shutdown, wait_for_events,
                         tcp_listen, tcp_accept, tcp_has_data,
                         tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};
}

// ---- Re-exported platform functions (no wrapper needed) ----------------------

pub use backend::{log, config_port, check_shutdown, wait_for_events, tcp_poll};

// ---- TcpListener ------------------------------------------------------------

/// A TCP listener socket, bound to a port and accepting connections.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpListener(*mut ());

impl TcpListener {
    /// Bind and listen on the given port. Returns `None` on failure.
    pub fn bind(port: u16) -> Option<Self> {
        let p = backend::tcp_listen(port);
        if p.is_null() { None } else { Some(TcpListener(p)) }
    }

    /// Accept a pending connection. Returns `None` if no connection is waiting.
    pub fn accept(&self) -> Option<TcpStream> {
        let p = backend::tcp_accept(self.0);
        if p.is_null() { None } else { Some(TcpStream(p)) }
    }

    /// Close the listener socket.
    pub fn close(&self) {
        backend::tcp_close(self.0);
    }
}

// ---- TcpStream --------------------------------------------------------------

/// An accepted TCP connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpStream(*mut ());

impl TcpStream {
    pub fn has_data(&self) -> bool {
        backend::tcp_has_data(self.0)
    }

    pub fn recv(&self, buf: &mut [u8]) -> usize {
        backend::tcp_recv(self.0, buf)
    }

    pub fn send(&self, data: &[u8]) -> i32 {
        backend::tcp_send(self.0, data)
    }

    pub fn close(&self) {
        backend::tcp_close(self.0);
    }

    pub fn is_closed(&self) -> bool {
        backend::tcp_is_closed(self.0)
    }
}
