// uni/lib.rs — Platform abstraction API
//
// Provides safe Rust types: TcpListener, TcpStream, log(), config_port(), etc.
//
// Backend selected at compile time via #[cfg]:
//   - platform_unikernel: unikernel module (lifecycle) + net_stack (TCP)
//   - platform_native:    native module (POSIX sockets + stdio)

#![no_std]
#![allow(static_mut_refs)]

// Re-export the #[uni::main] proc macro.
pub use uni_macros::main;

#[cfg(platform_unikernel)]
extern crate kernel;
#[cfg(platform_unikernel)]
extern crate drivers;
#[cfg(platform_unikernel)]
extern crate net;

#[cfg(platform_unikernel)]
mod unikernel;

#[cfg(platform_native)]
pub mod native;

pub mod http;

// ---- Backend dispatch --------------------------------------------------------

#[cfg(platform_unikernel)]
mod backend {
    pub use crate::unikernel::{log, config_port, check_shutdown, wait_for_events};
    pub use net::{tcp_listen, tcp_accept, tcp_has_data,
                        tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};
}

#[cfg(platform_native)]
mod backend {
    pub use crate::native::{log, config_port, check_shutdown, wait_for_events,
                            tcp_listen, tcp_accept, tcp_has_data,
                            tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};
}

// ---- Re-exported platform functions ------------------------------------------

pub use backend::{log, config_port, check_shutdown, wait_for_events, tcp_poll};

// ---- TcpListener ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpListener(*mut ());

impl TcpListener {
    pub fn bind(port: u16) -> Option<Self> {
        let p = backend::tcp_listen(port);
        if p.is_null() { None } else { Some(TcpListener(p)) }
    }

    pub fn accept(&self) -> Option<TcpStream> {
        let p = backend::tcp_accept(self.0);
        if p.is_null() { None } else { Some(TcpStream(p)) }
    }

    pub fn close(&self) {
        backend::tcp_close(self.0);
    }
}

// ---- TcpStream --------------------------------------------------------------

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
