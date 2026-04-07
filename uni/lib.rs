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
    pub use net::tcp::{listen as tcp_listen, accept as tcp_accept, has_data as tcp_has_data,
                       recv as tcp_recv, send as tcp_send, close as tcp_close,
                       is_closed as tcp_is_closed, listen_on_core as tcp_listen_on};
    pub use net::poll as tcp_poll;

    // Event loop
    pub fn num_workers() -> u32 { kernel::percpu::num_cores() }
    pub fn set_service(f: fn(u32) -> bool) { kernel::eventloop::set_service(f); }
    pub fn set_ready() { kernel::eventloop::set_ready(); }
    #[allow(dead_code)]
    pub fn run(id: u32) -> ! { kernel::eventloop::run(id) }
    pub fn request_shutdown() { kernel::eventloop::request_shutdown(); }
}

#[cfg(platform_native)]
mod backend {
    pub use crate::native::{log, config_port, check_shutdown, wait_for_events,
                            tcp_listen, tcp_accept, tcp_has_data,
                            tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};

    // Event loop — maps to native threading
    static mut NUM_WORKERS: u32 = 1;
    static mut SERVICE_FN: Option<fn(u32) -> bool> = None;
    static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub fn num_workers() -> u32 {
        unsafe {
            if NUM_WORKERS == 1 {
                NUM_WORKERS = crate::native::num_cpus() as u32;
            }
            NUM_WORKERS
        }
    }
    pub fn set_service(f: fn(u32) -> bool) {
        unsafe { core::ptr::write_volatile(&raw mut SERVICE_FN, Some(f)); }
    }
    pub fn get_service() -> Option<fn(u32) -> bool> {
        unsafe { core::ptr::read_volatile(&raw const SERVICE_FN) }
    }
    pub fn set_ready() {
        READY.store(true, core::sync::atomic::Ordering::Release);
    }
    #[allow(dead_code)]
    pub fn is_ready() -> bool {
        READY.load(core::sync::atomic::Ordering::Acquire)
    }
    #[allow(dead_code)]
    pub fn run(_id: u32) -> ! {
        // On native, run() returns — the main() in native.rs manages threads.
        // This is a no-op; the blocking happens in native_worker_loop.
        loop {}
    }
    pub fn request_shutdown() {
        unsafe { crate::native::SHUTDOWN = true; }
    }

    /// TCP listen on a specific worker (SO_REUSEPORT).
    pub fn tcp_listen_on(_worker_id: u32, port: u16) -> *mut () {
        // Native: each thread creates its own listener.
        // For worker 0, tcp_listen is called normally.
        // For workers > 0, this is called from native_worker_loop.
        crate::native::tcp_listen(port)
    }
}

// ---- Re-exported platform functions ------------------------------------------

pub use backend::{log, config_port, check_shutdown, wait_for_events, tcp_poll};
pub use backend::{num_workers, set_service, set_ready, request_shutdown};
pub use backend::tcp_listen_on;

// ---- UDP --------------------------------------------------------------------

/// Bind a UDP port handler. Callback receives (src_ip_octets, src_port, payload).
#[cfg(platform_unikernel)]
pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    net::udp::bind(port, handler);
}

/// Send a UDP datagram.
#[cfg(platform_unikernel)]
pub fn udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    net::udp::send(dst_ip, src_port, dst_port, data);
}

#[cfg(platform_native)]
pub fn udp_bind(_port: u16, _handler: fn([u8; 4], u16, &[u8])) {}

#[cfg(platform_native)]
pub fn udp_send(_dst_ip: [u8; 4], _src_port: u16, _dst_port: u16, _data: &[u8]) {}

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
