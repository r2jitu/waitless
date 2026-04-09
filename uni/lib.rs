// uni/lib.rs — Platform abstraction API
//
// Provides safe Rust types: TcpListener, TcpStream, log(), config_port(), etc.
//
// Backend selected at compile time via #[cfg]:
//   - platform_unikernel: unikernel module (lifecycle) + net_stack (TCP)
//   - platform_native:    native module (POSIX sockets + stdio)

#![no_std]

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

pub mod heap;
pub mod owned;
pub use owned::{Box, Buffer};

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

    /// Register an IO poll callback. On unikernel, this is handled by
    /// kernel::eventloop callbacks (net_poll, net_drain, etc). For app-level
    /// IO sources, this is a placeholder — real registration goes through
    /// kernel::eventloop directly.
    #[allow(dead_code)]
    pub fn register_io_poll(_f: fn(u32) -> bool) {
        // Unikernel IO sources register with kernel::eventloop directly
        // (e.g., net::init_eventloop sets net_poll/net_drain/net_flush).
    }
}

#[cfg(platform_native)]
mod backend {
    pub use crate::native::{log, config_port, check_shutdown, wait_for_events,
                            tcp_listen, tcp_accept, tcp_has_data,
                            tcp_recv, tcp_send, tcp_close, tcp_is_closed, tcp_poll};

    // ── Callback-driven event loop (mirrors kernel::eventloop) ──────────
    // Same pattern as the unikernel: register callbacks, all workers run
    // the same loop. On native, "worker" = OS thread.

    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    type PollFn = fn(u32) -> bool;

    /// Up to 4 IO poll callbacks (network, storage, ...). Each slot is an
    /// `AtomicPtr<()>` (null = empty, non-null = `PollFn`); `IO_POLL_COUNT`
    /// is the number of slots that have been claimed. Slots are filled in
    /// order during init by `register_io_poll`, then read by all worker
    /// threads. Volatile reads/writes (the previous design) are NOT a
    /// synchronisation primitive in the Rust memory model.
    const IO_POLL_MAX: usize = 4;
    static IO_POLL: [AtomicPtr<()>; IO_POLL_MAX] = [
        AtomicPtr::new(core::ptr::null_mut()),
        AtomicPtr::new(core::ptr::null_mut()),
        AtomicPtr::new(core::ptr::null_mut()),
        AtomicPtr::new(core::ptr::null_mut()),
    ];
    static IO_POLL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static SERVICE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    #[inline]
    fn load_poll(slot: &AtomicPtr<()>) -> Option<PollFn> {
        let p = slot.load(Ordering::Acquire);
        if p.is_null() {
            None
        } else {
            // SAFETY: only `register_io_poll`/`set_service` write here, and
            // both write valid `PollFn` pointers.
            Some(unsafe { core::mem::transmute::<*mut (), PollFn>(p) })
        }
    }

    // NUM_WORKERS removed: num_workers() now reads native::NUM_THREADS directly.
    static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub fn num_workers() -> u32 {
        // NUM_THREADS is set by init_native() from the THREADS env var (or
        // num_cpus() as default). Use it directly — don't override with num_cpus().
        unsafe { crate::native::NUM_THREADS as u32 }
    }

    /// Register an IO poll callback (network, storage, etc).
    /// Multiple sources can be registered; all are called each iteration.
    /// Designed to be called from a single init thread; the atomic
    /// fetch_add reserves the slot index race-free even if that contract
    /// is ever violated.
    pub fn register_io_poll(f: PollFn) {
        let idx = IO_POLL_COUNT.fetch_add(1, Ordering::AcqRel);
        if idx < IO_POLL_MAX {
            IO_POLL[idx].store(f as *mut (), Ordering::Release);
        } else {
            // Roll back to keep IO_POLL_COUNT bounded.
            IO_POLL_COUNT.store(IO_POLL_MAX, Ordering::Release);
        }
    }

    pub fn set_service(f: PollFn) {
        SERVICE.store(f as *mut (), Ordering::Release);
    }

    pub fn get_service() -> Option<PollFn> {
        load_poll(&SERVICE)
    }

    pub fn set_ready() {
        READY.store(true, core::sync::atomic::Ordering::Release);
    }

    pub fn is_ready() -> bool {
        READY.load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn request_shutdown() {
        unsafe { crate::native::SHUTDOWN = true; }
    }

    pub fn tcp_listen_on(worker_id: u32, port: u16) -> *mut () {
        crate::native::tcp_listen_for(port, worker_id)
    }

    /// Run the worker event loop on this thread. Same structure as kernel's.
    /// Called by native_worker_loop after thread setup.
    pub fn run_worker(worker_id: u32) {
        // Wait for ready
        while !is_ready() && !crate::native::check_shutdown() {
            crate::native::wait_for_events();
        }

        loop {
            if crate::native::check_shutdown() { break; }

            let mut did_work = false;

            // 1. IO poll callbacks (network, future storage, etc)
            let n = IO_POLL_COUNT.load(Ordering::Acquire).min(IO_POLL_MAX);
            for i in 0..n {
                if let Some(f) = load_poll(&IO_POLL[i]) {
                    if f(worker_id) { did_work = true; }
                }
            }

            // 2. App service callback
            if let Some(f) = get_service() {
                if f(worker_id) { did_work = true; }
            }

            // 3. Idle if no work
            if !did_work {
                crate::native::wait_for_events();
            }
        }
    }
}

// ---- Re-exported platform functions ------------------------------------------

pub use backend::{log, config_port, check_shutdown, wait_for_events, tcp_poll};
pub use backend::{num_workers, set_service, set_ready, request_shutdown, register_io_poll};
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
pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    native::native_udp_bind(port, handler);
}

#[cfg(platform_native)]
pub fn udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    native::native_udp_send(dst_ip, src_port, dst_port, data);
}

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
