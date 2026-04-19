// uni/lib.rs — Platform abstraction API
//
// Provides safe Rust types: TcpListener, TcpStream, log(), config_port(), etc.
//
// Backend selected at compile time via #[cfg]:
//   - platform_unikernel: unikernel module (lifecycle) + net_stack (TCP)
//   - platform_native:    native module (POSIX sockets + stdio)

#![no_std]

// `extern crate alloc` makes the `alloc` crate's types (`Box`, `Vec`,
// `String`, …) visible to this crate and to apps built on top of it.
// On bare-metal the backing allocator is `kernel::mm::GLOBAL_ALLOCATOR`
// (talc); on native host builds, libstd's own global allocator.
extern crate alloc;

// Re-export the #[uni::main] proc macro.
pub use uni_macros::main;

#[cfg(platform_unikernel)]
extern crate kernel;
#[cfg(platform_unikernel)]
extern crate drivers;
#[cfg(platform_unikernel)]
extern crate net;

// The hand-rolled TLS 1.3 state machine from `//net:tls_server`
// is used on BOTH platforms so there's a single source of truth
// for handshake behaviour. On the unikernel it's reached via the
// umbrella `net::tls_server` path (already imported above); on
// native we need a direct `extern crate` because the umbrella
// `//net:net` isn't built on the hosted target (it depends on
// //kernel for TCP). Aliased via a helper `net` module so
// `uni/http.rs` can keep writing `net::tls_server::X` on both
// platforms.
#[cfg(platform_native)]
extern crate net_tls_server as net_tls_server_impl;
#[cfg(platform_native)]
pub mod net {
    pub mod tls_server {
        pub use crate::net_tls_server_impl::*;
    }
}

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
    pub use crate::unikernel::{log, config_port, config_tls_port, check_shutdown, wait_for_events};
    pub use net::tcp::{listen as tcp_listen, accept as tcp_accept, has_data as tcp_has_data,
                       recv as tcp_recv, send as tcp_send, close as tcp_close,
                       is_closed as tcp_is_closed, listen_on_core as tcp_listen_on};
    pub use net::poll as tcp_poll;

    // Event loop
    pub fn num_workers() -> u32 { kernel::percpu::num_cores() }
    pub fn set_service(f: fn(u32) -> bool) { kernel::eventloop::set_service(f); }
    pub fn set_ready() { kernel::eventloop::set_ready(); }
    pub fn request_shutdown() { kernel::eventloop::request_shutdown(); }

    /// Register an IO poll callback. On unikernel, this is handled by
    /// kernel::eventloop callbacks (net_poll, net_drain, etc). For app-level
    /// IO sources, this is a placeholder — real registration goes through
    /// kernel::eventloop directly. The no-op body is intentional — apps
    /// that target both unikernel and native can call this unconditionally
    /// and the unikernel side is simply a shim.
    pub fn register_io_poll(_f: fn(u32) -> bool) {}
}

#[cfg(platform_native)]
mod backend {
    pub use crate::native::{log, config_port, config_tls_port, check_shutdown, wait_for_events,
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

pub use backend::{log, config_port, config_tls_port, check_shutdown, wait_for_events, tcp_poll};
pub use backend::{num_workers, set_service, set_ready, request_shutdown, register_io_poll};
pub use backend::tcp_listen_on;

/// Current core / worker ID. On unikernel this reads the percpu TLS
/// register (~2 cycles). On native there's no per-thread state, so
/// this returns 0 — native handlers should not rely on per-core
/// scratch storage.
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(platform_unikernel)]
    { kernel::cpu_id() }
    #[cfg(platform_native)]
    { 0 }
}

// ---- UDP --------------------------------------------------------------------

/// Bind a UDP port handler. Callback receives (src_ip_octets, src_port, payload).
#[cfg(platform_unikernel)]
pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    net::udp::bind(port, handler);
}

/// Per-queue RX frame counts. Indexed by queue-pair number; zeros
/// for unused queues. Useful for debugging RSS / flow-hash imbalance
/// under Tier 1 multi-queue. Max array size matches the driver's
/// MAX_QUEUE_PAIRS (8); consumers should take `[..num_queue_pairs()]`
/// or just ignore the tail zeros.
#[cfg(platform_unikernel)]
pub fn net_rx_counts() -> [u64; 8] {
    drivers::net::rx_counts()
}
#[cfg(platform_native)]
pub fn net_rx_counts() -> [u64; 8] { [0; 8] }

/// Number of virtio-net queue pairs actually active (after MQ
/// activation on Tier 1 paths). 1 for single-queue / Tier 2.
#[cfg(platform_unikernel)]
pub fn net_num_queue_pairs() -> u16 {
    drivers::net::num_queue_pairs()
}
#[cfg(platform_native)]
pub fn net_num_queue_pairs() -> u16 { 1 }

/// Per-RX-queue `(device_idx, driver_cursor)` used-ring snapshots.
/// See `drivers::net::rx_used_cursors` for interpretation —
/// lets `/stats` surface whether traffic is stuck on the device side
/// (Andromeda not distributing) vs. the driver side (we're not
/// polling qp N fast enough).
#[cfg(platform_unikernel)]
pub fn net_rx_used_cursors() -> [(u16, u16); 8] {
    drivers::net::rx_used_cursors()
}
#[cfg(platform_native)]
pub fn net_rx_used_cursors() -> [(u16, u16); 8] { [(0, 0); 8] }

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
