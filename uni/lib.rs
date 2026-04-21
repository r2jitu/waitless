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

// Re-export the #[uni::boot] proc macro.
pub use uni_macros::boot;

#[cfg(platform_unikernel)]
extern crate kernel;
#[cfg(platform_unikernel)]
extern crate drivers;
// Bare-metal net umbrella crate. Renamed from plain `net` in Phase
// 3 so the name doesn't collide with this crate's own `pub mod net`
// (which hosts the `Net::enable` API and, in Phase 5, becomes the
// `uni-net` crate). The `pub mod net` below re-exports everything
// from `net_umbrella::*`, so downstream `uni::net::{tcp, udp,
// tls_server, …}` paths keep working unchanged.
#[cfg(platform_unikernel)]
extern crate net as net_umbrella;

// The hand-rolled TLS 1.3 state machine from `//net:tls_server`
// is used on BOTH platforms so there's a single source of truth
// for handshake behaviour. On the unikernel it's reached via the
// umbrella `net_umbrella::tls_server` path (already imported above);
// on native we need a direct `extern crate` because the umbrella
// `//net:net` isn't built on the hosted target (it depends on
// //kernel for TCP). Aliased via a helper `net_umbrella` module so
// `uni/net.rs` can keep writing `net_umbrella::tls_server::X` on
// both platforms.
#[cfg(platform_native)]
extern crate net_tls_server as net_tls_server_impl;
#[cfg(platform_native)]
pub mod net_umbrella {
    pub mod tls_server {
        pub use crate::net_tls_server_impl::*;
    }
}

#[cfg(platform_unikernel)]
mod unikernel;

#[cfg(platform_native)]
pub mod native;

pub mod boot_info;
pub mod error;
pub mod http;
pub mod net;

pub use boot_info::{boot_info, BootInfo, NicInfo};
pub use error::{DhcpError, NetError, NicError};

// ----------------------------------------------------------------------------
// App framework — the runtime's handle on the user's program
// ----------------------------------------------------------------------------
//
// `uni::App` is an empty marker trait the user implements on the
// type that holds their program's long-lived state (HTTP `Server`,
// TLS config, background-task handles, …). Inside `#[uni::boot]
// fn boot()` the user constructs an instance and calls `uni::run(it)`
// to transfer ownership to the runtime.
//
// The runtime holds the app for the lifetime of the event loop and
// drops it on graceful shutdown. Teardown uses Rust's standard
// `Drop` — apps that need custom shutdown logic implement it
// themselves.
//
// There are no required trait methods and no `Send`/`Sync` bounds.
// The runtime handles the app on the boot CPU only (core 0 on
// unikernel, main thread on native), so multi-core aliasing isn't
// an issue at this layer.
//
// Soundness: the runtime stores `Box<dyn App>` in a static slot
// wrapped in `UnsafeCell`. One `unsafe impl Sync` lets the static
// hold it; the contract is "boot CPU only", upheld by the two
// access sites (`run` from `uni_main`, `shutdown_and_drop` from
// the BSP branch of the event-loop exit or native's main after
// `pthread_join`).

/// Marker trait identifying the program's top-level app type.
/// Implement with an empty body; the runtime only needs the type
/// identity plus a `Drop` impl (which every type has by default).
pub trait App: 'static {}

// --- Runtime storage --------------------------------------------------------

/// Single-slot storage for the runtime-owned app. Accessed only
/// from the boot CPU (see `unsafe impl Sync` below).
struct AppSlot(core::cell::UnsafeCell<Option<alloc::boxed::Box<dyn App>>>);

// SAFETY: every read/write of `APP_SLOT` is on the boot CPU:
//   - `run` is called from `uni_main` (BSP on unikernel, main thread
//     on native).
//   - `shutdown_and_drop` is called from `kernel::eventloop`'s
//     BSP-only shutdown branch (unikernel) or from native's `main`
//     after `pthread_join` returns (native).
// Manual `Sync` impl so the static can hold it without requiring the
// inner `Box<dyn App>: Sync` (which would force `A: Send + Sync`
// bounds on every user App).
unsafe impl Sync for AppSlot {}

static APP_SLOT: AppSlot =
    AppSlot(core::cell::UnsafeCell::new(None));

/// Transfer ownership of `app` to the runtime for the lifetime of
/// the event loop. Typically called from `#[uni::boot] fn boot()`.
/// Returns immediately; the kernel event loop (unikernel) or
/// native C main (native) takes over from here.
///
/// Signals the event loop that app initialization is complete, so
/// worker cores can begin servicing requests.
///
/// On graceful shutdown, the runtime drops the box — your app's
/// `Drop` impl runs, then field destructors cascade.
pub fn run<A: App>(app: A) {
    let boxed: alloc::boxed::Box<dyn App> = alloc::boxed::Box::new(app);
    // SAFETY: boot-CPU-only; see `unsafe impl Sync for AppSlot`.
    unsafe {
        *APP_SLOT.0.get() = Some(boxed);
    }
    install_shutdown_hook();
    backend::set_ready();
}

/// Invoked from the event-loop exit path (unikernel BSP after the
/// loop breaks, native `main` after `pthread_join`) to drop the app
/// exactly once. Idempotent: `Option::take` clears the slot on
/// first call.
pub fn shutdown_and_drop() {
    #[cfg(platform_unikernel)]
    debug_assert_eq!(
        kernel::cpu_id(),
        0,
        "uni::shutdown_and_drop must run on BSP; see AppSlot Sync contract",
    );

    // SAFETY: boot-CPU-only; see `unsafe impl Sync for AppSlot`.
    let taken = unsafe { (*APP_SLOT.0.get()).take() };
    // `taken` drops at end of scope: Box::drop walks the vtable,
    // runs the concrete A's Drop impl (if any), and returns the
    // allocation to the heap.
    drop(taken);
}

/// Route `shutdown_and_drop` into the platform-specific event-loop
/// exit path. Called once during `run`.
#[cfg(platform_unikernel)]
fn install_shutdown_hook() {
    kernel::eventloop::set_on_shutdown(shutdown_and_drop);
}

/// Native's C `main` calls `shutdown_and_drop` directly after
/// `pthread_join`. Nothing to register at the kernel side.
#[cfg(platform_native)]
fn install_shutdown_hook() {}

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

// ---- Heap stats -------------------------------------------------------------

/// Platform-agnostic snapshot of the allocator: byte counts plus live-
/// allocation counters. Zero-cost to call on bare-metal (reads talc's
/// counters under the spinlock); returns zeros on native since
/// libstd's allocator doesn't expose equivalent accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeapStats {
    pub allocated_bytes: usize,
    pub available_bytes: usize,
    pub claimed_bytes: usize,
    pub allocation_count: usize,
    pub fragment_count: usize,
    pub total_allocation_count: u64,
}

/// Snapshot the heap. Cheap on bare-metal (O(1) + spinlock); best-
/// effort zero on native.
#[cfg(platform_unikernel)]
pub fn heap_stats() -> HeapStats {
    let s = kernel::mm::heap_stats();
    HeapStats {
        allocated_bytes: s.allocated_bytes,
        available_bytes: s.available_bytes,
        claimed_bytes: s.claimed_bytes,
        allocation_count: s.allocation_count,
        fragment_count: s.fragment_count,
        total_allocation_count: s.total_allocation_count,
    }
}

#[cfg(platform_native)]
pub fn heap_stats() -> HeapStats {
    HeapStats::default()
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
