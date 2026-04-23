// Platform abstraction: `TcpListener`, `TcpStream`, `log`, `config_port`,
// etc. Backend dispatched by `target_os` — `uni_kernel` on bare-metal,
// `uni_native` on hosted.

#![no_std]

extern crate alloc;

pub use uni_macros::boot;

#[cfg(target_os = "none")]
extern crate kernel;
#[cfg(target_os = "none")]
extern crate drivers;
#[cfg(target_os = "none")]
extern crate uni_kernel;

#[cfg(not(target_os = "none"))]
extern crate uni_native;

pub extern crate uni_net as net;

/// Native entry from `native_main.rs`. Plugs boot_info and shutdown
/// callbacks into `uni_native::run` so the native backend doesn't
/// need a dep back on `uni`.
#[cfg(not(target_os = "none"))]
pub fn native_run() -> i32 {
    use crate::boot_info::{BootInfoParams, NicInfo, MAX_NICS};

    uni_native::run(uni_native::RunConfig {
        boot_info_fn: |num_cpus, ram_bytes| {
            crate::boot_info::init_boot_info(BootInfoParams {
                ram_bytes,
                num_cpus,
                boot_args: "",
                nics: [NicInfo::EMPTY; MAX_NICS],
                nic_count: 0,
                rtc_epoch: None,
            });
        },
        shutdown_fn: crate::shutdown_and_drop,
    })
}

/// Per-worker pre-spawn hook for SO_REUSEPORT listener setup on
/// native (no-op on unikernel, where each core runs its own
/// `kernel::eventloop::run` + per-core `Server::listen`).
pub fn set_add_worker_listener(f: fn(u32)) {
    #[cfg(not(target_os = "none"))]
    uni_native::set_add_worker_listener(f);
    #[cfg(target_os = "none")]
    let _ = f;
}

pub mod boot_info;
pub mod rng;

pub use boot_info::{boot_info, BootInfo, NicInfo};

pub use net::{DhcpError, NetError, NicError};

/// Also reachable as `uni::error::NetError`, etc. The types live in
/// `uni_net` so driver crates can reach them without depending on
/// `uni`.
pub mod error {
    pub use crate::net::{DhcpError, NetError, NicError};
}

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
    #[cfg(target_os = "none")]
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

    // Tear down the Phase-4 NET slot symmetrically. The Box is a
    // ZST today, so the drop is a no-op allocation-wise, but the
    // `Option::take` resets `is_enabled()` to false — useful on
    // native if the runtime is ever re-entered.
    net::clear_on_shutdown();
}

/// Route `shutdown_and_drop` into the platform-specific event-loop
/// exit path. Called once during `run`.
#[cfg(target_os = "none")]
fn install_shutdown_hook() {
    kernel::eventloop::set_on_shutdown(shutdown_and_drop);
}

/// Native's C `main` calls `shutdown_and_drop` directly after
/// `pthread_join`. Nothing to register at the kernel side.
#[cfg(not(target_os = "none"))]
fn install_shutdown_hook() {}

// ---- Backend dispatch --------------------------------------------------------

#[cfg(target_os = "none")]
mod backend {
    pub use uni_kernel::{log, config_port, config_tls_port, check_shutdown, wait_for_events};
    pub use net::tcp::{listen as tcp_listen, accept as tcp_accept, has_data as tcp_has_data,
                       recv as tcp_recv, send as tcp_send, close as tcp_close,
                       is_closed as tcp_is_closed, listen_on_core as tcp_listen_on};
    pub use net::poll as tcp_poll;
    pub use net::udp::{bind as udp_bind, send as udp_send};
    pub use drivers::net::{
        rx_counts as net_rx_counts,
        num_queue_pairs as net_num_queue_pairs,
        rx_used_cursors as net_rx_used_cursors,
    };

    // Event loop — pure re-exports, matching the native backend's
    // `pub use uni_native::…` style. `num_workers` is aliased from
    // the kernel's `num_cores` (same signature, cleaner app-facing
    // name).
    pub use kernel::percpu::num_cores as num_workers;
    pub use kernel::eventloop::{set_service, set_ready, request_shutdown};

    // Async runtime — backend dispatch for `uni::executor`.
    pub use uni_kernel::executor::{spawn as executor_spawn, sleep_us as executor_sleep_us};

    /// Register an IO poll callback. On unikernel, this is handled by
    /// kernel::eventloop callbacks (net_poll, net_drain, etc). For app-level
    /// IO sources, this is a placeholder — real registration goes through
    /// kernel::eventloop directly. The no-op body is intentional — apps
    /// that target both unikernel and native can call this unconditionally
    /// and the unikernel side is simply a shim.
    pub fn register_io_poll(_f: fn(u32) -> bool) {}

    /// Heap counters from the bare-metal talc allocator. Cheap —
    /// O(1) read under the allocator spinlock.
    pub fn heap_stats() -> crate::HeapStats {
        let s = kernel::mm::heap_stats();
        crate::HeapStats {
            allocated_bytes: s.allocated_bytes,
            available_bytes: s.available_bytes,
            claimed_bytes: s.claimed_bytes,
            allocation_count: s.allocation_count,
            fragment_count: s.fragment_count,
            total_allocation_count: s.total_allocation_count,
        }
    }
}

/// Native-platform dispatch — pure re-export from the `uni_native`
/// crate (host POSIX backend: sockets, pthread workers, kqueue/epoll
/// event loop). Sits behind the same `mod backend` shape as the
/// unikernel dispatch above so the cross-platform `pub use
/// backend::…` block below works uniformly.
///
/// Driver-specific queries (`net_rx_counts` etc.) are stubs here —
/// native has no NIC driver; POSIX sockets go through the host stack.
/// Likewise `heap_stats` returns `Default` because libstd's allocator
/// doesn't expose the talc-style counters.
#[cfg(not(target_os = "none"))]
mod backend {
    pub use uni_native::{
        log, config_port, config_tls_port, check_shutdown, wait_for_events,
        tcp_listen, tcp_accept, tcp_has_data, tcp_recv, tcp_send, tcp_close,
        tcp_is_closed, tcp_poll, tcp_listen_on, udp_bind, udp_send,
        num_workers, register_io_poll, set_service, set_ready, request_shutdown,
    };
    pub use uni_native::executor::{spawn as executor_spawn, sleep_us as executor_sleep_us};

    pub fn net_rx_counts() -> [u64; 8] { [0; 8] }
    pub fn net_num_queue_pairs() -> u16 { 1 }
    pub fn net_rx_used_cursors() -> [(u16, u16); 8] { [(0, 0); 8] }

    pub fn heap_stats() -> crate::HeapStats { crate::HeapStats::default() }
}

// ---- Re-exported platform functions ------------------------------------------

pub use backend::{log, config_port, config_tls_port, check_shutdown, wait_for_events, tcp_poll};
pub use backend::{num_workers, set_service, set_ready, request_shutdown, register_io_poll};

// ---- Async runtime ---------------------------------------------------------
//
// Cross-platform wrapper over the backend's executor. On the unikernel
// this dispatches into `kernel::executor` (polled by `kernel::eventloop`);
// on native it dispatches into `uni_native::executor` (polled by
// `uni_native::run_worker`). Same `async fn` app code runs either way.

pub mod executor {
    use core::future::Future;

    /// Spawn a future onto the current worker / core's task list.
    /// `Err(())` if the arena is full.
    #[inline]
    pub fn spawn<F>(f: F) -> Result<(), ()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        super::backend::executor_spawn(f)
    }

    /// Sleep for `us` microseconds. Returns an opaque `impl Future`
    /// so the backend-specific Sleep type doesn't leak.
    #[inline]
    pub fn sleep_us(us: u64) -> impl Future<Output = ()> {
        super::backend::executor_sleep_us(us)
    }
}

/// Create a TCP listener on `port`, bound to a specific worker.
/// `uni_http` uses this to set up per-worker SO_REUSEPORT listeners
/// after the main thread creates the first one. Apps shouldn't
/// normally need this; use `TcpListener::bind` for ordinary cases.
pub fn tcp_listen_on(worker_id: u32, port: u16) -> Option<TcpListener> {
    let p = backend::tcp_listen_on(worker_id, port);
    if p.is_null() { None } else { Some(TcpListener(p)) }
}


/// Current core / worker ID. On unikernel this reads the percpu TLS
/// register (~2 cycles). On native there's no per-thread state, so
/// this returns 0 — native handlers should not rely on per-core
/// scratch storage.
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(target_os = "none")]
    { kernel::cpu_id() }
    #[cfg(not(target_os = "none"))]
    { 0 }
}

// ---- UDP --------------------------------------------------------------------

/// Bind a UDP port handler. Callback receives (src_ip_octets, src_port, payload).
pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    backend::udp_bind(port, handler);
}

/// Send a UDP datagram.
pub fn udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    backend::udp_send(dst_ip, src_port, dst_port, data);
}

// ---- NIC driver diagnostics -------------------------------------------------
//
// Unikernel paths return driver-reported counters; native stubs out all
// three (no NIC driver — POSIX sockets go through the host stack) so
// callers stay platform-agnostic.

/// Per-queue RX frame counts. Indexed by queue-pair number; zeros
/// for unused queues. Useful for debugging RSS / flow-hash imbalance
/// under Tier 1 multi-queue. Max array size matches the driver's
/// MAX_QUEUE_PAIRS (8); consumers should take `[..num_queue_pairs()]`
/// or just ignore the tail zeros.
pub fn net_rx_counts() -> [u64; 8] { backend::net_rx_counts() }

/// Number of virtio-net queue pairs actually active (after MQ
/// activation on Tier 1 paths). 1 for single-queue / Tier 2.
pub fn net_num_queue_pairs() -> u16 { backend::net_num_queue_pairs() }

/// Per-RX-queue `(device_idx, driver_cursor)` used-ring snapshots.
/// See `drivers::net::rx_used_cursors` for interpretation —
/// lets `/stats` surface whether traffic is stuck on the device side
/// (Andromeda not distributing) vs. the driver side (we're not
/// polling qp N fast enough).
pub fn net_rx_used_cursors() -> [(u16, u16); 8] { backend::net_rx_used_cursors() }

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
pub fn heap_stats() -> HeapStats { backend::heap_stats() }

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
