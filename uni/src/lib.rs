// Platform abstraction: `TcpListener`, `TcpStream`, `log`, `config_port`,
// etc. Dispatch goes through `//uni-backend` which cfg-selects the
// unikernel or POSIX impl internally — `uni/lib.rs` stays uniform.

#![no_std]

extern crate alloc;

pub use uni_macros::boot;

extern crate uni_backend;

#[cfg(target_os = "none")]
extern crate uni_kernel;

pub extern crate uni_net as net;

/// Native entry from `native_main.rs`. Plugs boot_info and shutdown
/// callbacks into `uni_backend::run` so the backend doesn't need a
/// dep back on `uni`.
#[cfg(not(target_os = "none"))]
pub fn native_run() -> i32 {
    use crate::boot_info::{BootInfoParams, NicInfo, MAX_NICS};

    uni_backend::run(uni_backend::RunConfig {
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
/// `uni_kernel::eventloop::run` + per-core `Server::listen`).
pub fn set_add_worker_listener(f: fn(u32)) {
    #[cfg(not(target_os = "none"))]
    uni_backend::set_add_worker_listener(f);
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
//   - `shutdown_and_drop` is called from `uni_kernel::eventloop`'s
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
    uni_backend::set_ready();
}

/// Invoked from the event-loop exit path (unikernel BSP after the
/// loop breaks, native `main` after `pthread_join`) to drop the app
/// exactly once. Idempotent: `Option::take` clears the slot on
/// first call.
pub fn shutdown_and_drop() {
    #[cfg(target_os = "none")]
    debug_assert_eq!(
        uni_kernel::cpu_id(),
        0,
        "uni::shutdown_and_drop must run on BSP; see AppSlot Sync contract",
    );

    // SAFETY: boot-CPU-only; see `unsafe impl Sync for AppSlot`.
    let taken = unsafe { (*APP_SLOT.0.get()).take() };
    drop(taken);

    // Tear down the NET slot symmetrically.
    net::clear_on_shutdown();
}

/// Route `shutdown_and_drop` into the platform-specific event-loop
/// exit path. Called once during `run`.
#[cfg(target_os = "none")]
fn install_shutdown_hook() {
    uni_kernel::eventloop::set_on_shutdown(shutdown_and_drop);
}

/// Native's C `main` calls `shutdown_and_drop` directly after
/// `pthread_join`. Nothing to register at the kernel side.
#[cfg(not(target_os = "none"))]
fn install_shutdown_hook() {}

// ---- Re-exported platform functions ---------------------------------------

pub use uni_backend::{
    check_shutdown, config_port, config_tls_port, log, num_workers, register_io_poll,
    request_shutdown, set_ready, set_service, tcp_poll, wait_for_events, HeapStats,
};

// ---- Async runtime --------------------------------------------------------

/// Re-export of the shared async runtime. `use uni::runtime::spawn;`
/// works on both unikernel and native.
pub mod runtime {
    pub use uni_backend::runtime::{sleep_us, spawn, spawn_on_each_worker, Sleep};
    pub use uni_runtime::net::{
        RawTcpStream, TcpAccept, TcpBindError, TcpListener,
        UdpBindError, UdpRecv, UdpSocket,
    };
}

/// Create a TCP listener on `port`, bound to a specific worker.
/// `uni_http` uses this to set up per-worker SO_REUSEPORT listeners
/// after the main thread creates the first one.
pub fn tcp_listen_on(worker_id: u32, port: u16) -> Option<TcpListener> {
    let p = uni_backend::tcp_listen_on(worker_id, port);
    if p.is_null() { None } else { Some(TcpListener(p)) }
}

/// Current core / worker ID. On unikernel this reads the percpu TLS
/// register (~2 cycles). On native there's no per-thread state, so
/// this returns 0 — native handlers should not rely on per-core
/// scratch storage.
#[inline]
pub fn cpu_id() -> u32 {
    #[cfg(target_os = "none")]
    { uni_kernel::cpu_id() }
    #[cfg(not(target_os = "none"))]
    { 0 }
}

// ---- UDP ------------------------------------------------------------------

/// Bind a UDP port handler. Callback receives (src_ip_octets, src_port, payload).
pub fn udp_bind(port: u16, handler: fn([u8; 4], u16, &[u8])) {
    uni_backend::udp_bind(port, handler);
}

/// Send a UDP datagram.
pub fn udp_send(dst_ip: [u8; 4], src_port: u16, dst_port: u16, data: &[u8]) {
    uni_backend::udp_send(dst_ip, src_port, dst_port, data);
}

// ---- NIC driver diagnostics ------------------------------------------------

pub fn net_rx_counts() -> [u64; 8] { uni_backend::net_rx_counts() }
pub fn net_num_queue_pairs() -> u16 { uni_backend::net_num_queue_pairs() }
pub fn net_rx_used_cursors() -> [(u16, u16); 8] { uni_backend::net_rx_used_cursors() }

// ---- Heap stats -----------------------------------------------------------

/// Snapshot the heap. Cheap on bare-metal (O(1) + spinlock); best-
/// effort zero on native.
pub fn heap_stats() -> HeapStats { uni_backend::heap_stats() }

// ---- TcpListener ----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpListener(*mut ());

impl TcpListener {
    pub fn bind(port: u16) -> Option<Self> {
        let p = uni_backend::tcp_listen(port);
        if p.is_null() { None } else { Some(TcpListener(p)) }
    }

    pub fn accept(&self) -> Option<TcpStream> {
        let p = uni_backend::tcp_accept(self.0);
        if p.is_null() { None } else { Some(TcpStream(p)) }
    }

    pub fn close(&self) {
        uni_backend::tcp_close(self.0);
    }
}

// ---- TcpStream ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TcpStream(*mut ());

impl TcpStream {
    pub fn has_data(&self) -> bool {
        uni_backend::tcp_has_data(self.0)
    }

    pub fn recv(&self, buf: &mut [u8]) -> usize {
        uni_backend::tcp_recv(self.0, buf)
    }

    pub fn send(&self, data: &[u8]) -> i32 {
        uni_backend::tcp_send(self.0, data)
    }

    pub fn close(&self) {
        uni_backend::tcp_close(self.0);
    }

    pub fn is_closed(&self) -> bool {
        uni_backend::tcp_is_closed(self.0)
    }
}
