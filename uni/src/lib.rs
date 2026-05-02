// Platform abstraction: `TcpListener`, `TcpStream`, `log`, etc.
// Dispatch goes through `//uni-backend` which cfg-selects the
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
    use crate::boot_info::BootInfoParams;
    use alloc::vec::Vec;

    uni_backend::run(uni_backend::RunConfig {
        boot_info_fn: |num_cpus, ram_bytes| {
            crate::boot_info::init_boot_info(BootInfoParams {
                ram_bytes,
                num_cpus,
                boot_args: "",
                nics: Vec::new(),
                rtc_epoch: None,
            });
        },
        shutdown_fn: crate::shutdown_and_drop,
    })
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
// Lifetime model — listeners run forever, no user-side bag
// ----------------------------------------------------------------------------
//
// Listener handles returned by `listen` / `tcp_listen` / etc. are
// leaked into a process-lifetime registry by the helpers below.
// User code never holds an aliveness witness; the runtime tears
// every leaked handle down at `shutdown_and_drop` time.
//
// State that an *app* needs to keep alive (Net, app-config Box,
// shared cache) is held in idiomatic Rust ways: a local in
// `boot()` scope, a `Box::leak` for forever, a `OnceLock`/`static`,
// or a `Box::leak` of an `Arc` shared into closures. There is no
// framework wrapper.

/// Slot of leaked listener handles. Each entry is a `Box<dyn Any>`
/// owning a `TcpHandle` / `UdpHandle` that user code never names.
/// Only the boot CPU writes; `shutdown_and_drop` drains and drops.
struct Bag(core::cell::UnsafeCell<alloc::vec::Vec<alloc::boxed::Box<dyn core::any::Any>>>);

// SAFETY: writes happen only on the boot CPU during `boot()`;
// reads happen only from `shutdown_and_drop`, also on the boot CPU.
unsafe impl Sync for Bag {}

static LISTENERS: Bag =
    Bag(core::cell::UnsafeCell::new(alloc::vec::Vec::new()));

/// Internal: take ownership of a listener handle so it lives for
/// the rest of the process. Called by `tcp_listen` / `udp_listen` /
/// `http::listen` / `https::listen` after a successful bind.
#[doc(hidden)]
pub fn _retain<T: 'static>(handle: T) {
    // SAFETY: boot-CPU-only writer; see `unsafe impl Sync for Bag`.
    unsafe { (*LISTENERS.0.get()).push(alloc::boxed::Box::new(handle)); }
}

/// Invoked from the event-loop exit path (unikernel BSP after the
/// loop breaks, native `main` after `pthread_join`) to drop every
/// retained listener and tear down the network stack.
pub fn shutdown_and_drop() {
    #[cfg(target_os = "none")]
    debug_assert_eq!(
        uni_kernel::cpu_id(),
        0,
        "uni::shutdown_and_drop must run on BSP",
    );

    // SAFETY: boot-CPU-only; see `unsafe impl Sync for Bag`.
    let drained: alloc::vec::Vec<_> =
        unsafe { core::mem::take(&mut *LISTENERS.0.get()) };
    drop(drained);

    // Tear down the NET slot symmetrically.
    net::clear_on_shutdown();
}

/// Route `shutdown_and_drop` into the platform-specific event-loop
/// exit path. Called once from the boot macro after the user's
/// `boot()` body completes.
#[doc(hidden)]
#[cfg(target_os = "none")]
pub fn _install_shutdown_hook() {
    uni_kernel::eventloop::set_on_shutdown(shutdown_and_drop);
}

#[doc(hidden)]
#[cfg(not(target_os = "none"))]
pub fn _install_shutdown_hook() {}

// ---- Re-exported platform functions ---------------------------------------

pub use uni_backend::{
    check_shutdown, log, num_workers, request_shutdown, set_ready,
    wait_for_events, HeapStats,
};

/// Format-and-log helper for `uni::log!("…", args)`. Allocates a
/// scratch `String` because `core::fmt::write` doesn't have a
/// no-alloc collector. For static-message logs prefer `uni::log`
/// directly to skip the allocation.
#[doc(hidden)]
pub fn _log_fmt(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write as _;
    let mut s = alloc::string::String::new();
    let _ = s.write_fmt(args);
    log(s.as_bytes());
}

/// Formatted log line, no trailing newline added. `uni::log!("x={}", x)`.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        $crate::_log_fmt(::core::format_args!($($arg)*));
    }};
}

/// Formatted log line + trailing `\n`. The expected serial-output
/// shape — `uni::println!("hello {}", name)` is the no_std analog
/// of `println!`.
#[macro_export]
macro_rules! println {
    () => {{
        $crate::log(b"\n");
    }};
    ($($arg:tt)*) => {{
        $crate::_log_fmt(::core::format_args!("{}\n", ::core::format_args!($($arg)*)));
    }};
}

// ---- Async runtime --------------------------------------------------------

/// Re-export of the shared async runtime. `use uni::runtime::spawn;`
/// works on both unikernel and native.
pub mod runtime {
    pub use uni_backend::runtime::{sleep_us, spawn, Sleep};
    pub use uni_runtime::TaskHandle;
    pub use uni_runtime::event::{AsyncEvent, WaitEvent};
    pub use uni_runtime::launcher::{LaunchTable, Launcher};
    pub use uni_runtime::net::{
        tcp_listen, udp_listen,
        TcpBindError, TcpHandle, TcpListener, TcpRecv, TcpSend, TcpStream,
        UdpBindError, UdpClient, UdpHandle, UdpRecv, UdpRecvInplace, UdpSocket,
    };
    pub use uni_runtime::select::{
        join, join3, select, select3, timeout_us, Either, Three,
    };
}

// Top-level shortcuts for the most common runtime calls. The full
// `uni::runtime::*` namespace stays available for power users who
// need raw handle ownership (tests, manual teardown).
pub use uni_runtime::net::UdpClient;

/// Listen for TCP on `port`; the listener runs for the rest of
/// the process. The returned `Result` reports bind success or
/// failure; on success the listener handle is retained internally
/// (no per-app bag) and torn down at `shutdown_and_drop`.
///
/// `body` is invoked once per accepted connection. Use
/// [`runtime::tcp_listen`] directly if you need explicit
/// ownership of the listener handle (e.g. teardown mid-run).
pub fn tcp_listen<H, F>(
    port: u16,
    body: H,
) -> Result<(), uni_runtime::net::TcpBindError>
where
    H: Fn(uni_runtime::net::TcpStream) -> F + Send + Sync + 'static,
    F: core::future::Future<Output = ()> + 'static,
{
    let handle = uni_runtime::net::tcp_listen(port, body)?;
    _retain(handle);
    Ok(())
}

/// Listen for UDP on `port`; semantics match [`tcp_listen`].
pub fn udp_listen<H, F>(
    port: u16,
    body: H,
) -> Result<(), uni_runtime::net::UdpBindError>
where
    H: Fn(alloc::sync::Arc<uni_runtime::net::UdpSocket>) -> F + Send + Sync + 'static,
    F: core::future::Future<Output = ()> + 'static,
{
    let handle = uni_runtime::net::udp_listen(port, body)?;
    _retain(handle);
    Ok(())
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

// ---- Diagnostics ----------------------------------------------------------

/// Observability surface — runtime counters and snapshots most
/// apps don't need but debug endpoints / monitoring agents do.
/// Kept under its own namespace so the top-level `uni::*` view
/// stays focused on what apps actually call.
pub mod diagnostics {
    /// Per-queue RX frame counts (Tier 1 multi-queue NIC). Index
    /// is the queue-pair number; `[0..num_queue_pairs()]` are
    /// meaningful, the rest are zero.
    pub fn net_rx_counts() -> [u64; 8] { uni_backend::net_rx_counts() }

    /// Negotiated RX/TX queue-pair count. Tier 2 (single-queue)
    /// reports 1; Tier 1 reports the per-vCPU count.
    pub fn net_num_queue_pairs() -> u16 { uni_backend::net_num_queue_pairs() }

    /// Per-queue used-ring cursors `(device, driver)`. Useful for
    /// spotting "device produced but driver didn't consume" gaps
    /// (cursors apart) vs "host not delivering" (both stuck).
    pub fn net_rx_used_cursors() -> [(u16, u16); 8] { uni_backend::net_rx_used_cursors() }

    /// Snapshot the heap. Cheap on bare-metal (O(1) + spinlock);
    /// best-effort zero on native.
    pub fn heap_stats() -> super::HeapStats { uni_backend::heap_stats() }
}

