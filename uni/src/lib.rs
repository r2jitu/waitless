// Platform abstraction: `TcpListener`, `TcpStream`, `log`, etc.
// Dispatch goes through `//uni-backend` which cfg-selects the
// unikernel or POSIX impl internally — `uni/lib.rs` stays uniform.

#![no_std]

extern crate alloc;

pub use uni_macros::init;

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
/// retained listener and tear down the network stack. Logs a
/// `HEAP_LEAK_CHECK` line at the end summarising the live-heap
/// delta versus the snapshot taken at `set_ready` time — a small
/// negative delta is normal (the boot task itself drains), but
/// growth is a leak.
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

    // Force-drop every live task across all workers' arenas. Listener
    // drops above flagged per-worker recv/accept tasks for abort, but
    // abort is normally honoured on the next `tick` — and APs have
    // already left the eventloop, so no further ticks happen. Walking
    // the arenas explicitly reclaims the `Box<dyn Future>` storage
    // before `arch::shutdown()` powers the VM off.
    uni_runtime::drain_all_arenas();

    // RST every still-open TCP connection so peers see an immediate
    // close instead of timing out via TCP keepalive. On the unikernel
    // this matters: `arch::shutdown()` would otherwise just power
    // the VM off mid-handshake. On native this is a no-op (the
    // kernel FINs every fd at process exit).
    uni_runtime::net::shutdown_all_tcp();

    // Tear down the NET slot symmetrically.
    net::clear_on_shutdown();

    // Heap-leak check. On native the backend's `heap_stats` returns
    // zeros (libstd's allocator exposes no counters), so the line
    // is informational only; on unikernel it's the actual talc
    // counters and a leaked allocation shows up as `LEAK +Nbytes`.
    let s = uni_backend::heap_stats();
    let bsl_b = HEAP_BASELINE_BYTES.load(core::sync::atomic::Ordering::Acquire);
    let bsl_a = HEAP_BASELINE_ALLOCS.load(core::sync::atomic::Ordering::Acquire);
    if s.allocated_bytes > bsl_b || s.allocation_count > bsl_a {
        crate::log!(
            "HEAP_LEAK_CHECK LEAK bytes={}->{} allocs={}->{} delta=+{}B,+{}allocs\n",
            bsl_b, s.allocated_bytes, bsl_a, s.allocation_count,
            s.allocated_bytes.saturating_sub(bsl_b),
            s.allocation_count.saturating_sub(bsl_a),
        );
    } else {
        crate::log!(
            "HEAP_LEAK_CHECK ok bytes={}->{} allocs={}->{}\n",
            bsl_b, s.allocated_bytes, bsl_a, s.allocation_count,
        );
    }
}

/// Snapshot of the heap at `set_ready` time. `shutdown_and_drop`
/// compares against this to decide whether teardown left memory
/// behind. Single-writer (BSP at end of boot), single-reader (BSP
/// during shutdown), so `Acquire` / `Release` is sufficient.
static HEAP_BASELINE_BYTES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static HEAP_BASELINE_ALLOCS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Signal that boot is complete and worker cores can leave their
/// READY-wait spin. Snapshots the heap allocation counters so
/// `shutdown_and_drop` can detect a leak. Called from the `#[uni::init]`
/// macro after the user's `init()` body returns.
pub fn set_ready() {
    let s = uni_backend::heap_stats();
    HEAP_BASELINE_BYTES.store(s.allocated_bytes, core::sync::atomic::Ordering::Release);
    HEAP_BASELINE_ALLOCS.store(s.allocation_count, core::sync::atomic::Ordering::Release);
    uni_backend::set_ready();
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
    check_shutdown, log, num_workers, request_shutdown,
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
        TcpBindError, TcpHandle, TcpListener, TcpRecv, TcpSendChain, TcpStream,
        UdpBindError, UdpClient, UdpHandle, UdpRecv, UdpRecvInplace, UdpSocket,
    };
    pub use uni_runtime::select::{
        join, join3, select, select3, timeout_us, Either, Three,
    };
    /// Family-agnostic IP address used in `UdpSocket::recv_from` /
    /// `send_to` and elsewhere on the runtime API. Re-exported so
    /// callers don't need to add a `net_types` dep just to pattern-
    /// match the source of an inbound datagram.
    pub use uni_runtime::ip::{IpAddr, Ipv4Addr, Ipv6Addr};
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

    /// TX-side hot-path counters: per-qp packet counts + small/big
    /// pool saturation + scan-depth aggregates. `None` when no
    /// driver is bound or the active driver hasn't wired the
    /// accessor.
    ///
    /// Read-side division gives the average linear-scan depth on
    /// small-pool acquires:
    /// `small_pool_scan_iters / small_pool_acquires`. High values
    /// (e.g. > pool_size/2) suggest replacing the
    /// `[AtomicBool; N]` scan with a real freelist; low values
    /// mean the linear scan is fine and a freelist would just add
    /// code.
    ///
    /// `small_pool_full_spins` and `big_pool_full_returns` flag
    /// pool sizing — a steady non-zero rate means the pool is
    /// undersized for the load.
    pub fn net_tx_diag() -> Option<uni_backend::NetTxDiag> {
        uni_backend::net_tx_diag()
    }

    /// Snapshot the active driver's TX descriptor capture log into
    /// the caller's buffer. Returns the number of valid entries
    /// written. Returns 0 on native and on drivers without per-
    /// descriptor instrumentation (currently only gve has it,
    /// for TSO-on-GCE debug). Surfaced via `/diag-gve`.
    pub fn net_tx_desc_log_snapshot(out: &mut [uni_backend::NetTxDescLogEntry]) -> usize {
        uni_backend::net_tx_desc_log_snapshot(out)
    }

    /// Per-core event-loop stats: `(loops, poll_work, drain_work,
    /// service_work, idle_enters, busy_cycles, idle_cycles)`.
    ///
    /// `busy_cycles + idle_cycles` ≈ wall-clock cycles since boot
    /// on this core; `idle_cycles / total` is the per-core idle
    /// fraction. The work counters tell whether the busy time was
    /// going to net poll / inbox drain / app service. All zeros
    /// on native (the OS owns scheduling).
    pub fn core_stats(core_id: u32) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        uni_backend::core_stats(core_id)
    }

    /// Cycles-per-microsecond multiplier — divide cycle deltas by
    /// this to get microseconds. 0 on native.
    pub fn cycles_per_us() -> u64 {
        uni_backend::cycles_per_us()
    }

    pub use uni_backend::NET_DIAG_QP_CAP;
    pub use uni_backend::NetTxDescLogEntry;
    pub use uni_backend::NetTxDiag;

    /// Snapshot the heap. Cheap on bare-metal (O(1) + spinlock);
    /// best-effort zero on native.
    pub fn heap_stats() -> super::HeapStats { uni_backend::heap_stats() }

    /// Append a byte slice to the in-band diag buffer. For boot-time
    /// KATs and one-shot probes that want their results to land in
    /// `/diag-panic` alongside any later panic traces.
    pub fn diag_append(bytes: &[u8]) { uni_backend::diag_append(bytes) }

    /// Append a 16-char hex-encoded u64 (no `0x` prefix). Pairs with
    /// `diag_append` for format-free logging from boot-critical code
    /// paths.
    pub fn diag_append_hex(value: u64) { uni_backend::diag_append_hex(value) }

    /// Append a 2-char hex-encoded u8. For dumps of byte windows
    /// where the u64 form would print 14 leading zeros per byte.
    pub fn diag_append_hex_u8(value: u8) {
        uni_backend::diag_append_hex_u8(value)
    }

    /// Snapshot the in-band diag-capture buffer (kernel panics +
    /// unhandled CPU exceptions + `diag_append` records). Returns
    /// the byte count written to `out`. Native build returns 0 (no
    /// kernel panics to capture).
    ///
    /// The buffer is FIFO-bounded; up to ~4 KiB of records survive
    /// the panicking core's halt and are readable by any other core
    /// (or the same core after recovery, if it didn't actually
    /// halt). See `kernel::diag` for the format.
    pub fn diag_snapshot(out: &mut [u8]) -> usize {
        uni_backend::diag_snapshot(out)
    }

    /// Bytes captured so far. Cheap "is there anything to show?"
    /// check for the `/diag-panic` endpoint.
    pub fn diag_captured_len() -> usize {
        uni_backend::diag_captured_len()
    }

    /// Reset the diag buffer to empty. Used by debugger workflows
    /// that want a fresh capture per repro iteration.
    pub fn diag_reset() {
        uni_backend::diag_reset()
    }
}

