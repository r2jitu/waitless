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
// App framework — the runtime's handle on the user's program
// ----------------------------------------------------------------------------
//
// The user constructs any value (typically a struct holding the
// app's long-lived state — HTTP `Server`, TLS config, background-
// task handles, …) inside `#[uni::boot] fn boot()` and hands it
// to `uni::run`. The runtime stores it for the lifetime of the
// event loop and drops it on graceful shutdown — Drop is the
// teardown hook.
//
// The runtime touches the app only from the boot CPU (core 0 on
// unikernel, main thread on native), so the `T: 'static` bound is
// the only constraint — no `Send`/`Sync`, no marker trait.
//
// Soundness: the runtime stores `Box<dyn Any>` in a static slot
// wrapped in `UnsafeCell`. One `unsafe impl Sync` lets the static
// hold it; the contract is "boot CPU only", upheld by the two
// access sites (`run` from `uni_boot`, `shutdown_and_drop` from
// the BSP branch of the event-loop exit or native's main after
// `pthread_join`).

/// A bag for values that exist solely so their `Drop` runs at
/// shutdown — typically [`runtime::TcpHandle`] / [`runtime::UdpHandle`]
/// returned from `listen` / `run`, and the [`net::Net`] guard.
///
/// **Why this exists.** The naive "store each handle as
/// `_http: Option<TcpHandle>` field on your App struct" pattern
/// works but is a footgun: a reader who sees `_http` reasonably
/// concludes it's unused and deletes it, silently tearing down the
/// listener at boot. `Handles::keep` says explicitly "this value
/// is alive because I asked for it to be."
///
/// ```rust,ignore
/// let mut handles = uni::Handles::new();
/// handles.keep(uni::http::listen(80, handle_request)?);
/// handles.keep(uni::http::listen_tls(443, handle_request, cert, key)?);
/// handles.keep(udp_echo);
/// uni::run(MyApp { handles, /* ... */ });
/// ```
///
/// Items drop in insertion order when the `Handles` itself drops —
/// store `Net` last (or a separate field) if you need network
/// teardown to outlive listener tasks.
pub struct Handles {
    items: alloc::vec::Vec<alloc::boxed::Box<dyn core::any::Any>>,
}

impl Handles {
    /// Empty bag.
    pub fn new() -> Self {
        Handles { items: alloc::vec::Vec::new() }
    }

    /// Take ownership of `value` so it stays alive until the
    /// `Handles` itself drops. Returns `&mut self` for chaining.
    pub fn keep<T: 'static>(&mut self, value: T) -> &mut Self {
        self.items.push(alloc::boxed::Box::new(value));
        self
    }

    /// Keep `result` if it's `Ok`; log a `[<name>] bind failed` line
    /// if it's `Err`. The label appears verbatim in the log;
    /// keeping it short and consistent (`"http"`, `"tcp echo"`,
    /// `"gateway"`) makes integration-test grep predictable.
    ///
    /// Idiomatic for the bind cascade in `#[uni::boot]`: each
    /// listener that fails to bind logs and is skipped, and
    /// successful binds collect into the bag with no `match` ladder.
    pub fn keep_or_log<T: 'static, E>(
        &mut self,
        name: &str,
        result: Result<T, E>,
    ) -> &mut Self {
        match result {
            Ok(v) => {
                crate::println!("[{}] listening", name);
                self.items.push(alloc::boxed::Box::new(v));
            }
            Err(_) => {
                crate::println!("[{}] bind failed", name);
            }
        }
        self
    }

    /// Number of items currently kept.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True iff no items are kept.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Default for Handles {
    fn default() -> Self {
        Self::new()
    }
}

// --- Runtime storage --------------------------------------------------------

/// Single-slot storage for the runtime-owned app. Accessed only
/// from the boot CPU (see `unsafe impl Sync` below).
struct AppSlot(core::cell::UnsafeCell<Option<alloc::boxed::Box<dyn core::any::Any>>>);

// SAFETY: every read/write of `APP_SLOT` is on the boot CPU:
//   - `run` is called from `uni_boot` (BSP on unikernel, main thread
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
pub fn run<A: 'static>(app: A) {
    let boxed: alloc::boxed::Box<dyn core::any::Any> = alloc::boxed::Box::new(app);
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
    check_shutdown, config_port, log, num_workers, request_shutdown, set_ready,
    wait_for_events, HeapStats,
};

/// Backward-compatible alias for `config_port`. Both HTTP and HTTPS
/// run over plain TCP, so the env-var namespace is shared
/// (`UNIKERNEL_TCP_<port>`); calling `config_port(443)` is the same
/// thing.
#[deprecated = "use config_port — HTTPS uses the same TCP env namespace"]
pub fn config_tls_port(default_port: u16) -> u16 {
    config_port(default_port)
}

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
        UdpBindError, UdpFlow, UdpHandle, UdpRecv, UdpRecvInplace, UdpSocket,
    };
    pub use uni_runtime::select::{
        join, join3, select, select3, timeout_us, Either, Three,
    };
}

// Top-level shortcuts for the most common runtime calls. The full
// `uni::runtime::*` namespace stays available for everything else.
pub use uni_runtime::net::{tcp_listen, udp_listen, UdpFlow};

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

