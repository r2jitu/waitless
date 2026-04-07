// kernel/eventloop.rs — Unified per-core event loop.
//
// Every core runs the same loop: poll IO → drain inbox → service app →
// flush TX → idle if no work. All callbacks are registered via function
// pointers to avoid circular crate dependencies.
//
// After the app's main() returns, all cores enter eventloop::run().
// The loop runs until shutdown.

use core::sync::atomic::{AtomicBool, Ordering};

/// Callback types. All receive core_id, return true if work was done.
type PollFn = fn(u32) -> bool;

/// Registered callbacks. Written once during init, read by all cores.
struct Callbacks {
    /// Network poll: try to distribute RX, flush TX staging.
    net_poll: Option<PollFn>,
    /// Drain this core's RX inbox and process packets.
    net_drain: Option<PollFn>,
    /// Flush TX staging.
    net_flush: Option<fn()>,
    /// App-level service (HTTP connections, etc).
    service: Option<PollFn>,
    /// Check for shutdown signal (serial Ctrl-C).
    check_shutdown: Option<fn() -> bool>,
    /// Idle — sleep until interrupt/event.
    idle: Option<fn(u32)>,  // receives core_id
}

static mut CB: Callbacks = Callbacks {
    net_poll: None,
    net_drain: None,
    net_flush: None,
    service: None,
    check_shutdown: None,
    idle: None,
};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);

// ---- Registration API (called during boot/app init) ----

pub fn set_net_poll(f: PollFn) {
    unsafe { core::ptr::write_volatile(&raw mut CB.net_poll, Some(f)); }
}

pub fn set_net_drain(f: PollFn) {
    unsafe { core::ptr::write_volatile(&raw mut CB.net_drain, Some(f)); }
}

pub fn set_net_flush(f: fn()) {
    unsafe { core::ptr::write_volatile(&raw mut CB.net_flush, Some(f)); }
}

pub fn set_service(f: PollFn) {
    unsafe { core::ptr::write_volatile(&raw mut CB.service, Some(f)); }
}

pub fn set_check_shutdown(f: fn() -> bool) {
    unsafe { core::ptr::write_volatile(&raw mut CB.check_shutdown, Some(f)); }
}

pub fn set_idle(f: fn(u32)) {
    unsafe { core::ptr::write_volatile(&raw mut CB.idle, Some(f)); }
}

/// Signal that the app has finished initialization and the event loop
/// can start processing. Called by boot code after uni_main() returns.
pub fn set_ready() {
    READY.store(true, Ordering::Release);
    // Wake all cores so they stop waiting and enter the loop.
    crate::wake_cores();
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Run the event loop on the current core. Does not return until shutdown.
pub fn run(core_id: u32) -> ! {
    // Wait for the app to finish initialization before processing.
    // Core 0 calls set_ready() after uni_main() returns or Server::run() starts.
    while !READY.load(Ordering::Acquire) && !is_shutdown() {
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)); }
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    }

    loop {
        if is_shutdown() { break; }

        let mut did_work = false;

        // 1. Network poll: try to distribute RX + flush TX (rotating distributor)
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_poll) } {
            if f(core_id) { did_work = true; }
        }

        // 2. Drain this core's inbox
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_drain) } {
            if f(core_id) { did_work = true; }
        }

        // 3. App service (connections, handlers)
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.service) } {
            if f(core_id) { did_work = true; }
        }

        // 4. Check for shutdown
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.check_shutdown) } {
            if f() {
                request_shutdown();
                break;
            }
        }

        // 6. Idle if no work
        if !did_work {
            if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_flush) } {
                f(); // one more flush before sleeping
            }
            if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.idle) } {
                f(core_id);
            } else {
                #[cfg(target_arch = "aarch64")]
                unsafe { core::arch::asm!("wfe", options(nomem, nostack)); }
                #[cfg(target_arch = "x86_64")]
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
            }
        }
    }

    // Shutdown
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // PSCI CPU_OFF for APs, shutdown for BSP
        if core_id != 0 {
            core::arch::asm!(
                "hvc #0",
                in("x0") 0x8400_0002u64,
                options(nostack, nomem),
            );
        }
        loop { core::arch::asm!("wfi"); }
    }
    #[cfg(target_arch = "x86_64")]
    loop { unsafe { core::arch::asm!("hlt"); } }
}
