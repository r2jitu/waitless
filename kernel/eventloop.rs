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
    while !READY.load(Ordering::Acquire) && !is_shutdown() {
        #[cfg(target_arch = "aarch64")]
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
    }


    // Per-core counters for diagnostics.
    let mut loops: u64 = 0;
    let mut poll_work: u64 = 0;
    let mut drain_work: u64 = 0;
    let mut service_work: u64 = 0;
    let mut idle_count: u64 = 0;
    let mut consecutive_idle: u32 = 0;

    loop {
        if loops & 63 == 0 && is_shutdown() { break; }
        loops += 1;

        let mut did_work = false;

        // 1. Network poll: try to distribute RX + flush TX (rotating distributor)
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_poll) } {
            if f(core_id) { did_work = true; poll_work += 1; }
        }

        // 2. Drain this core's inbox
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_drain) } {
            if f(core_id) { did_work = true; drain_work += 1; }
        }

        // 3. App service (connections, handlers)
        if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.service) } {
            if f(core_id) { did_work = true; service_work += 1; }
        }

        // Periodic diagnostics (every ~1M loops)
        let print_interval = if core_id == 0 { 0x3FFFF } else { 0x1FFF };
        if loops & print_interval == 0 && loops > 0 {
            crate::serial::puts(b"[ev");
            crate::serial::puts(&[b'0' + (core_id as u8 % 10)]);
            crate::serial::puts(b"] L=");
            print_u64(loops);
            crate::serial::puts(b" p=");
            print_u64(poll_work);
            crate::serial::puts(b" d=");
            print_u64(drain_work);
            crate::serial::puts(b" s=");
            print_u64(service_work);
            crate::serial::puts(b" i=");
            print_u64(idle_count);
            crate::serial::puts(b"\n");
        }

        // 4. Check for shutdown (every 64 iterations to avoid MMIO overhead)
        if loops & 63 == 0 {
            if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.check_shutdown) } {
                if f() {
                    request_shutdown();
                    break;
                }
            }
        }

        // 5. Idle if no work
        if did_work {
            consecutive_idle = 0;
        } else {
            idle_count += 1;
            consecutive_idle = consecutive_idle.saturating_add(1);

            // Flush before sleeping (responses may be staged).
            if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.net_flush) } {
                f();
            }

            // Graduated backoff: spin briefly first, then deep sleep.
            // This reduces wasted HLT/WFI wakeups under MTTCG where
            // HLT doesn't properly block the host thread.
            if consecutive_idle < 8 {
                // Light idle: brief spin, stay responsive for incoming work
                for _ in 0..100u32 { core::hint::spin_loop(); }
            } else {
                // Heavy idle: deep sleep (interrupt-armed)
                if let Some(f) = unsafe { core::ptr::read_volatile(&raw const CB.idle) } {
                    f(core_id);
                } else {
                    #[cfg(target_arch = "aarch64")]
                    unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
                    #[cfg(target_arch = "x86_64")]
                    unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
                }
            }
        }
    }

    // Print diagnostics
    crate::serial::puts(b"[evloop] core ");
    crate::serial::puts(&[b'0' + (core_id as u8 % 10)]);
    crate::serial::puts(b": loops=");
    print_u64(loops);
    crate::serial::puts(b" poll=");
    print_u64(poll_work);
    crate::serial::puts(b" drain=");
    print_u64(drain_work);
    crate::serial::puts(b" svc=");
    print_u64(service_work);
    crate::serial::puts(b" idle=");
    print_u64(idle_count);
    crate::serial::puts(b"\n");

    // Shutdown — allow APs to print before exiting
    for _ in 0..100_000u32 { core::hint::spin_loop(); }

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

fn print_u64(mut val: u64) {
    if val == 0 { crate::serial::puts(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut len = 0;
    while val > 0 {
        buf[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    let mut out = [0u8; 20];
    for i in 0..len { out[i] = buf[len - 1 - i]; }
    crate::serial::puts(&out[..len]);
}
