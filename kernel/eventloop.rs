// kernel/eventloop.rs — Unified per-core event loop.
//
// Every core runs the same loop: poll IO → drain inbox → service app →
// flush TX → idle if no work. All callbacks are registered via function
// pointers to avoid circular crate dependencies.
//
// After the app's main() returns, all cores enter eventloop::run().
// The loop runs until shutdown.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::sync::AtomicFn;

/// Callback types. All receive core_id, return true if work was done.
type PollFn = fn(u32) -> bool;
type VoidFn = fn();
type BoolFn = fn() -> bool;
type IdleFn = fn(u32);

/// Registered callbacks. Each `AtomicFn<F>` publishes a typed function
/// pointer with `Release` ordering on store / `Acquire` on load, so any
/// data the registrant wrote before publication is visible to consumer
/// cores when they observe the slot.
static NET_POLL: AtomicFn<PollFn> = AtomicFn::null();
static NET_DRAIN: AtomicFn<PollFn> = AtomicFn::null();
static NET_FLUSH: AtomicFn<VoidFn> = AtomicFn::null();
static SERVICE: AtomicFn<PollFn> = AtomicFn::null();
static CHECK_SHUTDOWN: AtomicFn<BoolFn> = AtomicFn::null();
static IDLE: AtomicFn<IdleFn> = AtomicFn::null();
/// Re-arm RX notifications for this core right before we HLT/WFI.
/// Returns true if work became available during the arm (a packet
/// arrived in the tiny window between the driver's last poll and
/// writing out the used-event sentinel). When that happens the loop
/// skips the idle and goes around again. See the NAPI pattern in
/// the event loop below.
type ArmFn = fn(u32) -> bool;
static NET_REARM_RX: AtomicFn<ArmFn> = AtomicFn::null();

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);

// ---- Registration API (called during boot/app init) ----

pub fn set_net_poll(f: PollFn) {
    NET_POLL.store(f);
}

pub fn set_net_drain(f: PollFn) {
    NET_DRAIN.store(f);
}

pub fn set_net_flush(f: VoidFn) {
    NET_FLUSH.store(f);
}

pub fn set_service(f: PollFn) {
    SERVICE.store(f);
}

pub fn set_check_shutdown(f: BoolFn) {
    CHECK_SHUTDOWN.store(f);
}

pub fn set_idle(f: IdleFn) {
    IDLE.store(f);
}

pub fn set_net_rearm_rx(f: ArmFn) {
    NET_REARM_RX.store(f);
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

    loop {
        if loops & 63 == 0 && is_shutdown() { break; }
        loops += 1;

        let mut did_work = false;

        // 1. Network poll: try to distribute RX + flush TX (rotating distributor)
        if let Some(f) = NET_POLL.load() {
            if f(core_id) { did_work = true; poll_work += 1; }
        }

        // 2. Drain this core's inbox
        if let Some(f) = NET_DRAIN.load() {
            if f(core_id) { did_work = true; drain_work += 1; }
        }

        // 3. App service (connections, handlers)
        if let Some(f) = SERVICE.load() {
            if f(core_id) { did_work = true; service_work += 1; }
        }

        // 3b. Flush TX after service — responses must be sent immediately
        // so keep-alive follow-up requests arrive promptly.
        if did_work {
            if let Some(f) = NET_FLUSH.load() { f(); }
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
            if let Some(f) = CHECK_SHUTDOWN.load() {
                if f() {
                    request_shutdown();
                    break;
                }
            }
        }

        // 5. Idle if no work
        if did_work {
            // work done — loop immediately
        } else {
            idle_count += 1;

            // Flush before sleeping (responses may be staged).
            if let Some(f) = NET_FLUSH.load() {
                f();
            }

            // NAPI-style re-arm: tell the device to notify us on the
            // next RX. The callback returns true if a packet already
            // landed between the last poll and now, in which case we
            // skip HLT and loop so we don't miss it.
            if let Some(arm) = NET_REARM_RX.load() {
                if arm(core_id) {
                    continue;
                }
            }

            // Sleep until interrupt. WFI/HLT yields the CPU to the
            // host; the hypervisor resumes us when an interrupt fires.
            if let Some(f) = IDLE.load() {
                f(core_id);
            } else {
                #[cfg(target_arch = "aarch64")]
                unsafe { core::arch::asm!("wfi", options(nomem, nostack)); }
                #[cfg(target_arch = "x86_64")]
                unsafe { core::arch::asm!("hlt", options(nomem, nostack)); }
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
