// kernel/eventloop.rs — Unified per-core event loop.
//
// Every core runs the same loop: poll IO → drain inbox → service app →
// flush TX → idle if no work. All callbacks are registered via function
// pointers to avoid circular crate dependencies.
//
// All cores enter eventloop::run() after boot. Core 0 drives the
// spawned boot task (see `#[uni::boot]`); APs wait for `set_ready`
// from the app's `uni::run(app)`. The loop runs until shutdown.

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
/// Invoked on the BSP exactly once, right after the loop breaks and
/// before the machine powers off. Lets upper layers (e.g. `uni`'s
/// App dispatch) run `destroy`-style teardown while the heap is
/// still intact. Nothing else in the kernel depends on a running
/// app at this point, so ordering is simple.
static ON_SHUTDOWN: AtomicFn<VoidFn> = AtomicFn::null();
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

/// Register a teardown callback invoked on the BSP between the event
/// loop exit and the architectural power-off. `uni` uses this to run
/// `App::destroy` with the heap still live.
pub fn set_on_shutdown(f: VoidFn) {
    ON_SHUTDOWN.store(f);
}

pub fn set_net_rearm_rx(f: ArmFn) {
    NET_REARM_RX.store(f);
}

/// Signal that the app has finished initialization and the event loop
/// can start processing. Called by boot code after uni_init() returns.
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

/// True after `set_ready()` has been called. Pre-`set_ready` is the
/// boot-task window: APs are still idling at the top of `run()`,
/// only the BSP is polling. Used by the net stack to widen the
/// BSP's RX coverage during this window so packets vhost-net
/// hashes to a queue whose owning AP hasn't started polling yet
/// (e.g. DHCP replies on queue 1 of a multi-queue NIC) still get
/// drained.
pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Run the event loop on the current core. Does not return until shutdown.
pub fn run(core_id: u32) -> ! {
    // APs wait for the app's `set_ready` so they don't hammer the
    // NIC / inbox machinery before listeners are registered. Core 0
    // skips this wait — its event loop drives the spawned boot task
    // (see `#[uni::boot]`), and that task is what eventually calls
    // `set_ready`. Blocking here would deadlock because nothing
    // else polls the runtime.
    if core_id != 0 {
        while !READY.load(Ordering::Acquire) && !is_shutdown() {
            crate::cpu::idle_unbounded();
        }
    }


    // Per-core counters for diagnostics.
    let mut loops: u64 = 0;
    let mut poll_work: u64 = 0;
    let mut drain_work: u64 = 0;
    let mut service_work: u64 = 0;
    let mut idle_count: u64 = 0;
    // Consecutive iterations with did_work == false. Used to spin for
    // a short window before we commit to HLT/WFI, so back-to-back
    // interactive requests don't eat an IRQ round-trip each.
    let mut idle_streak: u32 = 0;

    // How many no-work iterations to spin through before arming the
    // next RX IRQ and going idle. Each iteration is a full poll +
    // drain + service cycle and costs ~200ns.
    //
    // 64 (~13 µs) was the original; comments-of-record had it
    // verified on HVF udp_peak as no-difference vs 1024 / u32::MAX,
    // and tuned to "longer than one KVM exit+enter round-trip" so
    // an interactive keep-alive caught the next packet without
    // arming an IRQ. Empirically that's not the right floor on
    // either current path:
    // - On *nested-KVM* dev benches (`scripts/bench.py --env kvm`),
    //   tcp_echo_max with 16 conns/core ping-ponging hits a ~1.1 ms
    //   per-conn RTT floor because the guest halts between every
    //   batch and eats halt→IRQ→wake on the critical path. Widening
    //   to ~10 k iterations keeps the guest in poll mode through one
    //   full host-side bounce and lifts tcp_echo from ~44 k to ~169 k
    //   msg/s on KVM 3c; `*_c1` (single-flow) workloads see 4–10×.
    // - On *deployed gVNIC* (production target), reverting to 64
    //   crushes everything roughly the same way: `health_max` 418 k
    //   → 111 k, `tcp_echo_max` 216 k → 60 k, `health_c1` 15 k → 1 k.
    //   The async-reactor refactor (commits 4cfa316 / 53841c2 /
    //   2f91e17) added per-packet inbox+wake overhead; with a 13 µs
    //   spin window the guest halts between every dispatch boundary.
    //
    // 10 000 (~2 ms) keeps both deployed and nested-virt paths in
    // poll mode through their natural inter-batch gaps. Idle
    // workloads still halt within 2 ms; the extra busy-spin is
    // bounded.
    const IDLE_SPIN_BEFORE_HLT: u32 = 10_000;

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

        // 3a. Async runtime: advance timers (drain pending MPSC + fire
        // expired), then poll every ready task slot in the per-core
        // arena. Spawned futures live here. See uni_kernel::runtime.
        if uni_runtime::tick(core_id) {
            did_work = true;
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
            idle_streak = 0;
        } else {
            idle_count += 1;
            idle_streak += 1;

            // Busy-poll for a short window before committing to HLT.
            // A pure "did_work==false → HLT" policy pays one IRQ
            // round-trip per request on interactive TCP (SYN, then
            // ACK, then GET, …) which costs several microseconds each
            // and caps per-core throughput. Spinning for a brief
            // window after the queue empties catches follow-up packets
            // without leaving poll mode.
            if idle_streak < IDLE_SPIN_BEFORE_HLT {
                continue;
            }

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
                    idle_streak = 0;
                    continue;
                }
            }

            // Sleep until interrupt. WFI/HLT yields the CPU to the
            // host; the hypervisor resumes us when an interrupt fires.
            idle_streak = 0;
            if uni_runtime::has_pending(core_id) {
                // The executor has a pending timer or a task ready to
                // re-poll. Force a local-timer-bounded idle so we wake
                // promptly — the normal IDLE hook on HVF uses the
                // cooperative yield register, which only wakes on host
                // IO and would strand a timer-driven task indefinitely.
                let cycles_per_ms = crate::time::cycles_per_us().saturating_mul(1000);
                crate::cpu::idle_until_cycles(cycles_per_ms);
            } else if let Some(f) = IDLE.load() {
                f(core_id);
            } else {
                crate::cpu::idle_bounded();
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

    // App teardown — only the BSP runs this, and it runs before the
    // architectural power-off (which never returns). APs fall through
    // to their own CPU_OFF below without touching app state.
    if core_id == 0 {
        if let Some(f) = ON_SHUTDOWN.load() {
            f();
        }
    }

    // Shutdown — allow APs to print before exiting
    for _ in 0..100_000u32 { core::hint::spin_loop(); }

    #[cfg(target_arch = "aarch64")]
    unsafe {
        // APs: PSCI CPU_OFF (0x8400_0002) and park in WFI.
        // BSP: PSCI SYSTEM_OFF (0x8400_0008) — actually powers the
        // machine off. Previously the BSP branch fell into `loop wfi`
        // without ever issuing SYSTEM_OFF, so Ctrl-C would break out
        // of the event loop, print the `[evloop] …` diagnostic, and
        // then hang forever waiting for a signal that never came
        // (the hvf-runner's handle_hvc only exits on SYSTEM_OFF).
        if core_id != 0 {
            core::arch::asm!(
                "hvc #0",
                in("x0") 0x8400_0002u64,
                options(nostack, nomem),
            );
        } else {
            core::arch::asm!(
                "movz x0, #0x8400, lsl #16",
                "movk x0, #0x0008",
                "hvc #0",
                out("x0") _,
                options(nomem, nostack),
            );
        }
        loop { core::arch::asm!("wfi"); }
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // BSP: ACPI S5 (soft off) via PM1_CNT. Same port/value triples
        // as boot::arch_shutdown — try QEMU/KVM (0x604 ← 0x2000), the
        // old Bochs value (0x604 ← 0x3400), and VirtualBox (0xb004 ←
        // 0x2000). The aarch64 branch above issues PSCI SYSTEM_OFF; on
        // x86 this used to fall straight into `loop { hlt }`, so Ctrl-C
        // would break the event loop, print `[evloop] …`, and hang
        // forever with QEMU still running. APs just HLT: when the BSP
        // successfully writes PM1_CNT, QEMU tears the whole VM down.
        if core_id == 0 {
            core::arch::asm!("out dx, ax", in("dx") 0x0604u16, in("ax") 0x2000u16, options(nomem, nostack));
            core::arch::asm!("out dx, ax", in("dx") 0x0604u16, in("ax") 0x3400u16, options(nomem, nostack));
            core::arch::asm!("out dx, ax", in("dx") 0xb004u16, in("ax") 0x2000u16, options(nomem, nostack));
        }
        loop { core::arch::asm!("cli", "hlt", options(nomem, nostack)); }
    }
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
