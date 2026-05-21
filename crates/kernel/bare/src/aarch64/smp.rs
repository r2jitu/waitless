// kernel/aarch64/smp.rs — Multi-core boot for aarch64.
//
// Uses PSCI CPU_ON to start secondary cores (APs). Core 0 (BSP) calls
// this after all init is complete.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::exceptions;
use crate::mm;
use crate::serial;

/// Per-core stack size: 64KB (16 pages).
const AP_STACK_SIZE: usize = 64 * 1024;

/// Global shutdown flag — set by core 0, checked by all APs.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Number of cores that have come online (BSP + APs that called `ap_entry`).
static NUM_CORES_ONLINE: AtomicU32 = AtomicU32::new(1); // BSP is always online

/// Get the current CPU's logical core index.
///
/// Reads TPIDR_EL1 which points to this core's PerCore struct, then
/// loads the `id` field (offset 0). Cost: ~2 cycles (mrs + ldr).
pub fn cpu_id() -> u32 {
    let id: u32;
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, tpidr_el1",
            "ldr {id:w}, [{tmp}]",
            tmp = out(reg) _,
            id = out(reg) id,
            options(nomem, nostack),
        );
    }
    id
}

/// Set TPIDR_EL1 to point at this core's PerCore struct. Called once per core.
pub fn init_tls(id: u32) {
    unsafe {
        let addr = crate::percpu::get(id) as *const crate::percpu::PerCore as u64;
        core::arch::asm!("msr tpidr_el1, {}", in(reg) addr, options(nomem, nostack));
    }
}

/// Returns the number of cores that have booted.
pub fn num_cores_online() -> u32 {
    NUM_CORES_ONLINE.load(Ordering::Acquire)
}

/// PSCI CPU_ON via HVC (QEMU virt uses PSCI 0.2 conduit=hvc).
/// Returns 0 on success, negative PSCI error otherwise.
/// PSCI CPU_ON via HVC (QEMU virt default conduit).
///
/// The return value is not reliably captured on HVF — the host's
/// `hv_vcpu_set_reg(X0, PSCI_SUCCESS)` writeback is shadowed on
/// resume by something in HVF's exception-state plumbing, so the
/// guest reads back a stack-aliased kernel pointer regardless of
/// what we set. The same asm captures non-zero sentinels correctly
/// (we tested with 0xDEAD…BABE), which narrows it to HVF's handling
/// of zero-valued GPR writebacks. QEMU TCG returns 0 properly.
///
/// Callers should treat this function as "side-effect only" and
/// confirm AP startup by polling `NUM_CORES_ONLINE` rather than
/// gating on the return value.
fn psci_cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") 0xC400_0003u64 => ret,
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
            options(nomem, nostack),
        );
    }
    ret
}

/// Boot secondary cores. Called by core 0 after all init is complete.
///
/// No BSP-side wait or count print. APs come up asynchronously and
/// each prints its own `[SMP] core N online` from the AP entry path;
/// that's the source of truth for "did the core come up." A previous
/// BSP wait expired before slow APs (TCG: 100-500 ms wall-clock per
/// core for PSCI CPU_ON + MMU + percpu TLS setup) and printed
/// "3/4 cores online" right before the slow AP's own line.
///
/// Code that needs all cores up before proceeding waits on its own
/// signal: `eventloop::run` on each AP spins on `READY` until user
/// init's `set_ready()` fires; tests use `kernel::wait_for_cores_online`.
///
/// # Safety
///
/// Must be called exactly once, by the BSP only, after the MMU,
/// per-core areas, GIC, and page allocator are fully initialized.
/// `cpu_count` must be the core count reported by the FDT — the
/// loop issues PSCI `CPU_ON` for logical CPUs `1..cpu_count`, so a
/// value larger than the platform's core count starts non-existent
/// cores. Each AP runs the assembly trampoline and `ap_entry`,
/// which assumes those facilities are already live.
pub unsafe fn start_secondary_cores(cpu_count: u32) {
    if cpu_count <= 1 {
        return;
    }
    serial::puts(b"[SMP] Starting secondary cores...\n");

    for i in 1..cpu_count {
        let stack_pages = AP_STACK_SIZE / 4096;
        let stack_base = mm::alloc_pages(stack_pages);
        if stack_base == 0 {
            serial::puts(b"[SMP] Failed to allocate stack for core\n");
            continue;
        }
        let stack_top = stack_base + AP_STACK_SIZE as u64;

        // Start the AP at the assembly trampoline (handles MMU + VBAR setup).
        // stack_top passed as context_id (x0 when AP starts).
        unsafe extern "C" {
            fn ap_trampoline();
        }
        // Cast through a function pointer, then `usize`, before
        // widening to `u64`: rust 1.93+ rejects casting a function
        // item directly to an integer, and clippy rejects casting a
        // function pointer straight to `u64`.
        let entry = ap_trampoline as unsafe extern "C" fn() as usize as u64;
        // PSCI return doesn't survive the HVF X0 writeback (see
        // `psci_cpu_on` docs), so we don't gate the loop on it. The
        // AP-incremented online counter is the source of truth, and
        // we wait briefly for each AP before moving to the next
        // because:
        //   1. ap_entry's first runtime tick lazily allocates this
        //      core's TaskArena (~2 MB). Without serialisation,
        //      several APs racing into the heap allocator at once
        //      can OOM each other before the BSP's next stack
        //      allocation runs.
        //   2. Per-AP latency on PSCI CPU_ON via HVF is sub-ms, so
        //      the wait barely costs anything in the success path.
        // PSCI return doesn't survive HVF's X0 writeback (see
        // `psci_cpu_on` docs), so we don't trust it. Wait for the
        // AP to increment the online counter before launching the
        // next one, with a generous spin budget rather than a
        // wall-clock deadline (now_cycles can read stale values
        // when LLVM hoists the mrs instruction). The wait also
        // serializes per-AP heap allocation: without it, multiple
        // APs racing into `eventloop::run` → first `tick` →
        // `TaskArena::new()` exhaust the heap before the BSP's
        // next stack alloc.
        // Wait briefly for the AP to come online. PSCI's return code
        // doesn't survive HVF's X0 writeback (see `psci_cpu_on` docs)
        // so we use the AP-incremented counter as ground truth, bounded
        // by `udelay`-paced retries. The wait also serializes per-AP
        // heap allocation: without it, multiple APs racing into
        // `eventloop::run` → first `tick` → `TaskArena::new()` exhaust
        // the heap before the BSP's next stack alloc.
        let before = NUM_CORES_ONLINE.load(Ordering::Acquire);
        let _ = psci_cpu_on(i as u64, entry, stack_top);
        for _ in 0..500 {
            if NUM_CORES_ONLINE.load(Ordering::Acquire) > before {
                break;
            }
            crate::time::udelay(100); // 100 µs × 500 = 50 ms cap
        }
        if NUM_CORES_ONLINE.load(Ordering::Acquire) <= before {
            serial::puts(b"[SMP] core failed to come online\n");
        }
    }
}

/// AP entry point — called from ap_trampoline (boot.S) after MMU + VBAR + stack
/// are set up. x0 = stack_top (unused here, stack already set by trampoline).
#[unsafe(no_mangle)]
unsafe extern "C" fn ap_entry(_stack_top: u64) -> ! {
    unsafe {
        // Set TPIDR_EL1 for fast cpu_id(). MPIDR Aff0 = logical core index on QEMU virt.
        let mpidr: u64;
        core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr, options(nomem, nostack));
        init_tls((mpidr & 0xFF) as u32);

        // Initialize this core's GIC redistributor
        exceptions::init_ap();

        // Register SGI 0 handler for IPI
        exceptions::register_irq(0, sgi_handler);

        // Unmask IRQs so SGI can be delivered
        core::arch::asm!("msr daifclr, #0x2", options(nomem, nostack));

        // Mark this core as online.
        NUM_CORES_ONLINE.fetch_add(1, Ordering::AcqRel);

        // Log
        let id = cpu_id();
        let mut buf = [0u8; 24];
        let mut pos = 0;
        for &b in b"[SMP] core " {
            buf[pos] = b;
            pos += 1;
        }
        pos += fmt_u32(&mut buf[pos..], id);
        for &b in b" online\n" {
            buf[pos] = b;
            pos += 1;
        }
        serial::puts(&buf[..pos]);

        // Enter the unified kernel event loop.
        // Runs: net poll → inbox drain → app service → TX flush → idle.
        // Does not return until shutdown.
        crate::eventloop::run(cpu_id());
    }
}

/// Counter of IPIs received across all cores (for testing).
static IPI_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Send SGI 0 to a specific core.
/// Supports both GICv2 (GICD_SGIR MMIO) and GICv3 (ICC_SGI1_EL1).
pub fn send_sgi_to(target_core: u32) {
    unsafe {
        let fdt = super::fdt::info();
        if fdt.gic_version == 3 {
            // GICv3: ICC_SGI1_EL1 system register
            let sgi_val: u64 = 1u64 << (target_core as u64);
            core::arch::asm!(
                "msr S3_0_C12_C11_5, {0}",
                "isb",
                in(reg) sgi_val,
                options(nostack),
            );
        } else {
            // GICv2: GICD_SGIR at offset 0xF00 from distributor base
            // Bits [25:24] = 0 (target list filter: use target list)
            // Bits [23:16] = target CPU mask
            // Bits [3:0] = SGI INTID (0)
            let sgir = fdt.gic_dist_base + 0xF00;
            // [23:16] = target CPU mask; [3:0] = SGI INTID 0 (zero).
            let val: u32 = 1 << (16 + target_core);
            core::ptr::write_volatile(sgir as *mut u32, val);
        }
    }
}

/// SGI 0 handler — called on the receiving core by the GIC exception dispatcher.
/// This is just a wakeup signal — all real work happens in the event loop.
/// The fetch-add serves a second purpose: `ipi_count()` reads it from
/// tests (tests/integration/smp) to verify the SGI actually landed. On the hot
/// path the cost is a single Relaxed add per interrupt.
pub fn sgi_handler(_irq: u32) {
    IPI_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get the total IPI count (for testing).
pub fn ipi_count() -> u32 {
    IPI_COUNT.load(Ordering::Relaxed)
}

/// Signal all APs to shut down. Called by core 0 before system poweroff.
pub fn request_shutdown() {
    if num_cores_online() <= 1 {
        return;
    }
    SHUTDOWN.store(true, Ordering::Relaxed);
    // Send SGI 0 to all other cores to wake them from WFI
    unsafe {
        let fdt = super::fdt::info();
        if fdt.gic_version == 3 {
            let sgi_val: u64 = 1 << 40; // IRM=1: all other PEs
            core::arch::asm!(
                "msr S3_0_C12_C11_5, {0}",
                "isb",
                in(reg) sgi_val,
                options(nostack),
            );
        } else {
            // GICv2: GICD_SGIR, broadcast to all other CPUs
            let sgir = fdt.gic_dist_base + 0xF00;
            // [25:24] = 0b01 (target filter: all other PEs); [3:0] = SGI INTID 0 (zero).
            let val: u32 = 1 << 24;
            core::ptr::write_volatile(sgir as *mut u32, val);
        }
    }
}

/// Check if shutdown has been requested.
pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Format a u32 into decimal in a byte buffer. Returns bytes written.
fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = tmp[len - 1 - i];
    }
    len
}
