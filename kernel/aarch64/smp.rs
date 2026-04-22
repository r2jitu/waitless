// kernel/aarch64/smp.rs — Multi-core boot for aarch64.
//
// Uses PSCI CPU_ON to start secondary cores (APs). Core 0 (BSP) calls
// this after all init is complete.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::serial;
use crate::mm;
use super::exceptions;

/// Per-core stack size: 64KB (16 pages).
const AP_STACK_SIZE: usize = 64 * 1024;

/// Maximum number of cores supported.
pub const MAX_CORES: usize = 8;

/// Global shutdown flag — set by core 0, checked by all APs.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Per-core state, allocated by core 0 during boot.
struct CoreState {
    stack_top: u64,
}

// Per-core state is written exclusively on the BSP during boot
// (`start_secondary_cores`) before the targeted AP starts reading it —
// `stack_top` is handed to PSCI CPU_ON as the context id, which the AP
// picks up in x0 on entry. `UnsafeCell` + `unsafe impl Sync` captures
// the single-writer-during-boot contract without the `static_mut_refs`
// footgun (plan Phase 7).
struct CoreArraySlot(core::cell::UnsafeCell<[CoreState; MAX_CORES]>);
// SAFETY: BSP-only writes during boot; APs consume stack_top via PSCI
// context_id, not by reading back through this static.
unsafe impl Sync for CoreArraySlot {}

static CORES: CoreArraySlot = CoreArraySlot(
    core::cell::UnsafeCell::new([const { CoreState { stack_top: 0 } }; MAX_CORES])
);

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
fn psci_cpu_on(target_cpu: u64, entry_point: u64, context_id: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") 0xC400_0003u64 => ret,  // PSCI CPU_ON (SMC64)
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
            options(nomem, nostack),
        );
    }
    ret
}

/// Boot secondary cores. Called by core 0 after all init is complete.
pub unsafe fn start_secondary_cores(cpu_count: u32) {
    unsafe {
    if cpu_count <= 1 {
        return;
    }

    let count = cpu_count.min(MAX_CORES as u32);
    serial::puts(b"[SMP] Starting secondary cores...\n");

    for i in 1..count {
        // Allocate stack for this AP
        let stack_pages = AP_STACK_SIZE / 4096;
        let stack_base = mm::alloc_pages(stack_pages);
        if stack_base == 0 {
            serial::puts(b"[SMP] Failed to allocate stack for core\n");
            continue;
        }
        let stack_top = stack_base + AP_STACK_SIZE as u64;
        (*CORES.0.get())[i as usize].stack_top = stack_top;

        // Start the AP at the assembly trampoline (handles MMU + VBAR setup).
        // stack_top passed as context_id (x0 when AP starts).
        unsafe extern "C" { fn ap_trampoline(); }
        // Cast through a function pointer first; rust 1.93+ rejects
        // casting a function item directly to an integer.
        let entry = ap_trampoline as unsafe extern "C" fn() as u64;
        let ret = psci_cpu_on(i as u64, entry, stack_top);
        if ret != 0 {
            serial::puts(b"[SMP] PSCI CPU_ON failed\n");
        }
    }

    // Wait for all APs to come online (timeout after ~100ms)
    for _ in 0..100_000 {
        if num_cores_online() >= count {
            break;
        }
        core::arch::asm!("nop");
    }

    // Log result
    let online = num_cores_online();
    let mut buf = [0u8; 40];
    let mut pos = 0;
    for &b in b"[SMP] " { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], online);
    for &b in b"/" { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], count);
    for &b in b" cores online\n" { buf[pos] = b; pos += 1; }
    serial::puts(&buf[..pos]);
    } // unsafe
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
        for &b in b"[SMP] core " { buf[pos] = b; pos += 1; }
        pos += fmt_u32(&mut buf[pos..], id);
        for &b in b" online\n" { buf[pos] = b; pos += 1; }
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
            let val: u32 = (1 << (16 + target_core)) | 0; // target core, SGI 0
            core::ptr::write_volatile(sgir as *mut u32, val);
        }
    }
}

/// SGI 0 handler — called on the receiving core by the GIC exception dispatcher.
/// This is just a wakeup signal — all real work happens in the event loop.
/// The fetch-add serves a second purpose: `ipi_count()` reads it from
/// tests (apps/test_smp) to verify the SGI actually landed. On the hot
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
            let val: u32 = (1 << 24) | 0; // target filter = all other, SGI 0
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
