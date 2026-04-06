// kernel/aarch64/smp.rs — Multi-core boot for aarch64.
//
// Uses PSCI CPU_ON to start secondary cores (APs). Core 0 (BSP) calls
// this after all init is complete.

use crate::serial;
use crate::mm;
use super::exceptions;

/// Per-core stack size: 64KB (16 pages).
const AP_STACK_SIZE: usize = 64 * 1024;

/// Maximum number of cores supported.
pub const MAX_CORES: usize = 8;

/// Per-core state, allocated by core 0 during boot.
struct CoreState {
    stack_top: u64,
}

static mut CORES: [CoreState; MAX_CORES] = [const { CoreState { stack_top: 0 } }; MAX_CORES];
static mut NUM_CORES_ONLINE: u32 = 1; // BSP is always online

/// Get the current CPU ID from MPIDR_EL1.
pub fn cpu_id() -> u32 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr) };
    // Aff0 is the core ID within a cluster
    (mpidr & 0xFF) as u32
}

/// Returns the number of cores that have booted.
pub fn num_cores_online() -> u32 {
    unsafe { core::ptr::read_volatile(&NUM_CORES_ONLINE) }
}

/// PSCI CPU_ON via HVC (QEMU virt uses PSCI 0.2 conduit=hvc).
/// Returns 0 on success, negative PSCI error otherwise.
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
        CORES[i as usize].stack_top = stack_top;

        // Start the AP — pass stack_top as context_id (x3)
        let entry = ap_entry as u64;
        let ret = psci_cpu_on(i as u64, entry, stack_top);
        if ret != 0 {
            serial::puts(b"[SMP] PSCI CPU_ON failed for core\n");
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

/// AP entry point — called by PSCI CPU_ON.
/// x0 = context_id (stack_top), set by PSCI.
#[unsafe(no_mangle)]
unsafe extern "C" fn ap_entry(stack_top: u64) -> ! {
    unsafe {
        // Set stack pointer
        core::arch::asm!(
            "mov sp, {0}",
            in(reg) stack_top,
            options(nostack),
        );

        // Install exception vector table (same as BSP)
        core::arch::asm!(
            "adr {0}, exception_vector_table",
            "msr VBAR_EL1, {0}",
            "isb",
            out(reg) _,
        );

        // Initialize this core's GIC redistributor
        exceptions::init_ap();

        // Mark this core as online (atomic increment)
        core::arch::asm!(
            "1: ldaxr {0:w}, [{1}]",
            "add {0:w}, {0:w}, #1",
            "stlxr {2:w}, {0:w}, [{1}]",
            "cbnz {2:w}, 1b",
            out(reg) _,
            in(reg) &NUM_CORES_ONLINE as *const u32,
            out(reg) _,
            options(nostack),
        );

        // Log
        let id = cpu_id();
        let mut buf = [0u8; 24];
        let mut pos = 0;
        for &b in b"[SMP] core " { buf[pos] = b; pos += 1; }
        pos += fmt_u32(&mut buf[pos..], id);
        for &b in b" online\n" { buf[pos] = b; pos += 1; }
        serial::puts(&buf[..pos]);

        // Idle loop — WFI until work is available (Phase 2b+)
        loop {
            core::arch::asm!("wfi");
        }
    }
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
