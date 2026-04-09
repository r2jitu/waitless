#![allow(unsafe_op_in_unsafe_fn)]
// kernel/x86_64/smp.rs — Multi-core boot for x86_64.
//
// Uses INIT-SIPI-SIPI to start secondary cores (APs).
// The AP trampoline (boot/x86_64/ap_boot.S) transitions from
// 16-bit real mode to 64-bit long mode.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::serial;
use crate::mm;
use super::apic;

/// Per-core stack size: 64KB.
const AP_STACK_SIZE: usize = 64 * 1024;

/// Physical address where the AP trampoline is copied.
/// Must be page-aligned and below 1MB. 0x8000 is conventionally safe.
const AP_TRAMPOLINE_ADDR: u64 = 0x8000;

/// Maximum cores.
pub const MAX_CORES: usize = 8;

/// Global shutdown flag.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static NUM_CORES_ONLINE: AtomicU32 = AtomicU32::new(1);

/// Get current CPU's logical core index.
///
/// Reads from GS:0 which is the `id` field of this core's PerCore struct.
/// Each core sets GS_BASE to point at its PerCore during boot.
/// Cost: one segment-prefixed load (~1 cycle) vs APIC MMIO (~200+ under TCG).
pub fn cpu_id() -> u32 {
    let id: u32;
    unsafe {
        core::arch::asm!(
            "mov {:e}, gs:[0]",
            out(reg) id,
            options(nomem, nostack, preserves_flags),
        );
    }
    id
}

/// Set GS_BASE to point at this core's PerCore struct. Called once per core.
pub fn init_tls(id: u32) {
    unsafe {
        let addr = crate::percpu::get(id) as *const crate::percpu::PerCore as u64;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC0000101u32, // IA32_GS_BASE
            in("eax") addr as u32,
            in("edx") (addr >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// Number of online cores.
pub fn num_cores_online() -> u32 {
    NUM_CORES_ONLINE.load(Ordering::Relaxed)
}

/// Boot secondary cores. Called by core 0 after all init.
pub unsafe fn start_secondary_cores(cpu_count: u32) {
    if cpu_count <= 1 {
        return;
    }
    let count = cpu_count.min(MAX_CORES as u32);
    serial::puts(b"[SMP] Starting secondary cores...\n");

    // Copy AP trampoline to low memory
    unsafe extern "C" {
        static ap_trampoline_start: u8;
        static ap_trampoline_end: u8;
    }
    let trampoline_src = &ap_trampoline_start as *const u8;
    let trampoline_size = (&ap_trampoline_end as *const u8 as usize)
        - (trampoline_src as usize);
    let trampoline_dst = AP_TRAMPOLINE_ADDR as *mut u8;

    core::ptr::copy_nonoverlapping(trampoline_src, trampoline_dst, trampoline_size);

    // Set up the GDT at offset 0xF00 in the trampoline page
    let gdt_ptr_addr = (AP_TRAMPOLINE_ADDR + 0xF00) as *mut u8;
    setup_ap_gdt(gdt_ptr_addr);

    // Get the current PML4 address (CR3)
    let cr3: u64;
    core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));

    // Write PML4 address at offset 0xFF0
    let pml4_slot = (AP_TRAMPOLINE_ADDR + 0xFF0) as *mut u32;
    core::ptr::write_volatile(pml4_slot, cr3 as u32);

    let sipi_vector = (AP_TRAMPOLINE_ADDR / 0x1000) as u8;

    for i in 1..count {
        // Allocate stack
        let stack_pages = AP_STACK_SIZE / 4096;
        let stack_base = mm::alloc_pages(stack_pages);
        if stack_base == 0 {
            serial::puts(b"[SMP] Failed to allocate AP stack\n");
            continue;
        }
        let stack_top = stack_base + AP_STACK_SIZE as u64;

        // Write stack pointer at offset 0xFF8
        let stack_slot = (AP_TRAMPOLINE_ADDR + 0xFF8) as *mut u64;
        core::ptr::write_volatile(stack_slot, stack_top);

        // INIT-SIPI-SIPI for this specific AP
        let topo = super::acpi::topology();
        let target_apic_id = topo.apic_ids[i as usize] as u32;
        let expected = num_cores_online() + 1;

        apic::send_init(target_apic_id);
        for _ in 0..10_000_000u64 { core::hint::spin_loop(); }
        apic::send_sipi(target_apic_id, sipi_vector);
        for _ in 0..1_000_000u64 { core::hint::spin_loop(); }
        apic::send_sipi(target_apic_id, sipi_vector);

        // Wait for this AP to come online before starting the next
        for _ in 0..10_000_000u64 {
            if num_cores_online() >= expected {
                break;
            }
            core::hint::spin_loop();
        }
    }

    // Wait for APs
    for _ in 0..100_000_000u64 {
        if num_cores_online() >= count {
            break;
        }
        core::hint::spin_loop();
    }

    let online = num_cores_online();
    let mut buf = [0u8; 40];
    let mut pos = 0;
    for &b in b"[SMP] " { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], online);
    for &b in b"/" { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], count);
    for &b in b" cores online\n" { buf[pos] = b; pos += 1; }
    serial::puts(&buf[..pos]);
}

/// IPI wakeup vector (must not conflict with PIC IRQs 32-47 or exceptions 0-31).
pub const IPI_VECTOR: u8 = 0x40;

/// AP entry point — called from the trampoline in 64-bit mode.
#[unsafe(no_mangle)]
extern "C" fn ap_entry_x86(_ctx: u64) -> ! {
    // Load BSP's GDT (AP trampoline GDT has wrong selector layout for IDT).
    super::gdt::load_on_ap();

    // Initialize this AP's APIC
    unsafe { apic::init_ap(); }

    // Set GS_BASE for fast cpu_id() — look up logical core index from APIC ID.
    let apic_id = apic::apic_id();
    let topo = super::acpi::topology();
    let mut logical_id = 0u32;
    for i in 0..topo.cpu_count as usize {
        if topo.apic_ids[i] as u32 == apic_id {
            logical_id = i as u32;
            break;
        }
    }
    init_tls(logical_id);

    // Load the IDT (same one BSP set up) so this AP can handle interrupts.
    super::idt::load_idt_on_ap();

    // Mark online
    NUM_CORES_ONLINE.fetch_add(1, Ordering::SeqCst);

    let id = cpu_id();
    let mut buf = [0u8; 24];
    let mut pos = 0;
    for &b in b"[SMP] core " { buf[pos] = b; pos += 1; }
    pos += fmt_u32(&mut buf[pos..], id);
    for &b in b" online\n" { buf[pos] = b; pos += 1; }
    serial::puts(&buf[..pos]);

    // Enable interrupts so IPI can be delivered.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }

    // Enter the unified kernel event loop.
    crate::eventloop::run(id);
}

/// Signal APs to shut down.
pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
    // On x86, APs will wake from HLT on next interrupt and check SHUTDOWN.
    // Send IPI to all APs to wake them.
    // For simplicity, broadcast NMI (vector 2) — they'll check SHUTDOWN.
}

/// Set up a minimal GDT for the AP trampoline at the given address.
/// Format: 2 bytes limit + 4 bytes base (32-bit GDT pointer for lgdt in 16/32-bit mode)
/// followed by GDT entries.
unsafe fn setup_ap_gdt(addr: *mut u8) {
    // GDT entries start at addr + 6 (after the 6-byte GDT pointer)
    let gdt_base = addr.add(6);

    // Entry 0 (0x00): null descriptor
    core::ptr::write_bytes(gdt_base, 0, 8);

    // Entry 1 (0x08): 32-bit code segment (for real→protected mode)
    let e1 = gdt_base.add(8) as *mut u64;
    // Limit=0xFFFFF, Base=0, Access=0x9A, Flags=0xC0 (G=1,D=1,L=0)
    core::ptr::write_volatile(e1, 0x00CF9A000000FFFFu64);

    // Entry 2 (0x10): 32-bit data segment
    let e2 = gdt_base.add(16) as *mut u64;
    // Limit=0xFFFFF, Base=0, Access=0x92, Flags=0xC0 (G=1,D=1)
    core::ptr::write_volatile(e2, 0x00CF92000000FFFFu64);

    // Entry 3 (0x18): 64-bit code segment (for protected→long mode)
    let e3 = gdt_base.add(24) as *mut u64;
    // Limit=0, Base=0, Access=0x9A, Flags=0xA0 (L=1,D=0)
    core::ptr::write_volatile(e3, 0x00209A0000000000u64);

    // GDT pointer: limit (4 entries × 8 - 1 = 31), base = physical addr of GDT
    let ptr = addr as *mut u16;
    core::ptr::write_volatile(ptr, 31); // limit
    let base_ptr = addr.add(2) as *mut u32;
    core::ptr::write_volatile(base_ptr, gdt_base as u32);
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
