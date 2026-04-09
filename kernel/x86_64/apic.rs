#![allow(unsafe_op_in_unsafe_fn)]
// kernel/x86_64/apic.rs — Local APIC initialization for x86_64.
//
// Detects and configures the Local APIC for each CPU core.
// Replaces the legacy 8259 PIC for interrupt delivery on SMP systems.

use crate::serial;
use crate::mm;

/// Local APIC register offsets (from APIC base address).
const APIC_ID: u32 = 0x020;
const APIC_VERSION: u32 = 0x030;
const APIC_TPR: u32 = 0x080;
const APIC_EOI: u32 = 0x0B0;
const APIC_SVR: u32 = 0x0F0;
const APIC_ICR_LO: u32 = 0x300;
const APIC_ICR_HI: u32 = 0x310;
// LVT registers — used when APIC is fully enabled (Phase 2b)
#[allow(dead_code)]
const APIC_LVT_TIMER: u32 = 0x320;
#[allow(dead_code)]
const APIC_LVT_LINT0: u32 = 0x350;
#[allow(dead_code)]
const APIC_LVT_LINT1: u32 = 0x360;

/// Spurious interrupt vector (must be 0xXF per Intel spec).
const SPURIOUS_VECTOR: u32 = 0xFF;

/// MSR for APIC base address.
const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// Virtual address of the Local APIC MMIO page. Set once on the BSP via
/// `init()` before any AP starts; read by every core for MMIO access.
static APIC_BASE: crate::once::InitOnce<u64> = crate::once::InitOnce::new();

/// Read an MSR.
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack),
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR.
unsafe fn wrmsr(msr: u32, val: u64) {
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") val as u32,
        in("edx") (val >> 32) as u32,
        options(nomem, nostack),
    );
}

/// Read a Local APIC register.
unsafe fn apic_read(reg: u32) -> u32 {
    let addr = (*APIC_BASE.get() + reg as u64) as *const u32;
    core::ptr::read_volatile(addr)
}

/// Write a Local APIC register.
unsafe fn apic_write(reg: u32, val: u32) {
    let addr = (*APIC_BASE.get() + reg as u64) as *mut u32;
    core::ptr::write_volatile(addr, val);
}

/// Get the current CPU's APIC ID.
pub fn apic_id() -> u32 {
    unsafe { apic_read(APIC_ID) >> 24 }
}

/// Send End-Of-Interrupt to the Local APIC.
pub fn eoi() {
    unsafe { apic_write(APIC_EOI, 0); }
}

/// Disable the legacy 8259 PIC by masking all IRQs.
/// Only call when device IRQs are fully routed through APIC/MSI-X.
#[allow(dead_code)]
unsafe fn disable_pic() {
    core::arch::asm!("out dx, al", in("dx") 0x21u16, in("al") 0xFFu8, options(nomem, nostack));
    core::arch::asm!("out dx, al", in("dx") 0xA1u16, in("al") 0xFFu8, options(nomem, nostack));
}

/// Initialize the Local APIC on the current core (BSP or AP).
pub unsafe fn init() {
    unsafe {
        // Read APIC base from MSR
        let msr_val = rdmsr(IA32_APIC_BASE_MSR);
        let phys_base = msr_val & 0xFFFF_F000; // bits 12-35

        // Map APIC MMIO page via HHDM and publish for all cores.
        APIC_BASE.init(mm::phys_to_virt(phys_base) as u64);

        // Enable APIC in virtual wire mode: PIC interrupts route through
        // LINT0 of the BSP's Local APIC. This lets PIC device IRQs work
        // while the APIC is active (needed for INIT-SIPI-SIPI).
        apic_write(APIC_SVR, 0x100 | SPURIOUS_VECTOR);
        apic_write(APIC_TPR, 0);

        // LINT0 = ExtINT (PIC passthrough), edge-triggered, unmasked
        apic_write(APIC_LVT_LINT0, 0x00000700); // delivery mode 111 = ExtINT
        // LINT1 = NMI, edge-triggered, unmasked
        apic_write(APIC_LVT_LINT1, 0x00000400); // delivery mode 100 = NMI
        // Timer = masked (not used yet)
        apic_write(APIC_LVT_TIMER, 0x10000);

        let id = apic_read(APIC_ID) >> 24;
        let ver = apic_read(APIC_VERSION) & 0xFF;
        serial::puts(b"       APIC init: ID=");
        let mut buf = [0u8; 16];
        let len = fmt_u32(&mut buf, id);
        serial::puts(&buf[..len]);
        serial::puts(b" ver=0x");
        let len = fmt_hex(&mut buf, ver);
        serial::puts(&buf[..len]);
        serial::puts(b"\n");
    }
}

/// Initialize the Local APIC on a secondary core (AP).
/// The BSP has already disabled PIC and mapped the APIC base.
pub unsafe fn init_ap() {
    unsafe {
        // Read APIC base from MSR (same physical address as BSP)
        let msr_val = rdmsr(IA32_APIC_BASE_MSR);
        let phys_base = msr_val & 0xFFFF_F000;

        // Ensure global enable bit is set
        wrmsr(IA32_APIC_BASE_MSR, msr_val | (1 << 11));

        // Use same virtual mapping as BSP
        let base = mm::phys_to_virt(phys_base) as u64;

        // Enable APIC
        let addr = (base + APIC_SVR as u64) as *mut u32;
        core::ptr::write_volatile(addr, 0x100 | SPURIOUS_VECTOR);

        // Accept all interrupts
        let addr = (base + APIC_TPR as u64) as *mut u32;
        core::ptr::write_volatile(addr, 0);
    }
}

/// Send an IPI (Inter-Processor Interrupt) to a specific APIC ID.
pub unsafe fn send_ipi(target_apic_id: u32, vector: u8) {
    unsafe {
        // Set destination in ICR high
        apic_write(APIC_ICR_HI, target_apic_id << 24);
        // Send: fixed delivery, physical mode, assert, edge-triggered
        apic_write(APIC_ICR_LO, vector as u32);
    }
}

/// Send INIT IPI to a target core.
pub unsafe fn send_init(target_apic_id: u32) {
    unsafe {
        apic_write(APIC_ICR_HI, target_apic_id << 24);
        // INIT: delivery mode 101, level assert, edge
        apic_write(APIC_ICR_LO, 0x00004500);
        // Wait for delivery
        for _ in 0..100_000 { core::arch::asm!("pause", options(nomem, nostack)); }
        // Deassert
        apic_write(APIC_ICR_HI, target_apic_id << 24);
        apic_write(APIC_ICR_LO, 0x00008500);
        for _ in 0..100_000 { core::arch::asm!("pause", options(nomem, nostack)); }
    }
}

/// Send Startup IPI (SIPI) to a target core.
/// `vector` is the page number (4KB-aligned) where the AP trampoline lives.
/// e.g., if trampoline is at 0x8000, vector = 0x08.
pub unsafe fn send_sipi(target_apic_id: u32, vector: u8) {
    unsafe {
        apic_write(APIC_ICR_HI, target_apic_id << 24);
        // SIPI: delivery mode 110, vector = page number
        apic_write(APIC_ICR_LO, 0x00004600 | vector as u32);
        for _ in 0..100_000 { core::arch::asm!("pause", options(nomem, nostack)); }
    }
}

/// Broadcast INIT to all cores except self.
pub unsafe fn send_init_broadcast() {
    apic_write(APIC_ICR_HI, 0);
    // INIT (101), all excluding self (11 in bits 19:18)
    apic_write(APIC_ICR_LO, 0x000C4500);
    for _ in 0..100_000 { core::arch::asm!("pause", options(nomem, nostack)); }
}

/// Broadcast SIPI to all cores except self.
pub unsafe fn send_sipi_broadcast(vector: u8) {
    apic_write(APIC_ICR_HI, 0);
    // SIPI (110), all excluding self (11 in bits 19:18)
    apic_write(APIC_ICR_LO, 0x000C4600 | vector as u32);
    for _ in 0..100_000 { core::arch::asm!("pause", options(nomem, nostack)); }
}

fn fmt_u32(buf: &mut [u8], mut val: u32) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 10];
    let mut len = 0;
    while val > 0 { tmp[len] = b'0' + (val % 10) as u8; val /= 10; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}

fn fmt_hex(buf: &mut [u8], val: u32) -> usize {
    let hex = b"0123456789abcdef";
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 8];
    let mut len = 0;
    let mut v = val;
    while v > 0 { tmp[len] = hex[(v & 0xF) as usize]; v >>= 4; len += 1; }
    for i in 0..len { buf[i] = tmp[len - 1 - i]; }
    len
}
