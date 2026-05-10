// kernel/x86_64/idt.rs -- Interrupt Descriptor Table implementation
//
// This file sets up the full x86_64 IDT:
//   1. Remaps the 8259 PIC to vectors 32-47
//   2. Installs 256 ISR stubs (defined in idt_stubs.S) into the IDT
//   3. Loads the IDTR
//   4. Provides a common dispatcher called from the assembly stubs
//
// The ISR assembly stubs and their table are defined in a separate .S file.
// That file provides `isr_stub_table`: an array of 256 function pointers.

use core::arch::asm;
use core::cell::UnsafeCell;

// ============================================================================
// Interrupt frame — matches the stack layout built by ISR stubs + CPU
// ============================================================================

/// Interrupt stack frame as seen by Rust handlers.
///
/// Stack layout (low address = top of struct):
///   [pushed by stub]       r15..rax   (general regs)
///   [pushed by stub]       vector
///   [pushed by CPU/stub]   error_code
///   [pushed by CPU]        rip, cs, rflags, rsp, ss
#[repr(C, packed)]
pub struct InterruptFrame {
    // General-purpose registers (pushed by ISR stub, in reverse order)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // Pushed by the ISR stub
    pub vector: u64,
    pub error_code: u64,
    // Pushed by the CPU on interrupt
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Handler function pointer type.
pub type InterruptHandler = unsafe extern "C" fn(*mut InterruptFrame);

// ============================================================================
// IDT entry (16 bytes, Interrupt Gate Descriptor in long mode)
// ============================================================================

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,  // Target offset bits 0-15
    selector: u16,    // Code segment selector
    ist: u8,          // Interrupt Stack Table offset (bits 0-2), rest zero
    type_attr: u8,    // Type and attributes (P, DPL, type)
    offset_mid: u16,  // Target offset bits 16-31
    offset_high: u32, // Target offset bits 32-63
    zero: u32,        // Reserved, must be zero
}

impl IdtEntry {
    const ZEROED: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        zero: 0,
    };
}

// ============================================================================
// Descriptor table pointer (IDTR layout: 2-byte limit + 8-byte base)
// ============================================================================

#[repr(C, packed)]
struct DescriptorTablePtr {
    limit: u16,
    base: u64,
}

// ============================================================================
// Static storage
// ============================================================================
//
// `IDT_ENTRIES`, `IDTR`, and `HANDLERS` live in one
// `UnsafeCell<IdtState>`. Single-owner discipline: `init()` writes
// on the BSP during boot (before any AP is running).
// `register_handler()` writes `HANDLERS` from the BSP.
// `load_idt_on_ap` only reads `IDTR`. The ISR dispatcher reads
// `HANDLERS[vector]` from any core in interrupt context; per-slot
// writes + reads are single-word and thus tearing-safe on x86_64,
// which matches the pre-refactor invariant.
//
// `InitOnce<Box<_>>` isn't viable: `lidt` takes a raw pointer and
// the IDT must live where the CPU can physically see it.

struct IdtState {
    entries: [IdtEntry; 256],
    idtr: DescriptorTablePtr,
    handlers: [Option<InterruptHandler>; 256],
}

impl IdtState {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::ZEROED; 256],
            idtr: DescriptorTablePtr { limit: 0, base: 0 },
            handlers: [None; 256],
        }
    }
}

struct IdtCell(UnsafeCell<IdtState>);
// SAFETY: see module-level contract above.
unsafe impl Sync for IdtCell {}

static IDT: IdtCell = IdtCell(UnsafeCell::new(IdtState::new()));

// ============================================================================
// ISR stub table — defined in idt_stubs.S
// ============================================================================

// The assembly file defines `isr_stub_table` as an array of 256 function
// pointers (addresses of isr_stub_0 through isr_stub_255).
unsafe extern "C" {
    static isr_stub_table: [usize; 256];
}

// ============================================================================
// Port I/O helpers
// ============================================================================

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    unsafe {
        let val: u8;
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
        val
    }
}

/// Small I/O delay by writing to port 0x80 (POST diagnostic port).
#[inline(always)]
fn io_wait() {
    unsafe { outb(0x80, 0); }
}

// ============================================================================
// 8259 PIC initialization
// ============================================================================

// PIC port addresses
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW (Initialization Command Word) constants
const ICW1_INIT: u8 = 0x10; // Initialization bit
const ICW1_ICW4: u8 = 0x01; // ICW4 will be sent
const ICW4_8086: u8 = 0x01; // 8086 mode

fn pic_remap() {
    unsafe {
        // Save current masks (unused, preserved for spec compliance)
        let _mask1 = inb(PIC1_DATA);
        let _mask2 = inb(PIC2_DATA);

        // ICW1: begin initialization sequence (cascade mode, ICW4 needed)
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: set vector offsets
        outb(PIC1_DATA, 32); // Master PIC: IRQ 0-7  -> vectors 32-39
        io_wait();
        outb(PIC2_DATA, 40); // Slave PIC:  IRQ 8-15 -> vectors 40-47
        io_wait();

        // ICW3: configure cascading
        outb(PIC1_DATA, 0x04); // Master: IRQ2 has slave (bit 2)
        io_wait();
        outb(PIC2_DATA, 0x02); // Slave: cascade identity 2
        io_wait();

        // ICW4: set 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all IRQs initially, except IRQ2 (cascade from slave)
        // Bit set = masked (disabled), bit clear = enabled
        outb(PIC1_DATA, 0xFB); // 1111_1011: all masked except IRQ2
        outb(PIC2_DATA, 0xFF); // 1111_1111: all masked
    }
}

// ============================================================================
// IDT entry setup
// ============================================================================

unsafe fn set_idt_entry(vector: usize, handler_addr: u64, selector: u16, ist: u8, type_attr: u8) {
    unsafe {
        (*IDT.0.get()).entries[vector] = IdtEntry {
            offset_low: (handler_addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x07,
            type_attr,
            offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
            offset_high: ((handler_addr >> 32) & 0xFFFF_FFFF) as u32,
            zero: 0,
        };
    }
}

// ============================================================================
// Common C interrupt dispatcher — called from assembly (isr_common)
// ============================================================================

/// Called from the assembly common stub after all GP registers are saved.
/// Dispatches to registered Rust handlers, sends PIC EOI for hardware IRQs,
/// and halts on unhandled CPU exceptions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_common_handler(frame: *mut InterruptFrame) {
    unsafe {
    let vector = (*frame).vector as usize;

    // Dispatch to registered handler if one exists
    if let Some(handler) = (*IDT.0.get()).handlers[vector] {
        handler(frame);
        // Send EOI for hardware IRQs (vectors 32-47) via PIC
        if vector >= 32 && vector < 48 {
            if vector >= 40 {
                outb(PIC2_CMD, 0x20); // Slave PIC EOI
            }
            outb(PIC1_CMD, 0x20); // Master PIC EOI
        } else if vector >= 48 {
            // APIC vector — send APIC EOI
            super::apic::eoi();
        }
        return;
    }

    // No handler registered — handle defaults

    // For hardware IRQs without handlers, just send EOI (spurious/unhandled)
    if vector >= 32 && vector < 48 {
        if vector >= 40 {
            outb(PIC2_CMD, 0x20);
        }
        outb(PIC1_CMD, 0x20);
        return;
    }

    // APIC vectors without handlers: send EOI and return
    if vector >= 48 {
        super::apic::eoi();
        return;
    }

    // Unhandled CPU exception — capture diagnostic, print it, halt
    // the offending core. Other cores keep running and can read the
    // capture via `/diag-panic` — critical when serial-port-output is
    // not externally accessible (sandboxed GCE deploys).
    if vector < 32 {
        let rip = (*frame).rip;
        let err = (*frame).error_code;
        let rsp = (*frame).rsp;
        let rflags = (*frame).rflags;
        let mut cr2: u64;
        asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack));

        // Capture into the in-band diag buffer first so it lands
        // even on systems where the serial sink is silently
        // dropped. We use the byte-oriented `append*` helpers to
        // avoid pulling in `core::fmt` from a potentially-corrupt
        // execution context.
        crate::diag::append(b"\n!!! UNHANDLED EXCEPTION on cpu ");
        crate::diag::append_u32(crate::cpu_id());
        crate::diag::append(b" !!!\n  vector=0x");
        crate::diag::append_hex(vector as u64);
        crate::diag::append(b" err=0x");
        crate::diag::append_hex(err);
        crate::diag::append(b"\n  rip=0x");
        crate::diag::append_hex(rip);
        crate::diag::append(b" rsp=0x");
        crate::diag::append_hex(rsp);
        crate::diag::append(b"\n  rflags=0x");
        crate::diag::append_hex(rflags);
        crate::diag::append(b" cr2=0x");
        crate::diag::append_hex(cr2);
        crate::diag::append(b"\n");

        // Mirror to serial for the case where the operator HAS
        // serial access — same bytes either way.
        crate::serial::puts(b"\n!!! UNHANDLED EXCEPTION !!!\n");
        crate::serial::puts(b"  vector=");
        crate::serial::print_hex(vector as u64);
        crate::serial::puts(b" err=");
        crate::serial::print_hex(err);
        crate::serial::puts(b"\n  rip=");
        crate::serial::print_hex(rip);
        crate::serial::puts(b" rsp=");
        crate::serial::print_hex(rsp);
        crate::serial::puts(b"\n  rflags=");
        crate::serial::print_hex(rflags);
        crate::serial::puts(b" cr2=");
        crate::serial::print_hex(cr2);
        crate::serial::puts(b"\nSystem halted.\n");
        loop {
            asm!("cli", "hlt", options(nomem, nostack));
        }
    }
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Kernel code segment selector (must match GDT layout: index 1, RPL 0).
const KERNEL_CODE_SELECTOR: u16 = 0x08;

/// Initialize the IDT: clear handlers, remap PIC, install all 256 ISR stubs,
/// and load the IDTR.
pub fn init() {
    unsafe {
        let idt = &mut *IDT.0.get();

        // Clear all handlers
        for h in idt.handlers.iter_mut() {
            *h = None;
        }

        // Remap the 8259 PIC so hardware IRQs don't overlap CPU exceptions
        pic_remap();

        // Install all 256 ISR stubs into the IDT.
        // Type/attr = 0x8E: Present=1, DPL=0, Type=0xE (64-bit interrupt gate)
        // An interrupt gate automatically clears IF on entry (unlike a trap gate).
        for i in 0..256 {
            let stub_addr = isr_stub_table[i] as u64;
            set_idt_entry(i, stub_addr, KERNEL_CODE_SELECTOR, 0, 0x8E);
        }

        // Load the IDTR
        idt.idtr.limit = (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16;
        idt.idtr.base = &raw const idt.entries as u64;
        asm!("lidt [{}]", in(reg) &raw const idt.idtr, options(nostack));
    }
}

/// Register a handler for a specific interrupt vector.
/// The handler will be called by the common dispatcher with a pointer
/// to the saved register state.
pub fn register_handler(vector: u8, handler: InterruptHandler) {
    unsafe {
        (*IDT.0.get()).handlers[vector as usize] = Some(handler);
    }
}

/// Enable a specific IRQ line on the PIC (unmask it).
/// irq: 0-15 (0-7 = master PIC, 8-15 = slave PIC)
pub fn enable_irq(irq: u8) {
    unsafe {
        let (port, bit) = if irq < 8 {
            (PIC1_DATA, irq)
        } else {
            (PIC2_DATA, irq - 8)
        };
        let mask = inb(port);
        outb(port, mask & !(1 << bit)); // Clear the bit to unmask
    }
}

/// Load the IDT on an AP (same IDT as BSP). APs share the IDT and handler table.
pub fn load_idt_on_ap() {
    unsafe {
        asm!("lidt [{}]", in(reg) &raw const (*IDT.0.get()).idtr, options(nostack));
    }
}

/// Disable a specific IRQ line on the PIC (mask it).
pub fn disable_irq(irq: u8) {
    unsafe {
        let (port, bit) = if irq < 8 {
            (PIC1_DATA, irq)
        } else {
            (PIC2_DATA, irq - 8)
        };
        let mask = inb(port);
        outb(port, mask | (1 << bit)); // Set the bit to mask
    }
}
