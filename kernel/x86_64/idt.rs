// kernel/x86_64/idt.rs -- Interrupt Descriptor Table implementation (Rust port)
//
// This file sets up the full x86_64 IDT:
//   1. Remaps the 8259 PIC to vectors 32-47
//   2. Installs 256 ISR stubs (defined in idt_stubs.S) into the IDT
//   3. Loads the IDTR
//   4. Provides a common C-linkage dispatcher called from assembly
//
// The ISR assembly stubs and their table are defined in a separate .S file.
// That file provides `isr_stub_table`: an array of 256 function pointers.

use core::arch::asm;

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

static mut IDT_ENTRIES: [IdtEntry; 256] = [IdtEntry::ZEROED; 256];

static mut IDTR: DescriptorTablePtr = DescriptorTablePtr { limit: 0, base: 0 };

static mut HANDLERS: [Option<InterruptHandler>; 256] = [None; 256];

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
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    val
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
        // Save current masks (unused, but matches C++ for correctness)
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
    IDT_ENTRIES[vector] = IdtEntry {
        offset_low: (handler_addr & 0xFFFF) as u16,
        selector,
        ist: ist & 0x07,
        type_attr,
        offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
        offset_high: ((handler_addr >> 32) & 0xFFFF_FFFF) as u32,
        zero: 0,
    };
}

// ============================================================================
// Common C interrupt dispatcher — called from assembly (isr_common)
// ============================================================================

/// Called from the assembly common stub after all GP registers are saved.
/// Dispatches to registered Rust handlers, sends PIC EOI for hardware IRQs,
/// and halts on unhandled CPU exceptions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isr_common_handler(frame: *mut InterruptFrame) {
    let vector = (*frame).vector as usize;

    // Dispatch to registered handler if one exists
    if let Some(handler) = HANDLERS[vector] {
        handler(frame);
        // Send EOI for hardware IRQs (vectors 32-47)
        if vector >= 32 && vector < 48 {
            if vector >= 40 {
                outb(PIC2_CMD, 0x20); // Slave PIC EOI
            }
            outb(PIC1_CMD, 0x20); // Master PIC EOI
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

    // Unhandled CPU exception — print simple diagnostic and halt
    if vector < 32 {
        unsafe extern "C" {
            fn serial_puts(s: *const u8);
        }
        serial_puts(b"\n!!! UNHANDLED EXCEPTION !!!\nSystem halted.\n\0".as_ptr());
        loop {
            asm!("cli", "hlt", options(nomem, nostack));
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
        // Clear all handlers
        for i in 0..256 {
            HANDLERS[i] = None;
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
        IDTR.limit = (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16;
        IDTR.base = &IDT_ENTRIES as *const _ as u64;
        asm!("lidt [{}]", in(reg) &IDTR, options(nostack));
    }
}

/// Register a handler for a specific interrupt vector.
/// The handler will be called by the common dispatcher with a pointer
/// to the saved register state.
pub fn register_handler(vector: u8, handler: InterruptHandler) {
    unsafe {
        HANDLERS[vector as usize] = Some(handler);
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
