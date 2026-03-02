#pragma once

// kernel/idt.h — Interrupt Descriptor Table interface
//
// Sets up the x86_64 IDT with 256 entries for:
//   - Vectors 0-31:  CPU exceptions
//   - Vectors 32-47: Hardware IRQs (remapped via 8259 PIC)
//   - Vectors 48-255: Software interrupts / reserved
//
// Each vector has an ISR stub that saves all registers, pushes the
// vector number, and calls into a common C++ dispatcher.

#include <stdint.h>

namespace idt {

// Interrupt stack frame as seen by the C++ handler.
// The ISR stub pushes all general-purpose registers, then the vector
// number. The CPU pushes error_code (or the stub pushes 0), RIP, CS,
// RFLAGS, RSP, and SS before the stub runs.
//
// Stack layout (low address = top of struct):
//   [pushed by stub]  r15, r14, ..., rax   (general regs)
//   [pushed by stub]  vector_number
//   [pushed by CPU/stub]  error_code
//   [pushed by CPU]   rip, cs, rflags, rsp, ss
struct __attribute__((packed)) InterruptFrame {
    // General-purpose registers (pushed by ISR stub, in reverse order)
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;

    // Pushed by the ISR stub
    uint64_t vector;
    uint64_t error_code;

    // Pushed by the CPU on interrupt
    uint64_t rip;
    uint64_t cs;
    uint64_t rflags;
    uint64_t rsp;
    uint64_t ss;
};

// Function pointer type for interrupt handlers
using InterruptHandler = void (*)(InterruptFrame*);

// IDT entry: 16 bytes, packed (Interrupt Gate Descriptor in long mode)
struct __attribute__((packed)) IDTEntry {
    uint16_t offset_low;    // Target offset bits 0-15
    uint16_t selector;      // Code segment selector
    uint8_t  ist;           // Interrupt Stack Table offset (bits 0-2), rest zero
    uint8_t  type_attr;     // Type and attributes (P, DPL, type)
    uint16_t offset_mid;    // Target offset bits 16-31
    uint32_t offset_high;   // Target offset bits 32-63
    uint32_t zero;          // Reserved, must be zero
};

// Initialize the IDT: set up 256 entries, install ISR stubs,
// remap the 8259 PIC, and load the IDTR.
void init();

// Register a C++ handler for a specific interrupt vector.
// The handler will be called by the common dispatcher with a pointer
// to the saved register state.
void register_handler(uint8_t vector, InterruptHandler handler);

// Enable a specific IRQ line on the PIC (unmask it).
// irq: 0-15 (0-7 = master PIC, 8-15 = slave PIC)
void enable_irq(uint8_t irq);

// Disable a specific IRQ line on the PIC (mask it).
void disable_irq(uint8_t irq);

} // namespace idt
