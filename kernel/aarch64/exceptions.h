#pragma once
// kernel/aarch64/exceptions.h — ARM64 exception handling
//
// ARM64 exception vectors are laid out as a 2KB-aligned table (VBAR_EL1).
// Each of the 16 slots is exactly 0x80 bytes (32 instructions).
//
// For the unikernel, all unexpected exceptions panic.
// IRQs go through a minimal GIC driver that routes to registered handlers.

#include <stdint.h>

namespace exceptions {

// ExceptionFrame: the register state pushed by the vector stubs.
//
// Stack layout when exception_handler() is called (sp points to esr):
//   sp+ 0: esr       (ESR_EL1)
//   sp+ 8: far       (FAR_EL1)
//   sp+16: x[0..30]  (x0..x30, 31 × 8 bytes)
//   sp+264: sp       (original SP before the handler frame)
//   sp+272: pc       (ELR_EL1)
//   sp+280: pstate   (SPSR_EL1)
struct Frame {
    uint64_t esr;            // ESR_EL1 — syndrome register
    uint64_t far;            // FAR_EL1 — fault address
    uint64_t x[31];          // x0..x30 (general purpose)
    uint64_t sp;             // original SP
    uint64_t pc;             // ELR_EL1
    uint64_t pstate;         // SPSR_EL1
};

// C-level exception dispatcher, called by the vector stubs.
extern "C" void exception_handler(uint32_t kind, Frame* frame);

// Install the exception vector table and initialise the GIC.
void init();

// Register a handler for IRQ number `irq`.
void register_irq(uint32_t irq, void (*handler)(uint32_t irq));

} // namespace exceptions
