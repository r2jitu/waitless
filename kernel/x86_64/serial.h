#pragma once

// kernel/x86_64/serial.h — x86_64-specific serial extensions
//
// Interrupt-driven serial RX for waking HLT on Ctrl-C.
// Include this alongside kernel/serial.h on x86_64.

namespace serial {

// Enable UART RX interrupt (ERBFI bit in IER).  Call after the IDT handler
// for IRQ4 (vector 36) is registered and IRQ4 is unmasked in the PIC.
void enable_rx_irq();

// Drain the UART RX FIFO and set the shutdown flag if 0x03 is seen.
// Must be called from the IRQ4 ISR to clear the interrupt condition.
void rx_isr();

} // namespace serial
