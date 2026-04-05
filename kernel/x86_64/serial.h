#pragma once

// kernel/x86_64/serial.h — x86_64-specific serial extensions
//
// Interrupt-driven serial RX for waking HLT on Ctrl-C.
// Thin wrappers around Rust serial functions (kernel/serial.rs).

extern "C" {
void serial_enable_rx_irq();
void serial_rx_isr();
}

namespace serial {

inline void enable_rx_irq() { serial_enable_rx_irq(); }
inline void rx_isr() { serial_rx_isr(); }

} // namespace serial
