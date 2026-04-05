#pragma once
// kernel/aarch64/exceptions.h — Thin C++ wrapper around the Rust exceptions module
//
// The actual implementation lives in kernel/exceptions.rs (exceptions_rs crate).
// This header provides exceptions::init(), register_irq(), enable_timer_wakeup()
// for C++ callers (entry.cc, drivers_ffi.cc).

#include <stdint.h>

extern "C" {
void exceptions_init();
void exceptions_register_irq(uint32_t irq, void (*handler)(uint32_t));
void exceptions_enable_timer_wakeup();
}

namespace exceptions {

inline void init() { exceptions_init(); }
inline void register_irq(uint32_t irq, void (*handler)(uint32_t)) {
  exceptions_register_irq(irq, handler);
}
inline void enable_timer_wakeup() { exceptions_enable_timer_wakeup(); }

} // namespace exceptions
