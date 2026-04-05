// drivers/drivers_ffi.cc — C-linkage FFI bridge for Rust driver code
//
// Exposes kernel IRQ functions to the Rust driver crate.
// FDT, memory management, serial output, and MMU mapping are now
// handled directly in Rust via kernel rlib dependencies.

#if defined(__aarch64__)
#include "kernel/aarch64/exceptions.h"
#elif defined(__x86_64__)
#include "kernel/x86_64/idt.h"
#endif

extern "C" {

// ---- Platform-specific: aarch64 ---------------------------------------------

#if defined(__aarch64__)

// IRQ registration — single handler trampoline (only one virtio-net IRQ active).
static void (*g_rust_irq_fn)() = nullptr;
static void irq_dispatch(uint32_t) {
  if (g_rust_irq_fn) g_rust_irq_fn();
}
void driver_register_irq(uint32_t intid, void (*handler)()) {
  g_rust_irq_fn = handler;
  exceptions::register_irq(intid, irq_dispatch);
}

// ---- Platform-specific: x86_64 ----------------------------------------------

#elif defined(__x86_64__)

// x86 IDT handler trampoline (virtio-net IRQ only needs one).
static void (*g_rust_x86_irq_fn)() = nullptr;
void driver_register_irq(uint32_t vector, void (*handler)()) {
  g_rust_x86_irq_fn = handler;
  idt::register_handler((uint8_t)vector,
                        [](idt::InterruptFrame *) {
                          if (g_rust_x86_irq_fn) g_rust_x86_irq_fn();
                        });
}

void driver_x86_enable_irq(uint32_t irq) {
  idt::enable_irq((uint8_t)irq);
}

#endif

} // extern "C"
