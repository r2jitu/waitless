// drivers/drivers_ffi.cc — C-linkage FFI bridge for Rust driver code
//
// Exposes x86_64 IDT functions to the Rust driver crate.
// On aarch64, all kernel functions are now called directly from Rust.

#if defined(__x86_64__)
#include "kernel/x86_64/idt.h"
#endif

extern "C" {

#if defined(__x86_64__)

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
