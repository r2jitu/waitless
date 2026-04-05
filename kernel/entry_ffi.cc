// kernel/entry_ffi.cc — C-linkage wrappers for Rust entry.rs
//
// Exports C++ namespace functions as extern "C" symbols so the Rust
// kernel entry point can call them. Temporary — these will be removed
// when gdt.cc/idt.cc are migrated to Rust.

#include "kernel/arch.h"

#if defined(__x86_64__)
#include "kernel/x86_64/gdt.h"
#include "kernel/x86_64/idt.h"
#endif

extern "C" {

void arch_shutdown() { arch::shutdown(); }

#if defined(__x86_64__)
void gdt_init() { gdt::init(); }
void idt_init() { idt::init(); }
void idt_register_handler(uint8_t vector, idt::InterruptHandler handler) {
  idt::register_handler(vector, handler);
}
void idt_enable_irq(uint8_t irq) { idt::enable_irq(irq); }
#endif

} // extern "C"
