// drivers/drivers_ffi.cc — C-linkage FFI bridge for Rust driver code
//
// Exposes kernel functions (memory management, serial, FDT, MMU, IRQ)
// to the Rust driver crate. Architecture-specific I/O (port I/O, MMIO,
// barriers) is handled directly in Rust via inline assembly.

#include "kernel/serial.h"
#include "kernel/mm.h"

#if defined(__aarch64__)
#include "kernel/aarch64/fdt.h"
#include "kernel/aarch64/mmu.h"
#include "kernel/aarch64/exceptions.h"
#elif defined(__x86_64__)
#include "kernel/x86_64/idt.h"
#include "kernel/x86_64/serial.h"
#endif

extern "C" {

// ---- Serial output ----------------------------------------------------------

void driver_log(const char *msg) { serial::printf("%s", msg); }

// ---- Memory management ------------------------------------------------------

uint64_t driver_alloc_frame() { return mm::alloc_frame(); }
void *driver_phys_to_virt(uint64_t phys) { return mm::phys_to_virt(phys); }
uint64_t driver_virt_to_phys(const void *virt) { return mm::virt_to_phys(virt); }
void *driver_kmalloc(size_t size) { return mm::kmalloc(size); }
void driver_kfree(void *ptr) { mm::kfree(ptr); }

// ---- Platform-specific: aarch64 ---------------------------------------------

#if defined(__aarch64__)

// FDT info struct — layout must match the Rust DriverFdtInfo exactly.
struct DriverFdtInfo {
  uint64_t uart_base;
  uint64_t virtio_bases[32];
  uint32_t virtio_irqs[32];
  int32_t virtio_count;
  uint64_t gic_dist_base;
  uint64_t gic_redist_base;
  uint8_t gic_version;
  uint64_t pcie_ecam_base;
  uint64_t pcie_ecam_size;
  uint64_t ram_base;
  uint64_t ram_size;
  uint64_t pci_mmio32_base;
  uint64_t pci_mmio32_size;
  uint32_t pci_irqs[8];
};

void driver_get_fdt_info(DriverFdtInfo *out) {
  const fdt::Info &info = fdt::info();
  out->uart_base = info.uart_base;
  out->virtio_count = info.virtio_count;
  for (int i = 0; i < 32; i++) {
    out->virtio_bases[i] = info.virtio_bases[i];
    out->virtio_irqs[i] = info.virtio_irqs[i];
  }
  out->gic_dist_base = info.gic_dist_base;
  out->gic_redist_base = info.gic_redist_base;
  out->gic_version = info.gic_version;
  out->pcie_ecam_base = info.pcie_ecam_base;
  out->pcie_ecam_size = info.pcie_ecam_size;
  out->ram_base = info.ram_base;
  out->ram_size = info.ram_size;
  out->pci_mmio32_base = info.pci_mmio32_base;
  out->pci_mmio32_size = info.pci_mmio32_size;
  for (int i = 0; i < 8; i++)
    out->pci_irqs[i] = info.pci_irqs[i];
}

void driver_mmu_map_device_range(uint64_t base, uint64_t size) {
  mmu::map_device_range(base, size);
}

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

// Stubs for aarch64-only functions
void driver_get_fdt_info(void *) {}
void driver_mmu_map_device_range(uint64_t, uint64_t) {}

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
