#pragma once
// kernel/aarch64/fdt.h — Thin C++ wrapper around the Rust FDT parser
//
// The actual parser lives in kernel/fdt.rs (fdt_rs crate).
// This header provides fdt::init() and fdt::info() for C++ callers
// (entry.cc, boot_shim.cc, exceptions.cc, limine_entry.cc).
// On x86_64, provides no-op stubs.

#include <stdint.h>

// Rust extern "C" functions from kernel/fdt.rs
extern "C" {
void fdt_init(uint64_t dtb_addr);
}

namespace fdt {

// Must match kernel/fdt.rs FdtInfo exactly.
struct Info {
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

#if defined(__aarch64__)

extern "C" const Info *fdt_info_ptr();

inline void init(uint64_t dtb_addr) { fdt_init(dtb_addr); }
inline const Info &info() { return *fdt_info_ptr(); }

#else

// x86_64: no device tree; provide no-op stubs so shared code compiles.
inline void init(uint64_t) {}
inline const Info &info() {
  static Info empty{};
  return empty;
}

#endif // __aarch64__

} // namespace fdt
