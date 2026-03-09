#pragma once
// kernel/fdt.h — Minimal Flattened Device Tree scanner
//
// Parses just enough of the DTB to discover MMIO device base addresses.
// Called from kernel_main() (C++, after MMU) before serial::init().
// On x86_64 this header provides no-op stubs; all real code is aarch64-only.

#include <stdint.h>

namespace fdt {

struct Info {
    uint64_t uart_base;          // PL011 base, 0 if not found
    uint64_t virtio_bases[32];   // virtio-mmio device base addresses
    int      virtio_count;       // number found
    uint64_t gic_dist_base;      // GICv2 distributor base (arm,gic-400).
                                 // 0 if not found or if GICv3 (skip GIC init).
    uint64_t pcie_ecam_base;     // PCIe ECAM base, 0 if not found
    uint64_t pcie_ecam_size;     // PCIe ECAM region size
    uint64_t ram_base;           // Physical RAM base from /memory node (0 if not found)
    uint64_t ram_size;           // RAM size in bytes (0 if not found in FDT)
    uint64_t pci_mmio32_base;    // PCIe 32-bit MMIO aperture CPU address (from PCI ranges), 0 if not found
    uint64_t pci_mmio32_size;    // PCIe 32-bit MMIO aperture size
};

#if defined(__aarch64__)

// Parse the DTB at the given physical address.  Must be called once before
// any other fdt:: function.  Safe to call with dtb_addr=0 (no-op).
void init(uint64_t dtb_addr);

// Return the parsed device information (populated by init()).
const Info& info();

#else

// x86_64: no device tree; provide no-op stubs so shared code compiles.
inline void       init(uint64_t) {}
inline const Info& info() { static Info empty{}; return empty; }

#endif // __aarch64__

} // namespace fdt
