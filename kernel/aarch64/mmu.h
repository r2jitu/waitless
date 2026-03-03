#pragma once
// kernel/aarch64/mmu.h — Dynamic page table mapping for device MMIO regions
//
// After boot.S sets up the initial L1 page table (4GB normal-cached + one
// device entry at L1[256] for QEMU ECAM), this module allows C++ code to
// add device mappings for addresses discovered at runtime (e.g., VZ.framework
// ECAM base, 64-bit PCI BARs above 4GB).
//
// Uses 2MB block descriptors (L2 table) for precise mapping without
// polluting adjacent memory with device attributes.

#include <stdint.h>

namespace mmu {

// Map a range of physical addresses as device memory (nGnRnE, AttrIdx=0).
// phys_base must be 2MB-aligned; size is rounded up to 2MB granularity.
// Addresses in the first 4GB are already mapped (normal-cached); VZ Stage-2
// overrides to device for MMIO, so this is only needed for addresses > 4GB.
// Safe to call before mm::init() (uses static BSS pool for L2 tables).
void map_device_range(uint64_t phys_base, uint64_t size);

} // namespace mmu
