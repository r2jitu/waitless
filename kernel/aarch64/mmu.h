#pragma once
// kernel/aarch64/mmu.h — Thin C++ wrapper around the Rust MMU module
//
// The actual implementation lives in kernel/mmu.rs (mmu_rs crate).
// This header provides mmu::map_device_range() for C++ callers.

#include <stdint.h>

extern "C" void mmu_map_device_range(uint64_t phys_base, uint64_t size);

namespace mmu {

inline void map_device_range(uint64_t phys_base, uint64_t size) {
  mmu_map_device_range(phys_base, size);
}

} // namespace mmu
