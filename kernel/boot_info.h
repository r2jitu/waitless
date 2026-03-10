#pragma once
// kernel/boot_info.h — Unified boot information structure
//
// Every boot protocol (Multiboot2, PVH, FDT, Limine) populates this struct
// via a thin shim, giving kernel_main() a single, arch-agnostic view of
// the machine's physical memory layout.

#include <stdint.h>

namespace boot {

enum class Protocol : uint8_t {
  UNKNOWN = 0,
  MULTIBOOT2,
  PVH,
  FDT,
  LIMINE,
};

struct MemoryRegion {
  uint64_t base;
  uint64_t length;
  enum Type : uint32_t {
    AVAILABLE = 1,
    RESERVED = 2,
  } type;
  uint32_t _pad;
};

static constexpr int MAX_MEMORY_REGIONS = 64;

struct BootInfo {
  Protocol protocol;
  int memory_map_count;
  MemoryRegion memory_map[MAX_MEMORY_REGIONS];
  uint64_t dtb_addr; // aarch64 DTB pointer; 0 on x86

  // Limine higher-half: physical/virtual base of kernel image.
  // When kernel_virt_base != 0, the kernel is linked in higher-half and
  // mm::init() uses these to compute physical addresses for the frame
  // bitmap and heap.
  uint64_t kernel_phys_base; // 0 for identity-mapped boots
  uint64_t kernel_virt_base; // 0 for identity-mapped boots

  // Limine HHDM offset: physical memory is mapped at (hhdm_offset + phys_addr).
  // Limine revision 3 dropped identity mapping of the first 4GB; all physical
  // memory access must go through HHDM.  0 for identity-mapped boots.
  uint64_t hhdm_offset;
};

} // namespace boot
