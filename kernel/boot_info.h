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
};

} // namespace boot
