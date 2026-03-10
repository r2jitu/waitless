// kernel/boot_shim.cc — Boot protocol shims
//
// Translates raw boot protocol data (Multiboot2, PVH, FDT) into the
// unified BootInfo struct used by mm::init() and kernel_main().

#include "kernel/boot_shim.h"
#include "kernel/serial.h"

#if defined(__aarch64__)
#include "kernel/fdt.h"
#endif

namespace boot {

#if defined(__x86_64__)

// ---- x86_64 boot protocol structures ----------------------------------------

// Multiboot2
struct MultibootTag {
  uint32_t type;
  uint32_t size;
};

struct MultibootMmapEntry {
  uint64_t addr;
  uint64_t len;
  uint32_t type; // 1 = available RAM
  uint32_t reserved;
};

struct MultibootMmapTag {
  uint32_t type; // 6 = memory map
  uint32_t size;
  uint32_t entry_size;
  uint32_t entry_version;
  MultibootMmapEntry entries[];
};

static constexpr uint32_t MULTIBOOT_TAG_END = 0;
static constexpr uint32_t MULTIBOOT_TAG_MMAP = 6;
static constexpr uint32_t MULTIBOOT_MEMORY_AVAILABLE = 1;

// PVH (Xen HVM) — used by QEMU 10.x
static constexpr uint32_t HVM_START_MAGIC_VALUE = 0x336ec578U;
static constexpr uint32_t HVM_MEMMAP_TYPE_RAM = 1U;

struct HvmMemmapEntry {
  uint64_t addr;
  uint64_t size;
  uint32_t type;
  uint32_t reserved;
};

struct HvmStartInfo {
  uint32_t magic;
  uint32_t version;
  uint32_t flags;
  uint32_t nr_modules;
  uint64_t modlist_paddr;
  uint64_t cmdline_paddr;
  uint64_t rsdp_paddr;
  uint64_t memmap_paddr;
  uint32_t memmap_entries;
  uint32_t reserved;
};

static inline uint64_t align_up_8(uint64_t val) { return (val + 7) & ~7ULL; }

void shim_x86(BootInfo *info, uint64_t boot_info_addr) {
  info->protocol = Protocol::UNKNOWN;
  info->memory_map_count = 0;
  info->dtb_addr = 0;
  info->kernel_phys_base = 0;
  info->kernel_virt_base = 0;
  info->hhdm_offset = 0;

  if (boot_info_addr == 0) {
    // Fallback: assume 128MB
    info->memory_map[0] = {0, 128ULL * 1024 * 1024, MemoryRegion::AVAILABLE, 0};
    info->memory_map_count = 1;
    serial::printf("  Boot protocol: fallback (no boot info)\n");
    return;
  }

  const auto *magic_ptr = reinterpret_cast<const uint32_t *>(boot_info_addr);

  if (*magic_ptr == HVM_START_MAGIC_VALUE) {
    // ---- PVH boot ----
    info->protocol = Protocol::PVH;
    const auto *hvm = reinterpret_cast<const HvmStartInfo *>(boot_info_addr);
    const auto *entries =
        reinterpret_cast<const HvmMemmapEntry *>(hvm->memmap_paddr);

    int count = 0;
    for (uint32_t i = 0; i < hvm->memmap_entries && count < MAX_MEMORY_REGIONS;
         i++) {
      info->memory_map[count].base = entries[i].addr;
      info->memory_map[count].length = entries[i].size;
      info->memory_map[count].type = (entries[i].type == HVM_MEMMAP_TYPE_RAM)
                                         ? MemoryRegion::AVAILABLE
                                         : MemoryRegion::RESERVED;
      info->memory_map[count]._pad = 0;
      count++;
    }
    info->memory_map_count = count;
    serial::printf("  Boot protocol: PVH (%d memory regions)\n", count);
    return;
  }

  // ---- Try Multiboot2 ----
  uint32_t mb2_total_size = *reinterpret_cast<const uint32_t *>(boot_info_addr);
  if (mb2_total_size >= 8 && mb2_total_size < 65536) {
    const MultibootMmapTag *mmap_tag = nullptr;
    uint64_t tag_addr = boot_info_addr + 8;
    while (true) {
      const auto *tag = reinterpret_cast<const MultibootTag *>(tag_addr);
      if (tag->type == MULTIBOOT_TAG_END)
        break;
      if (tag->type == MULTIBOOT_TAG_MMAP)
        mmap_tag = reinterpret_cast<const MultibootMmapTag *>(tag_addr);
      tag_addr = align_up_8(tag_addr + tag->size);
    }

    if (mmap_tag) {
      info->protocol = Protocol::MULTIBOOT2;
      uint64_t entries_start =
          reinterpret_cast<uint64_t>(&mmap_tag->entries[0]);
      uint64_t entries_end =
          reinterpret_cast<uint64_t>(mmap_tag) + mmap_tag->size;
      uint32_t entry_size = mmap_tag->entry_size;

      int count = 0;
      for (uint64_t ea = entries_start;
           ea < entries_end && count < MAX_MEMORY_REGIONS; ea += entry_size) {
        const auto *e = reinterpret_cast<const MultibootMmapEntry *>(ea);
        info->memory_map[count].base = e->addr;
        info->memory_map[count].length = e->len;
        info->memory_map[count].type = (e->type == MULTIBOOT_MEMORY_AVAILABLE)
                                           ? MemoryRegion::AVAILABLE
                                           : MemoryRegion::RESERVED;
        info->memory_map[count]._pad = 0;
        count++;
      }
      info->memory_map_count = count;
      serial::printf("  Boot protocol: Multiboot2 (%d memory regions)\n",
                     count);
      return;
    }
  }

  // ---- Fallback ----
  info->memory_map[0] = {0, 128ULL * 1024 * 1024, MemoryRegion::AVAILABLE, 0};
  info->memory_map_count = 1;
  serial::printf("  Boot protocol: fallback (unrecognized boot info)\n");
}

#elif defined(__aarch64__)

void shim_fdt(BootInfo *info, uint64_t dtb_addr) {
  info->protocol = Protocol::FDT;
  info->dtb_addr = dtb_addr;
  info->kernel_phys_base = 0;
  info->kernel_virt_base = 0;
  info->hhdm_offset = 0;

  const fdt::Info &fdt_mem = fdt::info();
  uint64_t ram_base =
      (fdt_mem.ram_size != 0) ? fdt_mem.ram_base : 0x40000000ULL;
  uint64_t ram_size =
      (fdt_mem.ram_size != 0) ? fdt_mem.ram_size : 128ULL * 1024 * 1024;

  info->memory_map[0] = {ram_base, ram_size, MemoryRegion::AVAILABLE, 0};
  info->memory_map_count = 1;
  serial::printf("  Boot protocol: FDT (RAM 0x%lx + %u MB)\n", ram_base,
                 (unsigned)(ram_size / (1024 * 1024)));
}

#endif

} // namespace boot
