// kernel/mm.cc — Memory management implementation
//
// Two-tier memory management:
//
// 1. Physical frame allocator:
//    A bitmap where each bit represents a 4KB page frame. Bit=1 means used.
//    The bitmap lives immediately after _kernel_end. We parse the multiboot2
//    memory map to find available regions and mark everything else as used.
//
// 2. Kernel heap allocator:
//    A classic free-list allocator with block headers. Each block has a
//    header containing {size, next pointer, free flag}. kmalloc() walks the
//    free list looking for a suitable block (first-fit), splitting if the
//    block is significantly larger than requested. kfree() marks the block
//    as free and coalesces with physically adjacent free blocks.
//
//    The heap starts after the frame bitmap and grows upward. We pre-allocate
//    a fixed heap region (e.g., 16MB) from the available physical memory.

#include "kernel/mm.h"
#include "kernel/panic.h"
#include "kernel/serial.h"
#if defined(__aarch64__)
#include "kernel/fdt.h"
#endif

// Linker-provided symbol marking the end of the kernel image
extern "C" uint8_t _kernel_end[];

namespace mm {

// ============================================================================
// Physical frame allocator state
// ============================================================================

// Bitmap: one bit per 4KB frame. bit[i]=1 means frame i is in use.
static uint8_t *frame_bitmap = nullptr;
static uint64_t frame_bitmap_size = 0;  // Size of bitmap in bytes
static uint64_t total_frames = 0;       // Total number of frames tracked
static uint64_t used_frames = 0;        // Number of frames currently in use
static uint64_t total_memory_bytes = 0; // Total RAM detected
static uint64_t max_physical_addr = 0;  // Highest usable physical address

// ============================================================================
// Bitmap helpers
// ============================================================================

static inline void bitmap_set(uint64_t frame) {
  if (frame < total_frames) {
    frame_bitmap[frame / 8] |= (1 << (frame % 8));
  }
}

static inline void bitmap_clear(uint64_t frame) {
  if (frame < total_frames) {
    frame_bitmap[frame / 8] &= ~(1 << (frame % 8));
  }
}

static inline bool bitmap_test(uint64_t frame) {
  if (frame < total_frames) {
    return (frame_bitmap[frame / 8] & (1 << (frame % 8))) != 0;
  }
  return true; // Out-of-range frames are considered "in use"
}

// Mark a range of frames as used
static void mark_frames_used(uint64_t start_addr, uint64_t end_addr) {
  uint64_t start_frame = start_addr / PAGE_SIZE;
  uint64_t end_frame = (end_addr + PAGE_SIZE - 1) / PAGE_SIZE;

  if (end_frame > total_frames)
    end_frame = total_frames;

  for (uint64_t i = start_frame; i < end_frame; i++) {
    if (!bitmap_test(i)) {
      bitmap_set(i);
      used_frames++;
    }
  }
}

// ============================================================================
// Kernel heap allocator
// ============================================================================

// Block header for the heap free-list allocator.
// Each allocation is preceded by this header. Adjacent free blocks are
// coalesced on free() to reduce fragmentation.
struct BlockHeader {
  uint64_t size;      // Size of the usable region (excluding header)
  BlockHeader *next;  // Next block in physical memory order (not free-list)
  bool free;          // true if this block is available for allocation
  uint8_t padding[7]; // Pad to 24 bytes for 16-byte alignment of payload
};

// Ensure the header is the right size for alignment
static_assert(sizeof(BlockHeader) == 24, "BlockHeader must be 24 bytes");

// Minimum allocation size to avoid excessive fragmentation.
// Blocks smaller than this won't be split.
static constexpr size_t MIN_BLOCK_SIZE = 16;

// Heap size: 16 MB should be plenty for a unikernel's network stack
static constexpr size_t HEAP_SIZE = 16 * 1024 * 1024;

// Heap state
static uint8_t *heap_start = nullptr;
static uint8_t *heap_end = nullptr;
static BlockHeader *heap_head = nullptr; // First block in the heap

// ============================================================================
// Boot protocol parsing (multiboot2 and PVH/Xen hvm_start_info)
// ============================================================================

#if !defined(__aarch64__)

// Align a value up to an 8-byte boundary (multiboot2 tag alignment)
static inline uint64_t align_up_8(uint64_t val) { return (val + 7) & ~7ULL; }

// PVH (Xen HVM) boot info structures — used by QEMU 10.x PVH kernel loading
static constexpr uint32_t HVM_START_MAGIC_VALUE = 0x336ec578U;
static constexpr uint32_t HVM_MEMMAP_TYPE_RAM = 1U;

struct HvmMemmapEntry {
  uint64_t addr;
  uint64_t size;
  uint32_t type; // 1 = usable RAM
  uint32_t reserved;
};

struct HvmStartInfo {
  uint32_t magic; // HVM_START_MAGIC_VALUE
  uint32_t version;
  uint32_t flags;
  uint32_t nr_modules;
  uint64_t modlist_paddr;
  uint64_t cmdline_paddr;
  uint64_t rsdp_paddr;
  uint64_t memmap_paddr; // physical address of HvmMemmapEntry array
  uint32_t memmap_entries;
  uint32_t reserved;
};

#endif // !defined(__aarch64__)

// Align a value up to a page boundary
static inline uint64_t align_up_page(uint64_t val) {
  return (val + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

// ============================================================================
// Public API implementation
// ============================================================================

void init(uint64_t boot_info_addr) {
  uint64_t bitmap_end;

#if defined(__aarch64__)
  // ---- ARM64: use FDT-discovered RAM base and size -------------------------
  // VZ.framework maps RAM at GPA 0x00000000; QEMU virt uses 0x40000000.
  // We read the base and size from the /memory node parsed by fdt::init().
  // If the FDT didn't supply a memory node (dtb_addr==0 or missing node),
  // fall back to the QEMU virt default of 128 MB at 0x40000000.
  const fdt::Info &fdt_mem = fdt::info();
  uint64_t ram_base =
      (fdt_mem.ram_size != 0) ? fdt_mem.ram_base : 0x40000000ULL;
  uint64_t ram_size =
      (fdt_mem.ram_size != 0) ? fdt_mem.ram_size : 128ULL * 1024 * 1024;

  max_physical_addr = ram_base + ram_size;
  total_memory_bytes = ram_size;

  serial::printf("  Physical memory: %u MB (FDT/ARM64, 0x%lx-0x%lx)\n",
                 (unsigned)(ram_size / (1024 * 1024)), ram_base,
                 max_physical_addr);

  // Frame bitmap placed after the kernel image
  total_frames = max_physical_addr / PAGE_SIZE;
  frame_bitmap_size = (total_frames + 7) / 8;
  frame_bitmap = reinterpret_cast<uint8_t *>(
      align_up_page(reinterpret_cast<uint64_t>(_kernel_end)));

  // Start: all frames used
  for (uint64_t i = 0; i < frame_bitmap_size; i++)
    frame_bitmap[i] = 0xFF;
  used_frames = total_frames;

  // Free the available region (after bitmap, within RAM range)
  bitmap_end = reinterpret_cast<uint64_t>(frame_bitmap) + frame_bitmap_size;
  uint64_t free_start = align_up_page(bitmap_end);
  for (uint64_t addr = free_start; addr < max_physical_addr;
       addr += PAGE_SIZE) {
    uint64_t frame = addr / PAGE_SIZE;
    if (frame < total_frames && bitmap_test(frame)) {
      bitmap_clear(frame);
      used_frames--;
    }
  }

  // Keep the RAM base through kernel+bitmap reserved
  mark_frames_used(ram_base, bitmap_end);

#else
  // ---- x86_64: parse boot info (multiboot2 or PVH hvm_start_info) -----
  //
  // QEMU 10.x boots 64-bit ELF kernels via PVH (Xen HVM start), passing
  // hvm_start_info in ESI (which boot.S saves in RDI → boot_info_addr).
  // Older QEMU / GRUB uses multiboot2 and passes the info struct in EBX.
  // We detect the protocol by checking the magic at boot_info_addr.

  uint64_t mbi_addr = boot_info_addr;
  total_memory_bytes = 0;
  max_physical_addr = 0;

  const uint32_t *magic_ptr = reinterpret_cast<const uint32_t *>(mbi_addr);
  if (mbi_addr != 0 && *magic_ptr == HVM_START_MAGIC_VALUE) {
    // ---- PVH boot (QEMU 10.x) ----------------------------------------
    const HvmStartInfo *info = reinterpret_cast<const HvmStartInfo *>(mbi_addr);
    const HvmMemmapEntry *entries =
        reinterpret_cast<const HvmMemmapEntry *>((uint64_t)info->memmap_paddr);

    for (uint32_t i = 0; i < info->memmap_entries; i++) {
      if (entries[i].type == HVM_MEMMAP_TYPE_RAM) {
        total_memory_bytes += entries[i].size;
        uint64_t end = entries[i].addr + entries[i].size;
        if (end > max_physical_addr)
          max_physical_addr = end;
      }
    }

    serial::printf("  Physical memory: %u MB (PVH, max addr 0x%lx)\n",
                   (unsigned)(total_memory_bytes / (1024 * 1024)),
                   max_physical_addr);

    total_frames = max_physical_addr / PAGE_SIZE;
    frame_bitmap_size = (total_frames + 7) / 8;
    frame_bitmap = reinterpret_cast<uint8_t *>(
        align_up_page(reinterpret_cast<uint64_t>(_kernel_end)));

    for (uint64_t i = 0; i < frame_bitmap_size; i++)
      frame_bitmap[i] = 0xFF;
    used_frames = total_frames;

    for (uint32_t i = 0; i < info->memmap_entries; i++) {
      if (entries[i].type != HVM_MEMMAP_TYPE_RAM)
        continue;
      uint64_t start = align_up_page(entries[i].addr);
      uint64_t end = (entries[i].addr + entries[i].size) & ~(PAGE_SIZE - 1);
      for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
        uint64_t frame = addr / PAGE_SIZE;
        if (frame < total_frames && bitmap_test(frame)) {
          bitmap_clear(frame);
          used_frames--;
        }
      }
    }

    bitmap_end = reinterpret_cast<uint64_t>(frame_bitmap) + frame_bitmap_size;
    mark_frames_used(0, bitmap_end);
    mark_frames_used(mbi_addr, mbi_addr + sizeof(HvmStartInfo));
  } else {
    // ---- Try multiboot2 (GRUB / older QEMU with SeaBIOS) ---------------
    const MultibootMmapTag *mmap_tag = nullptr;
    bool multiboot2_valid = false;

    // Multiboot2 info: first dword is total_size (must be > 8 and < 64KB)
    uint32_t mb2_total_size =
        mbi_addr ? *reinterpret_cast<const uint32_t *>(mbi_addr) : 0;
    if (mb2_total_size >= 8 && mb2_total_size < 65536) {
      uint64_t tag_addr = mbi_addr + 8;
      while (true) {
        const MultibootTag *tag =
            reinterpret_cast<const MultibootTag *>(tag_addr);
        if (tag->type == MULTIBOOT_TAG_END)
          break;
        if (tag->type == MULTIBOOT_TAG_MMAP) {
          mmap_tag = reinterpret_cast<const MultibootMmapTag *>(tag_addr);
        }
        tag_addr = align_up_8(tag_addr + tag->size);
      }
      if (mmap_tag)
        multiboot2_valid = true;
    }

    if (multiboot2_valid) {
      uint64_t mmap_entries_start =
          reinterpret_cast<uint64_t>(&mmap_tag->entries[0]);
      uint64_t mmap_entries_end =
          reinterpret_cast<uint64_t>(mmap_tag) + mmap_tag->size;
      uint32_t entry_size = mmap_tag->entry_size;

      for (uint64_t ea = mmap_entries_start; ea < mmap_entries_end;
           ea += entry_size) {
        const MultibootMmapEntry *e =
            reinterpret_cast<const MultibootMmapEntry *>(ea);
        if (e->type == MULTIBOOT_MEMORY_AVAILABLE) {
          total_memory_bytes += e->len;
          uint64_t end = e->addr + e->len;
          if (end > max_physical_addr)
            max_physical_addr = end;
        }
      }

      serial::printf("  Physical memory: %u MB (multiboot2, max addr 0x%lx)\n",
                     (unsigned)(total_memory_bytes / (1024 * 1024)),
                     max_physical_addr);

      total_frames = max_physical_addr / PAGE_SIZE;
      frame_bitmap_size = (total_frames + 7) / 8;
      frame_bitmap = reinterpret_cast<uint8_t *>(
          align_up_page(reinterpret_cast<uint64_t>(_kernel_end)));

      for (uint64_t i = 0; i < frame_bitmap_size; i++)
        frame_bitmap[i] = 0xFF;
      used_frames = total_frames;

      for (uint64_t ea = mmap_entries_start; ea < mmap_entries_end;
           ea += entry_size) {
        const MultibootMmapEntry *e =
            reinterpret_cast<const MultibootMmapEntry *>(ea);
        if (e->type != MULTIBOOT_MEMORY_AVAILABLE)
          continue;
        uint64_t start = align_up_page(e->addr);
        uint64_t end = (e->addr + e->len) & ~(PAGE_SIZE - 1);
        for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
          uint64_t frame = addr / PAGE_SIZE;
          if (frame < total_frames && bitmap_test(frame)) {
            bitmap_clear(frame);
            used_frames--;
          }
        }
      }

      bitmap_end = reinterpret_cast<uint64_t>(frame_bitmap) + frame_bitmap_size;
      mark_frames_used(0, bitmap_end);

      uint32_t mbi_total_size_val =
          *reinterpret_cast<const uint32_t *>(mbi_addr);
      mark_frames_used(mbi_addr, mbi_addr + mbi_total_size_val);
    } else {
      // ---- Fallback: fixed QEMU memory layout (no valid boot info) ---
      // When neither PVH nor multiboot2 info is available (e.g., QEMU
      // 10.x with SeaBIOS that doesn't support multiboot2), use a
      // hardcoded layout matching QEMU PC machine with -m 128.
      static constexpr uint64_t QEMU_X86_RAM_SIZE = 128ULL * 1024 * 1024;
      max_physical_addr = QEMU_X86_RAM_SIZE;
      total_memory_bytes = QEMU_X86_RAM_SIZE;

      serial::printf("  Physical memory: %u MB (hardcoded QEMU default)\n",
                     (unsigned)(total_memory_bytes / (1024 * 1024)));

      total_frames = max_physical_addr / PAGE_SIZE;
      frame_bitmap_size = (total_frames + 7) / 8;
      frame_bitmap = reinterpret_cast<uint8_t *>(
          align_up_page(reinterpret_cast<uint64_t>(_kernel_end)));

      for (uint64_t i = 0; i < frame_bitmap_size; i++)
        frame_bitmap[i] = 0xFF;
      used_frames = total_frames;

      // Free RAM above the kernel image
      bitmap_end = reinterpret_cast<uint64_t>(frame_bitmap) + frame_bitmap_size;
      uint64_t free_start = align_up_page(bitmap_end);
      for (uint64_t addr = free_start; addr < max_physical_addr;
           addr += PAGE_SIZE) {
        uint64_t frame = addr / PAGE_SIZE;
        if (frame < total_frames && bitmap_test(frame)) {
          bitmap_clear(frame);
          used_frames--;
        }
      }

      // Reserve low memory (BIOS/VGA area) and kernel
      mark_frames_used(0, bitmap_end);
    }
  }
#endif

  serial::printf("  Frame allocator: %u total frames, %u free frames\n",
                 (unsigned)total_frames,
                 (unsigned)(total_frames - used_frames));

  // ---- Phase 4: Set up the kernel heap ----

  // The heap starts after the bitmap, page-aligned
  heap_start = reinterpret_cast<uint8_t *>(align_up_page(bitmap_end));
  heap_end = heap_start + HEAP_SIZE;

  // Mark heap pages as used in the frame allocator
  mark_frames_used(reinterpret_cast<uint64_t>(heap_start),
                   reinterpret_cast<uint64_t>(heap_end));

  // Initialize the heap with a single large free block
  heap_head = reinterpret_cast<BlockHeader *>(heap_start);
  heap_head->size = HEAP_SIZE - sizeof(BlockHeader);
  heap_head->next = nullptr;
  heap_head->free = true;

  serial::printf("  Heap: %u KB at 0x%lx - 0x%lx\n",
                 (unsigned)(HEAP_SIZE / 1024), (uint64_t)heap_start,
                 (uint64_t)heap_end);
}

uint64_t alloc_frame() {
  // Linear scan for the first free frame.
  // This is O(n) but simple. For a unikernel with limited physical memory
  // use, it's acceptable. A more advanced allocator could use a free stack.
  for (uint64_t i = 0; i < total_frames; i++) {
    if (!bitmap_test(i)) {
      bitmap_set(i);
      used_frames++;
      return i * PAGE_SIZE;
    }
  }

  serial::printf("mm::alloc_frame: out of physical memory!\n");
  return 0;
}

void free_frame(uint64_t addr) {
  uint64_t frame = addr / PAGE_SIZE;
  if (frame >= total_frames)
    return;

  if (bitmap_test(frame)) {
    bitmap_clear(frame);
    used_frames--;
  }
}

void *kmalloc(size_t size) {
  if (size == 0)
    return nullptr;

  // Align requested size up to 16 bytes for alignment guarantees
  size = (size + 15) & ~15ULL;

  // First-fit search through the block list
  BlockHeader *current = heap_head;
  while (current) {
    if (current->free && current->size >= size) {
      // Found a suitable free block.

      // Split the block if it's significantly larger than needed.
      // We need room for at least a header + MIN_BLOCK_SIZE in the remainder.
      if (current->size >= size + sizeof(BlockHeader) + MIN_BLOCK_SIZE) {
        // Create a new free block after the allocated region
        BlockHeader *new_block = reinterpret_cast<BlockHeader *>(
            reinterpret_cast<uint8_t *>(current) + sizeof(BlockHeader) + size);
        new_block->size = current->size - size - sizeof(BlockHeader);
        new_block->next = current->next;
        new_block->free = true;

        current->size = size;
        current->next = new_block;
      }

      current->free = false;

      // Return pointer to usable region (just past the header)
      return reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(current) +
                                      sizeof(BlockHeader));
    }
    current = current->next;
  }

  // No suitable block found
  serial::printf("mm::kmalloc: out of heap memory (requested %u bytes)!\n",
                 (unsigned)size);
  return nullptr;
}

void kfree(void *ptr) {
  if (!ptr)
    return;

  // Retrieve the block header (it's immediately before the usable region)
  BlockHeader *block = reinterpret_cast<BlockHeader *>(
      reinterpret_cast<uint8_t *>(ptr) - sizeof(BlockHeader));

  // Sanity check: make sure this looks like a valid allocation
  uint8_t *block_addr = reinterpret_cast<uint8_t *>(block);
  if (block_addr < heap_start || block_addr >= heap_end) {
    serial::printf("mm::kfree: pointer %p is outside the heap!\n", ptr);
    return;
  }

  if (block->free) {
    serial::printf("mm::kfree: double free detected at %p!\n", ptr);
    return;
  }

  block->free = true;

  // Coalesce with the next block if it's also free
  if (block->next && block->next->free) {
    block->size += sizeof(BlockHeader) + block->next->size;
    block->next = block->next->next;
  }

  // Coalesce with the previous block if it's also free.
  // We need to walk from the head to find the predecessor — this is O(n)
  // but keeps the allocator simple. A doubly-linked list would be O(1).
  BlockHeader *prev = nullptr;
  BlockHeader *current = heap_head;
  while (current && current != block) {
    prev = current;
    current = current->next;
  }

  if (prev && prev->free) {
    prev->size += sizeof(BlockHeader) + block->size;
    prev->next = block->next;
  }
}

size_t get_total_memory() { return total_memory_bytes; }

size_t get_free_memory() { return (total_frames - used_frames) * PAGE_SIZE; }

} // namespace mm
