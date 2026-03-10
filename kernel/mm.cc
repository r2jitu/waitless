// kernel/mm.cc — Memory management implementation
//
// Two-tier memory management:
//
// 1. Physical frame allocator:
//    A bitmap where each bit represents a 4KB page frame. Bit=1 means used.
//    The bitmap lives immediately after _kernel_end. We walk the BootInfo
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
static uint64_t g_hhdm_offset = 0;      // Limine HHDM offset (0 = identity-mapped)
static uint64_t g_kernel_phys_base = 0; // Physical load address of kernel image
static uint64_t g_kernel_virt_base = 0; // Virtual base of kernel image

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

// Align a value up to a page boundary
static inline uint64_t align_up_page(uint64_t val) {
  return (val + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

// ============================================================================
// Public API implementation
// ============================================================================

void init(const boot::BootInfo &info) {
  // ---- Phase 1: Compute total memory and max physical address ----
  g_hhdm_offset = info.hhdm_offset;
  g_kernel_phys_base = info.kernel_phys_base;
  g_kernel_virt_base = info.kernel_virt_base;
  total_memory_bytes = 0;
  max_physical_addr = 0;

  for (int i = 0; i < info.memory_map_count; i++) {
    if (info.memory_map[i].type == boot::MemoryRegion::AVAILABLE) {
      total_memory_bytes += info.memory_map[i].length;
      uint64_t end = info.memory_map[i].base + info.memory_map[i].length;
      if (end > max_physical_addr)
        max_physical_addr = end;
    }
  }

  serial::printf("  Physical memory: %u MB (max addr 0x%lx)\n",
                 (unsigned)(total_memory_bytes / (1024 * 1024)),
                 max_physical_addr);

  // ---- Phase 2: Set up frame bitmap ----
  // When the kernel is linked in the higher half (Limine boot),
  // _kernel_end is a virtual address like 0xFFFFFFFF801xxxxx.
  // Compute the physical end using the phys/virt base from BootInfo.
  // Limine revision 3 dropped identity mapping; access physical memory
  // via HHDM: virtual = hhdm_offset + physical.
  uint64_t kern_end_phys;
  if (info.kernel_virt_base != 0) {
    kern_end_phys = info.kernel_phys_base +
                    (reinterpret_cast<uint64_t>(_kernel_end) -
                     info.kernel_virt_base);
  } else {
    kern_end_phys = reinterpret_cast<uint64_t>(_kernel_end);
  }

  total_frames = max_physical_addr / PAGE_SIZE;
  frame_bitmap_size = (total_frames + 7) / 8;

  // Find where to place the bitmap + heap.  We need bitmap_size + HEAP_SIZE
  // of contiguous physical memory.  For identity-mapped boots the kernel is
  // at 0x100000 (start of the big region), so placing after it works.
  // For Limine, the kernel is near the END of RAM, so we search the memory
  // map for the largest available region and place our structures there.
  uint64_t needed = align_up_page(frame_bitmap_size) + HEAP_SIZE;
  uint64_t placement_phys = 0;

  if (info.kernel_virt_base != 0) {
    // Higher-half (Limine): find the largest available region
    uint64_t best_size = 0;
    for (int i = 0; i < info.memory_map_count; i++) {
      if (info.memory_map[i].type != boot::MemoryRegion::AVAILABLE)
        continue;
      uint64_t rbase = align_up_page(info.memory_map[i].base);
      uint64_t rend =
          (info.memory_map[i].base + info.memory_map[i].length) &
          ~(PAGE_SIZE - 1);
      if (rend > rbase && (rend - rbase) > best_size &&
          (rend - rbase) >= needed) {
        best_size = rend - rbase;
        placement_phys = rbase;
      }
    }
  }

  if (placement_phys == 0) {
    // Identity-mapped boot or fallback: place after kernel
    placement_phys = align_up_page(kern_end_phys);
  }

  uint64_t bitmap_phys = placement_phys;
  frame_bitmap =
      reinterpret_cast<uint8_t *>(g_hhdm_offset + bitmap_phys);

  // Start: all frames used
  for (uint64_t i = 0; i < frame_bitmap_size; i++)
    frame_bitmap[i] = 0xFF;
  used_frames = total_frames;

  // ---- Phase 3: Free available regions from memory map ----
  for (int i = 0; i < info.memory_map_count; i++) {
    if (info.memory_map[i].type != boot::MemoryRegion::AVAILABLE)
      continue;
    uint64_t start = align_up_page(info.memory_map[i].base);
    uint64_t end =
        (info.memory_map[i].base + info.memory_map[i].length) & ~(PAGE_SIZE - 1);
    for (uint64_t addr = start; addr < end; addr += PAGE_SIZE) {
      uint64_t frame = addr / PAGE_SIZE;
      if (frame < total_frames && bitmap_test(frame)) {
        bitmap_clear(frame);
        used_frames--;
      }
    }
  }

  // Reserve kernel image (physical) + bitmap
  mark_frames_used(info.kernel_phys_base, kern_end_phys);
  uint64_t bitmap_end_phys = bitmap_phys + align_up_page(frame_bitmap_size);
  mark_frames_used(bitmap_phys, bitmap_end_phys);

  serial::printf("  Frame allocator: %u total frames, %u free frames\n",
                 (unsigned)total_frames,
                 (unsigned)(total_frames - used_frames));

  // ---- Phase 4: Set up the kernel heap ----
  // Heap starts after the bitmap, page-aligned. All pointers are virtual
  // (HHDM-offset on Limine, identity-mapped otherwise).
  uint64_t heap_phys = bitmap_end_phys;
  heap_start = reinterpret_cast<uint8_t *>(g_hhdm_offset + heap_phys);
  heap_end = heap_start + HEAP_SIZE;

  // Mark heap pages as used in the frame allocator (physical addresses)
  mark_frames_used(heap_phys, heap_phys + HEAP_SIZE);

  // Initialize the heap with a single large free block
  heap_head = reinterpret_cast<BlockHeader *>(heap_start);
  heap_head->size = HEAP_SIZE - sizeof(BlockHeader);
  heap_head->next = nullptr;
  heap_head->free = true;

  serial::printf("  Heap: %u KB at phys 0x%lx\n",
                 (unsigned)(HEAP_SIZE / 1024), heap_phys);
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

#if !defined(__aarch64__)
void *phys_to_virt(uint64_t phys) {
  return reinterpret_cast<void *>(g_hhdm_offset + phys);
}

uint64_t virt_to_phys(const void *virt) {
  uint64_t addr = reinterpret_cast<uint64_t>(virt);
  // Check kernel virtual range first — it's at higher addresses
  // (0xFFFFFFFF80xxxxxx) than HHDM (0xFFFF800000000000).
  if (g_kernel_virt_base != 0 && addr >= g_kernel_virt_base) {
    return addr - g_kernel_virt_base + g_kernel_phys_base;
  }
  if (g_hhdm_offset != 0 && addr >= g_hhdm_offset) {
    return addr - g_hhdm_offset;
  }
  return addr; // identity-mapped
}
#endif

} // namespace mm
