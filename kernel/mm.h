#pragma once

// kernel/mm.h — Memory management interface
//
// Provides:
//   - Physical frame allocator (bitmap-based, 4KB pages)
//   - Kernel heap allocator (free-list with splitting and coalescing)
//   - Multiboot2 memory map parsing
//
// The physical frame allocator manages all available RAM above the kernel.
// The heap allocator provides kmalloc/kfree for dynamic allocations needed
// by the network stack, drivers, etc.

#include <stdint.h>
#include <stddef.h>

namespace mm {

// ============================================================================
// Multiboot2 structures for memory map parsing
// ============================================================================

struct MultibootTag {
    uint32_t type;
    uint32_t size;
};

struct MultibootMmapEntry {
    uint64_t addr;
    uint64_t len;
    uint32_t type;      // 1 = available RAM
    uint32_t reserved;
};

struct MultibootMmapTag {
    uint32_t type;          // 6 = memory map
    uint32_t size;
    uint32_t entry_size;
    uint32_t entry_version;
    MultibootMmapEntry entries[];
};

// Multiboot2 tag types
static constexpr uint32_t MULTIBOOT_TAG_END  = 0;
static constexpr uint32_t MULTIBOOT_TAG_MMAP = 6;

// Multiboot2 memory types
static constexpr uint32_t MULTIBOOT_MEMORY_AVAILABLE = 1;

// Page size
static constexpr uint64_t PAGE_SIZE = 4096;

// ============================================================================
// Public API
// ============================================================================

// Initialize the memory manager.
// Parses the multiboot2 memory map, sets up the physical frame bitmap,
// and initializes the kernel heap.
void init(uint64_t multiboot_info_addr);

// Allocate a single 4KB physical page frame.
// Returns the physical address of the frame, or 0 on failure.
uint64_t alloc_frame();

// Free a previously allocated physical page frame.
void free_frame(uint64_t addr);

// Allocate memory from the kernel heap.
// Returns a pointer to at least `size` bytes of usable memory, or
// nullptr if the heap is exhausted. The returned pointer is aligned
// to 16 bytes.
void* kmalloc(size_t size);

// Free memory previously allocated by kmalloc.
// Marks the block as free and attempts to coalesce with adjacent
// free blocks.
void kfree(void* ptr);

// Return the total amount of physical RAM detected (in bytes).
size_t get_total_memory();

// Return the amount of free physical RAM (in bytes).
size_t get_free_memory();

} // namespace mm
