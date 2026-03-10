#pragma once

// kernel/mm.h — Memory management interface
//
// Provides:
//   - Physical frame allocator (bitmap-based, 4KB pages)
//   - Kernel heap allocator (free-list with splitting and coalescing)
//
// The physical frame allocator manages all available RAM above the kernel.
// The heap allocator provides kmalloc/kfree for dynamic allocations needed
// by the network stack, drivers, etc.

#include <stddef.h>
#include <stdint.h>

#include "kernel/boot_info.h"

namespace mm {

// Page size
static constexpr uint64_t PAGE_SIZE = 4096;

// ============================================================================
// Public API
// ============================================================================

// Initialize the memory manager from the unified boot info.
// Sets up the physical frame bitmap and kernel heap.
void init(const boot::BootInfo &info);

// Allocate a single 4KB physical page frame.
// Returns the physical address of the frame, or 0 on failure.
uint64_t alloc_frame();

// Free a previously allocated physical page frame.
void free_frame(uint64_t addr);

// Allocate memory from the kernel heap.
// Returns a pointer to at least `size` bytes of usable memory, or
// nullptr if the heap is exhausted. The returned pointer is aligned
// to 16 bytes.
void *kmalloc(size_t size);

// Free memory previously allocated by kmalloc.
// Marks the block as free and attempts to coalesce with adjacent
// free blocks.
void kfree(void *ptr);

// Return the total amount of physical RAM detected (in bytes).
size_t get_total_memory();

// Return the amount of free physical RAM (in bytes).
size_t get_free_memory();

// Convert between physical and virtual addresses.
// For identity-mapped boots (QEMU direct, VZ), these are no-ops.
// For Limine higher-half boot, they apply the HHDM offset.
void *phys_to_virt(uint64_t phys);
uint64_t virt_to_phys(const void *virt);

} // namespace mm
