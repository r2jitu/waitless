#pragma once

// kernel/mm.h — Memory management interface
//
// Thin C++ wrapper around the Rust mm implementation (kernel/mm.rs).
// The extern "C" functions are exported by the Rust static library;
// the namespace mm inlines provide source-compatible C++ API.

#include <stddef.h>
#include <stdint.h>

#include "kernel/boot_info.h"

// ---- Rust extern "C" functions (kernel/mm.rs) ----

extern "C" {
void mm_init(const boot::BootInfo *info);
uint64_t mm_alloc_frame();
void mm_free_frame(uint64_t addr);
void *mm_kmalloc(size_t size);
void mm_kfree(void *ptr);
size_t mm_get_total_memory();
size_t mm_get_free_memory();
void *mm_phys_to_virt(uint64_t phys);
uint64_t mm_virt_to_phys(const void *virt);
}

// ---- Source-compatible C++ namespace wrappers ----

namespace mm {

static constexpr uint64_t PAGE_SIZE = 4096;

inline void init(const boot::BootInfo &info) { mm_init(&info); }
inline uint64_t alloc_frame() { return mm_alloc_frame(); }
inline void free_frame(uint64_t addr) { mm_free_frame(addr); }
inline void *kmalloc(size_t size) { return mm_kmalloc(size); }
inline void kfree(void *ptr) { mm_kfree(ptr); }
inline size_t get_total_memory() { return mm_get_total_memory(); }
inline size_t get_free_memory() { return mm_get_free_memory(); }
inline void *phys_to_virt(uint64_t phys) { return mm_phys_to_virt(phys); }
inline uint64_t virt_to_phys(const void *virt) { return mm_virt_to_phys(virt); }

} // namespace mm
