#pragma once

// kernel/arch.h — Architecture-specific helpers (dispatcher)
//
// Includes the right per-architecture header based on the compiler target.
// All code that includes this header gets a uniform `arch::` namespace
// regardless of the target CPU.

#if defined(__aarch64__)
#  include "kernel/aarch64/arch.h"
#elif defined(__x86_64__)

#include <stdint.h>

namespace arch {

// ============================================================================
// Descriptor table pointer structures
// ============================================================================

// GDTR/IDTR layout: 2-byte limit followed by 8-byte base address
struct __attribute__((packed)) DescriptorTablePtr {
    uint16_t limit;
    uint64_t base;
};

// ============================================================================
// Port I/O
// ============================================================================

// Write a byte to an I/O port
static inline void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

// Read a byte from an I/O port
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// Write a word (16-bit) to an I/O port
static inline void outw(uint16_t port, uint16_t val) {
    asm volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

// Read a word (16-bit) from an I/O port
static inline uint16_t inw(uint16_t port) {
    uint16_t ret;
    asm volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// Write a doubleword (32-bit) to an I/O port
static inline void outl(uint16_t port, uint32_t val) {
    asm volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

// Read a doubleword (32-bit) from an I/O port
static inline uint32_t inl(uint16_t port) {
    uint32_t ret;
    asm volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// Small I/O delay by writing to port 0x80 (POST diagnostic port).
// This is the standard technique for adding a ~1us delay after I/O
// operations to slow devices (e.g., PIC, PIT).
static inline void io_wait() {
    outb(0x80, 0);
}

// ============================================================================
// Interrupt control
// ============================================================================

// Clear interrupt flag — disable maskable interrupts
static inline void cli() {
    asm volatile("cli");
}

// Set interrupt flag — enable maskable interrupts
static inline void sti() {
    asm volatile("sti");
}

// Halt the processor until the next interrupt
static inline void hlt() {
    asm volatile("hlt");
}

// ============================================================================
// Model-Specific Registers (MSRs)
// ============================================================================

// Read a 64-bit value from an MSR
static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

// Write a 64-bit value to an MSR
static inline void wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val;
    uint32_t hi = (uint32_t)(val >> 32);
    asm volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(msr));
}

// ============================================================================
// TLB management
// ============================================================================

// Invalidate the TLB entry for the page containing the given address
static inline void invlpg(uint64_t addr) {
    asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
}

// ============================================================================
// Control registers
// ============================================================================

// Read CR2 — contains the faulting linear address on a page fault
static inline uint64_t read_cr2() {
    uint64_t val;
    asm volatile("mov %%cr2, %0" : "=r"(val));
    return val;
}

// Read CR3 — contains the physical address of the PML4 table
static inline uint64_t read_cr3() {
    uint64_t val;
    asm volatile("mov %%cr3, %0" : "=r"(val));
    return val;
}

// Write CR3 — set the PML4 table base address (flushes TLB)
static inline void write_cr3(uint64_t val) {
    asm volatile("mov %0, %%cr3" : : "r"(val) : "memory");
}

// ============================================================================
// Descriptor table loading
// ============================================================================

// Load the Global Descriptor Table register
static inline void lgdt(const DescriptorTablePtr* ptr) {
    asm volatile("lgdt (%0)" : : "r"(ptr) : "memory");
}

// Load the Interrupt Descriptor Table register
static inline void lidt(const DescriptorTablePtr* ptr) {
    asm volatile("lidt (%0)" : : "r"(ptr) : "memory");
}

// Load the Task Register with a selector
static inline void ltr(uint16_t selector) {
    asm volatile("ltr %0" : : "r"(selector));
}

// ============================================================================
// Virtio register I/O — x86_64 uses I/O port instructions
// ============================================================================
// These dispatch to inb/inw/inl on x86, and to mmio_readN on ARM64,
// giving virtio.cc a single arch-neutral API regardless of BAR type.

static inline uint8_t  virtio_read8 (uint64_t base) { return inb ((uint16_t)base); }
static inline uint16_t virtio_read16(uint64_t base) { return inw ((uint16_t)base); }
static inline uint32_t virtio_read32(uint64_t base) { return inl ((uint16_t)base); }
static inline void virtio_write8 (uint64_t base, uint8_t  v) { outb((uint16_t)base, v); }
static inline void virtio_write16(uint64_t base, uint16_t v) { outw((uint16_t)base, v); }
static inline void virtio_write32(uint64_t base, uint32_t v) { outl((uint16_t)base, v); }

// Hint to the CPU to reduce power during a spin-wait loop.
static inline void cpu_relax() { asm volatile("pause" ::: "memory"); }

} // namespace arch

#else
#  error "Unknown target architecture — add an arch.h include above"
#endif
