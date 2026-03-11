#pragma once

// kernel/arch.h — Architecture-specific helpers (dispatcher)
//
// Includes the right per-architecture header based on the compiler target.
// All code that includes this header gets a uniform `arch::` namespace
// regardless of the target CPU.

#if defined(__aarch64__)
#include "kernel/aarch64/arch.h"
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
static inline void io_wait() { outb(0x80, 0); }

// ============================================================================
// Interrupt control
// ============================================================================

// Clear interrupt flag — disable maskable interrupts
static inline void cli() { asm volatile("cli"); }

// Set interrupt flag — enable maskable interrupts
static inline void sti() { asm volatile("sti"); }

// Halt the processor until the next interrupt
static inline void hlt() { asm volatile("hlt"); }

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
static inline void lgdt(const DescriptorTablePtr *ptr) {
  asm volatile("lgdt (%0)" : : "r"(ptr) : "memory");
}

// Load the Interrupt Descriptor Table register
static inline void lidt(const DescriptorTablePtr *ptr) {
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

static inline uint8_t virtio_read8(uint64_t base) {
  return inb((uint16_t)base);
}
static inline uint16_t virtio_read16(uint64_t base) {
  return inw((uint16_t)base);
}
static inline uint32_t virtio_read32(uint64_t base) {
  return inl((uint16_t)base);
}
static inline void virtio_write8(uint64_t base, uint8_t v) {
  outb((uint16_t)base, v);
}
static inline void virtio_write16(uint64_t base, uint16_t v) {
  outw((uint16_t)base, v);
}
static inline void virtio_write32(uint64_t base, uint32_t v) {
  outl((uint16_t)base, v);
}

// Memory barriers.  x86 TSO guarantees store-store and load-load ordering,
// so these are no-ops here.  On aarch64 (see kernel/aarch64/arch.h) they
// emit the corresponding DSB instructions required by ARM's weak model.
static inline void dsb_st() { asm volatile("" ::: "memory"); } // store barrier
static inline void dsb_sy() { asm volatile("" ::: "memory"); } // full barrier
static inline void dsb_ld() { asm volatile("" ::: "memory"); } // load barrier

// Read the Time Stamp Counter (monotonic cycle counter).
static inline uint64_t rdtsc() {
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
}

// Calibrate TSC frequency using the PIT channel 2 (one-shot mode).
// Returns TSC ticks per microsecond.  Called once during boot.
static inline uint64_t calibrate_tsc_per_us() {
  // PIT oscillator frequency: 1,193,182 Hz.
  // Count for ~10ms: 1193182/100 = 11932 ticks → ~10.000ms.
  constexpr uint16_t PIT_COUNT = 11932;
  constexpr uint16_t PIT_CH2_PORT = 0x42;
  constexpr uint16_t PIT_CMD_PORT = 0x43;
  constexpr uint16_t PIT_GATE_PORT = 0x61;

  // Disable speaker, enable gate for channel 2
  uint8_t gate = inb(PIT_GATE_PORT);
  gate = (gate & 0xFD) | 0x01; // clear speaker bit, set gate bit
  outb(PIT_GATE_PORT, gate);

  // Channel 2, mode 0 (one-shot), binary, lo/hi byte
  outb(PIT_CMD_PORT, 0xB0);
  outb(PIT_CH2_PORT, (uint8_t)(PIT_COUNT & 0xFF));
  outb(PIT_CH2_PORT, (uint8_t)(PIT_COUNT >> 8));

  // Reset the latch by toggling the gate
  gate = inb(PIT_GATE_PORT);
  outb(PIT_GATE_PORT, gate & 0xFE); // gate low → reset
  outb(PIT_GATE_PORT, gate | 0x01); // gate high → start counting

  uint64_t start = rdtsc();

  // Wait for OUT pin (bit 5 of port 0x61) to go high (counter reached 0)
  while (!(inb(PIT_GATE_PORT) & 0x20)) {
    asm volatile("nop");
  }

  uint64_t elapsed = rdtsc() - start;
  // PIT_COUNT ticks at 1,193,182 Hz = PIT_COUNT/1193182 seconds
  // = PIT_COUNT/1193182 * 1e6 microseconds = PIT_COUNT * 1e6 / 1193182
  // TSC per microsecond = elapsed / (PIT_COUNT * 1e6 / 1193182)
  //                     = elapsed * 1193182 / (PIT_COUNT * 1000000)
  // Simplify: elapsed * 1193182 / 11932000000
  //         ≈ elapsed / 10000  (since 11932/1193182 ≈ 0.01s)
  return elapsed / 10000;
}

// Busy-wait for approximately `microseconds` microseconds.
// On first call, calibrates the TSC frequency via the PIT.
static inline void udelay(uint64_t microseconds) {
  static uint64_t tsc_per_us = 0;
  if (tsc_per_us == 0) {
    tsc_per_us = calibrate_tsc_per_us();
    if (tsc_per_us == 0)
      tsc_per_us = 1; // safety fallback
  }
  uint64_t end = rdtsc() + tsc_per_us * microseconds;
  while (rdtsc() < end) {
    asm volatile("pause" ::: "memory");
  }
}

// Hint to the CPU to reduce power during a spin-wait loop.
static inline void cpu_relax() { asm volatile("pause" ::: "memory"); }

// IRQ mask/unmask — no-ops on x86 because idle() uses sti;hlt;cli internally.
static inline void mask_irq() {}
static inline void unmask_irq() {}

// Yield the CPU until the next hardware interrupt.
// STI enables interrupts; HLT halts until an IRQ fires (ISR runs, sends EOI);
// CLI re-masks interrupts.  The STI;HLT pair is architecturally atomic — the
// CPU checks for pending interrupts after STI but before HLT, so there is no
// window where an IRQ could be missed.
static inline void idle() { asm volatile("sti; hlt; cli" ::: "memory"); }

// Power off the machine via ACPI S5 sleep.
// Tries multiple PM1_CNT ports and SLP_TYP values to cover:
//   - SeaBIOS/Limine boot (S5 SLP_TYP=0, PIIX4 PM at 0x600)
//   - Direct QEMU -kernel boot (no DSDT, accepts any SLP_TYP)
//   - Q35 machine type (PM at 0xb000)
// Never returns.
[[noreturn]] static inline void shutdown() {
  // PM1_CNT: SLP_EN (bit 13) | SLP_TYP (bits 12:10)
  outw(0x0604, 0x2000);  // i440fx, SLP_TYP=0 (SeaBIOS default S5)
  outw(0x0604, 0x3400);  // i440fx, SLP_TYP=5
  outw(0xb004, 0x2000);  // Q35, SLP_TYP=0
  cli();
  while (true)
    hlt();
}

} // namespace arch

#else
#error "Unknown target architecture — add an arch.h include above"
#endif
