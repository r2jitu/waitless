#pragma once

// kernel/gdt.h — Global Descriptor Table interface
//
// Sets up the x86_64 GDT with kernel code/data segments and a TSS.
// In long mode, most segmentation is ignored, but we still need:
//   - A null descriptor (index 0)
//   - A 64-bit kernel code segment (index 1, selector 0x08)
//   - A kernel data segment (index 2, selector 0x10)
//   - A TSS descriptor (index 3, 16 bytes, selector 0x18)
//
// The TSS is needed for interrupt stack switching (RSP0).

#include <stdint.h>

namespace gdt {

// Segment selectors
static constexpr uint16_t KERNEL_CODE_SELECTOR = 0x08;
static constexpr uint16_t KERNEL_DATA_SELECTOR = 0x10;
static constexpr uint16_t TSS_SELECTOR = 0x18;

// GDT entry: 8 bytes, packed
// Standard segment descriptor format (see Intel SDM Vol. 3A, 3.4.5)
struct __attribute__((packed)) GDTEntry {
  uint16_t limit_low;  // Segment limit bits 0-15
  uint16_t base_low;   // Base address bits 0-15
  uint8_t base_middle; // Base address bits 16-23
  uint8_t access;      // Access byte (type, DPL, present, etc.)
  uint8_t granularity; // Flags + limit bits 16-19
  uint8_t base_high;   // Base address bits 24-31
};

// Task State Segment: 104 bytes, packed
// Used in long mode primarily for RSP0 (kernel stack for ring transitions)
// and IST entries (interrupt stack table).
struct __attribute__((packed)) TSS {
  uint32_t reserved0;
  uint64_t rsp0; // Stack pointer for privilege level 0
  uint64_t rsp1; // Stack pointer for privilege level 1
  uint64_t rsp2; // Stack pointer for privilege level 2
  uint64_t reserved1;
  uint64_t ist1; // Interrupt Stack Table entry 1
  uint64_t ist2;
  uint64_t ist3;
  uint64_t ist4;
  uint64_t ist5;
  uint64_t ist6;
  uint64_t ist7;
  uint64_t reserved2;
  uint16_t reserved3;
  uint16_t iopb_offset; // I/O Permission Bitmap offset
};

// Initialize the GDT with kernel code/data segments and TSS.
// Loads the GDTR, reloads all segment registers, and loads the TSS.
void init();

// Set the kernel stack pointer in the TSS.
// Called when switching tasks or setting up the initial interrupt stack.
// When an interrupt occurs in ring 3 (if we ever add user mode), the
// CPU switches RSP to this value.
void set_kernel_stack(uint64_t stack);

} // namespace gdt
