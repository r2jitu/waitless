// kernel/gdt.cc — Global Descriptor Table implementation
//
// Sets up the flat-model GDT for x86_64 long mode:
//   Entry 0: Null descriptor
//   Entry 1: 64-bit kernel code segment (selector 0x08)
//   Entry 2: Kernel data segment (selector 0x10)
//   Entry 3: TSS descriptor (16 bytes, selector 0x18)
//
// After loading the GDTR, we reload CS via a far return and set all
// data segment registers to the kernel data selector.

#include "kernel/gdt.h"
#include "kernel/arch.h"
#include "kernel/serial.h"

namespace gdt {

// ============================================================================
// Static storage
// ============================================================================

// We need 5 GDTEntry slots: null + code + data + 2 for TSS (TSS is 16 bytes)
static GDTEntry gdt_entries[5];

// The single TSS instance
static TSS tss;

// GDTR pointer
static arch::DescriptorTablePtr gdtr;

// ============================================================================
// Internal helpers
// ============================================================================

// Encode a standard 8-byte GDT entry
static void set_entry(int index, uint32_t base, uint32_t limit,
                       uint8_t access, uint8_t flags) {
    gdt_entries[index].limit_low    = limit & 0xFFFF;
    gdt_entries[index].base_low     = base & 0xFFFF;
    gdt_entries[index].base_middle  = (base >> 16) & 0xFF;
    gdt_entries[index].access       = access;
    gdt_entries[index].granularity  = ((flags & 0xF0) | ((limit >> 16) & 0x0F));
    gdt_entries[index].base_high    = (base >> 24) & 0xFF;
}

// Set up the 16-byte TSS descriptor at GDT index 3 (and 4).
// A system segment descriptor in long mode is 16 bytes: the first 8 bytes
// follow the standard format, and the next 8 bytes hold base[63:32] + reserved.
static void set_tss_entry(int index, uint64_t base, uint32_t limit) {
    // First 8 bytes (standard descriptor format)
    gdt_entries[index].limit_low    = limit & 0xFFFF;
    gdt_entries[index].base_low     = base & 0xFFFF;
    gdt_entries[index].base_middle  = (base >> 16) & 0xFF;
    // Access: Present=1, DPL=0, Type=0x9 (64-bit TSS available)
    gdt_entries[index].access       = 0x89;
    gdt_entries[index].granularity  = ((limit >> 16) & 0x0F);
    gdt_entries[index].base_high    = (base >> 24) & 0xFF;

    // Second 8 bytes: upper 32 bits of base address + reserved
    // We treat gdt_entries[index+1] as raw bytes for the upper portion
    uint32_t* upper = reinterpret_cast<uint32_t*>(&gdt_entries[index + 1]);
    upper[0] = (base >> 32) & 0xFFFFFFFF; // Base bits 63:32
    upper[1] = 0;                          // Reserved
}

// ============================================================================
// Public API
// ============================================================================

void init() {
    // Zero out the TSS
    uint8_t* tss_bytes = reinterpret_cast<uint8_t*>(&tss);
    for (unsigned i = 0; i < sizeof(TSS); i++) {
        tss_bytes[i] = 0;
    }

    // Set the I/O permission bitmap offset past the end of the TSS
    // (effectively disabling it — no I/O bitmap)
    tss.iopb_offset = sizeof(TSS);

    // Entry 0: Null descriptor
    set_entry(0, 0, 0, 0, 0);

    // Entry 1: Kernel code segment (selector 0x08)
    // Access: Present=1, DPL=0, S=1, Exec=1, DC=0, RW=1, Accessed=0 = 0x9A
    // Flags: G=0, L=1 (long mode), D=0, AVL=0 => upper nibble = 0xA0
    // This encodes to the raw value 0x00AF9A000000FFFF
    set_entry(1, 0, 0xFFFFF, 0x9A, 0xA0);

    // Entry 2: Kernel data segment (selector 0x10)
    // Access: Present=1, DPL=0, S=1, Exec=0, DC=0, RW=1, Accessed=0 = 0x92
    // Flags: G=1, D=1, L=0, AVL=0 => upper nibble = 0xC0
    // This encodes to the raw value 0x00CF92000000FFFF
    set_entry(2, 0, 0xFFFFF, 0x92, 0xC0);

    // Entry 3-4: TSS descriptor (16 bytes, selector 0x18)
    uint64_t tss_base = reinterpret_cast<uint64_t>(&tss);
    set_tss_entry(3, tss_base, sizeof(TSS) - 1);

    // Load the GDTR
    gdtr.limit = sizeof(gdt_entries) - 1;
    gdtr.base  = reinterpret_cast<uint64_t>(&gdt_entries);
    arch::lgdt(&gdtr);

    // Reload segment registers.
    // CS must be reloaded via a far return (retfq) because you cannot
    // directly mov into CS. We push the new CS selector and the return
    // address onto the stack, then execute retfq.
    asm volatile(
        // Reload CS via far return
        "pushq %[cs]\n"              // Push new code selector
        "leaq 1f(%%rip), %%rax\n"    // Load address of label 1:
        "pushq %%rax\n"              // Push return address
        "lretq\n"                     // Far return: pops RIP and CS
        "1:\n"
        // Reload data segment registers
        "movw %[ds], %%ax\n"
        "movw %%ax, %%ds\n"
        "movw %%ax, %%es\n"
        "movw %%ax, %%ss\n"
        "movw $0, %%ax\n"            // FS and GS = 0 (not used)
        "movw %%ax, %%fs\n"
        "movw %%ax, %%gs\n"
        :
        : [cs] "i"((uint64_t)KERNEL_CODE_SELECTOR),
          [ds] "rm"(KERNEL_DATA_SELECTOR)
        : "rax", "memory"
    );

    // Load the Task Register
    arch::ltr(TSS_SELECTOR);
}

void set_kernel_stack(uint64_t stack) {
    tss.rsp0 = stack;
}

} // namespace gdt
