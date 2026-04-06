// boot/x86_64/ap_boot.S — AP trampoline for x86_64 SMP.
//
// INIT-SIPI-SIPI starts APs in 16-bit real mode at the address
// specified by the SIPI vector (page-aligned, below 1MB).
// This trampoline transitions: real mode → protected → long mode,
// then jumps to the Rust ap_entry function.
//
// The BSP copies this code to a low-memory page (e.g., 0x8000)
// before sending SIPI. Data at the end of the page contains the
// page table address and stack pointer set by the BSP.

.section .text

// ── 16-bit real mode entry ──────────────────────────────────────────────
.code16
.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:
    cli
    cld

    // Load the data page address (same page, offset 0xFF0)
    // The BSP writes the PML4 address and stack pointer here.
    // Since we're running at an unknown base, use CS-relative addressing.
    mov %cs, %ax
    mov %ax, %ds

    // Load GDT pointer (at offset 0xF00 in this page)
    lgdt (0xF00)

    // Enable protected mode (CR0.PE = 1)
    mov %cr0, %eax
    or  $1, %eax
    mov %eax, %cr0

    // Far jump to 32-bit code (selector 0x08 = code segment)
    // Use a data-based far jump since we don't know our load address
    ljmpl $0x08, $(ap_trampoline_32 - ap_trampoline_start + 0x8000)

// ── 32-bit protected mode ───────────────────────────────────────────────
.code32
ap_trampoline_32:
    // Set up data segments
    mov $0x10, %ax          // data segment selector
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss

    // Load PML4 from data area (offset 0xFF0 from page base)
    mov (0x8FF0), %eax
    mov %eax, %cr3

    // Enable PAE
    mov %cr4, %eax
    or  $(1 << 5), %eax
    mov %eax, %cr4

    // Enable long mode (EFER.LME)
    mov $0xC0000080, %ecx
    rdmsr
    or  $(1 << 8), %eax
    wrmsr

    // Enable paging (CR0.PG)
    mov %cr0, %eax
    or  $(1 << 31), %eax
    mov %eax, %cr0

    // Load 64-bit GDT and far jump to 64-bit code
    lgdt (0x8F00)
    ljmpl $0x08, $(ap_trampoline_64 - ap_trampoline_start + 0x8000)

// ── 64-bit long mode ────────────────────────────────────────────────────
.code64
ap_trampoline_64:
    // Reload data segments for long mode
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs

    // Load stack pointer from data area (offset 0xFF8)
    mov (0x8FF8), %rsp

    // Enable SSE (CR4 bits 9 & 10)
    mov %cr4, %rax
    or  $(3 << 9), %rax
    mov %rax, %cr4

    // Jump to Rust AP entry (defined in kernel/x86_64/smp.rs)
    // RDI = 0 (no context needed, stack already set)
    xor %rdi, %rdi
    call ap_entry_x86

    // Should not return
1:  hlt
    jmp 1b

ap_trampoline_end:
    nop
