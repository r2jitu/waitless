// boot/x86_64/ap_boot.S — AP trampoline for x86_64 SMP.
//
// Copied to 0x8000 by the BSP. APs start via SIPI vector=0x08.
// Data at end of page:
//   0x8F00: GDT descriptor (6 bytes) + GDT entries (24 bytes)
//   0x8FF0: PML4 physical address (4 bytes)
//   0x8FF8: stack pointer (8 bytes)

.section .text

.code16
.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:
    cli
    cld
    xor %ax, %ax
    mov %ax, %ds

// Load GDT: use o32 prefix for 32-bit GDTR base
    .byte 0x66
    lgdt (0x8F00)

    // Enable protected mode
    mov %cr0, %eax
    or  $1, %eax
    mov %eax, %cr0

    // Far jump to protected mode
    // In 16-bit mode: EA [2-byte offset] [2-byte selector]
    ljmpw $0x08, $(0x8000 + ap_pm32 - ap_trampoline_start)

.code32
.align 4
ap_pm32:
mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss

    // Load PML4
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

    // Enable paging
    mov %cr0, %eax
    or  $(1 << 31), %eax
    mov %eax, %cr0

    // Far jump to 64-bit long mode (selector 0x18 = 64-bit code)
    .byte 0xEA
    .long 0x8000 + (ap_lm64 - ap_trampoline_start)
    .word 0x18

.code64
.align 8
ap_lm64:
mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs

    // Load stack
    mov (0x8FF8), %rsp

    // Enable SSE + (optionally) AVX register state. Matches the
    // BSP sequence in `boot/x86_64/boot.S`: OSFXSR + OSXMMEXCPT
    // unconditionally, then OSXSAVE + XSETBV only if the CPU
    // reports XSAVE support via CPUID (so this still works on
    // pre-AVX CPU models like `qemu64`). Rust crypto crates
    // compiled with `+avx,+avx2` in MODULE.bazel emit YMM
    // instructions from per-core AP code paths (TLS handshake
    // state touched by the profiler hot path among them), so
    // the AP must land in the same CPU state as the BSP.
    mov %cr4, %rax
    or  $(1 << 9) | (1 << 10), %rax
    mov %rax, %cr4

    mov $1, %eax
    cpuid
    test $(1 << 26), %ecx           // CPUID.01h:ECX.XSAVE
    jz ap_sse_only

    mov %cr4, %rax
    or  $(1 << 18), %rax            // CR4.OSXSAVE
    mov %rax, %cr4

    mov $0xD, %eax
    xor %ecx, %ecx
    cpuid
    and $0x7, %eax                  // x87|SSE|AVX AND supported

    xor %rcx, %rcx
    xor %rdx, %rdx
    xsetbv

ap_sse_only:

    // Call Rust AP entry via absolute address (trampoline is copied to 0x8000,
    // so relative call would use wrong offset)
    xor %rdi, %rdi
    movabs $ap_entry_x86, %rax
    call *%rax

1:  hlt
    jmp 1b

ap_trampoline_end:
    nop
