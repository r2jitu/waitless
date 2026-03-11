// kernel/limine_boot.S — Limine entry stub for x86_64
//
// Limine enters with 64-bit mode and paging enabled, but does NOT enable
// SSE/SSE2 (CR4.OSFXSR).  The compiler generates XMM instructions for
// struct initialization, so we must enable SSE before calling C++ code.

#if defined(__x86_64__)

.section .text
.code64
.global limine_entry_stub

limine_entry_stub:
    // Enable SSE/SSE2: set CR4.OSFXSR (bit 9) and CR4.OSXMMEXCPT (bit 10).
    mov %cr4, %rax
    or  $(1 << 9) | (1 << 10), %rax
    mov %rax, %cr4

    // Clear RBP for clean stack traces
    xor %rbp, %rbp

    // Force 16-byte stack alignment before call.
    // Limine may CALL (not JMP) our entry, leaving RSP at 16n+8.
    // The System V ABI requires RSP % 16 == 0 before CALL.
    and $-16, %rsp

    // Call the C++ Limine entry point
    call limine_entry_cpp

    // Halt if it returns
1:
    cli
    hlt
    jmp 1b

#endif
