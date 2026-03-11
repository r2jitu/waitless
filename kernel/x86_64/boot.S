// kernel/boot.S — Multiboot2 boot entry point for x86_64
//
// This is the very first code that runs when GRUB (or QEMU via ISO) loads
// the unikernel. The machine starts in 32-bit protected mode (per the
// Multiboot2 spec). We must:
//
//   1. Save the multiboot magic and info pointer
//   2. Set up identity-mapped page tables for the first 1GB (2MB pages)
//   3. Enable PAE and long mode (via EFER MSR)
//   4. Enable paging
//   5. Load a 64-bit GDT
//   6. Far-jump to 64-bit code
//   7. Reload segment registers, set up the stack, call kernel_main()
//
// Memory layout (BSS, allocated by the linker):
//   stack:    64KB kernel stack
//   boot_pml4/pdpt/pd: bootstrap page tables (each 4KB, page-aligned)

// ============================================================================
// Multiboot2 header
// ============================================================================

.set MULTIBOOT2_MAGIC, 0xe85250d6
.set MULTIBOOT2_ARCH,  0              // i386 protected mode
.set HEADER_LENGTH,    (multiboot_header_end - multiboot_header)
.set CHECKSUM,         -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + HEADER_LENGTH)

.section .multiboot2, "a"
.align 8
multiboot_header:
    .long MULTIBOOT2_MAGIC
    .long MULTIBOOT2_ARCH
    .long HEADER_LENGTH
    .long CHECKSUM
    // End tag (type=0, flags=0, size=8)
    .word 0       // type
    .word 0       // flags
    .long 8       // size
multiboot_header_end:

// ============================================================================
// PVH (Xen) ELF note — required by QEMU 10.x to load 64-bit ELF kernels
// via -kernel. Without this, QEMU tries the PVH ELF path and errors with
// "Error loading uncompressed kernel without PVH ELF Note".
//
// Note format: namesz=4 ("Xen\0"), descsz=4 (32-bit entry point addr),
//              type=18 (XEN_ELFNOTE_PHYS32_ENTRY).
// The desc field (entry point) is our 32-bit _start, which handles both
// multiboot2 and PVH boot conventions.
// ============================================================================

.section .note.Xen, "a", @note
.align 4
.long 4             // namesz: "Xen\0" (4 bytes including null)
.long 4             // descsz: 32-bit entry point address (4 bytes)
.long 18            // note type: XEN_ELFNOTE_PHYS32_ENTRY
.byte 'X', 'e', 'n', 0  // name "Xen\0"
.align 4
.long _start        // 32-bit entry point for PVH boot

// ============================================================================
// Boot-time stack and page tables
//
// These live in a separate .boot_bss section so that zero_bss() in
// kernel_main (which zeroes [__bss_start, __bss_end]) does NOT overwrite
// them while they are still active in CR3.
// ============================================================================

.section .boot_bss, "aw", @nobits

// 64KB kernel stack (grows downward from stack_top)
.align 16
stack_bottom:
    .space 65536
stack_top:

// Bootstrap page tables — identity map the first 1GB with 2MB pages.
// PML4 -> PDPT -> PD (with 512 x 2MB entries = 1GB)
.align 4096
boot_pml4:
    .space 4096
boot_pdpt:
    .space 4096
boot_pd:
    .space 4096

// ============================================================================
// 32-bit entry point
// ============================================================================

.section .text
.code32
.global _start
_start:
    // Two boot protocols may call this entry point:
    //   Multiboot2: EAX = 0x36d76289 (magic), EBX = multiboot2 info ptr
    //   PVH/Xen:   EAX = undefined,            ESI = hvm_start_info ptr
    //
    // Save the boot-info pointer in EDI (→ RDI in 64-bit mode, first arg to
    // kernel_main). We detect the protocol by checking the multiboot2 magic.
    cmp  $0x36d76289, %eax
    je   .Lmb2_boot
    // PVH boot: hvm_start_info is in ESI
    mov  %esi, %edi
    jmp  .Lboot_common
.Lmb2_boot:
    // Multiboot2 boot: multiboot2 info is in EBX
    mov  %ebx, %edi
.Lboot_common:

    // ---- Set up identity-mapped page tables ----

    // PML4[0] -> boot_pdpt | Present | Writable
    lea boot_pdpt, %eax
    or  $0x3, %eax              // P=1, R/W=1
    mov %eax, (boot_pml4)

    // PDPT[0] -> boot_pd | Present | Writable
    lea boot_pd, %eax
    or  $0x3, %eax
    mov %eax, (boot_pdpt)

    // Fill boot_pd with 512 entries, each mapping a 2MB page.
    // Entry format: base_addr | PS(bit7) | R/W(bit1) | P(bit0) = 0x83
    // This maps physical addresses 0x00000000 - 0x3FFFFFFF (1GB).
    lea  boot_pd, %ebx
    mov  $0, %ecx               // Counter
    mov  $0x83, %eax             // First entry: addr=0, P=1, R/W=1, PS=1(2MB)
1:
    mov  %eax, (%ebx)           // Store low 32 bits of entry
    movl $0, 4(%ebx)            // Store high 32 bits (zero — all within 4GB)
    add  $0x200000, %eax        // Next 2MB page
    add  $8, %ebx               // Next PD entry (8 bytes each)
    inc  %ecx
    cmp  $512, %ecx
    jne  1b

    // ---- Load PML4 into CR3 ----
    lea boot_pml4, %eax
    mov %eax, %cr3

    // ---- Enable PAE (CR4 bit 5) ----
    mov %cr4, %eax
    or  $(1 << 5), %eax         // PAE = Physical Address Extension
    mov %eax, %cr4

    // ---- Enable long mode via EFER MSR ----
    // EFER (Extended Feature Enable Register) MSR address = 0xC0000080
    // Bit 8 = LME (Long Mode Enable)
    mov $0xC0000080, %ecx
    rdmsr
    or  $(1 << 8), %eax         // Set LME bit
    wrmsr

    // ---- Enable paging (CR0 bit 31) ----
    // With PAE + LME + page tables loaded, enabling paging activates long mode.
    mov %cr0, %eax
    or  $(1 << 31), %eax        // PG = Paging
    mov %eax, %cr0

    // ---- Load the bootstrap 64-bit GDT ----
    lgdt (gdt64_ptr32)

    // ---- Far jump to 64-bit code segment ----
    // This atomically switches CS to the 64-bit code segment selector (0x08)
    // and enters long mode.
    ljmp $0x08, $long_mode

// ============================================================================
// 64-bit entry point
// ============================================================================

.code64
long_mode:
    // Reload data segment registers with the 64-bit data selector
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    // Enable SSE/SSE2: set CR4.OSFXSR (bit 9) and CR4.OSXMMEXCPT (bit 10).
    // Without OSFXSR, any xmm/sse instruction raises #UD.
    // The compiler may emit xorps/movups for bulk memory operations (zero_bss).
    mov %cr4, %rax
    or  $(1 << 9) | (1 << 10), %rax
    mov %rax, %cr4

    // Set up the kernel stack
    lea stack_top(%rip), %rsp

    // EDI already contains the multiboot info pointer from 32-bit mode.
    // In 64-bit mode, the upper 32 bits of RDI are zero (hardware zeroes
    // them on 32->64 transition). RDI is the first argument register in
    // the System V AMD64 ABI.

    // Clear RBP for clean stack traces
    xor %rbp, %rbp

    // Call the C++ kernel entry point: kernel_main(uint64_t multiboot_info_addr)
    call kernel_main

    // kernel_main should never return, but if it does, halt the machine.
2:
    cli
    hlt
    jmp 2b

// ============================================================================
// Bootstrap GDT for the 32->64 bit transition
// ============================================================================
// This minimal GDT is only used during the transition. The kernel sets up
// a proper GDT with TSS in gdt::init().

.align 16
gdt64:
    .quad 0                      // Entry 0: Null descriptor
    .quad 0x00AF9A000000FFFF     // Entry 1: 64-bit code, DPL=0 (selector 0x08)
    .quad 0x00CF92000000FFFF     // Entry 2: Data, DPL=0 (selector 0x10)
gdt64_end:

// GDT pointer for 32-bit lgdt instruction (6 bytes: 2-byte limit + 4-byte base)
.align 4
gdt64_ptr32:
    .word gdt64_end - gdt64 - 1  // Limit: size of GDT - 1
    .long gdt64                   // Base: 32-bit address of GDT
