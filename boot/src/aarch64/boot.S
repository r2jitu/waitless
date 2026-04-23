// kernel/aarch64/boot.S — ARM64 boot entry point
//
// Implements the Linux ARM64 Image boot protocol so QEMU "-kernel" and the
// HVF runner can load and execute this binary directly. On entry:
//   x0  = physical address of the Device Tree Blob (DTB)
//   x1-x3 = 0 (reserved)
//   PC  = load address (0x40000000 for QEMU virt and the HVF runner)
//   EL  = EL2 or EL1, MMU off, caches off
//
// The kernel is linked at 0x00000000 with -fPIC/--pie (PIE).
// boot.S applies .rela.dyn relocations so absolute pointers in .data,
// vtables, and __init_array are correct at the actual load address.
//
// This code:
//   0. Applies R_AARCH64_RELATIVE relocations from .rela.dyn (load_base = adr(_start))
//   1. Stores the DTB address
//   2. Drops from EL2 to EL1 if needed
//   3. Sets up minimal ARM64 page tables (identity map first 4GB, all normal-cached)
//   4. Enables MMU + D-cache + I-cache
//   5. Installs the exception vector table
//   6. Zeroes BSS
//   7. Calls kernel_main(dtb_addr)

// ============================================================================
// Linux ARM64 Image header (must be exactly at offset 0)
// QEMU uses this to identify the kernel image format.
// ============================================================================

.section .text.boot, "ax"
.global _start
_start:
    // Offset +0: branch to actual code (first instruction)
    b       primary_entry
    .long   0                       // +4:  reserved

    // Offset +8: text_offset — image start relative to RAM base (0 = 2MB-aligned)
    .quad   0x0000000000000000

    // Offset +16: image_size (total memory footprint including BSS)
    // _image_size is computed by the linker script (. - _image_start at end of sections).
    .quad   _image_size

    // Offset +24: flags
    //   bit 0: BE=0 (little endian)
    //   bit 3:1: page size hint 01 = 4KB
    //   bit 4: phys placement 0 = anywhere 2MB-aligned
    .quad   0x000000000000000a      // LE + 4KB hint

    .quad   0                       // +32: reserved
    .quad   0                       // +40: reserved
    .quad   0                       // +48: reserved

    // Offset +56: magic = "ARM\x64" = 0x644d5241 (little-endian)
    .long   0x644d5241
    .long   0                       // +60: reserved (PE header offset)

// ============================================================================
// Primary entry point
// ============================================================================

primary_entry:
    // Save DTB address (x0) in a callee-saved register before we modify x0
    mov     x21, x0

    // ---- Apply R_AARCH64_RELATIVE relocations from .rela.dyn ---------------
    //
    // The kernel is linked at 0x00000000 with --pie.  The actual load address
    // (load_base) differs from the link address:
    //   QEMU / HVF runner: loaded at 0x40000000 → load_base = 0x40000000
    // We still process the relocation table unconditionally so a different
    // load address works without touching boot.S.
    //
    // For each R_AARCH64_RELATIVE entry (r_info & 0xFFFFFFFF == 1027 / 0x403):
    //   *(load_base + r_offset) = load_base + r_addend
    //
    // Registers used (callee-saved to avoid conflicts with EL2→EL1 code):
    //   x22 = load_base  (adr of _start)
    //   x23 = pointer into .rela.dyn (current entry)
    //   x24 = __rela_end  (end sentinel)
    //   x25 = r_offset
    //   x26 = r_info (low 32 bits = relocation type)
    //   x27 = r_addend
    //
    // adrp+add generates PC-relative references so it works before relocation.
    // No stack is needed — all register operations + memory stores only.
    //
    adr     x22, _start                         // load_base = runtime _start
    adrp    x23, __rela_start
    add     x23, x23, :lo12:__rela_start
    adrp    x24, __rela_end
    add     x24, x24, :lo12:__rela_end
.Lrela_loop:
    cmp     x23, x24
    bge     .Lrela_done
    ldp     x25, x26, [x23], #16        // r_offset, r_info; x23 += 16
    ldr     x27, [x23], #8              // r_addend;         x23 += 8 (total: +24)
    and     x26, x26, #0xffffffff       // extract reloc type from low 32 bits
    cmp     x26, #1027                  // R_AARCH64_RELATIVE = 1027 (0x403)
    bne     .Lrela_loop                 // skip non-RELATIVE entries
    add     x25, x25, x22              // slot address = load_base + r_offset
    add     x27, x27, x22              // value        = load_base + r_addend
    str     x27, [x25]                  // patch the slot
    b       .Lrela_loop
.Lrela_done:

    // ---- Drop from EL2 to EL1 (if started at EL2) -------------------------
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    bne     .Lel1_entry

    // Configure EL1 as AArch64
    mov     x0, #(1 << 31)          // HCR_EL2.RW = 1 → EL1 is AArch64
    msr     hcr_el2, x0

    // SPSR_EL2: EL1h (0x05), all DAIF bits masked (0x3c0)
    mov     x0, #0x3c5
    msr     spsr_el2, x0

    // ELR_EL2: return address after eret
    adr     x0, .Lel1_entry
    msr     elr_el2, x0

    // Disable EL2 traps that would cause problems in EL1
    msr     cptr_el2, xzr           // no FP/SVE trap
    msr     hstr_el2, xzr           // no coprocessor trap

    eret

.Lel1_entry:
    // ---- Mask all interrupts (DAIF = 0xF) ----------------------------------
    // Some hypervisors start the guest at EL1 directly (no EL2 eret) with
    // DAIF potentially unmasked.  Any IRQ before we handle it properly
    // would call exception_handler(1) → panic → WFE loop → VM killed.
    // Mask here unconditionally before any other EL1 setup.
    msr     daifset, #0xf

    // ---- Enable FP/NEON at EL1 (CPACR_EL1.FPEN = 0b11) -------------------
    // After reset, FPEN defaults to 0b00 which traps all FP/NEON instructions.
    // The compiler emits NEON instructions (e.g., for memset/memcpy), so we
    // must enable FP/NEON before any C code runs.
    mrs     x0, cpacr_el1
    orr     x0, x0, #(3 << 20)     // FPEN[21:20] = 0b11: no trap at EL0/EL1
    msr     cpacr_el1, x0
    isb

    // ---- Basic SCTLR_EL1 setup — ensure MMU and caches are off -----------
    mrs     x0, sctlr_el1
    bic     x0, x0, #(1 << 0)      // M=0 (MMU off)
    bic     x0, x0, #(1 << 1)      // A=0 (Alignment check off) — allow unaligned
    bic     x0, x0, #(1 << 2)      // C=0 (D-cache off)
    bic     x0, x0, #(1 << 12)     // I=0 (I-cache off)
    msr     sctlr_el1, x0
    isb

    // ---- Set up stack (boot stack is in BSS at a known address) -----------
    // Using adrp+add for ±4GB range (adr only has ±1MB, too small with Rust core)
    adrp    x0, boot_stack_top
    add     x0, x0, :lo12:boot_stack_top
    mov     sp, x0

    // ---- Set up page tables and enable MMU --------------------------------
    bl      setup_mmu

    // ---- Install exception vector table -----------------------------------
    adrp    x0, exception_vector_table
    add     x0, x0, :lo12:exception_vector_table
    msr     vbar_el1, x0
    isb

    // ---- Zero BSS -----------------------------------------------------------
    adrp    x0, __bss_start
    add     x0, x0, :lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, :lo12:__bss_end
    sub     x2, x1, x0
    cbz     x2, .Lbss_done
.Lbss_loop:
    str     xzr, [x0], #8
    subs    x2, x2, #8
    bgt     .Lbss_loop
.Lbss_done:

    // ---- Call C++ kernel main ---------------------------------------------
    mov     x0, x21                 // Restore DTB address as first arg
    bl      kernel_main

    // ---- Should never return — spin forever ------------------------------
.Lhalt:
    msr     daifset, #15            // Mask all interrupts
    wfe
    b       .Lhalt

// ============================================================================
// setup_mmu — build minimal identity-mapped page tables and enable MMU
//
// ARM64 address layout with T0SZ=25 (39-bit VA, 4KB granule):
//   TTBR0 → L1 table (512 × 8-byte entries, each covers 1GB)
//
// Mapping (all first-4GB as normal-cached):
//   L1[  0]: 0x0000_0000_0000 – 0x0000_003F_FFFF  (1GB, normal cached) — low MMIO / GIC
//   L1[  1]: 0x0000_4000_0000 – 0x0000_7FFF_FFFF  (1GB, normal cached) — main RAM
//   L1[  2]: 0x0000_8000_0000 – 0x0000_BFFF_FFFF  (1GB, normal cached) — more RAM
//   L1[  3]: 0x0000_C000_0000 – 0x0000_FFFF_FFFF  (1GB, normal cached) — more RAM
//   L1[256]: 0x0040_0000_0000 – 0x0040_3FFF_FFFF  (1GB, device nGnRnE) — PCIe ECAM
//
// Why all-normal-cached for the first 4GB?
//   • QEMU TCG: intercepts MMIO by device registration, ignoring Stage-1 attrs.
//   • HVF/KVM: hypervisor Stage-2 maps MMIO regions as device, overriding
//     the guest Stage-1 normal-cached setting.  No guest GIC driver needed.
// ============================================================================

setup_mmu:
    // ---- MAIR_EL1 ----------------------------------------------------------
    //
    // CRITICAL: this layout is not arbitrary — it must match the OVMF /
    // U-Boot / Linux convention with Normal Write-Back at AttrIdx 3.
    //
    // Apple Silicon HVF (verified empirically on M2) inspects the
    // descriptor's AttrIdx and only enables the guest exclusive monitor
    // (LDXR/STXR and LSE atomics) when it points at a "standard" MAIR
    // slot. Earlier versions of this file used MAIR_EL1 = 0x00FF with
    // WB at AttrIdx 1 — semantically identical per the ARMv8 spec, but
    // HVF rejected every LDXR/CASAL with DFSC=0x35 ("Unsupported
    // Exclusive or Atomic access") because slot 1 is normally where
    // the standard convention puts Device-nGnRE, not WB.
    //
    // The current value matches Linux's `pgtable-prot.h` and OVMF's
    // ArmMmuLib defaults, so HVF is happy and every other hypervisor
    // (QEMU/KVM/TCG) treats it identically to the old layout.
    //
    //   Attr0 = 0x00  Device nGnRnE       (used by L2_DEVICE_BLOCK in mmu.rs)
    //   Attr1 = 0x44  Normal NC in/out    (unused, kept for layout parity)
    //   Attr2 = 0xBB  Normal WT in/out    (unused)
    //   Attr3 = 0xFF  Normal WB in/out RW (used by all kernel/RAM mappings)
    ldr     x0, =0xFFBB4400
    msr     mair_el1, x0

    // ---- TCR_EL1 -----------------------------------------------------------
    // T0SZ=25     [5:0]   — 39-bit VA (64-25=39)
    // IRGN0=01    [9:8]   — inner write-back, read/write allocate
    // ORGN0=01    [11:10] — outer write-back, read/write allocate
    // SH0=11      [13:12] — inner shareable
    // TG0=00      [15:14] — 4KB granule
    // T1SZ=25     [21:16] — not used (EPD1=1 disables TTBR1)
    // EPD1=1      [23]    — disable TTBR1 (avoids faults from null TTBR1)
    // IRGN1=01    [25:24] — (don't care, EPD1=1)
    // ORGN1=01    [27:26] — (don't care)
    // SH1=11      [29:28] — (don't care)
    // TG1=10      [31:30] — 4KB (don't care)
    // IPS=101     [34:32] — 48-bit PA (maximum supported by most cores)
    ldr     x0, =0x00000005B5993519
    msr     tcr_el1, x0
    isb

    // ---- Fill L1 page table ------------------------------------------------
    adrp    x1, boot_l1_table
    add     x1, x1, :lo12:boot_l1_table

    // Block descriptor flags (must match the MAIR_EL1 layout above):
    //   Normal 1GB block  = PA | AttrIdx=3 | AF=1 | SH=11 | valid = PA | 0x070d
    //   Device 1GB block  = PA | AttrIdx=0 | AF=1 | SH=00 | valid = PA | 0x0401
    // bits [1:0]=01: block descriptor, bits [4:2]=AttrIndx, bit[10]=AF, bits[9:8]=SH

    // Entries 0-3: all normal-cached (covers 0x00000000–0xFFFFFFFF)
    // Entry 0 covers the QEMU low-MMIO region (GIC, UART, virtio-mmio);
    // QEMU TCG intercepts MMIO by device registration (page attrs irrelevant).
    ldr     x0, =0x000000000000070d    // PA=0x00000000, normal cached, AF=1
    str     x0, [x1, #0]

    // Entry 1: normal memory (RAM at 0x40000000 — QEMU virt RAM base)
    ldr     x0, =0x000000004000070d
    str     x0, [x1, #8]

    // Entry 2: normal memory (0x80000000)
    ldr     x0, =0x000000008000070d
    str     x0, [x1, #16]

    // Entry 3: normal memory (0xC0000000)
    ldr     x0, =0x00000000C000070d
    str     x0, [x1, #24]

    // Entry 256: device memory (PCIe ECAM, 0x4000000000–0x43FFFFFFFF)
    // QEMU 10.x places the PCIe ECAM at 0x4010000000 (from DTB).
    // L1[256] covers 256*1GB = 0x4000000000, which contains that range.
    ldr     x0, =0x0000004000000401    // PA=0x4000000000, device nGnRnE, AF=1
    str     x0, [x1, #(256*8)]

    // Make sure page table writes are visible
    dsb     sy

    // ---- Invalidate TLB before enabling MMU ---------------------------------
    tlbi    vmalle1
    dsb     sy
    isb

    // ---- Set TTBR0_EL1 to our L1 table ------------------------------------
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table
    msr     ttbr0_el1, x0
    isb

    // ---- Enable MMU, I-cache, and D-cache in SCTLR_EL1 -------------------
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)      // M=1  — enable MMU
    orr     x0, x0, #(1 << 2)      // C=1  — enable D-cache
    orr     x0, x0, #(1 << 12)     // I=1  — enable I-cache
    bic     x0, x0, #(1 << 1)      // A=0  — ensure alignment check stays off
    msr     sctlr_el1, x0
    isb

    ret

// ============================================================================
// Invalidate entire D-cache by set/way (all levels up to LoC).
// Clobbers: x0-x12. Safe to call with MMU off.
// Based on ARM Architecture Reference Manual D7.9.2.
// ============================================================================
invalidate_dcache:
    mrs     x0, clidr_el1
    ubfx    w3, w0, #24, #3         // w3 = LoC (Level of Coherence)
    cbz     w3, .Linv_done
    mov     w10, #0                 // w10 = current level * 2
.Linv_level:
    add     w12, w10, w10, lsr #1   // w12 = level * 3 (index into CLIDR)
    lsr     w1, w0, w12
    and     w1, w1, #7              // cache type at this level
    cmp     w1, #2                  // >= 2 means data or unified cache
    blt     .Linv_next_level
    msr     csselr_el1, x10         // select cache level
    isb
    mrs     x1, ccsidr_el1          // read cache geometry
    and     w2, w1, #7              // log2(line_size) - 4
    add     w2, w2, #4              // w2 = log2(line_size in bytes)
    ubfx    w4, w1, #3, #10         // w4 = associativity - 1 (ways)
    clz     w5, w4                  // w5 = bit position of way in DC ISW
    ubfx    w7, w1, #13, #15        // w7 = num sets - 1
.Linv_set:
    mov     w6, w4                  // w6 = current way
.Linv_way:
    lsl     w11, w6, w5             // way << way_shift
    lsl     w8, w7, w2              // set << set_shift
    orr     w11, w11, w8
    orr     w11, w11, w10           // level
    dc      isw, x11               // invalidate by set/way
    subs    w6, w6, #1
    bge     .Linv_way
    subs    w7, w7, #1
    bge     .Linv_set
.Linv_next_level:
    add     w10, w10, #2
    cmp     w3, w10
    bgt     .Linv_level
.Linv_done:
    dsb     sy
    ret

// ============================================================================
// Exception vector table (VBAR_EL1)
//
// Must be 2KB-aligned (11 zero low bits).
// 16 slots × 128 bytes each = 2048 bytes.
// Slot layout:
//   [  0–0x7F] SP_EL0  synchronous
//   [ 0x80–FF] SP_EL0  IRQ
//   [0x100–17F] SP_EL0  FIQ
//   [0x180–1FF] SP_EL0  SError
//   [0x200–27F] SP_EL1  synchronous  ← the ones we actually hit
//   [0x280–2FF] SP_EL1  IRQ
//   [0x300–37F] SP_EL1  FIQ
//   [0x380–3FF] SP_EL1  SError
//   [0x400–47F] Lower EL AArch64 sync
//   [0x480–4FF] Lower EL AArch64 IRQ
//   ...
// ============================================================================

// Each ARM64 exception vector slot is exactly 128 bytes (32 instructions).
// Our full exception handler is ~50 instructions (~200 bytes) — too large to
// fit in one slot.
//
// Solution: each slot contains a single 4-byte branch to a full handler that
// lives outside the 2048-byte vector table.  PAD_VECTOR fills the remaining
// 124 bytes with NOPs up to the next 128-byte boundary.

// Vector stub: one branch to the matching full handler (4 bytes, + padding).
.macro EXCEPTION_VECTOR kind
    b       .Lexc_full_\kind
.endm

// Pad to the next 128-byte boundary.
.macro PAD_VECTOR
    .balign 128
.endm

.balign 2048
.global exception_vector_table
exception_vector_table:

// ---- Group 1: current EL, SP_EL0 ------------------------------------------
    EXCEPTION_VECTOR 0      // Synchronous
    PAD_VECTOR
    EXCEPTION_VECTOR 1      // IRQ
    PAD_VECTOR
    EXCEPTION_VECTOR 2      // FIQ
    PAD_VECTOR
    EXCEPTION_VECTOR 3      // SError
    PAD_VECTOR

// ---- Group 2: current EL, SP_EL1 (the ones we actually hit in EL1h) -------
    EXCEPTION_VECTOR 0      // Synchronous
    PAD_VECTOR
    EXCEPTION_VECTOR 1      // IRQ
    PAD_VECTOR
    EXCEPTION_VECTOR 2      // FIQ
    PAD_VECTOR
    EXCEPTION_VECTOR 3      // SError
    PAD_VECTOR

// ---- Group 3: lower EL, AArch64 -------------------------------------------
    EXCEPTION_VECTOR 0
    PAD_VECTOR
    EXCEPTION_VECTOR 1
    PAD_VECTOR
    EXCEPTION_VECTOR 2
    PAD_VECTOR
    EXCEPTION_VECTOR 3
    PAD_VECTOR

// ---- Group 4: lower EL, AArch32 -------------------------------------------
    EXCEPTION_VECTOR 0
    PAD_VECTOR
    EXCEPTION_VECTOR 1
    PAD_VECTOR
    EXCEPTION_VECTOR 2
    PAD_VECTOR
    EXCEPTION_VECTOR 3
    PAD_VECTOR

// ============================================================================
// Full exception handlers — placed OUTSIDE the 128-byte vector slots.
//
// All four kinds share identical save/restore frames; only the `kind`
// argument to exception_handler() differs.
//   kind=0: synchronous (Data Abort, SVC, etc.) → prints + halts
//   kind=1: (unused placeholder)
//   kind=2: IRQ → dispatched to registered handler via GIC
//   kind=3: SError / FIQ → prints + halts
// ============================================================================

.macro EXCEPTION_FULL_HANDLER kind
.Lexc_full_\kind:
    // --- Save 31 GPRs + original SP + ELR (PC) + SPSR (PSTATE) -------------
    sub     sp,  sp,  #(34*8)
    stp     x0,  x1,  [sp, #(0*8)]
    stp     x2,  x3,  [sp, #(2*8)]
    stp     x4,  x5,  [sp, #(4*8)]
    stp     x6,  x7,  [sp, #(6*8)]
    stp     x8,  x9,  [sp, #(8*8)]
    stp     x10, x11, [sp, #(10*8)]
    stp     x12, x13, [sp, #(12*8)]
    stp     x14, x15, [sp, #(14*8)]
    stp     x16, x17, [sp, #(16*8)]
    stp     x18, x19, [sp, #(18*8)]
    stp     x20, x21, [sp, #(20*8)]
    stp     x22, x23, [sp, #(22*8)]
    stp     x24, x25, [sp, #(24*8)]
    stp     x26, x27, [sp, #(26*8)]
    stp     x28, x29, [sp, #(28*8)]
    str     x30,      [sp, #(30*8)]
    add     x0, sp, #(34*8)         // original SP (before sub above)
    str     x0,       [sp, #(31*8)]
    mrs     x0, elr_el1
    str     x0,       [sp, #(32*8)]
    mrs     x0, spsr_el1
    str     x0,       [sp, #(33*8)]

    // --- Save ESR_EL1 and FAR_EL1 just below the GPR frame -----------------
    sub     sp, sp, #(2*8)
    mrs     x0, esr_el1
    str     x0, [sp, #0]
    mrs     x0, far_el1
    str     x0, [sp, #8]

    // --- Call exception_handler(kind, frame_ptr) ----------------------------
    mov     x0, #\kind
    mov     x1, sp
    bl      exception_handler

    // --- Restore (reached only if handler returned — i.e. for IRQ) ---------
    add     sp, sp, #(2*8)          // skip ESR/FAR slot
    ldr     x30,      [sp, #(30*8)]
    ldp     x28, x29, [sp, #(28*8)]
    ldp     x26, x27, [sp, #(26*8)]
    ldp     x24, x25, [sp, #(24*8)]
    ldp     x22, x23, [sp, #(22*8)]
    ldp     x20, x21, [sp, #(20*8)]
    ldp     x18, x19, [sp, #(18*8)]
    ldp     x16, x17, [sp, #(16*8)]
    ldp     x14, x15, [sp, #(14*8)]
    ldp     x12, x13, [sp, #(12*8)]
    ldp     x10, x11, [sp, #(10*8)]
    ldp     x8,  x9,  [sp, #(8*8)]
    ldp     x6,  x7,  [sp, #(6*8)]
    ldp     x4,  x5,  [sp, #(4*8)]
    ldp     x2,  x3,  [sp, #(2*8)]
    ldp     x0,  x1,  [sp, #(0*8)]
    add     sp, sp, #(34*8)
    eret
.endm

EXCEPTION_FULL_HANDLER 0   // Synchronous → prints ESR/FAR/PC and panics
EXCEPTION_FULL_HANDLER 1   // (unused — panics)
EXCEPTION_FULL_HANDLER 2   // IRQ → dispatches via GIC
EXCEPTION_FULL_HANDLER 3   // SError / FIQ → panics

// ============================================================================
// AP (secondary core) trampoline
//
// PSCI CPU_ON starts the AP at this address with MMU OFF.
// x0 = context_id (stack_top, passed by BSP).
// We set up MMU (same page tables as BSP), install VBAR, set SP, then
// jump to the Rust ap_entry function.
// ============================================================================

.global ap_trampoline
.align 4
ap_trampoline:
    // Save stack_top (context_id from PSCI) in x19
    mov     x19, x0

    // Drop EL2 → EL1 if started at EL2 (same logic as BSP)
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    bne     .Lap_el1

    mov     x0, #(1 << 31)          // HCR_EL2.RW = 1
    msr     hcr_el2, x0
    mov     x0, #0x3c5              // SPSR_EL2: EL1h, DAIF masked
    msr     spsr_el2, x0
    adr     x0, .Lap_el1
    msr     elr_el2, x0
    msr     cptr_el2, xzr
    msr     hstr_el2, xzr
    eret

.Lap_el1:
    // Mask all interrupts
    msr     daifset, #0xF

    // Enable FP/NEON
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    // Set MAIR_EL1 — must match the BSP setup_mmu layout exactly
    // (Apple Silicon HVF requires WB at AttrIdx=3; see the long
    // explanation in setup_mmu).
    ldr     x0, =0xFFBB4400
    msr     mair_el1, x0

    // Set TCR_EL1
    ldr     x0, =0x00000005B5993519
    msr     tcr_el1, x0
    isb

    // Set TTBR0_EL1 to BSP's page table
    adrp    x0, boot_l1_table
    add     x0, x0, :lo12:boot_l1_table
    msr     ttbr0_el1, x0
    isb

    // Enable MMU + caches
    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)      // M=1 MMU
    orr     x0, x0, #(1 << 2)      // C=1 D-cache
    orr     x0, x0, #(1 << 12)     // I=1 I-cache
    bic     x0, x0, #(1 << 1)      // A=0 alignment check off
    msr     sctlr_el1, x0
    isb

    // Install exception vector table
    adr     x0, exception_vector_table
    msr     vbar_el1, x0
    isb

    // Set stack pointer
    mov     sp, x19

    // Jump to Rust AP entry (x0 = stack_top for the function argument)
    mov     x0, x19
    bl      ap_entry
    // Should not return; halt if it does
1:  wfi
    b       1b

// ============================================================================
// Boot-time stack and page table
//
// Placed in a separate .boot_bss section (outside [__bss_start, __bss_end])
// so that BSS zeroing — which runs with the MMU already active and using
// boot_l1_table — does NOT zero the live page tables.
// ============================================================================

.section .boot_bss, "aw", @nobits

.align 16
boot_stack_bottom:
    .space 65536                    // 64 KB kernel stack
boot_stack_top:

// L1 page table — must be 4KB-aligned (each entry = 8 bytes, 512 entries)
// Global so kernel::aarch64::mmu can add L2 table entries for device memory above 4GB.
.align 12
.global boot_l1_table
boot_l1_table:
    .space 4096
