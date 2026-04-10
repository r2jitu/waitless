// tools/hvf-runner/examples/stubs.s — Phase 0 smoke test stubs
//
// Three guest code stubs that exercise the HVF assumptions the plan
// depends on. Each stub lives in its own ELF section so build.rs can
// extract them with llvm-objcopy and include_bytes! them from the
// Rust smoke harness. Each stub is position-independent and assumes
// it is loaded at IPA 0x40000000 in a VM created by the harness.
//
// Register conventions:
//   The stub starts with all GPRs == 0, DAIF == masked, PC == 0x40000000
//   (set explicitly by the harness via hv_vcpu_set_reg(HV_REG_PC, ...)).
//   SP is unspecified but not used.
//
// Exit conventions:
//   Each stub ends with `hvc #<sentinel>` so the harness can identify
//   which stub signalled completion from ESR_EL1.ISS_HVC:
//     stub_atomics   → hvc #0xdead
//     stub_instr     → (intentionally faults on MMIO; no hvc)
//     stub_gic_spi   → hvc #0xbeef
//
// Memory map used by the stubs (all at the same VM):
//   IPA 0x40000000..0x40003fff   code region (one 16KB page)
//   IPA 0x40000800                counter (u64) — stub_atomics
//   IPA 0x40000808                STLRB target (u8) — stub_atomics
//   IPA 0x40000810                CASALB target (u8) — stub_atomics
//   IPA 0x09000000                unmapped PL011 DR — stub_instr
//                                 (unmapped → triggers stage-2 abort)

.section .stub_atomics, "ax"
.globl _stub_atomics_start, _stub_atomics_end
.balign 16
_stub_atomics_start:
    // Test the memory operations the real unikernel kernel actually
    // uses against its guest RAM. Disassembling bazel-bin/apps/webserver/
    // webserver.elf shows 0 LDXR / STXR / LDAXR / STLXR / CAS / LDADD
    // instructions and ~380 LDAR / STLR / LDARB / STLRB instructions
    // across the whole image — the kernel synchronises using only
    // release stores and acquire loads, no atomic RMW.
    //
    // We therefore test:
    //   1. Plain LDR / STR        — stage-2 cacheability is normal
    //   2. STLRB / LDARB          — release store + acquire load on a byte
    //   3. STLR  / LDAR  (32-bit) — same but word-width
    //
    // We intentionally DO NOT test LDXR/STXR or LSE CAS against
    // hv_vm_allocate'd guest RAM, because HVF on Apple Silicon does not
    // virtualize the exclusive monitor for guest memory and those ops
    // fault with DFSC=0x35 ("Unsupported Exclusive or Atomic access").
    // This is a documented VZ.framework quirk (see
    // memory/project_vz_atomic_limitation.md) and, as of macOS 26.x,
    // applies equally to the underlying HVF API. The unikernel's
    // Rust build appears to compile out all atomic RMW in release
    // mode (0 such instructions in the ELF), so this limitation does
    // not affect us in practice.

    // x0 = 0x40000800 (scratch base)
    movz    x0, #0x4000, lsl #16
    add     x0, x0, #0x800
    add     x4, x0, #8        // 0x40000808 — STLRB byte target
    add     x7, x0, #16       // 0x40000810 — STLR word target

    // --- Plain LDR/STR to 0x40000800 ---
    movz    w5, #7
    str     w5, [x0]
    ldr     w6, [x0]          // w6 should == 7

    // --- STLRB + LDARB to 0x40000808 ---
    movz    w5, #1
    stlrb   w5, [x4]
    ldarb   w6, [x4]

    // --- STLR (32-bit) + LDAR (32-bit) to 0x40000810 ---
    movz    w5, #0xbeef
    movk    w5, #0xdead, lsl #16
    stlr    w5, [x7]
    ldar    w6, [x7]

    hvc     #0xdead
.Lstub_atomics_halt:
    b       .Lstub_atomics_halt
_stub_atomics_end:


.section .stub_instr, "ax"
.globl _stub_instr_start, _stub_instr_end
.balign 16
_stub_instr_start:
    // Write a single word to PL011 DR at 0x09000000. That address is
    // intentionally NOT mapped in the VM, so the store triggers a
    // stage-2 data abort — and we expect the host to be able to fetch
    // the very instruction that faulted (this exact STR) by reading
    // host_ram + (ELR_EL1 - 0x40000000).
    movz    x0, #0x0900, lsl #16      // x0 = 0x09000000
    movz    w1, #'A'                  // w1 = 0x41
_stub_instr_fault:
    str     w1, [x0]                  // the faulting instruction

    // Never reached — included only so the stub decodes even if HVF
    // surprises us and resumes.
.Lstub_instr_halt:
    b       .Lstub_instr_halt
_stub_instr_end:


// Experiment 1 (Phase 0 follow-up): does LDXR/STXR work if the *guest*
// programs the MMU itself, rather than the host pre-configuring it?
//
// The stub expects:
//   x0 = guest physical address of the L1 page table (built by the host)
// Everything else starts at zero; MMU is off at entry.
//
// Behaviour:
//   1. Set MAIR_EL1 / TCR_EL1 / TTBR0_EL1 / CPACR_EL1 from inside the guest
//   2. Full barrier + TLB invalidate
//   3. Enable MMU via msr sctlr_el1
//   4. Increment a 64-bit counter at 0x40000800 via LDXR/STXR 100 times
//   5. Do a CASALB on the byte at 0x40000810
//   6. Signal via hvc #0xd00d, carrying in x0 the observed counter value
//      and in x1 the observed CASALB result byte. If LDXR faulted before
//      hvc could run, the host's debug vector table catches it instead.
.section .stub_mmu_self, "ax"
.globl _stub_mmu_self_start, _stub_mmu_self_end
.balign 16
_stub_mmu_self_start:
    // Save L1 table IPA in x9 (x0 will be reused below).
    mov     x9, x0

    // CPACR_EL1.FPEN = 0b11 — enable FP/SIMD at EL1 (matches boot.S).
    movz    x1, #0x30, lsl #16          // 0x30 << 16 = (3 << 20) = FPEN[21:20]=11
    msr     cpacr_el1, x1

    // MAIR_EL1 — match OVMF/EDK2 layout exactly:
    //   Attr0 = 0x00 (Device nGnRnE)
    //   Attr1 = 0x44 (Normal Non-cacheable inner+outer)
    //   Attr2 = 0xBB (Normal Write-through inner+outer)
    //   Attr3 = 0xFF (Normal Write-back inner+outer R/W allocate) ← cacheable
    // Value = 0xFFBB4400. Our stub now uses AttrIdx = 3 in the L1
    // descriptor (the host builds the L1 with attrs 0x70d below).
    movz    x1, #0x4400
    movk    x1, #0xffbb, lsl #16
    msr     mair_el1, x1

    // TCR_EL1 = 0x00000005_B5993519 (same value as kernel boot.S)
    movz    x1, #0x3519
    movk    x1, #0xb599, lsl #16
    movk    x1, #0x0005, lsl #32
    msr     tcr_el1, x1

    // TTBR0_EL1 = L1 table IPA
    msr     ttbr0_el1, x9

    // Barrier + TLB invalidate before enabling the MMU.
    dsb     sy
    tlbi    vmalle1
    dsb     sy
    isb

    // SCTLR_EL1 |= M | C | I; clear A.
    mrs     x1, sctlr_el1
    orr     x1, x1, #1                  // M bit — enable MMU
    orr     x1, x1, #4                  // C bit — data cache
    orr     x1, x1, #4096               // I bit — instruction cache
    bic     x1, x1, #2                  // clear A bit — alignment check off
    msr     sctlr_el1, x1
    isb

    // --- MMU is now on with identity-mapped Normal cacheable memory. ---

    // Atomic counter at 0x40000800.
    movz    x2, #0x4000, lsl #16
    add     x2, x2, #0x800
    str     xzr, [x2]

    // Increment 100 times via LDXR/STXR.
    movz    x3, #100
1:
    ldxr    x4, [x2]
    add     x4, x4, #1
    stxr    w5, x4, [x2]
    cbnz    w5, 1b
    subs    x3, x3, #1
    b.ne    1b

    // CASALB at 0x40000810 — swap 0 with 42.
    add     x6, x2, #16                  // 0x40000810
    movz    w7, #0
    movz    w8, #42
    casalb  w7, w8, [x6]

    // Signal: x0 = counter, x1 = CASALB result byte.
    ldr     x0, [x2]
    ldrb    w1, [x6]
    hvc     #0xd00d
.Lstub_mmu_self_halt:
    b       .Lstub_mmu_self_halt
_stub_mmu_self_end:


.section .stub_gic_spi, "ax"
.globl _stub_gic_spi_start, _stub_gic_spi_end
.balign 16
_stub_gic_spi_start:
    // Configure the GICv3 CPU interface via system registers. HVF
    // handles these natively when a hv_gic_create() device exists.
    movz    x0, #1
    msr     ICC_IGRPEN1_EL1, x0       // enable Group 1 interrupts

    movz    x0, #0xff
    msr     ICC_PMR_EL1, x0           // priority mask = all priorities

    movz    x0, #0
    msr     ICC_BPR1_EL1, x0          // binary point register = 0

    isb

    // Unmask IRQs in DAIF (clear bit 1 / daifclr #0x2).
    msr     daifclr, #0x2

    // Spin until ICC_IAR1_EL1 returns a real INTID. 1023 = spurious.
1:
    mrs     x0, ICC_IAR1_EL1
    cmp     x0, #1023
    b.eq    1b

    // Acknowledge the interrupt (EOI) and stash the INTID so the host
    // can read it from x0 on the HVC exit.
    msr     ICC_EOIR1_EL1, x0

    // Signal success.
    hvc     #0xbeef

.Lstub_gic_halt:
    b       .Lstub_gic_halt
_stub_gic_spi_end:
