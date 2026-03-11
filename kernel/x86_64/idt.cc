// kernel/x86_64/idt.cc — Interrupt Descriptor Table implementation
//
// This file sets up the full x86_64 IDT:
//   1. Defines ISR stubs for all 256 vectors using assembly macros
//   2. Defines the common ISR entry point that saves registers and calls C++
//   3. Remaps the 8259 PIC to vectors 32-47
//   4. Installs all stubs into the IDT and loads the IDTR
//
// The ISR stub calling convention:
//   - CPU pushes SS, RSP, RFLAGS, CS, RIP (and error code for some exceptions)
//   - Stub pushes a dummy error code (0) if the CPU didn't push one
//   - Stub pushes the vector number
//   - Stub jumps to isr_common which pushes all GP registers
//   - isr_common calls isr_common_handler(InterruptFrame*)
//   - On return, registers are restored and iretq returns to interrupted code

#include "kernel/x86_64/idt.h"
#include "kernel/arch.h"
#include "kernel/x86_64/gdt.h"
#include "kernel/serial.h"

namespace idt {

// ============================================================================
// Static storage
// ============================================================================

// The IDT: 256 entries, each 16 bytes
static IDTEntry idt_entries[256];

// IDTR pointer
static arch::DescriptorTablePtr idtr;

// Handler function pointers, one per vector
static InterruptHandler handlers[256];

// ============================================================================
// ISR stub macros
// ============================================================================

// For exceptions that do NOT push an error code, we push a dummy 0.
// For exceptions that DO push an error code, we skip the dummy push.
// Then we push the vector number and jump to the common handler.

// These macros define both the C++ extern declaration and the assembly stub.
// The assembly is placed in a top-level asm() block which the compiler
// emits directly into the .text section.

#define ISR_NOERR(n) extern "C" void isr_stub_##n();

#define ISR_ERR(n) extern "C" void isr_stub_##n();

// Declare all the ISR stubs
// Vectors 0-7: exceptions without error codes
ISR_NOERR(0) // #DE Divide Error
ISR_NOERR(1) // #DB Debug
ISR_NOERR(2) // NMI
ISR_NOERR(3) // #BP Breakpoint
ISR_NOERR(4) // #OF Overflow
ISR_NOERR(5) // #BR Bound Range Exceeded
ISR_NOERR(6) // #UD Invalid Opcode
ISR_NOERR(7) // #NM Device Not Available

// Vector 8: Double Fault (has error code)
ISR_ERR(8)

// Vector 9: Coprocessor Segment Overrun (no error code, legacy)
ISR_NOERR(9)

// Vectors 10-14: exceptions with error codes
ISR_ERR(10) // #TS Invalid TSS
ISR_ERR(11) // #NP Segment Not Present
ISR_ERR(12) // #SS Stack-Segment Fault
ISR_ERR(13) // #GP General Protection Fault
ISR_ERR(14) // #PF Page Fault

// Vector 15: reserved
ISR_NOERR(15)

// Vector 16: x87 FPU error
ISR_NOERR(16)

// Vector 17: Alignment Check (has error code)
ISR_ERR(17)

// Vectors 18-20: no error code
ISR_NOERR(18) // #MC Machine Check
ISR_NOERR(19) // #XM SIMD Exception
ISR_NOERR(20) // #VE Virtualization Exception

// Vector 21: Control Protection (has error code)
ISR_ERR(21)

// Vectors 22-28: reserved
ISR_NOERR(22)
ISR_NOERR(23)
ISR_NOERR(24)
ISR_NOERR(25)
ISR_NOERR(26)
ISR_NOERR(27)
ISR_NOERR(28)

// Vectors 29-30: have error codes
ISR_ERR(29) // #VC VMM Communication Exception
ISR_ERR(30) // #SX Security Exception

// Vector 31: reserved
ISR_NOERR(31)

// Vectors 32-47: IRQs (no error code)
ISR_NOERR(32)
ISR_NOERR(33)
ISR_NOERR(34)
ISR_NOERR(35)
ISR_NOERR(36)
ISR_NOERR(37)
ISR_NOERR(38)
ISR_NOERR(39)
ISR_NOERR(40)
ISR_NOERR(41)
ISR_NOERR(42)
ISR_NOERR(43)
ISR_NOERR(44)
ISR_NOERR(45)
ISR_NOERR(46)
ISR_NOERR(47)

// Vectors 48-255: software interrupts (no error code)
// We'll generate stubs for 48-255 with a generic macro approach.
// For practicality, we generate stubs for all 256 in the assembly block below.

// ============================================================================
// Assembly block: ISR stubs and common handler
// ============================================================================

// This is a single top-level asm block that defines all ISR stubs and the
// common interrupt entry point. Each stub is a small trampoline that
// normalizes the stack (error code or dummy) and jumps to isr_common.

asm(".text\n"

    // ---- Common interrupt handler entry point ----
    // At this point the stack has:
    //   [CPU pushed] SS, RSP, RFLAGS, CS, RIP
    //   error_code (real or dummy 0)
    //   vector number
    // We now save all general-purpose registers.
    ".global isr_common\n"
    "isr_common:\n"
    "  pushq %rax\n"
    "  pushq %rbx\n"
    "  pushq %rcx\n"
    "  pushq %rdx\n"
    "  pushq %rsi\n"
    "  pushq %rdi\n"
    "  pushq %rbp\n"
    "  pushq %r8\n"
    "  pushq %r9\n"
    "  pushq %r10\n"
    "  pushq %r11\n"
    "  pushq %r12\n"
    "  pushq %r13\n"
    "  pushq %r14\n"
    "  pushq %r15\n"

    // Pass pointer to InterruptFrame as first argument (RDI)
    "  movq %rsp, %rdi\n"

    // Ensure 16-byte stack alignment for the C++ call (ABI requirement).
    // We've pushed 15 GP regs + vector + error_code + 5 CPU values = 22 qwords.
    // 22 * 8 = 176 bytes. RSP might not be 16-byte aligned at this point.
    // We'll align and save the original RSP.
    "  movq %rsp, %rbp\n" // Save frame pointer
    "  andq $-16, %rsp\n" // Align stack to 16 bytes
    "  call isr_common_handler\n"
    "  movq %rbp, %rsp\n" // Restore original stack pointer

    // Restore all general-purpose registers
    "  popq %r15\n"
    "  popq %r14\n"
    "  popq %r13\n"
    "  popq %r12\n"
    "  popq %r11\n"
    "  popq %r10\n"
    "  popq %r9\n"
    "  popq %r8\n"
    "  popq %rbp\n"
    "  popq %rdi\n"
    "  popq %rsi\n"
    "  popq %rdx\n"
    "  popq %rcx\n"
    "  popq %rbx\n"
    "  popq %rax\n"

    // Remove vector number and error code from the stack
    "  addq $16, %rsp\n"

    // Return from interrupt
    "  iretq\n"

    // ---- ISR stubs for exceptions without error codes (push dummy 0) ----

    // Helper macros for the assembly stubs
    ".macro ISR_STUB_NOERR num\n"
    ".global isr_stub_\\num\n"
    "isr_stub_\\num:\n"
    "  pushq $0\n"
    "  pushq $\\num\n"
    "  jmp isr_common\n"
    ".endm\n"

    ".macro ISR_STUB_ERR num\n"
    ".global isr_stub_\\num\n"
    "isr_stub_\\num:\n"
    "  pushq $\\num\n"
    "  jmp isr_common\n"
    ".endm\n"

    // Vectors 0-7: no error code
    "ISR_STUB_NOERR 0\n"
    "ISR_STUB_NOERR 1\n"
    "ISR_STUB_NOERR 2\n"
    "ISR_STUB_NOERR 3\n"
    "ISR_STUB_NOERR 4\n"
    "ISR_STUB_NOERR 5\n"
    "ISR_STUB_NOERR 6\n"
    "ISR_STUB_NOERR 7\n"

    // Vector 8: error code
    "ISR_STUB_ERR 8\n"

    // Vector 9: no error code
    "ISR_STUB_NOERR 9\n"

    // Vectors 10-14: error code
    "ISR_STUB_ERR 10\n"
    "ISR_STUB_ERR 11\n"
    "ISR_STUB_ERR 12\n"
    "ISR_STUB_ERR 13\n"
    "ISR_STUB_ERR 14\n"

    // Vector 15-16: no error code
    "ISR_STUB_NOERR 15\n"
    "ISR_STUB_NOERR 16\n"

    // Vector 17: error code
    "ISR_STUB_ERR 17\n"

    // Vectors 18-20: no error code
    "ISR_STUB_NOERR 18\n"
    "ISR_STUB_NOERR 19\n"
    "ISR_STUB_NOERR 20\n"

    // Vector 21: error code
    "ISR_STUB_ERR 21\n"

    // Vectors 22-28: no error code (reserved)
    "ISR_STUB_NOERR 22\n"
    "ISR_STUB_NOERR 23\n"
    "ISR_STUB_NOERR 24\n"
    "ISR_STUB_NOERR 25\n"
    "ISR_STUB_NOERR 26\n"
    "ISR_STUB_NOERR 27\n"
    "ISR_STUB_NOERR 28\n"

    // Vectors 29-30: error code
    "ISR_STUB_ERR 29\n"
    "ISR_STUB_ERR 30\n"

    // Vector 31: no error code (reserved)
    "ISR_STUB_NOERR 31\n"

    // Vectors 32-47: IRQs (no error code)
    "ISR_STUB_NOERR 32\n"
    "ISR_STUB_NOERR 33\n"
    "ISR_STUB_NOERR 34\n"
    "ISR_STUB_NOERR 35\n"
    "ISR_STUB_NOERR 36\n"
    "ISR_STUB_NOERR 37\n"
    "ISR_STUB_NOERR 38\n"
    "ISR_STUB_NOERR 39\n"
    "ISR_STUB_NOERR 40\n"
    "ISR_STUB_NOERR 41\n"
    "ISR_STUB_NOERR 42\n"
    "ISR_STUB_NOERR 43\n"
    "ISR_STUB_NOERR 44\n"
    "ISR_STUB_NOERR 45\n"
    "ISR_STUB_NOERR 46\n"
    "ISR_STUB_NOERR 47\n"

    // Vectors 48-255: software interrupts (no error code)
    "ISR_STUB_NOERR 48\n"
    "ISR_STUB_NOERR 49\n"
    "ISR_STUB_NOERR 50\n"
    "ISR_STUB_NOERR 51\n"
    "ISR_STUB_NOERR 52\n"
    "ISR_STUB_NOERR 53\n"
    "ISR_STUB_NOERR 54\n"
    "ISR_STUB_NOERR 55\n"
    "ISR_STUB_NOERR 56\n"
    "ISR_STUB_NOERR 57\n"
    "ISR_STUB_NOERR 58\n"
    "ISR_STUB_NOERR 59\n"
    "ISR_STUB_NOERR 60\n"
    "ISR_STUB_NOERR 61\n"
    "ISR_STUB_NOERR 62\n"
    "ISR_STUB_NOERR 63\n"
    "ISR_STUB_NOERR 64\n"
    "ISR_STUB_NOERR 65\n"
    "ISR_STUB_NOERR 66\n"
    "ISR_STUB_NOERR 67\n"
    "ISR_STUB_NOERR 68\n"
    "ISR_STUB_NOERR 69\n"
    "ISR_STUB_NOERR 70\n"
    "ISR_STUB_NOERR 71\n"
    "ISR_STUB_NOERR 72\n"
    "ISR_STUB_NOERR 73\n"
    "ISR_STUB_NOERR 74\n"
    "ISR_STUB_NOERR 75\n"
    "ISR_STUB_NOERR 76\n"
    "ISR_STUB_NOERR 77\n"
    "ISR_STUB_NOERR 78\n"
    "ISR_STUB_NOERR 79\n"
    "ISR_STUB_NOERR 80\n"
    "ISR_STUB_NOERR 81\n"
    "ISR_STUB_NOERR 82\n"
    "ISR_STUB_NOERR 83\n"
    "ISR_STUB_NOERR 84\n"
    "ISR_STUB_NOERR 85\n"
    "ISR_STUB_NOERR 86\n"
    "ISR_STUB_NOERR 87\n"
    "ISR_STUB_NOERR 88\n"
    "ISR_STUB_NOERR 89\n"
    "ISR_STUB_NOERR 90\n"
    "ISR_STUB_NOERR 91\n"
    "ISR_STUB_NOERR 92\n"
    "ISR_STUB_NOERR 93\n"
    "ISR_STUB_NOERR 94\n"
    "ISR_STUB_NOERR 95\n"
    "ISR_STUB_NOERR 96\n"
    "ISR_STUB_NOERR 97\n"
    "ISR_STUB_NOERR 98\n"
    "ISR_STUB_NOERR 99\n"
    "ISR_STUB_NOERR 100\n"
    "ISR_STUB_NOERR 101\n"
    "ISR_STUB_NOERR 102\n"
    "ISR_STUB_NOERR 103\n"
    "ISR_STUB_NOERR 104\n"
    "ISR_STUB_NOERR 105\n"
    "ISR_STUB_NOERR 106\n"
    "ISR_STUB_NOERR 107\n"
    "ISR_STUB_NOERR 108\n"
    "ISR_STUB_NOERR 109\n"
    "ISR_STUB_NOERR 110\n"
    "ISR_STUB_NOERR 111\n"
    "ISR_STUB_NOERR 112\n"
    "ISR_STUB_NOERR 113\n"
    "ISR_STUB_NOERR 114\n"
    "ISR_STUB_NOERR 115\n"
    "ISR_STUB_NOERR 116\n"
    "ISR_STUB_NOERR 117\n"
    "ISR_STUB_NOERR 118\n"
    "ISR_STUB_NOERR 119\n"
    "ISR_STUB_NOERR 120\n"
    "ISR_STUB_NOERR 121\n"
    "ISR_STUB_NOERR 122\n"
    "ISR_STUB_NOERR 123\n"
    "ISR_STUB_NOERR 124\n"
    "ISR_STUB_NOERR 125\n"
    "ISR_STUB_NOERR 126\n"
    "ISR_STUB_NOERR 127\n"
    "ISR_STUB_NOERR 128\n"
    "ISR_STUB_NOERR 129\n"
    "ISR_STUB_NOERR 130\n"
    "ISR_STUB_NOERR 131\n"
    "ISR_STUB_NOERR 132\n"
    "ISR_STUB_NOERR 133\n"
    "ISR_STUB_NOERR 134\n"
    "ISR_STUB_NOERR 135\n"
    "ISR_STUB_NOERR 136\n"
    "ISR_STUB_NOERR 137\n"
    "ISR_STUB_NOERR 138\n"
    "ISR_STUB_NOERR 139\n"
    "ISR_STUB_NOERR 140\n"
    "ISR_STUB_NOERR 141\n"
    "ISR_STUB_NOERR 142\n"
    "ISR_STUB_NOERR 143\n"
    "ISR_STUB_NOERR 144\n"
    "ISR_STUB_NOERR 145\n"
    "ISR_STUB_NOERR 146\n"
    "ISR_STUB_NOERR 147\n"
    "ISR_STUB_NOERR 148\n"
    "ISR_STUB_NOERR 149\n"
    "ISR_STUB_NOERR 150\n"
    "ISR_STUB_NOERR 151\n"
    "ISR_STUB_NOERR 152\n"
    "ISR_STUB_NOERR 153\n"
    "ISR_STUB_NOERR 154\n"
    "ISR_STUB_NOERR 155\n"
    "ISR_STUB_NOERR 156\n"
    "ISR_STUB_NOERR 157\n"
    "ISR_STUB_NOERR 158\n"
    "ISR_STUB_NOERR 159\n"
    "ISR_STUB_NOERR 160\n"
    "ISR_STUB_NOERR 161\n"
    "ISR_STUB_NOERR 162\n"
    "ISR_STUB_NOERR 163\n"
    "ISR_STUB_NOERR 164\n"
    "ISR_STUB_NOERR 165\n"
    "ISR_STUB_NOERR 166\n"
    "ISR_STUB_NOERR 167\n"
    "ISR_STUB_NOERR 168\n"
    "ISR_STUB_NOERR 169\n"
    "ISR_STUB_NOERR 170\n"
    "ISR_STUB_NOERR 171\n"
    "ISR_STUB_NOERR 172\n"
    "ISR_STUB_NOERR 173\n"
    "ISR_STUB_NOERR 174\n"
    "ISR_STUB_NOERR 175\n"
    "ISR_STUB_NOERR 176\n"
    "ISR_STUB_NOERR 177\n"
    "ISR_STUB_NOERR 178\n"
    "ISR_STUB_NOERR 179\n"
    "ISR_STUB_NOERR 180\n"
    "ISR_STUB_NOERR 181\n"
    "ISR_STUB_NOERR 182\n"
    "ISR_STUB_NOERR 183\n"
    "ISR_STUB_NOERR 184\n"
    "ISR_STUB_NOERR 185\n"
    "ISR_STUB_NOERR 186\n"
    "ISR_STUB_NOERR 187\n"
    "ISR_STUB_NOERR 188\n"
    "ISR_STUB_NOERR 189\n"
    "ISR_STUB_NOERR 190\n"
    "ISR_STUB_NOERR 191\n"
    "ISR_STUB_NOERR 192\n"
    "ISR_STUB_NOERR 193\n"
    "ISR_STUB_NOERR 194\n"
    "ISR_STUB_NOERR 195\n"
    "ISR_STUB_NOERR 196\n"
    "ISR_STUB_NOERR 197\n"
    "ISR_STUB_NOERR 198\n"
    "ISR_STUB_NOERR 199\n"
    "ISR_STUB_NOERR 200\n"
    "ISR_STUB_NOERR 201\n"
    "ISR_STUB_NOERR 202\n"
    "ISR_STUB_NOERR 203\n"
    "ISR_STUB_NOERR 204\n"
    "ISR_STUB_NOERR 205\n"
    "ISR_STUB_NOERR 206\n"
    "ISR_STUB_NOERR 207\n"
    "ISR_STUB_NOERR 208\n"
    "ISR_STUB_NOERR 209\n"
    "ISR_STUB_NOERR 210\n"
    "ISR_STUB_NOERR 211\n"
    "ISR_STUB_NOERR 212\n"
    "ISR_STUB_NOERR 213\n"
    "ISR_STUB_NOERR 214\n"
    "ISR_STUB_NOERR 215\n"
    "ISR_STUB_NOERR 216\n"
    "ISR_STUB_NOERR 217\n"
    "ISR_STUB_NOERR 218\n"
    "ISR_STUB_NOERR 219\n"
    "ISR_STUB_NOERR 220\n"
    "ISR_STUB_NOERR 221\n"
    "ISR_STUB_NOERR 222\n"
    "ISR_STUB_NOERR 223\n"
    "ISR_STUB_NOERR 224\n"
    "ISR_STUB_NOERR 225\n"
    "ISR_STUB_NOERR 226\n"
    "ISR_STUB_NOERR 227\n"
    "ISR_STUB_NOERR 228\n"
    "ISR_STUB_NOERR 229\n"
    "ISR_STUB_NOERR 230\n"
    "ISR_STUB_NOERR 231\n"
    "ISR_STUB_NOERR 232\n"
    "ISR_STUB_NOERR 233\n"
    "ISR_STUB_NOERR 234\n"
    "ISR_STUB_NOERR 235\n"
    "ISR_STUB_NOERR 236\n"
    "ISR_STUB_NOERR 237\n"
    "ISR_STUB_NOERR 238\n"
    "ISR_STUB_NOERR 239\n"
    "ISR_STUB_NOERR 240\n"
    "ISR_STUB_NOERR 241\n"
    "ISR_STUB_NOERR 242\n"
    "ISR_STUB_NOERR 243\n"
    "ISR_STUB_NOERR 244\n"
    "ISR_STUB_NOERR 245\n"
    "ISR_STUB_NOERR 246\n"
    "ISR_STUB_NOERR 247\n"
    "ISR_STUB_NOERR 248\n"
    "ISR_STUB_NOERR 249\n"
    "ISR_STUB_NOERR 250\n"
    "ISR_STUB_NOERR 251\n"
    "ISR_STUB_NOERR 252\n"
    "ISR_STUB_NOERR 253\n"
    "ISR_STUB_NOERR 254\n"
    "ISR_STUB_NOERR 255\n");

// ============================================================================
// ISR stub table
// ============================================================================

// Build a table of function pointers to all 256 ISR stubs.
// We use an X-macro pattern to avoid writing 256 lines by hand.
// Each isr_stub_N was declared above and defined in the asm block.

using ISRStub = void (*)();

// Declare stubs for vectors 48-255
#define DECL_ISR(n) extern "C" void isr_stub_##n();
DECL_ISR(48)
DECL_ISR(49) DECL_ISR(50) DECL_ISR(51) DECL_ISR(52) DECL_ISR(53) DECL_ISR(
    54) DECL_ISR(55) DECL_ISR(56) DECL_ISR(57) DECL_ISR(58) DECL_ISR(59)
    DECL_ISR(60) DECL_ISR(61) DECL_ISR(62) DECL_ISR(63) DECL_ISR(64) DECL_ISR(
        65) DECL_ISR(66) DECL_ISR(67) DECL_ISR(68) DECL_ISR(69) DECL_ISR(70)
        DECL_ISR(71) DECL_ISR(72) DECL_ISR(73) DECL_ISR(74) DECL_ISR(75) DECL_ISR(
            76) DECL_ISR(77) DECL_ISR(78) DECL_ISR(79) DECL_ISR(80) DECL_ISR(81)
            DECL_ISR(82) DECL_ISR(83) DECL_ISR(84) DECL_ISR(85) DECL_ISR(
                86) DECL_ISR(87) DECL_ISR(88) DECL_ISR(89) DECL_ISR(90) DECL_ISR(91)
                DECL_ISR(92) DECL_ISR(93) DECL_ISR(94) DECL_ISR(95) DECL_ISR(
                    96) DECL_ISR(97) DECL_ISR(98) DECL_ISR(99) DECL_ISR(100)
                    DECL_ISR(101) DECL_ISR(102) DECL_ISR(103) DECL_ISR(104) DECL_ISR(
                        105) DECL_ISR(106) DECL_ISR(107) DECL_ISR(108) DECL_ISR(109)
                        DECL_ISR(110) DECL_ISR(111) DECL_ISR(112) DECL_ISR(
                            113) DECL_ISR(114) DECL_ISR(115) DECL_ISR(116)
                            DECL_ISR(117) DECL_ISR(118) DECL_ISR(119) DECL_ISR(
                                120) DECL_ISR(121) DECL_ISR(122) DECL_ISR(123)
                                DECL_ISR(124) DECL_ISR(125) DECL_ISR(126) DECL_ISR(
                                    127) DECL_ISR(128) DECL_ISR(129) DECL_ISR(130)
                                    DECL_ISR(131) DECL_ISR(132) DECL_ISR(
                                        133) DECL_ISR(134) DECL_ISR(135)
                                        DECL_ISR(136) DECL_ISR(137) DECL_ISR(
                                            138) DECL_ISR(139) DECL_ISR(140)
                                            DECL_ISR(141) DECL_ISR(142) DECL_ISR(
                                                143) DECL_ISR(144) DECL_ISR(145)
                                                DECL_ISR(146) DECL_ISR(147) DECL_ISR(
                                                    148) DECL_ISR(149) DECL_ISR(150)
                                                    DECL_ISR(151) DECL_ISR(
                                                        152) DECL_ISR(153) DECL_ISR(154)
                                                        DECL_ISR(155) DECL_ISR(
                                                            156) DECL_ISR(157) DECL_ISR(158)
                                                            DECL_ISR(159) DECL_ISR(
                                                                160) DECL_ISR(161) DECL_ISR(162)
                                                                DECL_ISR(163) DECL_ISR(
                                                                    164) DECL_ISR(165) DECL_ISR(166)
                                                                    DECL_ISR(167) DECL_ISR(
                                                                        168) DECL_ISR(169) DECL_ISR(170)
                                                                        DECL_ISR(171) DECL_ISR(
                                                                            172) DECL_ISR(173)
                                                                            DECL_ISR(174) DECL_ISR(
                                                                                175) DECL_ISR(176)
                                                                                DECL_ISR(177) DECL_ISR(
                                                                                    178) DECL_ISR(179)
                                                                                    DECL_ISR(180) DECL_ISR(
                                                                                        181) DECL_ISR(182)
                                                                                        DECL_ISR(
                                                                                            183)
                                                                                            DECL_ISR(
                                                                                                184)
                                                                                                DECL_ISR(
                                                                                                    185)
                                                                                                    DECL_ISR(
                                                                                                        186)
                                                                                                        DECL_ISR(
                                                                                                            187)
                                                                                                            DECL_ISR(
                                                                                                                188)
                                                                                                                DECL_ISR(189) DECL_ISR(190) DECL_ISR(191) DECL_ISR(192) DECL_ISR(193) DECL_ISR(194) DECL_ISR(195) DECL_ISR(196) DECL_ISR(197) DECL_ISR(198) DECL_ISR(199) DECL_ISR(200) DECL_ISR(201) DECL_ISR(202) DECL_ISR(203) DECL_ISR(204) DECL_ISR(205) DECL_ISR(206) DECL_ISR(207) DECL_ISR(208) DECL_ISR(209) DECL_ISR(210) DECL_ISR(211) DECL_ISR(212) DECL_ISR(213) DECL_ISR(214) DECL_ISR(215) DECL_ISR(216) DECL_ISR(217) DECL_ISR(218) DECL_ISR(219) DECL_ISR(220)
                                                                                                                    DECL_ISR(221) DECL_ISR(
                                                                                                                        222)
                                                                                                                        DECL_ISR(223) DECL_ISR(
                                                                                                                            224)
                                                                                                                            DECL_ISR(
                                                                                                                                225)
                                                                                                                                DECL_ISR(
                                                                                                                                    226)
                                                                                                                                    DECL_ISR(
                                                                                                                                        227)
                                                                                                                                        DECL_ISR(228) DECL_ISR(229) DECL_ISR(230) DECL_ISR(231) DECL_ISR(232) DECL_ISR(233) DECL_ISR(234) DECL_ISR(235) DECL_ISR(236) DECL_ISR(237) DECL_ISR(238) DECL_ISR(239) DECL_ISR(240) DECL_ISR(241) DECL_ISR(242) DECL_ISR(243) DECL_ISR(244) DECL_ISR(245) DECL_ISR(246) DECL_ISR(247) DECL_ISR(
                                                                                                                                            248) DECL_ISR(249) DECL_ISR(250) DECL_ISR(251)
                                                                                                                                            DECL_ISR(252) DECL_ISR(
                                                                                                                                                253) DECL_ISR(254)
                                                                                                                                                DECL_ISR(
                                                                                                                                                    255)
#undef DECL_ISR

    // Table of all 256 ISR stub pointers
    static ISRStub isr_stubs[256] = {
        isr_stub_0,   isr_stub_1,   isr_stub_2,   isr_stub_3,   isr_stub_4,
        isr_stub_5,   isr_stub_6,   isr_stub_7,   isr_stub_8,   isr_stub_9,
        isr_stub_10,  isr_stub_11,  isr_stub_12,  isr_stub_13,  isr_stub_14,
        isr_stub_15,  isr_stub_16,  isr_stub_17,  isr_stub_18,  isr_stub_19,
        isr_stub_20,  isr_stub_21,  isr_stub_22,  isr_stub_23,  isr_stub_24,
        isr_stub_25,  isr_stub_26,  isr_stub_27,  isr_stub_28,  isr_stub_29,
        isr_stub_30,  isr_stub_31,  isr_stub_32,  isr_stub_33,  isr_stub_34,
        isr_stub_35,  isr_stub_36,  isr_stub_37,  isr_stub_38,  isr_stub_39,
        isr_stub_40,  isr_stub_41,  isr_stub_42,  isr_stub_43,  isr_stub_44,
        isr_stub_45,  isr_stub_46,  isr_stub_47,  isr_stub_48,  isr_stub_49,
        isr_stub_50,  isr_stub_51,  isr_stub_52,  isr_stub_53,  isr_stub_54,
        isr_stub_55,  isr_stub_56,  isr_stub_57,  isr_stub_58,  isr_stub_59,
        isr_stub_60,  isr_stub_61,  isr_stub_62,  isr_stub_63,  isr_stub_64,
        isr_stub_65,  isr_stub_66,  isr_stub_67,  isr_stub_68,  isr_stub_69,
        isr_stub_70,  isr_stub_71,  isr_stub_72,  isr_stub_73,  isr_stub_74,
        isr_stub_75,  isr_stub_76,  isr_stub_77,  isr_stub_78,  isr_stub_79,
        isr_stub_80,  isr_stub_81,  isr_stub_82,  isr_stub_83,  isr_stub_84,
        isr_stub_85,  isr_stub_86,  isr_stub_87,  isr_stub_88,  isr_stub_89,
        isr_stub_90,  isr_stub_91,  isr_stub_92,  isr_stub_93,  isr_stub_94,
        isr_stub_95,  isr_stub_96,  isr_stub_97,  isr_stub_98,  isr_stub_99,
        isr_stub_100, isr_stub_101, isr_stub_102, isr_stub_103, isr_stub_104,
        isr_stub_105, isr_stub_106, isr_stub_107, isr_stub_108, isr_stub_109,
        isr_stub_110, isr_stub_111, isr_stub_112, isr_stub_113, isr_stub_114,
        isr_stub_115, isr_stub_116, isr_stub_117, isr_stub_118, isr_stub_119,
        isr_stub_120, isr_stub_121, isr_stub_122, isr_stub_123, isr_stub_124,
        isr_stub_125, isr_stub_126, isr_stub_127, isr_stub_128, isr_stub_129,
        isr_stub_130, isr_stub_131, isr_stub_132, isr_stub_133, isr_stub_134,
        isr_stub_135, isr_stub_136, isr_stub_137, isr_stub_138, isr_stub_139,
        isr_stub_140, isr_stub_141, isr_stub_142, isr_stub_143, isr_stub_144,
        isr_stub_145, isr_stub_146, isr_stub_147, isr_stub_148, isr_stub_149,
        isr_stub_150, isr_stub_151, isr_stub_152, isr_stub_153, isr_stub_154,
        isr_stub_155, isr_stub_156, isr_stub_157, isr_stub_158, isr_stub_159,
        isr_stub_160, isr_stub_161, isr_stub_162, isr_stub_163, isr_stub_164,
        isr_stub_165, isr_stub_166, isr_stub_167, isr_stub_168, isr_stub_169,
        isr_stub_170, isr_stub_171, isr_stub_172, isr_stub_173, isr_stub_174,
        isr_stub_175, isr_stub_176, isr_stub_177, isr_stub_178, isr_stub_179,
        isr_stub_180, isr_stub_181, isr_stub_182, isr_stub_183, isr_stub_184,
        isr_stub_185, isr_stub_186, isr_stub_187, isr_stub_188, isr_stub_189,
        isr_stub_190, isr_stub_191, isr_stub_192, isr_stub_193, isr_stub_194,
        isr_stub_195, isr_stub_196, isr_stub_197, isr_stub_198, isr_stub_199,
        isr_stub_200, isr_stub_201, isr_stub_202, isr_stub_203, isr_stub_204,
        isr_stub_205, isr_stub_206, isr_stub_207, isr_stub_208, isr_stub_209,
        isr_stub_210, isr_stub_211, isr_stub_212, isr_stub_213, isr_stub_214,
        isr_stub_215, isr_stub_216, isr_stub_217, isr_stub_218, isr_stub_219,
        isr_stub_220, isr_stub_221, isr_stub_222, isr_stub_223, isr_stub_224,
        isr_stub_225, isr_stub_226, isr_stub_227, isr_stub_228, isr_stub_229,
        isr_stub_230, isr_stub_231, isr_stub_232, isr_stub_233, isr_stub_234,
        isr_stub_235, isr_stub_236, isr_stub_237, isr_stub_238, isr_stub_239,
        isr_stub_240, isr_stub_241, isr_stub_242, isr_stub_243, isr_stub_244,
        isr_stub_245, isr_stub_246, isr_stub_247, isr_stub_248, isr_stub_249,
        isr_stub_250, isr_stub_251, isr_stub_252, isr_stub_253, isr_stub_254,
        isr_stub_255,
};

// ============================================================================
// Common C++ interrupt dispatcher
// ============================================================================

// Exception name table for diagnostic messages
static const char *exception_names[] = {
    "Divide Error",                // 0
    "Debug",                       // 1
    "NMI",                         // 2
    "Breakpoint",                  // 3
    "Overflow",                    // 4
    "Bound Range Exceeded",        // 5
    "Invalid Opcode",              // 6
    "Device Not Available",        // 7
    "Double Fault",                // 8
    "Coprocessor Segment Overrun", // 9
    "Invalid TSS",                 // 10
    "Segment Not Present",         // 11
    "Stack-Segment Fault",         // 12
    "General Protection Fault",    // 13
    "Page Fault",                  // 14
    "Reserved",                    // 15
    "x87 FPU Error",               // 16
    "Alignment Check",             // 17
    "Machine Check",               // 18
    "SIMD Exception",              // 19
    "Virtualization Exception",    // 20
    "Control Protection",          // 21
};

extern "C" void isr_common_handler(InterruptFrame *frame) {
  // Dispatch to registered handler if one exists
  if (handlers[frame->vector]) {
    handlers[frame->vector](frame);
    // Send EOI for hardware IRQs (vectors 32-47)
    if (frame->vector >= 32 && frame->vector < 48) {
      if (frame->vector >= 40) {
        arch::outb(0xA0, 0x20); // Slave PIC EOI
      }
      arch::outb(0x20, 0x20); // Master PIC EOI
    }
    return;
  }

  // No handler registered — handle defaults

  // For hardware IRQs without handlers, just send EOI (spurious/unhandled)
  if (frame->vector >= 32 && frame->vector < 48) {
    if (frame->vector >= 40) {
      arch::outb(0xA0, 0x20);
    }
    arch::outb(0x20, 0x20);
    return;
  }

  // Unhandled CPU exception — print diagnostics and halt
  if (frame->vector < 32) {
    serial::printf("\n!!! UNHANDLED EXCEPTION: ");
    if (frame->vector < 22) {
      serial::printf("%s", exception_names[frame->vector]);
    } else {
      serial::printf("Reserved (%u)", (unsigned)frame->vector);
    }
    serial::printf(" (vector %u) !!!\n", (unsigned)frame->vector);
    serial::printf("  Error code: 0x%lx\n", frame->error_code);
    serial::printf("  RIP: 0x%lx  CS: 0x%lx\n", frame->rip, frame->cs);
    serial::printf("  RFLAGS: 0x%lx\n", frame->rflags);
    serial::printf("  RSP: 0x%lx  SS: 0x%lx\n", frame->rsp, frame->ss);
    serial::printf("  RAX: 0x%lx  RBX: 0x%lx  RCX: 0x%lx  RDX: 0x%lx\n",
                   frame->rax, frame->rbx, frame->rcx, frame->rdx);
    serial::printf("  RSI: 0x%lx  RDI: 0x%lx  RBP: 0x%lx\n", frame->rsi,
                   frame->rdi, frame->rbp);
    serial::printf("  R8:  0x%lx  R9:  0x%lx  R10: 0x%lx  R11: 0x%lx\n",
                   frame->r8, frame->r9, frame->r10, frame->r11);
    serial::printf("  R12: 0x%lx  R13: 0x%lx  R14: 0x%lx  R15: 0x%lx\n",
                   frame->r12, frame->r13, frame->r14, frame->r15);

    if (frame->vector == 14) {
      serial::printf("  CR2 (fault addr): 0x%lx\n", arch::read_cr2());
    }

    // Halt — this is an unrecoverable CPU exception
    serial::printf("\nSystem halted.\n");
    for (;;) {
      arch::cli();
      arch::hlt();
    }
  }
}

// ============================================================================
// 8259 PIC initialization
// ============================================================================

// PIC port addresses
static constexpr uint16_t PIC1_CMD = 0x20;
static constexpr uint16_t PIC1_DATA = 0x21;
static constexpr uint16_t PIC2_CMD = 0xA0;
static constexpr uint16_t PIC2_DATA = 0xA1;

// ICW (Initialization Command Word) constants
static constexpr uint8_t ICW1_INIT = 0x10; // Initialization bit
static constexpr uint8_t ICW1_ICW4 = 0x01; // ICW4 will be sent
static constexpr uint8_t ICW4_8086 = 0x01; // 8086 mode

static void pic_remap() {
  // Save current masks
  uint8_t mask1 = arch::inb(PIC1_DATA);
  uint8_t mask2 = arch::inb(PIC2_DATA);

  // ICW1: begin initialization sequence (cascade mode, ICW4 needed)
  arch::outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
  arch::io_wait();
  arch::outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
  arch::io_wait();

  // ICW2: set vector offsets
  arch::outb(PIC1_DATA, 32); // Master PIC: IRQ 0-7  -> vectors 32-39
  arch::io_wait();
  arch::outb(PIC2_DATA, 40); // Slave PIC:  IRQ 8-15 -> vectors 40-47
  arch::io_wait();

  // ICW3: configure cascading
  arch::outb(PIC1_DATA, 0x04); // Master: IRQ2 has slave (bit 2)
  arch::io_wait();
  arch::outb(PIC2_DATA, 0x02); // Slave: cascade identity 2
  arch::io_wait();

  // ICW4: set 8086 mode
  arch::outb(PIC1_DATA, ICW4_8086);
  arch::io_wait();
  arch::outb(PIC2_DATA, ICW4_8086);
  arch::io_wait();

  // Mask all IRQs initially, except IRQ2 (cascade from slave)
  // Bit set = masked (disabled), bit clear = enabled
  arch::outb(PIC1_DATA, 0xFB); // 1111_1011: all masked except IRQ2
  arch::outb(PIC2_DATA, 0xFF); // 1111_1111: all masked

  (void)mask1;
  (void)mask2;
}

// ============================================================================
// IDT entry setup
// ============================================================================

static void set_idt_entry(uint8_t vector, uint64_t handler_addr,
                          uint16_t selector, uint8_t ist, uint8_t type_attr) {
  idt_entries[vector].offset_low = handler_addr & 0xFFFF;
  idt_entries[vector].selector = selector;
  idt_entries[vector].ist = ist & 0x07;
  idt_entries[vector].type_attr = type_attr;
  idt_entries[vector].offset_mid = (handler_addr >> 16) & 0xFFFF;
  idt_entries[vector].offset_high = (handler_addr >> 32) & 0xFFFFFFFF;
  idt_entries[vector].zero = 0;
}

// ============================================================================
// Public API
// ============================================================================

void init() {
  // Clear all handlers
  for (int i = 0; i < 256; i++) {
    handlers[i] = nullptr;
  }

  // Remap the 8259 PIC so hardware IRQs don't overlap CPU exceptions
  pic_remap();

  // Install all 256 ISR stubs into the IDT.
  // Type/attr = 0x8E: Present=1, DPL=0, Type=0xE (64-bit interrupt gate)
  // An interrupt gate automatically clears IF on entry (unlike a trap gate).
  for (int i = 0; i < 256; i++) {
    uint64_t stub_addr = reinterpret_cast<uint64_t>(isr_stubs[i]);
    set_idt_entry(i, stub_addr, gdt::KERNEL_CODE_SELECTOR, 0, 0x8E);
  }

  // Load the IDTR
  idtr.limit = sizeof(idt_entries) - 1;
  idtr.base = reinterpret_cast<uint64_t>(&idt_entries);
  arch::lidt(&idtr);
}

void register_handler(uint8_t vector, InterruptHandler handler) {
  handlers[vector] = handler;
}

void enable_irq(uint8_t irq) {
  uint16_t port;
  if (irq < 8) {
    port = PIC1_DATA;
  } else {
    port = PIC2_DATA;
    irq -= 8;
  }
  uint8_t mask = arch::inb(port);
  mask &= ~(1 << irq); // Clear the bit to unmask
  arch::outb(port, mask);
}

void disable_irq(uint8_t irq) {
  uint16_t port;
  if (irq < 8) {
    port = PIC1_DATA;
  } else {
    port = PIC2_DATA;
    irq -= 8;
  }
  uint8_t mask = arch::inb(port);
  mask |= (1 << irq); // Set the bit to mask
  arch::outb(port, mask);
}

} // namespace idt
