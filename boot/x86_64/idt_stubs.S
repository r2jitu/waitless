// boot/x86_64/idt_stubs.S — x86_64 ISR (Interrupt Service Routine) stubs
//
// Low-level interrupt entry points for all 256 IDT vectors on x86_64.
// The high-level handlers live in kernel::x86_64::idt.
//
// Contents:
//   1. isr_common      — common interrupt entry point. Saves all GP registers,
//                         calls isr_common_handler (Rust), restores
//                         registers, and returns via iretq.
//   2. isr_stub_0..255 — per-vector stubs. Each normalizes the stack by
//                         pushing a dummy error code (0) if the CPU didn't
//                         push one, then pushes the vector number and jumps
//                         to isr_common.
//   3. isr_stub_table  — array of 256 quad-word function pointers so that
//                         IDT init code can index stubs by vector number.
//
// Stack frame on entry to isr_common (growing downward):
//   [CPU]  SS
//   [CPU]  RSP
//   [CPU]  RFLAGS
//   [CPU]  CS
//   [CPU]  RIP
//   [stub] error_code  (real for HW-error-code exceptions, dummy 0 otherwise)
//   [stub] vector number
//
// isr_common then pushes all 15 GP registers (RAX..R15) to form the full
// InterruptFrame that is passed to isr_common_handler.

// External: the C/C++/Rust handler called from isr_common
.extern isr_common_handler

// ============================================================================
// Common interrupt handler
// ============================================================================

.text

.global isr_common
isr_common:
    // Save all general-purpose registers
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    // First argument (RDI) = pointer to InterruptFrame on stack
    movq %rsp, %rdi

    // Align stack to 16 bytes for the C ABI call.
    // We've pushed 15 GP regs + vector + error_code + 5 CPU values = 22 qwords
    // (176 bytes). The stack may not be 16-byte aligned, so save and align.
    movq %rsp, %rbp
    andq $-16, %rsp
    call isr_common_handler
    movq %rbp, %rsp

    // Restore all general-purpose registers
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    // Remove vector number and error code from the stack
    addq $16, %rsp

    iretq

// ============================================================================
// ISR stub macros
// ============================================================================

// For exceptions that do NOT push a hardware error code: push dummy 0, then
// vector number, then jump to isr_common.
.macro ISR_STUB_NOERR num
.global isr_stub_\num
isr_stub_\num:
    pushq $0
    pushq $\num
    jmp isr_common
.endm

// For exceptions that DO push a hardware error code: the CPU already pushed
// the error code, so just push the vector number and jump.
.macro ISR_STUB_ERR num
.global isr_stub_\num
isr_stub_\num:
    pushq $\num
    jmp isr_common
.endm

// ============================================================================
// ISR stubs for all 256 vectors
// ============================================================================

// Vectors 0-7: exceptions without error codes
ISR_STUB_NOERR 0    // #DE Divide Error
ISR_STUB_NOERR 1    // #DB Debug
ISR_STUB_NOERR 2    // NMI
ISR_STUB_NOERR 3    // #BP Breakpoint
ISR_STUB_NOERR 4    // #OF Overflow
ISR_STUB_NOERR 5    // #BR Bound Range Exceeded
ISR_STUB_NOERR 6    // #UD Invalid Opcode
ISR_STUB_NOERR 7    // #NM Device Not Available

// Vector 8: #DF Double Fault (error code)
ISR_STUB_ERR   8

// Vector 9: Coprocessor Segment Overrun (no error code, legacy)
ISR_STUB_NOERR 9

// Vectors 10-14: exceptions with error codes
ISR_STUB_ERR   10   // #TS Invalid TSS
ISR_STUB_ERR   11   // #NP Segment Not Present
ISR_STUB_ERR   12   // #SS Stack-Segment Fault
ISR_STUB_ERR   13   // #GP General Protection Fault
ISR_STUB_ERR   14   // #PF Page Fault

// Vector 15: reserved (no error code)
ISR_STUB_NOERR 15

// Vector 16: #MF x87 FPU Error (no error code)
ISR_STUB_NOERR 16

// Vector 17: #AC Alignment Check (error code)
ISR_STUB_ERR   17

// Vectors 18-20: no error code
ISR_STUB_NOERR 18   // #MC Machine Check
ISR_STUB_NOERR 19   // #XM SIMD Exception
ISR_STUB_NOERR 20   // #VE Virtualization Exception

// Vector 21: #CP Control Protection (error code)
ISR_STUB_ERR   21

// Vectors 22-28: reserved (no error code)
ISR_STUB_NOERR 22
ISR_STUB_NOERR 23
ISR_STUB_NOERR 24
ISR_STUB_NOERR 25
ISR_STUB_NOERR 26
ISR_STUB_NOERR 27
ISR_STUB_NOERR 28

// Vectors 29-30: error code
ISR_STUB_ERR   29   // #VC VMM Communication Exception
ISR_STUB_ERR   30   // #SX Security Exception

// Vector 31: reserved (no error code)
ISR_STUB_NOERR 31

// Vectors 32-255: IRQs and software interrupts (no error code)
ISR_STUB_NOERR 32
ISR_STUB_NOERR 33
ISR_STUB_NOERR 34
ISR_STUB_NOERR 35
ISR_STUB_NOERR 36
ISR_STUB_NOERR 37
ISR_STUB_NOERR 38
ISR_STUB_NOERR 39
ISR_STUB_NOERR 40
ISR_STUB_NOERR 41
ISR_STUB_NOERR 42
ISR_STUB_NOERR 43
ISR_STUB_NOERR 44
ISR_STUB_NOERR 45
ISR_STUB_NOERR 46
ISR_STUB_NOERR 47
ISR_STUB_NOERR 48
ISR_STUB_NOERR 49
ISR_STUB_NOERR 50
ISR_STUB_NOERR 51
ISR_STUB_NOERR 52
ISR_STUB_NOERR 53
ISR_STUB_NOERR 54
ISR_STUB_NOERR 55
ISR_STUB_NOERR 56
ISR_STUB_NOERR 57
ISR_STUB_NOERR 58
ISR_STUB_NOERR 59
ISR_STUB_NOERR 60
ISR_STUB_NOERR 61
ISR_STUB_NOERR 62
ISR_STUB_NOERR 63
ISR_STUB_NOERR 64
ISR_STUB_NOERR 65
ISR_STUB_NOERR 66
ISR_STUB_NOERR 67
ISR_STUB_NOERR 68
ISR_STUB_NOERR 69
ISR_STUB_NOERR 70
ISR_STUB_NOERR 71
ISR_STUB_NOERR 72
ISR_STUB_NOERR 73
ISR_STUB_NOERR 74
ISR_STUB_NOERR 75
ISR_STUB_NOERR 76
ISR_STUB_NOERR 77
ISR_STUB_NOERR 78
ISR_STUB_NOERR 79
ISR_STUB_NOERR 80
ISR_STUB_NOERR 81
ISR_STUB_NOERR 82
ISR_STUB_NOERR 83
ISR_STUB_NOERR 84
ISR_STUB_NOERR 85
ISR_STUB_NOERR 86
ISR_STUB_NOERR 87
ISR_STUB_NOERR 88
ISR_STUB_NOERR 89
ISR_STUB_NOERR 90
ISR_STUB_NOERR 91
ISR_STUB_NOERR 92
ISR_STUB_NOERR 93
ISR_STUB_NOERR 94
ISR_STUB_NOERR 95
ISR_STUB_NOERR 96
ISR_STUB_NOERR 97
ISR_STUB_NOERR 98
ISR_STUB_NOERR 99
ISR_STUB_NOERR 100
ISR_STUB_NOERR 101
ISR_STUB_NOERR 102
ISR_STUB_NOERR 103
ISR_STUB_NOERR 104
ISR_STUB_NOERR 105
ISR_STUB_NOERR 106
ISR_STUB_NOERR 107
ISR_STUB_NOERR 108
ISR_STUB_NOERR 109
ISR_STUB_NOERR 110
ISR_STUB_NOERR 111
ISR_STUB_NOERR 112
ISR_STUB_NOERR 113
ISR_STUB_NOERR 114
ISR_STUB_NOERR 115
ISR_STUB_NOERR 116
ISR_STUB_NOERR 117
ISR_STUB_NOERR 118
ISR_STUB_NOERR 119
ISR_STUB_NOERR 120
ISR_STUB_NOERR 121
ISR_STUB_NOERR 122
ISR_STUB_NOERR 123
ISR_STUB_NOERR 124
ISR_STUB_NOERR 125
ISR_STUB_NOERR 126
ISR_STUB_NOERR 127
ISR_STUB_NOERR 128
ISR_STUB_NOERR 129
ISR_STUB_NOERR 130
ISR_STUB_NOERR 131
ISR_STUB_NOERR 132
ISR_STUB_NOERR 133
ISR_STUB_NOERR 134
ISR_STUB_NOERR 135
ISR_STUB_NOERR 136
ISR_STUB_NOERR 137
ISR_STUB_NOERR 138
ISR_STUB_NOERR 139
ISR_STUB_NOERR 140
ISR_STUB_NOERR 141
ISR_STUB_NOERR 142
ISR_STUB_NOERR 143
ISR_STUB_NOERR 144
ISR_STUB_NOERR 145
ISR_STUB_NOERR 146
ISR_STUB_NOERR 147
ISR_STUB_NOERR 148
ISR_STUB_NOERR 149
ISR_STUB_NOERR 150
ISR_STUB_NOERR 151
ISR_STUB_NOERR 152
ISR_STUB_NOERR 153
ISR_STUB_NOERR 154
ISR_STUB_NOERR 155
ISR_STUB_NOERR 156
ISR_STUB_NOERR 157
ISR_STUB_NOERR 158
ISR_STUB_NOERR 159
ISR_STUB_NOERR 160
ISR_STUB_NOERR 161
ISR_STUB_NOERR 162
ISR_STUB_NOERR 163
ISR_STUB_NOERR 164
ISR_STUB_NOERR 165
ISR_STUB_NOERR 166
ISR_STUB_NOERR 167
ISR_STUB_NOERR 168
ISR_STUB_NOERR 169
ISR_STUB_NOERR 170
ISR_STUB_NOERR 171
ISR_STUB_NOERR 172
ISR_STUB_NOERR 173
ISR_STUB_NOERR 174
ISR_STUB_NOERR 175
ISR_STUB_NOERR 176
ISR_STUB_NOERR 177
ISR_STUB_NOERR 178
ISR_STUB_NOERR 179
ISR_STUB_NOERR 180
ISR_STUB_NOERR 181
ISR_STUB_NOERR 182
ISR_STUB_NOERR 183
ISR_STUB_NOERR 184
ISR_STUB_NOERR 185
ISR_STUB_NOERR 186
ISR_STUB_NOERR 187
ISR_STUB_NOERR 188
ISR_STUB_NOERR 189
ISR_STUB_NOERR 190
ISR_STUB_NOERR 191
ISR_STUB_NOERR 192
ISR_STUB_NOERR 193
ISR_STUB_NOERR 194
ISR_STUB_NOERR 195
ISR_STUB_NOERR 196
ISR_STUB_NOERR 197
ISR_STUB_NOERR 198
ISR_STUB_NOERR 199
ISR_STUB_NOERR 200
ISR_STUB_NOERR 201
ISR_STUB_NOERR 202
ISR_STUB_NOERR 203
ISR_STUB_NOERR 204
ISR_STUB_NOERR 205
ISR_STUB_NOERR 206
ISR_STUB_NOERR 207
ISR_STUB_NOERR 208
ISR_STUB_NOERR 209
ISR_STUB_NOERR 210
ISR_STUB_NOERR 211
ISR_STUB_NOERR 212
ISR_STUB_NOERR 213
ISR_STUB_NOERR 214
ISR_STUB_NOERR 215
ISR_STUB_NOERR 216
ISR_STUB_NOERR 217
ISR_STUB_NOERR 218
ISR_STUB_NOERR 219
ISR_STUB_NOERR 220
ISR_STUB_NOERR 221
ISR_STUB_NOERR 222
ISR_STUB_NOERR 223
ISR_STUB_NOERR 224
ISR_STUB_NOERR 225
ISR_STUB_NOERR 226
ISR_STUB_NOERR 227
ISR_STUB_NOERR 228
ISR_STUB_NOERR 229
ISR_STUB_NOERR 230
ISR_STUB_NOERR 231
ISR_STUB_NOERR 232
ISR_STUB_NOERR 233
ISR_STUB_NOERR 234
ISR_STUB_NOERR 235
ISR_STUB_NOERR 236
ISR_STUB_NOERR 237
ISR_STUB_NOERR 238
ISR_STUB_NOERR 239
ISR_STUB_NOERR 240
ISR_STUB_NOERR 241
ISR_STUB_NOERR 242
ISR_STUB_NOERR 243
ISR_STUB_NOERR 244
ISR_STUB_NOERR 245
ISR_STUB_NOERR 246
ISR_STUB_NOERR 247
ISR_STUB_NOERR 248
ISR_STUB_NOERR 249
ISR_STUB_NOERR 250
ISR_STUB_NOERR 251
ISR_STUB_NOERR 252
ISR_STUB_NOERR 253
ISR_STUB_NOERR 254
ISR_STUB_NOERR 255

// ============================================================================
// ISR stub table — 256 quad-word function pointers
// ============================================================================
//
// This table lets IDT init code look up stub addresses by vector index:
//   extern void* isr_stub_table[256];
//   idt_entry[i].offset = (uintptr_t)isr_stub_table[i];

.section .data
.global isr_stub_table
isr_stub_table:
    .quad isr_stub_0
    .quad isr_stub_1
    .quad isr_stub_2
    .quad isr_stub_3
    .quad isr_stub_4
    .quad isr_stub_5
    .quad isr_stub_6
    .quad isr_stub_7
    .quad isr_stub_8
    .quad isr_stub_9
    .quad isr_stub_10
    .quad isr_stub_11
    .quad isr_stub_12
    .quad isr_stub_13
    .quad isr_stub_14
    .quad isr_stub_15
    .quad isr_stub_16
    .quad isr_stub_17
    .quad isr_stub_18
    .quad isr_stub_19
    .quad isr_stub_20
    .quad isr_stub_21
    .quad isr_stub_22
    .quad isr_stub_23
    .quad isr_stub_24
    .quad isr_stub_25
    .quad isr_stub_26
    .quad isr_stub_27
    .quad isr_stub_28
    .quad isr_stub_29
    .quad isr_stub_30
    .quad isr_stub_31
    .quad isr_stub_32
    .quad isr_stub_33
    .quad isr_stub_34
    .quad isr_stub_35
    .quad isr_stub_36
    .quad isr_stub_37
    .quad isr_stub_38
    .quad isr_stub_39
    .quad isr_stub_40
    .quad isr_stub_41
    .quad isr_stub_42
    .quad isr_stub_43
    .quad isr_stub_44
    .quad isr_stub_45
    .quad isr_stub_46
    .quad isr_stub_47
    .quad isr_stub_48
    .quad isr_stub_49
    .quad isr_stub_50
    .quad isr_stub_51
    .quad isr_stub_52
    .quad isr_stub_53
    .quad isr_stub_54
    .quad isr_stub_55
    .quad isr_stub_56
    .quad isr_stub_57
    .quad isr_stub_58
    .quad isr_stub_59
    .quad isr_stub_60
    .quad isr_stub_61
    .quad isr_stub_62
    .quad isr_stub_63
    .quad isr_stub_64
    .quad isr_stub_65
    .quad isr_stub_66
    .quad isr_stub_67
    .quad isr_stub_68
    .quad isr_stub_69
    .quad isr_stub_70
    .quad isr_stub_71
    .quad isr_stub_72
    .quad isr_stub_73
    .quad isr_stub_74
    .quad isr_stub_75
    .quad isr_stub_76
    .quad isr_stub_77
    .quad isr_stub_78
    .quad isr_stub_79
    .quad isr_stub_80
    .quad isr_stub_81
    .quad isr_stub_82
    .quad isr_stub_83
    .quad isr_stub_84
    .quad isr_stub_85
    .quad isr_stub_86
    .quad isr_stub_87
    .quad isr_stub_88
    .quad isr_stub_89
    .quad isr_stub_90
    .quad isr_stub_91
    .quad isr_stub_92
    .quad isr_stub_93
    .quad isr_stub_94
    .quad isr_stub_95
    .quad isr_stub_96
    .quad isr_stub_97
    .quad isr_stub_98
    .quad isr_stub_99
    .quad isr_stub_100
    .quad isr_stub_101
    .quad isr_stub_102
    .quad isr_stub_103
    .quad isr_stub_104
    .quad isr_stub_105
    .quad isr_stub_106
    .quad isr_stub_107
    .quad isr_stub_108
    .quad isr_stub_109
    .quad isr_stub_110
    .quad isr_stub_111
    .quad isr_stub_112
    .quad isr_stub_113
    .quad isr_stub_114
    .quad isr_stub_115
    .quad isr_stub_116
    .quad isr_stub_117
    .quad isr_stub_118
    .quad isr_stub_119
    .quad isr_stub_120
    .quad isr_stub_121
    .quad isr_stub_122
    .quad isr_stub_123
    .quad isr_stub_124
    .quad isr_stub_125
    .quad isr_stub_126
    .quad isr_stub_127
    .quad isr_stub_128
    .quad isr_stub_129
    .quad isr_stub_130
    .quad isr_stub_131
    .quad isr_stub_132
    .quad isr_stub_133
    .quad isr_stub_134
    .quad isr_stub_135
    .quad isr_stub_136
    .quad isr_stub_137
    .quad isr_stub_138
    .quad isr_stub_139
    .quad isr_stub_140
    .quad isr_stub_141
    .quad isr_stub_142
    .quad isr_stub_143
    .quad isr_stub_144
    .quad isr_stub_145
    .quad isr_stub_146
    .quad isr_stub_147
    .quad isr_stub_148
    .quad isr_stub_149
    .quad isr_stub_150
    .quad isr_stub_151
    .quad isr_stub_152
    .quad isr_stub_153
    .quad isr_stub_154
    .quad isr_stub_155
    .quad isr_stub_156
    .quad isr_stub_157
    .quad isr_stub_158
    .quad isr_stub_159
    .quad isr_stub_160
    .quad isr_stub_161
    .quad isr_stub_162
    .quad isr_stub_163
    .quad isr_stub_164
    .quad isr_stub_165
    .quad isr_stub_166
    .quad isr_stub_167
    .quad isr_stub_168
    .quad isr_stub_169
    .quad isr_stub_170
    .quad isr_stub_171
    .quad isr_stub_172
    .quad isr_stub_173
    .quad isr_stub_174
    .quad isr_stub_175
    .quad isr_stub_176
    .quad isr_stub_177
    .quad isr_stub_178
    .quad isr_stub_179
    .quad isr_stub_180
    .quad isr_stub_181
    .quad isr_stub_182
    .quad isr_stub_183
    .quad isr_stub_184
    .quad isr_stub_185
    .quad isr_stub_186
    .quad isr_stub_187
    .quad isr_stub_188
    .quad isr_stub_189
    .quad isr_stub_190
    .quad isr_stub_191
    .quad isr_stub_192
    .quad isr_stub_193
    .quad isr_stub_194
    .quad isr_stub_195
    .quad isr_stub_196
    .quad isr_stub_197
    .quad isr_stub_198
    .quad isr_stub_199
    .quad isr_stub_200
    .quad isr_stub_201
    .quad isr_stub_202
    .quad isr_stub_203
    .quad isr_stub_204
    .quad isr_stub_205
    .quad isr_stub_206
    .quad isr_stub_207
    .quad isr_stub_208
    .quad isr_stub_209
    .quad isr_stub_210
    .quad isr_stub_211
    .quad isr_stub_212
    .quad isr_stub_213
    .quad isr_stub_214
    .quad isr_stub_215
    .quad isr_stub_216
    .quad isr_stub_217
    .quad isr_stub_218
    .quad isr_stub_219
    .quad isr_stub_220
    .quad isr_stub_221
    .quad isr_stub_222
    .quad isr_stub_223
    .quad isr_stub_224
    .quad isr_stub_225
    .quad isr_stub_226
    .quad isr_stub_227
    .quad isr_stub_228
    .quad isr_stub_229
    .quad isr_stub_230
    .quad isr_stub_231
    .quad isr_stub_232
    .quad isr_stub_233
    .quad isr_stub_234
    .quad isr_stub_235
    .quad isr_stub_236
    .quad isr_stub_237
    .quad isr_stub_238
    .quad isr_stub_239
    .quad isr_stub_240
    .quad isr_stub_241
    .quad isr_stub_242
    .quad isr_stub_243
    .quad isr_stub_244
    .quad isr_stub_245
    .quad isr_stub_246
    .quad isr_stub_247
    .quad isr_stub_248
    .quad isr_stub_249
    .quad isr_stub_250
    .quad isr_stub_251
    .quad isr_stub_252
    .quad isr_stub_253
    .quad isr_stub_254
    .quad isr_stub_255
