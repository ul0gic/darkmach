/*
 * sphinx-trampoline.S -- ARM64 shared trampoline for ObjC method tracing
 *
 * Part of the Sphinx LLM bridge (Sprint 13.3).
 * Compiled as a separate object, linked into sphinx-bridge.dylib.
 *
 * Architecture: arm64-apple-ios16.0-simulator
 * Reference: dev/frida-gum-interceptor-study.md sections 9.1, 9.4, 9.5
 *
 * Design:
 *   - One shared trampoline (_sphinx_method_trampoline) handles ALL hooks
 *   - 256 per-hook stubs load their hook_table entry pointer into X17,
 *     then branch to the shared trampoline
 *   - The trampoline saves argument registers, calls the C handler
 *     (_sphinx_on_method_enter), restores registers, and tail-calls
 *     the original method implementation
 *
 * Register convention:
 *   X17 = pointer to sphinx_hook_t for the active hook (set by stub)
 *   X16 = scratch register for loading original IMP (caller-saved)
 *
 * sphinx_hook_t layout (from sphinx-core.h, verified sizeof = 928):
 *   offset  0: Class cls           (8 bytes)
 *   offset  8: SEL sel             (8 bytes)
 *   offset 16: IMP original_imp    (8 bytes)
 *   offset 24: char class_name[128]
 *   offset 152: char sel_name[256]
 *   offset 408: char type_encoding[512]
 *   offset 920: int active         (4 bytes)
 *   offset 924: int call_count     (4 bytes)
 *   total: 928 bytes per entry
 *
 * Stack frame layout (208 bytes, 16-byte aligned):
 *   SP+0:    X0, X1    (self, _cmd)
 *   SP+16:   X2, X3
 *   SP+32:   X4, X5
 *   SP+48:   X6, X7
 *   SP+64:   X8, X17   (indirect result ptr, hook ptr backup)
 *   SP+80:   Q0, Q1    (SIMD/FP arg registers)
 *   SP+112:  Q2, Q3
 *   SP+144:  Q4, Q5
 *   SP+176:  Q6, Q7
 *
 * Build:
 *   clang -target arm64-apple-ios16.0-simulator \
 *     -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
 *     -c -o src/dylibs/sphinx-trampoline.o src/dylibs/bridge/sphinx-trampoline.S
 */

/* ===================================================================
 *  Offset constants from sphinx_hook_t
 * =================================================================== */

#define HOOK_ORIGINAL_IMP_OFF   16
#define HOOK_SIZEOF             928
#define SPHINX_MAX_HOOKS        256

/* Stack frame size: 10 GP regs (80 bytes) + 8 SIMD regs (128 bytes) = 208 */
#define FRAME_SIZE              208

/* ===================================================================
 *  Shared trampoline -- all traced methods dispatch through here
 *
 *  Entry: X17 = pointer to this hook's sphinx_hook_t entry
 *         All other registers are live ObjC method call arguments
 *  Exit:  Tail-call to original IMP with all registers restored
 *
 *  Total: 26 instructions (~104 bytes)
 * =================================================================== */

.text
.align 4
.globl _sphinx_method_trampoline

_sphinx_method_trampoline:
    /* 1. Save frame pointer and link register */
    stp     fp, lr, [sp, #-16]!
    mov     fp, sp

    /* 2. Allocate stack space for saved registers (208 bytes) */
    sub     sp, sp, #FRAME_SIZE

    /* 3. Save general-purpose argument registers */
    stp     x0, x1, [sp, #0]       /* self, _cmd                    */
    stp     x2, x3, [sp, #16]      /* arg2, arg3                    */
    stp     x4, x5, [sp, #32]      /* arg4, arg5                    */
    stp     x6, x7, [sp, #48]      /* arg6, arg7                    */
    stp     x8, x17, [sp, #64]     /* indirect result ptr, hook ptr */

    /* 4. Save SIMD/floating-point argument registers */
    stp     q0, q1, [sp, #80]
    stp     q2, q3, [sp, #112]
    stp     q4, q5, [sp, #144]
    stp     q6, q7, [sp, #176]

    /* 5. Call C handler: _sphinx_on_method_enter(hook_ptr, saved_regs) */
    mov     x0, x17                 /* arg0 = sphinx_hook_t*         */
    mov     x1, sp                  /* arg1 = pointer to saved regs  */
    bl      _sphinx_on_method_enter

    /* 6. Restore general-purpose argument registers */
    ldp     x0, x1, [sp, #0]
    ldp     x2, x3, [sp, #16]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x17, [sp, #64]

    /* 7. Restore SIMD/floating-point argument registers */
    ldp     q0, q1, [sp, #80]
    ldp     q2, q3, [sp, #112]
    ldp     q4, q5, [sp, #144]
    ldp     q6, q7, [sp, #176]

    /* 8. Deallocate stack frame */
    add     sp, sp, #FRAME_SIZE

    /* 9. Restore frame pointer and link register */
    ldp     fp, lr, [sp], #16

    /* 10. Tail-call original implementation via hook descriptor */
    ldr     x16, [x17, #HOOK_ORIGINAL_IMP_OFF]
    br      x16


/* ===================================================================
 *  Per-hook stub table -- 256 static stubs
 *
 *  Each stub is exactly 12 bytes (3 ARM64 instructions):
 *    ADRP  X17, (hook_table + N * 928)@PAGE
 *    ADD   X17, X17, (hook_table + N * 928)@PAGEOFF
 *    B     _sphinx_method_trampoline
 *
 *  The stub address for hook slot N is:
 *    (IMP)((char *)&_sphinx_stub_table + N * 12)
 *
 *  The hook_table symbol is defined in cmd-trace.c (linked at build time).
 * =================================================================== */

.align 4
.globl _sphinx_stub_table

/* Macro: emit one stub for hook slot N */
.macro STUB n
    adrp    x17, (_sphinx_hook_table + (\n * HOOK_SIZEOF))@PAGE
    add     x17, x17, (_sphinx_hook_table + (\n * HOOK_SIZEOF))@PAGEOFF
    b       _sphinx_method_trampoline
.endm

_sphinx_stub_table:
    STUB 0
    STUB 1
    STUB 2
    STUB 3
    STUB 4
    STUB 5
    STUB 6
    STUB 7
    STUB 8
    STUB 9
    STUB 10
    STUB 11
    STUB 12
    STUB 13
    STUB 14
    STUB 15
    STUB 16
    STUB 17
    STUB 18
    STUB 19
    STUB 20
    STUB 21
    STUB 22
    STUB 23
    STUB 24
    STUB 25
    STUB 26
    STUB 27
    STUB 28
    STUB 29
    STUB 30
    STUB 31
    STUB 32
    STUB 33
    STUB 34
    STUB 35
    STUB 36
    STUB 37
    STUB 38
    STUB 39
    STUB 40
    STUB 41
    STUB 42
    STUB 43
    STUB 44
    STUB 45
    STUB 46
    STUB 47
    STUB 48
    STUB 49
    STUB 50
    STUB 51
    STUB 52
    STUB 53
    STUB 54
    STUB 55
    STUB 56
    STUB 57
    STUB 58
    STUB 59
    STUB 60
    STUB 61
    STUB 62
    STUB 63
    STUB 64
    STUB 65
    STUB 66
    STUB 67
    STUB 68
    STUB 69
    STUB 70
    STUB 71
    STUB 72
    STUB 73
    STUB 74
    STUB 75
    STUB 76
    STUB 77
    STUB 78
    STUB 79
    STUB 80
    STUB 81
    STUB 82
    STUB 83
    STUB 84
    STUB 85
    STUB 86
    STUB 87
    STUB 88
    STUB 89
    STUB 90
    STUB 91
    STUB 92
    STUB 93
    STUB 94
    STUB 95
    STUB 96
    STUB 97
    STUB 98
    STUB 99
    STUB 100
    STUB 101
    STUB 102
    STUB 103
    STUB 104
    STUB 105
    STUB 106
    STUB 107
    STUB 108
    STUB 109
    STUB 110
    STUB 111
    STUB 112
    STUB 113
    STUB 114
    STUB 115
    STUB 116
    STUB 117
    STUB 118
    STUB 119
    STUB 120
    STUB 121
    STUB 122
    STUB 123
    STUB 124
    STUB 125
    STUB 126
    STUB 127
    STUB 128
    STUB 129
    STUB 130
    STUB 131
    STUB 132
    STUB 133
    STUB 134
    STUB 135
    STUB 136
    STUB 137
    STUB 138
    STUB 139
    STUB 140
    STUB 141
    STUB 142
    STUB 143
    STUB 144
    STUB 145
    STUB 146
    STUB 147
    STUB 148
    STUB 149
    STUB 150
    STUB 151
    STUB 152
    STUB 153
    STUB 154
    STUB 155
    STUB 156
    STUB 157
    STUB 158
    STUB 159
    STUB 160
    STUB 161
    STUB 162
    STUB 163
    STUB 164
    STUB 165
    STUB 166
    STUB 167
    STUB 168
    STUB 169
    STUB 170
    STUB 171
    STUB 172
    STUB 173
    STUB 174
    STUB 175
    STUB 176
    STUB 177
    STUB 178
    STUB 179
    STUB 180
    STUB 181
    STUB 182
    STUB 183
    STUB 184
    STUB 185
    STUB 186
    STUB 187
    STUB 188
    STUB 189
    STUB 190
    STUB 191
    STUB 192
    STUB 193
    STUB 194
    STUB 195
    STUB 196
    STUB 197
    STUB 198
    STUB 199
    STUB 200
    STUB 201
    STUB 202
    STUB 203
    STUB 204
    STUB 205
    STUB 206
    STUB 207
    STUB 208
    STUB 209
    STUB 210
    STUB 211
    STUB 212
    STUB 213
    STUB 214
    STUB 215
    STUB 216
    STUB 217
    STUB 218
    STUB 219
    STUB 220
    STUB 221
    STUB 222
    STUB 223
    STUB 224
    STUB 225
    STUB 226
    STUB 227
    STUB 228
    STUB 229
    STUB 230
    STUB 231
    STUB 232
    STUB 233
    STUB 234
    STUB 235
    STUB 236
    STUB 237
    STUB 238
    STUB 239
    STUB 240
    STUB 241
    STUB 242
    STUB 243
    STUB 244
    STUB 245
    STUB 246
    STUB 247
    STUB 248
    STUB 249
    STUB 250
    STUB 251
    STUB 252
    STUB 253
    STUB 254
    STUB 255


.subsections_via_symbols
