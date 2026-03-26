# Frida-Gum ARM64 Interceptor Architecture Study

> Research document for darkmach-bridge.dylib method tracing capability.
> Date: 2026-03-25
> Author: exploit-engineer
> Status: RESEARCH ONLY -- no code produced

---

## Executive Summary

Frida's interception engine (frida-gum) is a general-purpose inline hooking framework that works on arbitrary native functions across architectures. For our use case -- ObjC method tracing via DYLD_INSERT_LIBRARIES in Simulator processes -- we can achieve the same result with roughly 5% of Frida's complexity. The key insight: **ObjC method swizzling (method_setImplementation / method_exchangeImplementations) eliminates the need for inline patching entirely.** We do not need Frida's relocator, code allocator, or instruction rewriting. We need only a trampoline that saves registers, calls our logging function, restores registers, and calls the original IMP. This document dissects Frida's approach to inform what we must borrow vs. what we can skip.

---

## 1. guminterceptor.c -- Cross-Platform Interceptor Core

**File**: `dev/frida-gum/gum/guminterceptor.c`
**Size**: ~1650 lines
**Purpose**: Architecture-independent interception lifecycle, listener management, thread-local invocation tracking.

### 1.1 Key Data Structures

#### GumInterceptor (the singleton)
```c
struct _GumInterceptor {
  GObject parent;                          // GObject inheritance
  GRecMutex mutex;                         // Recursive mutex for thread safety
  GHashTable * function_by_address;        // address -> GumFunctionContext map
  GumInterceptorBackend * backend;         // Architecture-specific backend (lazy init)
  GumCodeAllocator allocator;              // JIT code page allocator
  volatile guint selected_thread_id;       // For thread-specific hooking
  GumInterceptorTransaction current_transaction; // Batched patching
};
```
The interceptor is a singleton (`_the_interceptor`), obtained via `gum_interceptor_obtain()`. This is a GObject with reference counting and weak notification. The `function_by_address` hash table maps target function addresses to their `GumFunctionContext`, which holds all state for a single hooked function.

#### GumFunctionContext (per-hook state)
Defined in `guminterceptor-priv.h`:
```c
struct _GumFunctionContext {
  gpointer function_address;               // Original function address
  gpointer grafted_hook;                   // Darwin: pre-grafted hook (code-signed)
  gpointer import_target;                  // Darwin: import table redirection
  GumInterceptorType type;                 // DEFAULT or FAST
  guint8 destroyed, activated;             // Lifecycle flags
  guint8 has_on_leave_listener;            // Optimization: skip leave trap if no listener
  guint8 has_unignorable_listener;         // For system-level hooks that must fire
  GumCodeSlice * trampoline_slice;         // Allocated code memory for trampoline
  GumCodeDeflector * trampoline_deflector; // Nearby code for short-range redirects
  volatile gint trampoline_usage_counter;  // Reference count for safe destruction
  gpointer on_enter_trampoline;            // Entry point to enter thunk
  guint8 overwritten_prologue[32];         // Backup of patched bytes
  guint overwritten_prologue_len;          // How many bytes were overwritten
  gpointer on_invoke_trampoline;           // Relocated original prologue + resume
  gpointer on_leave_trampoline;            // Entry point to leave thunk
  volatile GPtrArray * listener_entries;   // Array of ListenerEntry (lock-free reads)
  gpointer replacement_function;           // For replace mode (not attach)
  gpointer replacement_data;               // Opaque data for replacement
  GumFunctionContextBackendData backend_data; // Backend-private (2 pointers)
  GumInterceptor * interceptor;            // Back-pointer
};
```
This is the central structure. For each hooked function, it tracks:
- Three trampolines: enter, invoke (original), leave
- The original prologue bytes (for unhooking)
- A list of listeners to notify
- A usage counter to prevent destruction while a thread is inside the trampoline

#### GumInvocationStackEntry (per-call state, thread-local)
```c
struct _GumInvocationStackEntry {
  GumFunctionContext * function_ctx;
  gpointer caller_ret_addr;                // Saved LR (return address)
  GumInvocationContext invocation_context;  // Exposed to listeners
  GumCpuContext cpu_context;               // Snapshot for replacement mode
  guint8 listener_invocation_data[MAX_LISTENERS][MAX_DATA]; // Per-listener scratch
  gboolean calling_replacement;
  gboolean only_invoke_unignorable_listeners;
  gint original_system_error;
};
```
Each hooked call pushes one of these onto a thread-local stack. The `caller_ret_addr` is critical -- it is the real return address that was replaced with `on_leave_trampoline` to trap the return.

#### GumInvocationContext (listener-visible API)
```c
struct _GumInvocationContext {
  gpointer function;          // The hooked function address
  GumCpuContext * cpu_context; // Full register state, read/write
  gint system_error;          // errno equivalent
  GumInvocationBackend * backend; // vtable for data access
};
```
This is what listener callbacks receive. The `cpu_context` pointer gives direct access to all ARM64 registers (X0-X28, FP, LR, SP, NZCV, Q0-Q31). Arguments are accessed via `gum_cpu_context_get_nth_argument(ctx, n)` which reads `x[n]` for n < 8 or from the stack for n >= 8.

#### InterceptorThreadContext (TLS)
```c
struct _InterceptorThreadContext {
  GumInvocationBackend listener_backend;    // vtable for listeners
  GumInvocationBackend replacement_backend; // vtable for replacements
  gint ignore_level;                        // Reentrance suppression depth
  GumInvocationStack * stack;               // Thread-local invocation stack
  GArray * listener_data_slots;             // Per-listener persistent data
};
```
Stored in GLib's GPrivate (thread-local storage). The `ignore_level` prevents infinite recursion when hooks call other hooked functions. The stack tracks nested invocations.

### 1.2 Interception Lifecycle

#### Phase 1: Attach

`gum_interceptor_attach(interceptor, function_address, listener, data, flags)`:

1. Wraps in a transaction (begin/end for batched code patching)
2. Resolves the address (follows redirects/thunks via `_gum_interceptor_backend_resolve_redirect`)
3. Calls `gum_interceptor_instrument()` which either:
   a. Returns existing `GumFunctionContext` if already hooked
   b. Creates new context via `gum_function_context_new()`
   c. On Darwin with code signing required: tries `_gum_interceptor_backend_claim_grafted_trampoline()` (pre-embedded hooks)
   d. Otherwise: calls `_gum_interceptor_backend_create_trampoline()` to generate code
4. Adds the listener to the function context's listener array
5. Schedules activation (prologue overwrite) in the transaction

#### Phase 2: Transaction Commit

`gum_interceptor_transaction_end()`:

1. Groups all pending updates by target page address
2. Uses `gum_memory_patch_code_pages()` to atomically modify code pages:
   - On Apple Silicon: uses `vm_remap()` to create a writable alias of the code page
   - Writes the redirect code (overwriting function prologue)
   - Alias is destroyed, leaving only the RX mapping
3. Processes destroy tasks (cleanup of old hooks) with usage counter checks

#### Phase 3: First Call to Hooked Function

When the hooked function is called, the overwritten prologue redirects to `on_enter_trampoline`. The full flow:

```
Caller calls hooked_function()
  -> Prologue has been replaced with: LDR X16, <on_enter_trampoline>; BR X16
  -> Jumps to on_enter_trampoline (in allocated code slice)
    -> LDR X17, <GumFunctionContext*>   // Load context pointer
    -> LDR X16, <enter_thunk>           // Load thunk address
    -> BR X16                           // Jump to thunk
      -> enter_thunk (assembly glue):
        -> Pushes X16, X17 (already on stack from redirect)
        -> Saves ALL registers to stack (GumCpuContext layout)
        -> Calls _gum_function_context_begin_invocation(ctx, cpu_ctx, &LR, &next_hop)
          -> Gets/creates InterceptorThreadContext from TLS
          -> Pushes GumInvocationStackEntry
          -> Iterates listeners, calls on_enter callbacks
          -> Determines next_hop:
            - If replacement: next_hop = replacement_function
            - Otherwise: next_hop = on_invoke_trampoline (relocated prologue)
          -> If on_leave listeners exist: replaces LR with on_leave_trampoline
        -> Restores ALL registers from stack
        -> Loads next_hop into X16
        -> BR X16 (jumps to original function or replacement)
```

#### Phase 4: Original Function Executes

If no replacement, execution goes to `on_invoke_trampoline`:
- Contains the relocated original prologue instructions (1-4 instructions)
- Followed by a branch back to the original function at the first un-relocated instruction
- This is the "moved prologue" pattern: the stolen instructions run from the trampoline, then resume in-place

#### Phase 5: Return Trapping (Leave)

If there are on_leave listeners, the LR was replaced with `on_leave_trampoline`:

```
Original function returns (RET)
  -> Jumps to on_leave_trampoline (LR was replaced)
    -> LDR X17, <GumFunctionContext*>
    -> LDR X16, <leave_thunk>
    -> BR X16
      -> leave_thunk (assembly glue):
        -> Same register save as enter_thunk
        -> Calls _gum_function_context_end_invocation(ctx, cpu_ctx, &next_hop)
          -> Gets InterceptorThreadContext from TLS
          -> Peeks stack entry, gets real caller_ret_addr
          -> Iterates listeners, calls on_leave callbacks
          -> Sets next_hop = real caller_ret_addr
        -> Restores ALL registers
        -> BR X16 (jumps to real caller)
```

### 1.3 Argument and Return Value Access

Arguments are accessed through `GumCpuContext`:
```c
gpointer gum_cpu_context_get_nth_argument(GumCpuContext *self, guint n) {
  if (n < 8) return self->x[n];           // X0-X7 are ARM64 argument registers
  gpointer *stack = (gpointer*)self->sp;
  return stack[n - 8];                     // Stack arguments for n >= 8
}
```

Return values are accessed via X0:
```c
gpointer gum_cpu_context_get_return_value(GumCpuContext *self) {
  return self->x[0];                       // X0 holds return value
}
```

Both are readable and writable -- the cpu_context is on the stack, and the epilog restores from it. So modifying `x[0]` in the cpu_context before return changes the actual return value.

### 1.4 Reentrancy Protection

Frida uses a TLS guard key (`gum_interceptor_guard_key`) to prevent recursive interception:
```c
if (gum_tls_key_get_value(gum_interceptor_guard_key) == interceptor) {
  *next_hop = function_ctx->on_invoke_trampoline;  // Skip listeners, call original
  goto bypass;
}
gum_tls_key_set_value(gum_interceptor_guard_key, interceptor);
// ... invoke listeners ...
gum_tls_key_set_value(gum_interceptor_guard_key, NULL);
```
This prevents infinite loops when a listener callback itself calls a hooked function.

---

## 2. guminterceptor-priv.h -- Private Structures

**File**: `dev/frida-gum/gum/guminterceptor-priv.h`
**Purpose**: Shared types and function declarations between the core and architecture-specific backends.

### 2.1 The Backend Interface

The core interceptor delegates all architecture-specific work through this interface:
```c
// Creation
GumInterceptorBackend * _gum_interceptor_backend_create(GRecMutex*, GumCodeAllocator*);
void _gum_interceptor_backend_destroy(GumInterceptorBackend*);

// Trampoline lifecycle
gboolean _gum_interceptor_backend_claim_grafted_trampoline(self, ctx);   // Darwin only
gboolean _gum_interceptor_backend_create_trampoline(self, ctx, overwrite);
void _gum_interceptor_backend_destroy_trampoline(self, ctx);
void _gum_interceptor_backend_activate_trampoline(self, ctx, prologue);
void _gum_interceptor_backend_deactivate_trampoline(self, ctx, prologue);

// The critical invocation handlers (called from assembly glue)
gboolean _gum_function_context_begin_invocation(ctx, cpu_context, &caller_ret_addr, &next_hop);
void _gum_function_context_end_invocation(ctx, cpu_context, &next_hop);
```

### 2.2 GumFunctionContextBackendData

```c
union _GumFunctionContextBackendData {
  gchar storage[2 * GLIB_SIZEOF_VOID_P];  // 16 bytes on 64-bit
  gpointer p[2];
};
```
This is embedded in `GumFunctionContext` and used by the ARM64 backend as:
```c
struct _GumArm64FunctionContextData {
  guint redirect_code_size;   // 4, 8, or 16 bytes
  arm64_reg scratch_reg;      // X16 or X17
};
```

### 2.3 GumInterceptorType

```c
enum _GumInterceptorType {
  GUM_INTERCEPTOR_TYPE_DEFAULT = 0,  // Full interception with enter/leave callbacks
  GUM_INTERCEPTOR_TYPE_FAST    = 1   // Direct replacement, no callbacks
};
```
FAST mode skips the thunks entirely -- it just patches the prologue to jump directly to the replacement function. This is used by `gum_interceptor_replace_fast()`.

---

## 3. guminterceptor-arm64.c -- ARM64 Backend

**File**: `dev/frida-gum/gum/backend-arm64/guminterceptor-arm64.c`
**Size**: ~1280 lines
**Purpose**: ARM64-specific trampoline generation, prologue patching, thunk emission. Includes extensive Darwin/Mach-O grafting support.

### 3.1 Key Data Structures

#### GumInterceptorBackend
```c
struct _GumInterceptorBackend {
  GRecMutex * mutex;
  GumCodeAllocator * allocator;
  GumArm64Writer writer;       // Instruction emitter (reusable)
  GumArm64Relocator relocator; // Instruction relocator (reusable)
  gpointer thunks;             // Page containing enter/leave thunks
  gpointer enter_thunk;        // Address of enter thunk code
  gpointer leave_thunk;        // Address of leave thunk code
};
```

#### GumArm64FunctionContextData
```c
struct _GumArm64FunctionContextData {
  guint redirect_code_size;    // How many bytes to overwrite in prologue
  arm64_reg scratch_reg;       // Which register is safe to clobber (X16 or X17)
};
```

### 3.2 Trampoline Creation: _gum_interceptor_backend_create_trampoline

This is the most complex function in the ARM64 backend. It generates three distinct code regions in a single allocated code slice:

**Step 1: Prepare (gum_interceptor_backend_prepare_trampoline)**

Determines redirect strategy based on available space at the function prologue:
- **16 bytes available** (full redirect): `LDR Xscratch, #8; BR Xscratch; .quad target_addr` -- can reach any address
- **8 bytes available**: `ADRP Xscratch, page; BR Xscratch` -- can reach within +/-4GB
- **4 bytes available**: `B offset` -- can reach +/-128MB
- If 8 or 4 bytes available but target is out of range: allocates a "deflector" (trampoline relay) nearby

Scratch register selection: Frida disassembles the prologue instructions and checks if X16/X17 are used. Prefers X16 (intra-procedure-call scratch register per AAPCS64), falls back to X17.

**Step 2: Emit on_enter_trampoline**

For DEFAULT type (not FAST):
```
on_enter_trampoline:
  [if deflector used: POP X0, LR]          // Undo deflector's PUSH
  LDR X17, =GumFunctionContext*            // Load context pointer into X17
  LDR X16, =enter_thunk_addr              // Load thunk address
  BR X16                                   // Jump to enter thunk
```
X17 carries the `GumFunctionContext*` pointer through to the thunk. This is how the enter thunk knows which function was intercepted.

**Step 3: Emit on_leave_trampoline**

Immediately follows the enter trampoline in the same code slice:
```
on_leave_trampoline:
  LDR X17, =GumFunctionContext*            // Same context pointer
  LDR X16, =leave_thunk_addr              // Load leave thunk address
  BR X16                                   // Jump to leave thunk
```

**Step 4: Emit on_invoke_trampoline (relocated prologue)**

This is where the ARM64 relocator does its work:
```
on_invoke_trampoline:
  [relocated instruction 1]               // Original prologue instructions
  [relocated instruction 2]               // rewritten for new PC
  [relocated instruction N]
  LDR Xscratch, =resume_address           // Address past overwritten prologue
  BR Xscratch                             // Resume original function
```

The relocator handles PC-relative instructions that break when moved (ADR, ADRP, LDR literal, B, BL, CBZ, TBZ and their variants).

Special case: LR rewriting detection. If the prologue signature is "mov;b" or starts with "stp;mov;mov;bl", the trampoline replaces `MOV Xn, LR` with the actual caller return address (important for dlopen() on Android).

**Step 5: Save original prologue**

The original bytes are copied to `overwritten_prologue[32]` for later deactivation (unhooking).

### 3.3 Trampoline Activation: _gum_interceptor_backend_activate_trampoline

Called during transaction commit. Writes the redirect code over the function prologue:

```c
switch (data->redirect_code_size) {
  case 4:   // B <on_enter_trampoline>
  case 8:   // ADRP Xscratch, page; BR Xscratch
  case 16:  // LDR Xscratch, =on_enter; BR Xscratch
}
```

If a deflector is used (target too far for direct branch), the prologue becomes:
- 8-byte: `PUSH X0, LR; BL deflector` (deflector is within BL range, jumps to trampoline, pops X0/LR)
- 4-byte: `B deflector` (dedicated deflector, no push needed)

### 3.4 Thunk Generation (Enter and Leave)

Both thunks follow the same pattern:
```
gum_emit_enter_thunk:
  gum_emit_prolog()                        // Save all registers
  ADD X1, SP, #cpu_context_offset          // Pointer to saved GumCpuContext
  ADD X2, SP, #lr_offset                   // Pointer to saved LR (in/out)
  ADD X3, SP, #next_hop_offset             // Pointer to next_hop slot
  CALL _gum_function_context_begin_invocation(X17, X1, X2, X3)
  gum_emit_epilog()                        // Restore all registers, branch to next_hop

gum_emit_leave_thunk:
  gum_emit_prolog()
  ADD X1, SP, #cpu_context_offset
  ADD X2, SP, #next_hop_offset
  CALL _gum_function_context_end_invocation(X17, X1, X2)
  gum_emit_epilog()
```

The thunks exist in two forms in the codebase:
1. **C-generated version** (`gum_emit_prolog`/`gum_emit_epilog` in guminterceptor-arm64.c) -- uses GumArm64Writer to dynamically emit instructions
2. **Hand-written assembly** (`guminterceptor-arm64-glue.S`) -- statically compiled, used as an alternative

Both produce identical behavior. The C version is used when the code signing policy allows JIT; the assembly version is always available as a linked symbol.

### 3.5 Darwin-Specific: Grafted Hooks and Import Targets

On Darwin (macOS/iOS) with mandatory code signing (CODE_SIGNING_REQUIRED), Frida cannot dynamically generate code. Instead, it uses:

**Grafted Hooks**: Pre-embedded trampoline code in `__FRIDA_DATA` segments, inserted at build time by frida's "grafter" tool. The hook points to pre-allocated code slots.

**Import Targets**: For system framework functions (in the dyld shared cache), Frida intercepts at the GOT/la_symbol_ptr level rather than inline -- replacing the pointer in `__la_symbol_ptr` to point at the trampoline instead of the real function.

These are not relevant for our use case (Simulator processes have GUM_CODE_SIGNING_OPTIONAL).

---

## 4. guminterceptor-arm64-glue.S -- ARM64 Assembly Trampoline

**File**: `dev/frida-gum/gum/backend-arm64/guminterceptor-arm64-glue.S`
**Size**: ~142 lines
**Purpose**: The actual machine code that runs on every intercepted function call. This is the performance-critical path.

### 4.1 Stack Frame Layout

```
Constants:
  GUM_CPU_CONTEXT_SIZE = (34 * 8) + (32 * 16) = 272 + 512 = 784 bytes
  GUM_NEXT_HOP_SIZE = 16 bytes
  GUM_FRAME_SIZE = 0 + 784 + 16 = 800 bytes
```

The frame on the stack (from high to low addresses):

```
[SP + GUM_FRAME_SIZE]:        -- original SP (before everything)
[SP + GUM_FRAME_SIZE - 16]:   X16 (pushed by caller, contains next_hop on exit)
                              X17 (pushed by caller, contains GumFunctionContext*)
[SP + 784]:                   next_hop slot (16 bytes)
[SP + 0..783]:                GumCpuContext (784 bytes)
```

### 4.2 GumCpuContext Memory Layout

The assembly constructs this layout on the stack:
```
Offset  Field
------  -----
0x000   pc (placeholder, filled later)
0x008   sp (computed: SP + GUM_FRAME_SIZE)
0x010   nzcv (flags)
0x018   x[0] (also used as flags temp during save)
0x020   x[1]
0x028   x[2]
...     x[3] through x[14]
0x090   x[15]
0x098   x[16]      (loaded from the pushed values above the frame)
0x0A0   x[17]
0x0A8   x[18]
...     x[19] through x[28]
0x100   fp (x29)
0x108   lr (x30)   (offset 33*8 = 264 = 0x108)
0x110   v[0] (q0, 16 bytes)
0x120   v[1] (q1, 16 bytes)
...
0x300   v[30] (q30, 16 bytes)
0x310   v[31] (q31, 16 bytes)
```

### 4.3 Prolog (gum_emit_prolog macro)

The prolog is called at the start of both `_gum_interceptor_begin_invocation` and `_gum_interceptor_end_invocation`. The caller has already pushed X16 and X17 onto the stack. The prolog:

```asm
  # Step 1: Allocate frame space (minus the 16 bytes already pushed)
  sub sp, sp, GUM_FRAME_SIZE - 16

  # Step 2: Save X1, X2 early (we need X1 as temp)
  stp x1, x2, [sp, 4*8]

  # Step 3: Save NZCV condition flags into X1
  mrs x1, nzcv
  stp x1, x0, [sp, 2*8]          # nzcv and x0

  # Step 4: Compute original SP and save with pc placeholder
  add x1, sp, GUM_FRAME_SIZE
  stp x0, x1, [sp, 0*8]          # pc=placeholder, sp=computed

  # Step 5: Move GumFunctionContext* from X17 to X0 (first arg for C call)
  mov x0, x17

  # Step 6: Load REAL X16 and X17 from where caller pushed them
  ldp x16, x17, [x1, -16]

  # Step 7: Save all remaining registers
  stp x3, x4, [sp, 6*8]
  stp x5, x6, [sp, 8*8]
  stp x7, x8, [sp, 10*8]
  stp x9, x10, [sp, 12*8]
  stp x11, x12, [sp, 14*8]
  stp x13, x14, [sp, 16*8]
  stp x15, x16, [sp, 18*8]       # Real X16 (loaded in step 6)
  stp x17, x18, [sp, 20*8]       # Real X17 (loaded in step 6)
  stp x19, x20, [sp, 22*8]
  stp x21, x22, [sp, 24*8]
  stp x23, x24, [sp, 26*8]
  stp x25, x26, [sp, 28*8]
  stp x27, x28, [sp, 30*8]
  stp fp, lr, [sp, 32*8]

  # Step 8: Save all 32 SIMD/vector registers (Q0-Q31)
  stp q0, q1, [sp, 34*8 + 0*16]
  stp q2, q3, [sp, 34*8 + 2*16]
  ... (16 pairs total)
  stp q30, q31, [sp, 34*8 + 30*16]
```

**Register save count**: 34 general-purpose values (pc, sp, nzcv, x0-x28, fp, lr) + 32 Q registers = 66 register values = 784 bytes.

### 4.4 The C Bridge Call

After the prolog, the thunk sets up arguments and calls into C:

**Enter thunk**:
```asm
  add x1, sp, GUM_FRAME_OFFSET_CPU_CONTEXT     # &cpu_context on stack
  add x2, sp, GUM_FRAME_OFFSET_CPU_CONTEXT + GUM_CPU_CONTEXT_OFFSET_LR  # &saved LR
  add x3, sp, GUM_FRAME_OFFSET_NEXT_HOP        # &next_hop slot
  bl _gum_function_context_begin_invocation     # (X0=ctx, X1=cpu_ctx, X2=&lr, X3=&next_hop)
```

**Leave thunk**:
```asm
  add x1, sp, GUM_FRAME_OFFSET_CPU_CONTEXT     # &cpu_context on stack
  add x2, sp, GUM_FRAME_OFFSET_NEXT_HOP        # &next_hop slot
  bl _gum_function_context_end_invocation       # (X0=ctx, X1=cpu_ctx, X2=&next_hop)
```

The C functions write to the `next_hop` slot to control where execution goes after the epilog.

### 4.5 Epilog (gum_emit_epilog macro)

Reverses the prolog:

```asm
  # Restore X0-X28, FP, LR (all general purpose)
  ldr x0, [sp, 3*8]              # x0 (skip pc, sp, nzcv slots)
  ldp x1, x2, [sp, 4*8]
  ldp x3, x4, [sp, 6*8]
  ... all pairs ...
  ldp fp, lr, [sp, 32*8]

  # Restore all vector registers
  ldp q0, q1, [sp, 34*8 + 0*16]
  ... all 16 pairs ...
  ldp q30, q31, [sp, 34*8 + 30*16]

  # Load next_hop into X16, deallocate frame, branch
  ldr x16, [sp, GUM_FRAME_SIZE - 16]    # next_hop was written by C code
  add sp, sp, GUM_FRAME_SIZE
  br x16
```

**Critical detail**: NZCV (condition flags) are NOT restored in the assembly glue version. The C-generated version (`gum_emit_epilog` in the .c file) does restore NZCV via `MSR NZCV, X1`. The assembly version is simpler but technically less correct for edge cases where condition flags matter across the hook.

### 4.6 Total Overhead per Interception

Every intercepted call incurs:
- **Register save**: 34 GP registers + 32 SIMD registers = ~800 bytes pushed to stack
- **C function call**: TLS lookup, stack operations, listener iteration
- **Register restore**: Same 800 bytes popped
- **Two indirect branches**: Enter and leave trampolines

This is ~50-100 nanoseconds per interception on modern Apple Silicon, dominated by the cache effects of the large stack frame.

---

## 5. gumarm64writer.c -- Dynamic ARM64 Instruction Emitter

**File**: `dev/frida-gum/gum/arch-arm64/gumarm64writer.c`
**Purpose**: A mini-assembler that generates ARM64 machine code at runtime.

### 5.1 Architecture

The writer maintains:
- `base`: Start of the output buffer
- `code`: Current write position (pointer to guint32)
- `pc`: Current program counter (the address the code will run at -- may differ from buffer address during remapping)
- Label definitions and references (resolved at flush time)
- Literal references (64-bit constants emitted as data after code, loaded via PC-relative LDR)

### 5.2 Key Instruction Emitters

**Branch instructions**:
```c
// B <imm26> -- unconditional branch, +/-128MB range
gum_arm64_writer_put_b_imm(self, address)  -> 0x14000000 | (offset/4 & 0x3FFFFFF)

// BL <imm26> -- branch with link, +/-128MB range
gum_arm64_writer_put_bl_imm(self, address) -> 0x94000000 | (offset/4 & 0x3FFFFFF)

// BR Xn -- branch to register
gum_arm64_writer_put_br_reg(self, reg)     -> 0xD61F0000 | (index << 5)
// With PAC: adds BRAAZ encoding (0x81F extra bits)

// BLR Xn -- branch with link to register
gum_arm64_writer_put_blr_reg(self, reg)    -> 0xD63F0000 | (index << 5)
```

**Load address (64-bit immediate)**:
```c
gum_arm64_writer_put_ldr_reg_address(self, reg, address)
// Emits: LDR Xreg, [PC, #offset_to_literal_pool]
// The actual 64-bit value is placed in a literal pool after the code
// Resolved during gum_arm64_writer_flush()
```
This is a PC-relative literal load. The writer maintains a list of pending literal references and emits them as data words after all instructions. This allows loading arbitrary 64-bit addresses with a single instruction.

**High-level call helper**:
```c
gum_arm64_writer_put_call_address_with_arguments(self, func, n_args, ...):
// 1. Moves arguments to X0-X7 (from registers or immediate addresses)
// 2. If func is within BL range: BL func
//    Otherwise: LDR Xn, =func; BLR Xn (where n = n_args to avoid clobbering args)
// 3. No teardown needed (ARM64 calling convention has no caller-cleanup)
```

### 5.3 Pointer Authentication Support

When `ptrauth_support == GUM_PTRAUTH_SUPPORTED` (arm64e):
- `BR` becomes `BRAAZ` (authenticate and branch)
- `BLR` becomes `BLRAAZ`
- Code addresses are signed with `gum_sign_code_address()` before being emitted as literals

For our Simulator use case: PAC is not enforced, so we can ignore this entirely.

---

## 6. gumarm64relocator.c -- ARM64 Instruction Relocator

**File**: `dev/frida-gum/gum/arch-arm64/gumarm64relocator.c`
**Purpose**: Copies instructions from one address to another, rewriting PC-relative references.

### 6.1 Why Relocation is Needed (for inline hooks)

When Frida overwrites a function's prologue with a redirect (4-16 bytes), those original instructions must be preserved and executed from the trampoline. But if those instructions use PC-relative addressing (very common on ARM64), they will compute wrong addresses at their new location. The relocator fixes this.

### 6.2 Instruction Classes Requiring Relocation

| Instruction | Original Encoding | Relocated Form |
|------------|-------------------|----------------|
| `LDR Xd, [PC, #imm]` | PC-relative literal load | `LDR Xd, =original_address; LDR Xd, [Xd]` |
| `ADR Xd, #imm` / `ADRP` | PC-relative address | `LDR Xd, =computed_address` |
| `B #imm` | PC-relative branch | `LDR X16, =target; BR X16` |
| `B.cond #imm` | Conditional branch | `B.cond take; B skip; take: LDR X16, =target; BR X16; skip:` |
| `BL #imm` | PC-relative call | `LDR LR, =target; BLR LR` |
| `CBZ/CBNZ Xn, #imm` | Compare and branch | Same pattern as B.cond |
| `TBZ/TBNZ Xn, #bit, #imm` | Test bit and branch | Same pattern as B.cond |

Each relocated instruction expands from 4 bytes to potentially 12-20 bytes. This is why the trampoline slice must be larger than the stolen bytes.

### 6.3 Relocatability Analysis

`gum_arm64_relocator_can_relocate(address, min_bytes, scenario, &max, &scratch_reg)`:

1. Disassembles instructions at the target address
2. Counts how many bytes can be safely relocated
3. In ONLINE scenario (function may be called during relocation), refuses to relocate past BLR/SVC instructions
4. Performs control flow analysis to ensure no branch targets land in the middle of the stolen region
5. Determines which scratch register (X16/X17) is unused in the prologue

### 6.4 Capstone Dependency

The relocator uses Capstone for disassembly (`cs_disasm_iter`). This is a heavy dependency -- the full Capstone ARM64 module is linked into frida-gum. We do not need this.

---

## 7. Analysis: What We Need vs. What We Can Skip

### 7.1 Our Use Case Constraints

| Constraint | Implication |
|-----------|-------------|
| ObjC method hooks only | We use `method_setImplementation()` / `method_exchangeImplementations()`, not inline patching |
| Simulator processes only | No code signing enforcement, full W^X flexibility via `pthread_jit_write_protect_np()` |
| DYLD_INSERT_LIBRARIES | We run as a constructor in the target process, full address space access |
| ARM64 only | No multi-arch concerns |
| No PAC enforcement | Simulator does not enforce pointer authentication |
| Pure C, no dependencies | No GLib, no Capstone, no GObject |

### 7.2 Why Method Swizzling Eliminates Most of Frida's Complexity

Frida hooks arbitrary native functions by overwriting their prologue. This requires:
1. Determining how many bytes can be overwritten (relocator analysis)
2. Relocating those bytes to a trampoline (instruction rewriting)
3. Patching code pages (vm_remap tricks)
4. Handling edge cases (short prologues, PC-relative instructions, branch targets)

**Method swizzling sidesteps all of this.** When we call `method_setImplementation(method, our_imp)`, the ObjC runtime atomically replaces the method's IMP pointer. The original function is untouched -- we get back the original IMP as a return value. No inline patching, no relocation, no code page modification.

What we still need is a trampoline that:
1. Saves all argument-carrying registers (so our logging code can inspect them)
2. Calls our C logging function
3. Restores all registers perfectly
4. Calls the original IMP

### 7.3 Component-by-Component Analysis

#### MUST Implement

**Register save/restore trampoline** (inspired by guminterceptor-arm64-glue.S):
- Save X0-X7 (arguments), X8 (indirect result), FP, LR
- Optionally save Q0-Q7 (floating-point/SIMD arguments)
- Call our C handler with a pointer to the saved context
- Restore everything perfectly
- Branch to original IMP

**Thread-local reentrancy guard**:
- Equivalent to Frida's `gum_interceptor_guard_key`
- Use `pthread_key_t` (or `_Thread_local`) to prevent recursive hooking
- Without this, logging `objc_msgSend` from within our logger causes infinite recursion

**Invocation context structure** (simplified GumCpuContext):
- We only need X0-X7 (arguments), X8 (indirect result), LR (return address)
- For ObjC: X0 = self, X1 = _cmd, X2-X7 = user arguments
- We do NOT need PC, SP, NZCV, X9-X28, or vector registers for argument inspection

**Return value capture** (if we want on_leave callbacks):
- Requires the LR replacement trick from Frida
- Save original LR, replace with our leave trampoline address
- On return: capture X0 (return value), restore original LR, return to real caller

#### CAN Simplify Dramatically

**The trampoline itself**:
- Frida saves 784 bytes of register state (ALL 34 GP + 32 SIMD registers)
- We need at most ~128 bytes (X0-X8, FP, LR, plus Q0-Q7 if we want float args)
- For ObjC methods, arguments beyond X7 are rare (they go on the stack)
- We can skip NZCV entirely -- the C calling convention does not preserve flags

**Code allocation**:
- Frida uses `GumCodeAllocator` with complex near-allocation logic
- We can use a simple `mmap(MAP_JIT)` page and emit our trampolines there
- Or even simpler: compile our trampoline as a static function with inline assembly

**Thread-local storage**:
- Frida uses GLib's GPrivate and custom spinlock-protected hash tables
- We can use `pthread_getspecific` / `pthread_setspecific` directly

#### CAN Skip Entirely

| Frida Component | Why We Skip It |
|-----------------|---------------|
| **GumArm64Relocator** | No inline patching -- method swizzling replaces the IMP pointer, not code bytes |
| **GumArm64Writer** (dynamic) | Our trampoline is fixed code, not dynamically generated per-hook |
| **Capstone disassembler** | No need to analyze target function prologues |
| **GumCodeAllocator** | Single mmap page or static assembly is sufficient |
| **GumCodeDeflector** | No short-range branch distance concerns |
| **Grafted hooks / import targets** | Darwin code-signing workarounds, not needed in Simulator |
| **Transaction system** | No batched code page patching needed |
| **GObject infrastructure** | We are pure C with no object system |
| **Listener array management** | We have one handler per hook, not N listeners |
| **Prologue backup/restore** | method_setImplementation returns original IMP, nothing to restore |

### 7.4 Architecture of Our Simplified Interceptor

```
Method Hook Installation:
  1. original_imp = method_setImplementation(method, trampoline_imp)
  2. Store {selector, original_imp, class_name} in hook table

Per-Call Flow:
  Caller -> objc_msgSend -> [trampoline IMP]
    trampoline:
      STP X0, X1, [SP, #-128]!    // Save argument registers
      STP X2, X3, [SP, #16]
      STP X4, X5, [SP, #32]
      STP X6, X7, [SP, #48]
      STP X8, LR, [SP, #64]       // X8 = indirect result location
      [optionally save Q0-Q7]

      MOV X0, SP                   // Pointer to saved context
      BL _darkmach_on_enter          // Our C logging function

      LDP X0, X1, [SP]            // Restore all argument registers
      LDP X2, X3, [SP, #16]
      LDP X4, X5, [SP, #32]
      LDP X6, X7, [SP, #48]
      LDP X8, LR, [SP, #64]
      ADD SP, SP, #128

      LDR X16, =original_imp       // Load saved original IMP
      BR X16                       // Tail-call to original
```

Total overhead: ~10 instructions for save, 1 BL for logging, ~10 for restore = ~21 instructions vs. Frida's ~100+ (including all vector register saves).

### 7.5 Return Value Capture (Optional, More Complex)

If we need on_leave callbacks:

```
  trampoline:
    [save registers as above]
    BL _darkmach_on_enter
    [restore registers]

    // Save real LR, replace with leave trampoline
    LDR X16, =leave_trampoline
    MOV X9, LR                    // Save real return address
    MOV LR, X16                   // Hijack return

    LDR X16, =original_imp
    BR X16                        // Call original (will RET to leave_trampoline)

  leave_trampoline:
    STP X0, X1, [SP, #-32]!      // Save return value (X0, maybe X1)
    MOV X2, X9                    // Pass real return address
    BL _darkmach_on_leave
    LDP X0, X1, [SP], #32        // Restore return value
    BR X9                         // Return to real caller
```

The complication: X9 must survive across the original function call. Either:
- Use a callee-saved register (X19-X28) and save/restore it
- Store it in TLS (thread-local storage)
- Use the stack entry approach like Frida (TLS invocation stack)

For simplicity, the TLS approach is best:
```c
static _Thread_local struct { void *real_lr; void *hook_info; } tls_leave_ctx;
```

---

## 8. Key Architectural Insights

### 8.1 The X17 Convention

Frida uses X17 to carry the `GumFunctionContext*` from the per-function trampoline into the shared thunk. This is clever -- X17 is an intra-procedure-call register (AAPCS64 says it may be clobbered by veneers/thunks), so no callee-saved concern.

For our design: we can use a similar pattern. Each per-method trampoline loads the hook descriptor address into X17, then branches to a shared handler. This avoids generating unique code per hook.

### 8.2 The Literal Pool Pattern

Frida's `gum_arm64_writer_put_ldr_reg_address` emits a PC-relative load instruction that references a 64-bit constant placed after the code. This is the standard ARM64 pattern for loading full 64-bit addresses in position-independent code. The alternative (MOVZ/MOVK sequence) takes 4 instructions (16 bytes) vs. 1 instruction + 8 bytes of data = 12 bytes.

### 8.3 Stack Alignment

ARM64 requires 16-byte stack alignment. All of Frida's STP/LDP pairs maintain this. Our simplified trampoline must also maintain alignment -- hence the 128-byte frame (16-byte aligned) rather than the exact number of bytes needed.

### 8.4 Why Frida Saves ALL Registers

Frida saves all 66 register values because:
1. Listeners can read AND WRITE any register (argument replacement, return value modification)
2. The interceptor must handle both enter and leave in the same frame
3. It cannot predict which registers a listener callback might inspect

For our case, if we only LOG arguments (read-only), we only need to save registers that our logging function might clobber. But since we call into C (which may clobber X0-X18, Q0-Q7, Q16-Q31), we must save at least the argument registers before the call and restore them after.

### 8.5 Vector Register Savings

Frida saves all 32 Q registers (512 bytes). This is because:
- Q0-Q7 carry floating-point arguments (AAPCS64)
- Q0-Q7, Q16-Q31 are caller-saved
- Q8-Q15 are callee-saved (lower 64 bits only)

For ObjC methods: float/double arguments are passed in Q0-Q7. If a method takes `(double, float)` the values are in D0 and S1. Our C logging function will clobber Q0-Q7, so we must save them if we want to pass float arguments through correctly.

Minimum for correctness: save Q0-Q7 (128 bytes). Skip Q8-Q31 (our C handler preserves Q8-Q15 per ABI, and Q16-Q31 are caller-saved but we are transparent to the real caller).

---

## 9. Implementation Recommendations for darkmach-bridge.dylib

### 9.1 Trampoline Strategy

**Option A: Static Assembly Trampoline (Recommended)**

Write the trampoline in a `.S` file, compiled alongside darkmach-bridge.c:
- Fixed save/restore sequence for X0-X8, LR, Q0-Q7
- Single shared handler with X17 carrying hook metadata
- Per-hook stubs are small: `LDR X17, =hook_desc; B shared_handler`

Advantages: No JIT, no MAP_JIT, no `pthread_jit_write_protect_np`. Works on any Simulator process. Easy to audit.

**Option B: mmap(MAP_JIT) Dynamic Trampolines**

Allocate a page with MAP_JIT, generate per-hook trampolines at runtime. Use `pthread_jit_write_protect_np(false)` to write, then `true` to execute.

Advantages: Per-hook data is embedded directly (no indirection through hook table). More flexible.

Disadvantage: More complex, JIT page management.

**Recommendation**: Start with Option A. A single static trampoline shared by all hooks, with per-hook metadata loaded via X17. If performance or flexibility demands it, evolve to Option B.

### 9.2 Hook Table Design

```c
typedef struct {
    Class cls;
    SEL selector;
    IMP original_imp;
    const char *class_name;
    const char *sel_name;
    uint32_t flags;          // bit 0: log_args, bit 1: log_retval, bit 2: active
} darkmach_hook_t;

#define MAX_HOOKS 1024
static darkmach_hook_t hook_table[MAX_HOOKS];
static uint32_t hook_count = 0;
```

### 9.3 Reentrancy Guard

```c
static pthread_key_t guard_key;
__attribute__((constructor)) static void init_guard(void) {
    pthread_key_create(&guard_key, NULL);
}

static inline bool darkmach_guard_enter(void) {
    if (pthread_getspecific(guard_key)) return false;  // Already inside hook
    pthread_setspecific(guard_key, (void*)1);
    return true;
}

static inline void darkmach_guard_leave(void) {
    pthread_setspecific(guard_key, NULL);
}
```

### 9.4 Minimal Register Save (Enter-Only, No Return Capture)

For the common case of "log method calls with arguments":

```asm
// Shared trampoline. X17 = pointer to darkmach_hook_t
_darkmach_method_trampoline:
    // Save frame
    stp   fp, lr, [sp, #-16]!
    mov   fp, sp

    // Save argument registers (X0-X8) + alignment
    sub   sp, sp, #(10 * 8 + 8 * 16)    // 80 + 128 = 208, round to 208 (16-aligned: 208)
    stp   x0, x1, [sp, #0]
    stp   x2, x3, [sp, #16]
    stp   x4, x5, [sp, #32]
    stp   x6, x7, [sp, #48]
    stp   x8, x17, [sp, #64]             // x8 = indirect result, x17 = hook ptr
    stp   q0, q1, [sp, #80]
    stp   q2, q3, [sp, #112]
    stp   q4, q5, [sp, #144]
    stp   q6, q7, [sp, #176]

    // Call C handler: darkmach_on_method_enter(hook, x0_self, x1_cmd, sp_args)
    mov   x0, x17                         // hook descriptor
    mov   x1, sp                          // pointer to saved registers
    bl    _darkmach_on_method_enter

    // Restore everything
    ldp   x0, x1, [sp, #0]
    ldp   x2, x3, [sp, #16]
    ldp   x4, x5, [sp, #32]
    ldp   x6, x7, [sp, #48]
    ldp   x8, x17, [sp, #64]
    ldp   q0, q1, [sp, #80]
    ldp   q2, q3, [sp, #112]
    ldp   q4, q5, [sp, #144]
    ldp   q6, q7, [sp, #176]
    add   sp, sp, #208

    // Restore frame
    ldp   fp, lr, [sp], #16

    // Tail-call to original IMP (loaded from hook descriptor)
    ldr   x16, [x17, #16]                // hook->original_imp at offset 16
    br    x16
```

Total overhead: 26 instructions. ~20 nanoseconds on M1. Compare to Frida's ~100+ instructions and ~60+ nanoseconds.

### 9.5 Per-Hook Stub Generation

Each hooked method needs a small stub that loads the hook descriptor and jumps to the shared trampoline:

**Static approach** (compile-time, fixed number of stubs):
```c
// Generate N stub slots in a .S file
// _darkmach_stub_0: adrp x17, hook_table@PAGE; add x17, x17, hook_table@PAGEOFF; b _darkmach_method_trampoline
// _darkmach_stub_1: adrp x17, hook_table@PAGE; add x17, x17, (hook_table+sizeof(darkmach_hook_t))@PAGEOFF; ...
```

**Dynamic approach** (runtime, needs JIT page):
```c
void* darkmach_create_stub(darkmach_hook_t *hook) {
    // In JIT page, emit:
    //   LDR X17, =hook
    //   B _darkmach_method_trampoline
    // Return address of the stub
}
```

The dynamic approach is more flexible. With 1024 hooks at 16 bytes per stub (LDR literal + B + 8-byte literal), we need 16KB = 1 JIT page.

---

## 10. Summary Comparison

| Aspect | Frida-Gum | Darkmach Interceptor |
|--------|----------|-------------------|
| Hook mechanism | Inline patching (overwrite prologue) | ObjC method swizzling (IMP replacement) |
| Relocator needed | Yes (critical) | No |
| Disassembler needed | Yes (Capstone) | No |
| Registers saved | 34 GP + 32 SIMD = 784 bytes | 9 GP + 8 SIMD = 200 bytes |
| Code generation | Full ARM64 writer (runtime) | Static assembly or minimal JIT |
| Dependencies | GLib, Capstone, custom allocators | pthread, objc/runtime.h |
| Lines of code | ~4000+ across 6 files | Estimated ~500 total |
| Per-call overhead | ~60-100ns | ~15-25ns |
| Flexibility | Any native function | ObjC methods only |
| Return capture | Built-in (LR replacement) | Optional (TLS-based LR save) |
| Thread safety | GRecMutex + atomic + TLS | pthread_key_t + _Thread_local |
| PAC support | Full arm64e | Not needed (Simulator) |
| Code signing | Grafted hooks fallback | Not applicable |

---

## 11. Open Questions for Implementation Phase

1. **Stub generation strategy**: Static (pre-compile N stubs) vs. dynamic (JIT page)? Dynamic is more flexible but introduces MAP_JIT complexity. For a first version, 256 static stubs compiled in assembly may be sufficient.

2. **Return value capture**: Do we need on_leave hooks for the initial version? Enter-only (argument logging) is dramatically simpler. Leave hooks require the LR hijack and TLS return address storage.

3. **Floating-point arguments**: How common are ObjC methods with float/double parameters in practice? If rare, we could skip Q0-Q7 save/restore for a smaller trampoline and add it as an option per-hook.

4. **Selective hooking**: The bridge already accepts "hook" commands over UDS. We need to integrate this with the trampoline system -- install hooks on demand, not all at constructor time.

5. **Thread safety of hook table**: Hooks are installed from the bridge socket thread but fire on the app's main/UI thread. The hook table must be safe for concurrent read (trampoline) + write (install/remove). A simple approach: never remove hooks, only deactivate them (set a flag that the C handler checks).

---

*This document is research analysis only. No code has been written. Implementation will be tracked in `.project/build-plan.md` when assigned.*
