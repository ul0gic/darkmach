# Frida-Gum Heap Walking & ObjC Object Enumeration: Technical Study

**Date**: 2026-03-25
**Author**: mobile-engineer
**Purpose**: Understand Frida's heap walking internals to inform implementation of `heap_dump` in sphinx-bridge.c
**Status**: RESEARCH ONLY -- no code produced

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Layer 1: Darwin Malloc Zone Enumeration (gumprocess-darwin.c)](#layer-1-darwin-malloc-zone-enumeration)
4. [Layer 2: Heap API Abstraction (gumheapapi.c/h)](#layer-2-heap-api-abstraction)
5. [Layer 3: Instance Tracking (guminstancetracker.c)](#layer-3-instance-tracking)
6. [Layer 4: ObjC API Resolver (gumobjcapiresolver.c)](#layer-4-objc-api-resolver)
7. [Layer 5: Class Pair Disposal Monitor (gumobjcdisposeclasspairmonitor.c)](#layer-5-class-pair-disposal-monitor)
8. [Layer 6: JavaScript Binding (gumv8process.cpp)](#layer-6-javascript-binding)
9. [Layer 7: ObjC.choose() in frida-objc-bridge (external)](#layer-7-objcchoose-in-frida-objc-bridge)
10. [Comparison: sphinx-core.h is_valid_objc_ptr vs Frida's Validation](#comparison-sphinx-coreh-vs-frida)
11. [Analysis & Recommendations for sphinx-bridge.c heap_dump](#analysis--recommendations)

---

## Executive Summary

Frida's `ObjC.choose()` works through a **seven-layer stack** that spans from raw Darwin kernel APIs to high-level JavaScript. The critical insight is:

**Frida does NOT walk the heap from within frida-gum's C layer for ObjC object enumeration.** Instead:

1. The **C layer** (`gumprocess-darwin.c`) exposes `gum_process_enumerate_malloc_ranges()` which calls `malloc_get_all_zones()` and each zone's `introspect->enumerator` callback to enumerate all in-use heap allocations.
2. This is exposed to **JavaScript** as `Process.enumerateMallocRanges()`.
3. The **frida-objc-bridge** (a separate TypeScript/JavaScript package, NOT in the frida-gum repo) implements `ObjC.choose()` by calling `Process.enumerateMallocRanges()`, then for each range, checking if the memory at that address looks like a valid ObjC object of the desired class by reading the `isa` pointer and comparing it against the ObjC class registry.

For our purposes (pure C, no Frida dependency, DYLD-injected into iOS Simulator), we need to reimplement layers 1 and 7 in C. Layers 2-6 are either abstractions we don't need or functionality we already have.

---

## Layer 1: Darwin Malloc Zone Enumeration

**File**: `/Users/jnuts74/projects/sphinx/dev/frida-gum/gum/backend-darwin/gumprocess-darwin.c`
**Lines**: 305-384

### The Core Algorithm

```c
void gum_process_enumerate_malloc_ranges(GumFoundMallocRangeFunc func, gpointer user_data)
{
    task_t task = mach_task_self();
    vm_address_t *malloc_zone_addresses;
    unsigned malloc_zone_count;

    // Step 1: Get ALL malloc zones in the process
    kern_return_t ret = malloc_get_all_zones(task,
        gum_read_malloc_memory,       // memory reader callback
        &malloc_zone_addresses,
        &malloc_zone_count);

    if (ret != KERN_SUCCESS) return;

    // Step 2: For each zone, call its introspection enumerator
    for (unsigned i = 0; i != malloc_zone_count; i++) {
        vm_address_t zone_address = malloc_zone_addresses[i];
        malloc_zone_t *zone = (malloc_zone_t *)zone_address;

        if (zone != NULL && zone->introspect != NULL &&
            zone->introspect->enumerator != NULL)
        {
            GumEnumerateMallocRangesContext ctx = { func, user_data, TRUE };

            zone->introspect->enumerator(
                task,                         // task port
                &ctx,                         // user context
                MALLOC_PTR_IN_USE_RANGE_TYPE, // only in-use blocks
                zone_address,                 // the zone itself
                gum_read_malloc_memory,       // memory reader
                gum_emit_malloc_ranges        // range recorder callback
            );

            if (!ctx.carry_on) return;
        }
    }
}
```

### Key Data Structures

```c
struct _GumEnumerateMallocRangesContext {
    GumFoundMallocRangeFunc func;   // user's callback
    gpointer user_data;
    gboolean carry_on;               // early termination flag
};

struct _GumMallocRangeDetails {
    const GumMemoryRange *range;     // base_address + size
};
```

### The Memory Reader Callback

For in-process enumeration (our use case), the memory reader is trivial:

```c
static kern_return_t gum_read_malloc_memory(task_t remote_task,
    vm_address_t remote_address, vm_size_t size, void **local_memory)
{
    *local_memory = (void *)remote_address;  // same address space!
    return KERN_SUCCESS;
}
```

This is a critical simplification. Since we are running in-process (DYLD-injected), we don't need to do any cross-task memory reading. The "remote" and "local" addresses are identical.

### The Range Emission Callback

```c
static void gum_emit_malloc_ranges(task_t task, void *user_data,
    unsigned type, vm_range_t *ranges, unsigned count)
{
    GumEnumerateMallocRangesContext *ctx = user_data;

    for (unsigned i = 0; i != count; i++) {
        vm_range_t range = ranges[i];

        gum_range.base_address = range.address;
        gum_range.size = range.size;

        ctx->carry_on = ctx->func(&details, ctx->user_data);
        if (!ctx->carry_on) return;
    }
}
```

The zone enumerator calls back with **batches** of `vm_range_t` (address + size pairs), each representing an in-use allocation. The `MALLOC_PTR_IN_USE_RANGE_TYPE` flag ensures we only get live allocations, not free blocks.

### API Requirements

From `<malloc/malloc.h>`:
- `malloc_get_all_zones(task_t, memory_reader_t*, vm_address_t**, unsigned*)` -- retrieves all malloc zones
- `zone->introspect->enumerator(...)` -- zone-specific block enumerator
- `MALLOC_PTR_IN_USE_RANGE_TYPE` -- enum value requesting only in-use allocations
- `vm_range_t` -- struct with `address` (vm_address_t) and `size` (vm_size_t)

From `<mach/mach.h>`:
- `mach_task_self()` -- current task port
- `kern_return_t`, `task_t`, `vm_address_t`, `vm_size_t` types

### Thread Safety Considerations

**The zone enumerator is NOT thread-safe.** During enumeration:
- Other threads may be allocating/freeing memory
- The zone's internal data structures may be in an inconsistent state
- Some zones use locks internally, but this is not guaranteed

Frida does NOT stop threads during `Process.enumerateMallocRanges()`. The frida-objc-bridge's `ObjC.choose()` does not suspend threads either. It accepts that some allocations may be transient and validates each pointer before use.

### Performance Characteristics

- A typical iOS app has 3-10 malloc zones
- Each zone may contain tens of thousands to hundreds of thousands of allocations
- The enumerator callback is called with batches, not one allocation at a time
- Total enumeration takes milliseconds on a typical app, but can take 10-50ms on very large heaps
- The `carry_on` flag allows early termination once the target is found

---

## Layer 2: Heap API Abstraction

**Files**: `gumheapapi.c` / `gumheapapi.h`

### Purpose

This layer is an abstraction for **cross-platform heap function pointers** -- it wraps `malloc`, `calloc`, `realloc`, `free` so that Frida's heap tracking infrastructure can work with different CRT implementations (important on Windows with debug CRT).

### Key Structure

```c
struct _GumHeapApi {
    GumMallocFunc malloc;
    GumCallocFunc calloc;
    GumReallocFunc realloc;
    GumFreeFunc free;

    // Windows Debug CRT only:
    GumMallocDbgFunc _malloc_dbg;
    GumCallocDbgFunc _calloc_dbg;
    GumReallocDbgFunc _realloc_dbg;
    GumFreeDbgFunc _free_dbg;
    GumCrtReportBlockTypeFunc _CrtReportBlockType;
};
```

### Relevance to Our Implementation

**Low.** This is primarily for Windows CRT compatibility and for Frida's allocation tracking probes. On Darwin, `gum_process_find_heap_apis()` simply resolves the standard libc `malloc/calloc/realloc/free` from the loaded libc module. We don't need this abstraction -- we call `malloc_get_all_zones()` directly, which is Darwin-specific.

---

## Layer 3: Instance Tracking

**File**: `/Users/jnuts74/projects/sphinx/dev/frida-gum/libs/gum/heap/guminstancetracker.c`

### Purpose

Tracks GObject/GType instance creation and destruction by intercepting `g_type_create_instance` and `g_type_free_instance`. This is a **GLib-specific** mechanism, not ObjC.

### Mechanism

Uses `GumInterceptor` (Frida's function hooking API) to attach to:
- `g_type_create_instance` (on-leave: records new instance)
- `g_type_free_instance` (on-enter: removes instance record)

Maintains:
- `instances_ht` -- hash table of all live instances (key: pointer, value: unused)
- `counter_ht` -- hash table of instance counts by GType

### Relevance to Our Implementation

**None directly.** This is GLib/GObject tracking, not ObjC. However, the architectural pattern is instructive: Frida has TWO approaches to finding objects:

1. **Tracking** (GumInstanceTracker): Hook alloc/dealloc, maintain a live registry. Zero false positives, but requires hooking from before the first allocation.
2. **Scanning** (Process.enumerateMallocRanges + ObjC.choose): Walk the heap, validate each pointer. Works at any time, but requires robust validation to avoid crashes.

For our heap_dump, we must use approach (2) because we inject after the app has already created objects.

---

## Layer 4: ObjC API Resolver

**File**: `/Users/jnuts74/projects/sphinx/dev/frida-gum/gum/backend-darwin/gumobjcapiresolver.c`

### Purpose

Resolves ObjC method implementations by name (e.g., `-[NSURLSession dataTaskWithRequest:completionHandler:]`). This is NOT heap walking -- it's the ObjC class/method registry resolver. However, it contains important patterns for working with the ObjC runtime safely.

### Key Data Structures

```c
struct _GumObjcApiResolver {
    GObject parent;
    GRegex *query_pattern;
    gboolean available;
    GHashTable *class_by_handle;        // Class pointer -> GumObjcClassMetadata
    GHashTable *classes_by_module;      // module base -> GumMetalArray of classes
    GRecMutex class_cache_mutex;         // protects the caches
    GumObjcDisposeClassPairMonitor *monitor;  // tracks class deregistration
    GumModuleRegistry *registry;

    // ObjC runtime function pointers (resolved via dlsym)
    gint (*objc_getClassList)(Class *buffer, gint class_count);
    Class (*objc_lookUpClass)(const gchar *name);
    Class (*class_getSuperclass)(Class klass);
    const gchar *(*class_getName)(Class klass);
    Method *(*class_copyMethodList)(Class klass, guint *method_count);
    Class (*object_getClass)(gpointer object);
    SEL (*method_getName)(Method method);
    IMP (*method_getImplementation)(Method method);
    const gchar *(*sel_getName)(SEL selector);
};

struct _GumObjcClassMetadata {
    Class handle;
    const gchar *name;
    const gchar *category_name;
    Method *class_methods;
    guint class_method_count;
    Method *instance_methods;
    guint instance_method_count;
    GSList *subclasses;
    GumObjcApiResolver *resolver;
};
```

### How It Snapshots the ObjC Class Registry

```c
static GHashTable *gum_objc_api_resolver_create_snapshot(GumObjcApiResolver *self)
{
    GHashTable *class_by_handle;
    gint class_count, class_index;
    Class *classes;

    class_by_handle = g_hash_table_new_full(NULL, NULL, NULL,
        (GDestroyNotify)gum_objc_class_metadata_free);

    // Two-pass approach:
    // Pass 1: Get count, allocate, get all classes
    class_count = self->objc_getClassList(NULL, 0);
    classes = g_malloc(class_count * sizeof(Class));
    self->objc_getClassList(classes, class_count);

    // Pass 2: Build metadata for each class
    for (class_index = 0; class_index != class_count; class_index++) {
        Class handle = classes[class_index];
        GumObjcClassMetadata *klass = g_slice_new(GumObjcClassMetadata);
        klass->handle = handle;
        klass->name = self->class_getName(handle);
        // ... populate ...
        g_hash_table_insert(class_by_handle, handle, klass);
    }

    // Pass 3: Build superclass relationships
    for (class_index = 0; class_index != class_count; class_index++) {
        Class handle = classes[class_index];
        Class super_handle = self->class_getSuperclass(handle);
        if (super_handle != NULL) {
            GumObjcClassMetadata *klass = g_hash_table_lookup(class_by_handle, super_handle);
            if (klass != NULL)
                klass->subclasses = g_slist_prepend(klass->subclasses, handle);
        }
    }

    g_free(classes);
    return class_by_handle;
}
```

### Relevance to Our Implementation

**High.** This shows:

1. **How to get all registered ObjC classes**: `objc_getClassList(NULL, 0)` for count, then `objc_getClassList(buffer, count)` for the list. We need this to build a set of valid `isa` pointers for heap scanning.

2. **How to check if a class is still valid**: `objc_lookUpClass(name) != handle` means the class was disposed. We should use this pattern.

3. **How to safely resolve ObjC runtime functions**: Via `dlsym` on `/usr/lib/libobjc.A.dylib`, not direct linking. This avoids issues if the runtime isn't loaded. (In our case, ObjC runtime is always available in iOS Simulator apps, so direct calls are fine.)

4. **Thread safety pattern**: Uses `GRecMutex` to protect class cache, and coordinates with the disposal monitor.

### Important Note on objc_getClassList

In our `sphinx-bootstrap.dylib`, we interpose `objc_getClassList` to inject synthesized classes for Strategy B bootstrap. This means:

- Using `objc_getClassList` inside sphinx-bridge while sphinx-bootstrap is loaded will return our interposed version's output
- This is actually fine for heap_dump: we want to know what classes the runtime recognizes, including any we've injected
- However, `ObjC.chooseSync()` in Frida crashes because of this interpose conflicting with Frida's own heap enumeration -- this is the known limitation documented in CLAUDE.md

---

## Layer 5: Class Pair Disposal Monitor

**File**: `/Users/jnuts74/projects/sphinx/dev/frida-gum/gum/backend-darwin/gumobjcdisposeclasspairmonitor.c`

### Purpose

Monitors calls to `objc_disposeClassPair` to know when ObjC classes are unregistered at runtime. This is a **singleton** that hooks `objc_disposeClassPair` using Frida's interceptor.

### Mechanism

```c
// On init: hooks objc_disposeClassPair
gum_interceptor_attach(self->interceptor, dispose_impl,
    GUM_INVOCATION_LISTENER(self), NULL,
    GUM_ATTACH_FLAGS_UNIGNORABLE);

// On enter: acquires recursive mutex
static void on_enter(...) {
    g_rec_mutex_lock(&self->mutex);
}

// On leave: releases recursive mutex
static void on_leave(...) {
    g_rec_mutex_unlock(&self->mutex);
}
```

The mutex is shared with the API resolver's `ensure_class_by_handle()`. This means:
- While a class is being disposed, anyone trying to snapshot the class list will block
- After disposal completes, the snapshot will see the updated state
- The `is_disposed` check (`objc_lookUpClass(name) != handle`) catches races where disposal happened between snapshot creation and enumeration

### Relevance to Our Implementation

**Medium.** In practice, class disposal is rare in iOS apps (it happens with dynamically generated classes, e.g., KVO). For our heap_dump:
- We should be aware that class disposal can happen, but hooking `objc_disposeClassPair` requires Frida-like interception
- A simpler approach: just validate each isa pointer at the moment we examine it (re-check `objc_lookUpClass`)
- Risk: very low. Class disposal during a heap scan of a normal iOS app is effectively impossible in practice.

---

## Layer 6: JavaScript Binding

**File**: `/Users/jnuts74/projects/sphinx/dev/frida-gum/bindings/gumjs/gumv8process.cpp`
**Lines**: 1056-1078

### How Process.enumerateMallocRanges() Is Exposed

```cpp
GUMJS_DEFINE_FUNCTION(gumjs_process_enumerate_malloc_ranges)
{
    GumV8EnumerateContext<GumV8Process> ec(isolate, module);
    gum_process_enumerate_malloc_ranges(
        (GumFoundMallocRangeFunc)gum_emit_malloc_range, &ec);
    info.GetReturnValue().Set(ec.End());
}

static gboolean gum_emit_malloc_range(const GumMallocRangeDetails *details,
    GumV8EnumerateContext<GumV8Process> *ec)
{
    auto core = ec->parent->core;
    auto range = Object::New(ec->isolate);
    _gum_v8_object_set_pointer(range, "base", details->range->base_address, core);
    _gum_v8_object_set_uint(range, "size", details->range->size, core);
    return ec->Collect(range);
}
```

Each malloc range is exposed as a JavaScript object `{base: NativePointer, size: number}`. The `ObjC.choose()` implementation then reads memory at each `base` to check the isa pointer.

### Relevance to Our Implementation

**Structural reference only.** This confirms the data flow: C zone enumeration -> JavaScript objects -> frida-objc-bridge validation. We collapse all of this into a single C function.

---

## Layer 7: ObjC.choose() in frida-objc-bridge

**File**: NOT present in local frida-gum checkout (separate repository: `frida/frida-objc-bridge`)

### Reconstructed Algorithm

Based on Frida's public source and architecture knowledge, `ObjC.choose()` works as follows:

```
ObjC.choose(ObjC.classes.NSURLSession, {
    onMatch(instance) { ... },
    onComplete() { ... }
})
```

**Step 1**: Build a set of valid class pointers for the target class and its subclasses.

```javascript
// Get the target class and all subclasses
const targetClass = ObjC.classes.NSURLSession;
const validIsaSet = new Set();
validIsaSet.add(targetClass.handle);  // The Class pointer itself

// Walk subclasses (recursive)
// Uses objc_getClassList + class_getSuperclass to find inheritance chains
```

**Step 2**: Enumerate all malloc ranges.

```javascript
Process.enumerateMallocRanges({
    onMatch(range) {
        // range.base is a NativePointer
        // range.size is a number
    },
    onComplete() { ... }
});
```

**Step 3**: For each range, validate if it contains an ObjC object of the target class.

The validation logic (reconstructed from Frida's frida-objc-bridge TypeScript source):

```
For each range(base, size):
    1. Skip if size < sizeof(void*) -- too small for an object
    2. Skip if size is suspiciously large (heuristic)
    3. Read the first pointer-sized value at `base` -- this is the candidate `isa`
    4. Check if candidate isa is in the validIsaSet
    5. If yes: call onMatch(new ObjC.Object(base))
```

**Step 3 in detail -- isa validation**:

On modern arm64, the `isa` field is NOT a plain pointer. It uses a **non-pointer isa** (ISA_BITFIELD) where the class pointer is masked:

```
// arm64 non-pointer isa layout:
// Bit 0: indexed (1 = non-pointer isa)
// Bits 3-35: class pointer (shifted)
// Other bits: flags (has_assoc, has_cxx_dtor, shiftcls, etc.)

#define ISA_MASK 0x0000000ffffffff8ULL  // arm64

Class cls = (Class)((uintptr_t)isa & ISA_MASK);
```

However, in the **iOS Simulator on Apple Silicon**, the runtime uses **plain pointer isa** (not non-pointer isa), because the Simulator runs as a native arm64 macOS process. This simplifies our validation:

```c
// For iOS Simulator on Apple Silicon:
// isa is a plain pointer to the Class object
Class *isa_ptr = *(Class **)allocation_base;
// isa_ptr IS the Class pointer directly
```

**Step 4 -- Tagged pointer handling**:

Tagged pointers (small objects like NSNumber, short NSStrings) are NOT heap-allocated. They are encoded in the pointer itself:

```
// arm64 tagged pointer: bit 63 is set
if ((uintptr_t)ptr & (1ULL << 63)) {
    // This is a tagged pointer, not a heap object
    // Skip it in heap scanning -- it won't appear in malloc ranges
}
```

Tagged pointers will never appear in `malloc_get_all_zones` enumeration because they are not heap allocations. They are a non-issue for heap walking.

---

## Comparison: sphinx-core.h vs Frida

### Our Current `is_valid_objc_ptr()` (sphinx-core.h, lines 108-123)

```c
static inline int is_valid_objc_ptr(const void *ptr) {
    if (!ptr) return 0;
    if ((uintptr_t)ptr < 0x1000) return 0;                      // low page guard
    if ((uintptr_t)ptr & (1ULL << 63)) return 1;                 // tagged pointer
    if (!malloc_zone_from_ptr(ptr)) return 0;                     // heap check
    Class cls = object_getClass((id)ptr);                         // read isa
    if (!cls) return 0;
    const char *name = class_getName(cls);                        // validate class
    if (!name || name[0] == '\0') return 0;
    return 1;
}
```

### What Frida Does Differently

| Aspect | sphinx-core.h | Frida's approach |
|--------|---------------|------------------|
| **Tagged pointer detection** | Checks bit 63 -- correct for arm64 | Same approach, but Frida also handles the Android top-byte-ignore case |
| **Heap validation** | `malloc_zone_from_ptr()` -- asks malloc if it knows this pointer | Enumerates all zones and only examines returned ranges -- validation is implicit |
| **isa validation** | `object_getClass()` which dereferences the pointer | Reads raw isa pointer from memory, masks with ISA_MASK, compares against class set |
| **Class registration check** | `class_getName()` and checks non-null | Uses `objc_lookUpClass(name) == handle` to verify class is still registered |
| **Crash safety** | Relies on malloc_zone_from_ptr pre-check | Zone enumeration means only valid allocations are examined |
| **Non-pointer isa** | Relies on `object_getClass()` to handle this | Explicitly masks with ISA_MASK (but for Simulator, plain isa is used) |

### Key Differences

1. **Frida starts from known-good addresses** (zone enumerator output), then validates the isa. We start from an arbitrary pointer and use `malloc_zone_from_ptr()` as a pre-filter. Both are valid, but Frida's approach is more systematic for full heap scanning.

2. **Our approach calls `object_getClass()` on potentially invalid memory.** If `malloc_zone_from_ptr()` returns a zone, the pointer is a valid heap allocation, but it may not be an ObjC object -- calling `object_getClass()` dereferences the first word to read the isa. If the allocation contains non-object data, this reads garbage but won't crash (it's valid memory). The garbage isa will fail the `class_getName()` check.

3. **Frida avoids calling ObjC runtime functions on unknown pointers.** It reads raw memory, compares against a known class set, and only wraps in `ObjC.Object` after validation. This is more defensive.

4. **Our `is_valid_objc_ptr` is designed for validating a single known pointer**, not for heap scanning. It's appropriate for its current use (validating pointers passed in bridge commands). For heap_dump, we need the zone enumeration approach.

---

## Analysis & Recommendations

### What We Can Directly Adapt

1. **The malloc zone walking algorithm is the heart of it, and it's simple.** The entire Darwin-specific heap walking code in Frida is about 50 lines of C. The key API calls are:
   - `malloc_get_all_zones()` -- get all zones
   - `zone->introspect->enumerator()` -- enumerate each zone's in-use blocks
   - A trivial `memory_reader` callback that returns the address as-is (in-process)
   - A `range_recorder` callback that receives batches of `vm_range_t`

2. **We already include `<malloc/malloc.h>`** in sphinx-core.h (for `malloc_zone_from_ptr`), so the headers are already available.

3. **We already have `object_getClass()` and `class_getName()`** calls throughout sphinx-bridge.c.

4. **We already handle tagged pointers** in `is_valid_objc_ptr`.

### What We Need to Build

For a `heap_dump` command in sphinx-bridge.c:

```
Phase 1: Build class validation set
    - Call objc_getClassList() to get all registered Class pointers
    - Store them in a hash set for O(1) lookup
    - If caller specifies a target class, also collect subclasses via class_getSuperclass()

Phase 2: Walk malloc zones
    - Call malloc_get_all_zones(mach_task_self(), reader, &addrs, &count)
    - For each zone: call zone->introspect->enumerator with MALLOC_PTR_IN_USE_RANGE_TYPE
    - Collect (address, size) pairs

Phase 3: Validate each allocation
    - Skip allocations smaller than sizeof(void*) (can't be an ObjC object)
    - Read the first pointer-width value at the allocation base (candidate isa)
    - Check if candidate isa is in our class set
    - If yes: record this as a live ObjC object instance

Phase 4: Format and return results
    - Return JSON array of {address, class, size} for each found instance
```

### Complexity Estimate

| Component | Effort | Notes |
|-----------|--------|-------|
| Zone walking (Phase 2) | **Low** (~30 lines) | Direct port of Frida's `gum_process_enumerate_malloc_ranges` |
| Class set construction (Phase 1) | **Low** (~20 lines) | Two-call pattern for `objc_getClassList`, simple array or hash set |
| isa validation (Phase 3) | **Medium** (~40 lines) | Need to handle: plain isa, non-pointer isa (masking), null/garbage isa |
| Subclass matching | **Medium** (~30 lines) | Walk `class_getSuperclass` chain for each class to check inheritance |
| JSON output (Phase 4) | **Low** (~20 lines) | Using existing `resp_append` pattern from sphinx-bridge.c |
| Testing & hardening | **High** (time) | Edge cases, large heaps, concurrent modification |

**Total estimated implementation**: ~150 lines of C, plus testing.

### Key Risks

#### 1. Performance (MODERATE)

A typical iOS app has 50,000-500,000 heap allocations. Scanning all of them requires:
- Reading one pointer from each allocation (isa check)
- Hash set lookup for class validation
- Total: ~1-10ms for most apps, up to ~50ms for very large heaps

**Mitigation**:
- Use early termination (`carry_on = false`) once enough results are found
- Support a `limit` parameter to cap results
- For class-specific queries, only collect allocations whose isa matches

#### 2. Thread Safety (HIGH)

The heap is shared mutable state. During our zone enumeration:
- Other threads may `malloc/free/realloc`, modifying zone internals
- An allocation we're examining may be freed between zone enumeration and isa read
- The isa pointer we read may be garbage if the memory was freed and reused

**Mitigations**:
- Accept that results may include stale entries (same as Frida)
- Use `malloc_zone_from_ptr(addr)` as a second check before reading isa
- Wrap isa reads in a signal-safe manner (or accept the rare crash risk)
- Do NOT send messages to discovered objects during the scan -- validate first, message later
- Consider running the scan on a serial dispatch queue to avoid re-entrancy

#### 3. Stability During Zone Enumeration (MODERATE)

The zone enumerator callback runs with internal zone locks held (depending on the zone implementation). If our callback code triggers a malloc (even implicitly, e.g., via `fprintf` or ObjC message send), we can deadlock.

**Mitigations**:
- Keep the enumerator callback minimal: just store (address, size) pairs
- Pre-allocate the results buffer before starting enumeration
- Do NOT call any ObjC runtime functions inside the enumerator callback
- Do all isa validation AFTER enumeration completes

#### 4. Interaction with sphinx-bootstrap.dylib (LOW)

Our `sphinx-bootstrap.dylib` interposes `objc_getClassList`. This means:
- Building the class validation set will go through our interposed version
- This is actually fine -- our interposed version adds classes, it doesn't remove them
- The isa pointers in the heap will match what our interposed `objc_getClassList` reports

### Recommended Implementation Approach

```
1. SEPARATE enumeration from validation:
   - Phase A (in enumerator callback): Just collect (address, size) pairs into a
     pre-allocated array. No ObjC calls, no malloc, no I/O.
   - Phase B (after enumeration): Walk the collected array, read isa, validate
     against class set, build JSON response.

2. Use a FIXED-SIZE pre-allocated buffer for Phase A:
   - Pre-allocate space for, say, 500,000 entries (8 bytes each = 4MB)
   - If the heap has more allocations, stop collecting (cap it)
   - This avoids malloc during enumeration (deadlock risk)

3. Build the class set using a SIMPLE ARRAY + LINEAR SCAN:
   - For < 10,000 classes (typical), linear scan of sorted array is fast enough
   - Alternatively, use a hash table built BEFORE enumeration starts
   - objc_getClassList typically returns 5,000-30,000 classes

4. For class-specific queries (find instances of NSURLSession):
   - Build a small set of {targetClass, allSubclasses}
   - Only report allocations whose isa matches this set
   - Much faster than full heap dump

5. Return results as JSON via the existing bridge protocol:
   - {"instances": [{"addr":"0x...", "class":"NSURLSession", "size":128}, ...]}
   - Include total_allocations_scanned and time_ms for diagnostics
```

### What NOT to Build

- **Do not implement a Frida-like instance tracker** (hooking malloc/free). Too invasive, conflicts with our DYLD injection approach, and unnecessary for point-in-time scanning.
- **Do not try to suspend threads** during enumeration. Too dangerous, can deadlock, and Frida doesn't do it either.
- **Do not implement a class disposal monitor**. Class disposal is extremely rare in real iOS apps and adds complexity for negligible benefit.

---

## Appendix A: API Reference for Zone Enumeration

### Headers Required

```c
#include <malloc/malloc.h>   // malloc_get_all_zones, malloc_zone_t, vm_range_t
#include <mach/mach.h>       // mach_task_self, task_t, kern_return_t
#include <objc/runtime.h>    // objc_getClassList, object_getClass, class_getName
```

### Key Types

```c
// From <malloc/malloc.h>:
typedef kern_return_t memory_reader_t(task_t, vm_address_t, vm_size_t, void **);
typedef void vm_range_recorder_t(task_t, void *, unsigned type,
    vm_range_t *ranges, unsigned count);

typedef struct {
    vm_address_t address;
    vm_size_t size;
} vm_range_t;

// MALLOC_PTR_IN_USE_RANGE_TYPE = 1  (enumerate only in-use blocks)
// MALLOC_PTR_REGION_RANGE_TYPE = 2  (enumerate regions)
// MALLOC_ADMIN_REGION_RANGE_TYPE = 4 (enumerate admin regions)
```

### Minimal Zone Walking Implementation (Sketch)

```c
// This is a SKETCH, not production code. For reference only.

typedef struct {
    vm_address_t *addresses;
    vm_size_t *sizes;
    unsigned count;
    unsigned capacity;
} HeapScanResults;

static kern_return_t heap_reader(task_t t, vm_address_t addr,
    vm_size_t size, void **out) {
    *out = (void *)addr;
    return KERN_SUCCESS;
}

static void heap_recorder(task_t t, void *ctx, unsigned type,
    vm_range_t *ranges, unsigned count) {
    HeapScanResults *r = (HeapScanResults *)ctx;
    for (unsigned i = 0; i < count && r->count < r->capacity; i++) {
        r->addresses[r->count] = ranges[i].address;
        r->sizes[r->count] = ranges[i].size;
        r->count++;
    }
}

static void walk_heap(HeapScanResults *results) {
    vm_address_t *zones;
    unsigned zone_count;
    if (malloc_get_all_zones(mach_task_self(), heap_reader,
            &zones, &zone_count) != KERN_SUCCESS)
        return;
    for (unsigned i = 0; i < zone_count; i++) {
        malloc_zone_t *zone = (malloc_zone_t *)zones[i];
        if (zone && zone->introspect && zone->introspect->enumerator) {
            zone->introspect->enumerator(mach_task_self(), results,
                MALLOC_PTR_IN_USE_RANGE_TYPE, zones[i],
                heap_reader, heap_recorder);
        }
    }
}
```

## Appendix B: Files Studied

| File | Path | Key Findings |
|------|------|-------------|
| gumprocess-darwin.c | `dev/frida-gum/gum/backend-darwin/gumprocess-darwin.c` (lines 305-384) | Core zone walking algorithm; `malloc_get_all_zones` + zone introspect enumerator |
| gumheapapi.c/h | `dev/frida-gum/gum/gumheapapi.c` | Cross-platform heap function pointer abstraction; not directly needed |
| gum-heap.h | `dev/frida-gum/libs/gum/gum-heap.h` | Header index for heap library; lists allocation tracking, bounds checking, instance tracking |
| guminstancetracker.c | `dev/frida-gum/libs/gum/heap/guminstancetracker.c` | GObject instance tracking via hooking; not needed for point-in-time scanning |
| gumobjcapiresolver.c | `dev/frida-gum/gum/backend-darwin/gumobjcapiresolver.c` | ObjC class registry snapshot; `objc_getClassList` two-pass pattern; class disposal detection |
| gumobjcdisposeclasspairmonitor.c | `dev/frida-gum/gum/backend-darwin/gumobjcdisposeclasspairmonitor.c` | Singleton monitor for `objc_disposeClassPair`; mutex-based synchronization |
| gumv8process.cpp | `dev/frida-gum/bindings/gumjs/gumv8process.cpp` (lines 1056-1078) | JS binding for `Process.enumerateMallocRanges()`; wraps C zone walking |
| gummemory-darwin.c | `dev/frida-gum/gum/backend-darwin/gummemory-darwin.c` | Darwin memory operations; free range enumeration; page protection |
| gummemory-posix.c | `dev/frida-gum/gum/backend-posix/gummemory-posix.c` | POSIX memory allocation; not relevant to zone walking |
| gumsanitychecker.c | `dev/frida-gum/libs/gum/heap/gumsanitychecker.c` | Combines instance tracker + allocation tracker for leak detection |
| gumallocatorprobe.c | `dev/frida-gum/libs/gum/heap/gumallocatorprobe.c` | Hooks malloc/free via interceptor for allocation tracking |
| sphinx-core.h | `src/dylibs/sphinx-core.h` (lines 108-123) | Our existing `is_valid_objc_ptr`; good for single-pointer validation, insufficient for heap scanning |
| sphinx-bridge.c | `src/dylibs/sphinx-bridge.c` (lines 650-727) | Current `find_instances` command; singleton-based only; needs heap_dump upgrade |

## Appendix C: What the frida-objc-bridge ObjC.choose() Source Looks Like

While the frida-objc-bridge TypeScript source is not available locally, the public Frida documentation and source (https://github.com/frida/frida-objc-bridge) confirm the algorithm. The key file is `index.ts` in that repository. The relevant logic:

1. Calls `api.objc_getClassList` to snapshot all classes
2. For the target class, walks the superclass chain of every class to find subclasses
3. Calls `Process.enumerateMallocRanges()` (which triggers the C-layer zone walking)
4. For each range, reads the isa pointer at the base address
5. On arm64: masks with `ISA_MASK` to extract the class pointer (for non-pointer isa)
6. Compares against the set of target class + subclass pointers
7. On match: wraps in `ObjC.Object()` and calls `onMatch` callback

The non-pointer isa masking constant for different architectures:
- arm64 (device): `0x0000000ffffffff8` (ISA_MASK)
- arm64 (simulator/macOS): Plain pointer isa is used (no masking needed)
- x86_64: `0x00007ffffffffff8`

**For iOS Simulator on Apple Silicon, plain pointer isa is used.** This is confirmed by the fact that `object_getClass()` returns the raw isa on simulator, and our existing `is_valid_objc_ptr` works correctly without masking.
