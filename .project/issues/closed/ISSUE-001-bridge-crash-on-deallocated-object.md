# ISSUE-001: darkmach-bridge crashes on deallocated object pointer

**Severity**: HIGH
**Type**: Bug
**Discovered By**: mobile-engineer agent (via crash during AP News exploration)
**Discovered During**: Phase 5 App Testing Campaign — AP News
**Affected Tool**: `src/dylibs/darkmach-bridge.c` (`nsobject_desc`, `cmd_read_property`, `cmd_call_method`)
**Assigned To**: mobile-engineer
**Status**: Resolved

---

## Description

`cmd_read_property` casts a raw address to `id` and calls `objc_msgSend` on it without validating the pointer is still a live object. If the object has been deallocated between `heap_search` (which found the address) and `read_property` (which dereferences it), the `objc_msgSend` hits a freed/garbage pointer and crashes the entire app process with `EXC_BAD_ACCESS (SIGSEGV)`.

The crash occurred in `nsobject_desc()` (darkmach-core.h:108) which calls `[obj description]` via `objc_msgSend`. The same vulnerability exists in `cmd_call_method`.

## Reproduction

1. `darkmach run "/Applications/AP News.app"`
2. `darkmach bridge --command "heap_search SomeClass"` — get an address
3. Wait for the object to be deallocated (or trigger rapid-fire bridge commands)
4. `darkmach bridge --command "read_property <stale_address> someProperty"` — SIGSEGV

## Crash Details

```
Exception: EXC_BAD_ACCESS (SIGSEGV) KERN_INVALID_ADDRESS at 0x0000000000000001

Thread (crashed):
  0: libobjc.A.dylib     objc_msgSend
  1: darkmach-bridge.dylib  nsobject_desc      (darkmach-core.h:108)
  2: darkmach-bridge.dylib  cmd_read_property  (darkmach-bridge.c:323)
  3: darkmach-bridge.dylib  dispatch_command
  4: darkmach-bridge.dylib  handle_client
```

## Impact

Crashes the target app process. All interceptor data collection stops. Bridge connection lost. Requires full re-launch of the pipeline.

## Suggested Fix

Wrap `objc_msgSend` calls in `@try/@catch` in `nsobject_desc()` (darkmach-core.h) since it's the common path for all description formatting. Also wrap the `respondsToSelector:` checks in `cmd_read_property` and `cmd_call_method` since those are the first `objc_msgSend` calls on the raw pointer.

---

*Filed: 2026-03-25*
*Resolved: 2026-03-25*

## Resolution

Initial attempt with `@try/@catch` failed — `EXC_BAD_ACCESS` (SIGSEGV) is a Mach exception, not an ObjC exception, so `@try/@catch` doesn't catch it. Final fix uses pre-flight pointer validation:

1. **`darkmach-core.h`** — added `is_valid_objc_ptr()` that checks: low page addresses, tagged pointers, `malloc_zone_from_ptr()` for heap validity, and `object_getClass()` + `class_getName()` for valid isa. Added `#include <malloc/malloc.h>`. `nsobject_desc()` calls `is_valid_objc_ptr()` before any `objc_msgSend`.
2. **`darkmach-bridge.c:cmd_read_property()`** — calls `is_valid_objc_ptr()` before `respondsToSelector:`. Returns JSON error on invalid pointer.
3. **`darkmach-bridge.c:cmd_call_method()`** — same `is_valid_objc_ptr()` guard.
4. **`Makefile`** — added `-x objective-c -fobjc-exceptions` to darkmach-bridge build rule.

Validated: `0x1`, `0xFFFF`, `0xDEADBEEF` all return error JSON. Valid objects (`NSUserDefaults`) still work. App stays alive.
