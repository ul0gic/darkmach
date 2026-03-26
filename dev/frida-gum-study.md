# Frida-Gum Study: LOE Report & Implementation Recommendations

> Consolidated findings from exploit-engineer (interceptor) and mobile-engineer (heap walking).
> Date: 2026-03-25
> Purpose: Inform build plan for Phase 4.3 bridge capabilities.

---

## Executive Summary

After studying Frida's frida-gum engine, we've determined that our DYLD injection + ObjC swizzling approach lets us achieve Frida-equivalent capabilities at **5-10% of Frida's codebase complexity**. The key advantage: method swizzling eliminates the need for Frida's relocator, disassembler, code allocator, and transaction system entirely. We need only trampolines and zone walking — both well-understood patterns.

---

## LOE Estimates: All 20 Proposed Capabilities

### Tier 1: Critical

| # | Capability | LOE | Lines (est.) | Complexity | Dependencies | Notes |
|---|-----------|-----|-------------|------------|-------------|-------|
| 1.1 | `crypto_tap` | 2-3 days | ~300 | Medium | None | DYLD_INTERPOSE on CommonCrypto functions. We already do this pattern in darkmach-crypto.dylib — this wires it into the bridge protocol. |
| 1.2 | `net_tap` | 2-3 days | ~400 | Medium | None | Swizzle NSURLSession delegate methods + wrap completion handler blocks. We already have darkmach-net.dylib — wire into bridge. |
| 1.3 | `trace` | 3-5 days | ~500 | **High** | .S assembly file | The hardest single capability. Needs ARM64 trampoline (26 instructions), per-hook stub generation (static or JIT), ObjC type encoding parser, reentrancy guard. **Frida study reduced this from "weeks" to "days"** — swizzling eliminates relocator/disassembler. |
| 1.4 | `ui_interact` | 3-4 days | ~350 | Medium-High | UIKit private APIs | Synthesize UITouch events via UIApplication sendEvent:, text input via UITextInput protocol. Main thread dispatch required. Fragile across iOS versions. |
| 1.5 | `heap_dump` | 1-2 days | ~150 | **Low-Medium** | malloc/malloc.h | `malloc_get_all_zones()` + zone enumerator. Collect addresses in callback, validate isa pointers afterward. Our `is_valid_objc_ptr()` is the foundation. **Easiest high-impact capability.** |
| 1.6 | `proto_decode` | 5-7 days | ~800 | **Very High** | None | Protobuf wire format parser from scratch in C. Varint decoding, nested messages, schema reconstruction. Plus MessagePack/CBOR. Could defer CBOR/Thrift and just do protobuf first (~400 lines). |

### Tier 2: Advanced

| # | Capability | LOE | Lines (est.) | Complexity | Dependencies | Notes |
|---|-----------|-----|-------------|------------|-------------|-------|
| 2.1 | `auth_tap` | 2-3 days | ~300 | Medium | Requires net_tap | Hook ASWebAuthenticationSession, LAContext, filter net_tap for OAuth endpoints. JWT base64 decode is ~50 lines. |
| 2.2 | `pin_analyze` | 2 days | ~250 | Medium | None | Hook SecTrustEvaluateWithError, NSURLSessionDelegate challenge methods. Extract cert data via SecCertificateCopyData. |
| 2.3 | `event_tap` | 1-2 days | ~200 | **Low** | None | Swizzle NSNotificationCenter postNotification:. Register catch-all observer. Ring buffer. **Very easy, high value.** |
| 2.4 | `inject_class` | 2-3 days | ~300 | Medium | objc/runtime.h | objc_allocateClassPair + class_addMethod + objc_registerClassPair. Well-documented APIs. The tricky part is the pre-built implementation catalog. |
| 2.5 | `entitlement_scan` | 1-2 days | ~200 | Low-Medium | None | Parse LC_CODE_SIGNATURE from Mach-O headers via _dyld_get_image_header. We already parse Mach-O in our patcher. |
| 2.6 | `db_inject` | 1 day | ~150 | **Low** | sqlite3 | Extend existing db_dump to support INSERT/UPDATE/DELETE. Interpose sqlite3_prepare_v2 for query logging. We already link sqlite3. |
| 2.7 | `block_inspect` | 3-4 days | ~350 | **High** | None | Parse Block_layout struct (isa, flags, invoke, descriptor). Captured variable recovery requires descriptor analysis. Semi-documented internals. |

### Tier 3: Deep Tradecraft

| # | Capability | LOE | Lines (est.) | Complexity | Dependencies | Notes |
|---|-----------|-----|-------------|------------|-------------|-------|
| 3.1 | `diff_exec` | 5+ days | ~500 | **Very High** | All Tier 1 | Meta-capability. Needs session recording across all subsystems + structured diff. Defer until Tier 1 is stable. |
| 3.2 | `sdk_map` | 2-3 days | ~400 | Medium | None | _dyld_image_count() + fingerprint database. SDK credential extraction via known accessor patterns. |
| 3.3 | `timing_probe` | 1-2 days | ~150 | Low | mach/mach_time.h | mach_absolute_time() before/after method call. Statistical analysis (mean, stddev). Straightforward. |
| 3.4 | `mem_forensics` | 3-4 days | ~300 | High | malloc internals | Walk freed blocks via zone enumerator with different flags. Pattern scan freed memory. Risk: instability. |
| 3.5 | `stealth` | 2-3 days | ~350 | Medium | DYLD_INTERPOSE | Hook sysctl, ptrace, getenv, _dyld_image_count to hide ourselves. Known patterns from jailbreak community. |
| 3.6 | `deeplink_fuzz` | 2-3 days | ~300 | Medium | Requires ui_interact | URL scheme enumeration from Info.plist + programmatic openURL: with fuzz patterns. |
| 3.7 | `webview_extract` | 2-3 days | ~300 | Medium | None | Heap-find WKWebView instances, read configuration, evaluateJavaScript:. Requires heap_dump. |
| 3.8 | `cloud_extract` | 2-3 days | ~250 | Medium | CloudKit framework | NSUbiquitousKeyValueStore dump + CKContainer/CKQuery. May need framework linking. |
| 3.9 | `env_dump` | 0.5 days | ~100 | **Trivial** | None | Iterate `environ`, NSProcessInfo, _dyld_image_count loop, fd iteration. Almost free. |
| 3.10 | `persist` | 1 day | ~150 | Low | None | Write hook config to JSON in app tmp dir, restore on next bridge init. Notification observers for lifecycle. |

---

## Key Insight from Frida Study

**ObjC method swizzling vs. inline hooking** is the single biggest simplification:

| Frida's Approach (Inline Hooking) | Our Approach (Method Swizzling) |
|---|---|
| Overwrite function prologue with redirect | Replace IMP pointer atomically via ObjC runtime |
| Relocate stolen instructions to trampoline | No relocation needed — original function untouched |
| Disassemble prologue to determine safe steal size | No disassembly needed |
| Handle PC-relative instruction rewriting | N/A |
| Near-page allocation for branch range | N/A |
| Transaction system for batched patching | N/A |
| ~4000 lines of C + Assembly | **~500 lines** |

**Trade-off**: We can only hook ObjC methods, not arbitrary C functions. For C functions (CommonCrypto, sqlite3, etc.) we use DYLD_INTERPOSE, which is zero-code-modification interposition at dyld load time. Between the two mechanisms, we cover everything.

---

## Recommended Build Order

Based on impact, complexity, and dependency chains:

### Sprint 1: Foundation (3-4 days)
1. **`heap_dump`** (1.5) — 150 lines, low complexity, critical foundation for webview_extract, block_inspect, and general object discovery
2. **`event_tap`** (2.3) — 200 lines, low complexity, immediate intelligence value
3. **`env_dump`** (3.9) — 100 lines, trivial, instant process context
4. **`db_inject`** (2.6) — 150 lines, extends existing db_dump, low risk

### Sprint 2: Network Intelligence (3-4 days)
5. **`net_tap`** (1.2) — 400 lines, wires existing interceptor into bridge
6. **`crypto_tap`** (1.1) — 300 lines, wires existing interceptor into bridge
7. **`auth_tap`** (2.1) — 300 lines, builds on net_tap

### Sprint 3: The Trampoline (4-5 days)
8. **`trace`** (1.3) — 500 lines + assembly, the crown jewel. Requires:
   - ARM64 trampoline (.S file)
   - Per-hook stub generation
   - ObjC type encoding parser
   - Reentrancy guard
   - Integration with bridge command protocol

### Sprint 4: Active Capabilities (3-4 days)
9. **`ui_interact`** (1.4) — 350 lines, enables autonomous exploration
10. **`stealth`** (3.5) — 350 lines, required for hardened apps
11. **`pin_analyze`** (2.2) — 250 lines, validates SSL bypass

### Sprint 5: Deep Analysis (4-5 days)
12. **`webview_extract`** (3.7) — 300 lines, requires heap_dump
13. **`sdk_map`** (3.2) — 400 lines, supply chain mapping
14. **`inject_class`** (2.4) — 300 lines, runtime manipulation
15. **`entitlement_scan`** (2.5) — 200 lines, Mach-O parsing (reuse patcher code)

### Sprint 6: Advanced (5+ days)
16. **`block_inspect`** (2.7) — 350 lines, complex internals
17. **`proto_decode`** (1.6) — 800 lines, protobuf-only first pass
18. **`mem_forensics`** (3.4) — 300 lines, freed memory scanning
19. **`timing_probe`** (3.3) — 150 lines, side-channel analysis
20. **`deeplink_fuzz`** (3.6) — 300 lines, requires ui_interact

### Deferred
- **`diff_exec`** (3.1) — Meta-capability requiring all others. Build last.
- **`cloud_extract`** (3.8) — Framework dependency, app-specific value.
- **`persist`** (3.10) — Nice to have, build when session management becomes a pain point.

---

## Total LOE Summary

| Phase | Capabilities | Est. Days | Lines of Code |
|-------|-------------|-----------|--------------|
| Sprint 1: Foundation | heap_dump, event_tap, env_dump, db_inject | 3-4 days | ~600 |
| Sprint 2: Network | net_tap, crypto_tap, auth_tap | 3-4 days | ~1000 |
| Sprint 3: Trampoline | trace | 4-5 days | ~500 + asm |
| Sprint 4: Active | ui_interact, stealth, pin_analyze | 3-4 days | ~950 |
| Sprint 5: Deep | webview, sdk_map, inject_class, entitlements | 4-5 days | ~1200 |
| Sprint 6: Advanced | block_inspect, proto_decode, mem_forensics, timing, deeplink | 5+ days | ~1950 |
| **Total** | **20 capabilities** | **~23-27 days** | **~6200 lines** |

---

## Detailed Study Reports

- **Interceptor/Trampoline**: `dev/frida-gum-interceptor-study.md` (exploit-engineer, 1043 lines)
- **Heap Walking**: `dev/frida-gum-heap-study.md` (mobile-engineer, 795 lines)
- **Source**: `dev/frida-gum/` (frida-gum shallow clone)

---

*This document informs the build plan. Implementation decisions and sprint assignments should be added to `.project/build-plan.md` once approved.*
