# Darkmach Build Plan

> **CRITICAL INSTRUCTIONS FOR ALL AGENTS**
>
> ## Build Discipline
> 1. **Keep this document up to date** — Mark tasks as completed immediately after finishing them
> 2. **Test after every change** — Verify patching/analysis tools work against a real app bundle
> 3. **Zero tolerance for regressions** — A change that breaks existing functionality gets reverted
> 4. **Update changelog.md** — Log significant changes, fixes, and milestones
> 5. **Respect file ownership** — Never modify files outside your assigned boundary during parallel phases
>
> ## Engineer Assignments
>
> | Agent | Color | Domain Boundary | Owns |
> |-------|-------|----------------|------|
> | exploit-engineer | 🔴 | ARM64 shellcode, Mach-O surgery, trampolines, memory forensics, stealth, low-level C | `src/patch/`, `src/dylibs/bridge/cmd-trace.c`, `src/dylibs/bridge/cmd-forensics.c`, `src/dylibs/bridge/darkmach-trampoline.S`, `src/dylibs/stealth/`, `src/dylibs/tools/` |
> | mobile-engineer | 🔵 | DYLD injection, interceptor dylibs, runtime hooks, LLM bridge, bridge commands | `src/dylibs/bridge/darkmach-bridge.c`, `src/dylibs/bridge/cmd-recon.c`, `src/dylibs/bridge/cmd-network.c`, `src/dylibs/bridge/cmd-ui.c`, `src/dylibs/bridge/cmd-analysis.c`, `src/dylibs/bridge/cmd-inject.c`, `src/dylibs/bridge/cmd-events.c`, `src/dylibs/interceptors/`, `src/dylibs/compat/` |
> | code-engineer | 🟣 | Static analysis, Python bridge client, CLI, type encoding parser | `src/darkmach/` |
> | qa-engineer | 🟢 | pytest, test fixtures, coverage, regression prevention | `tests/` |
> | report-engineer | 🟠 | Finding reports, Apple Security Bounty | `.project/reports/` |
> | documentation-engineer | 📘 | Product docs, research methodology | `docs/` |

---

## Status Legend

| Icon | Status |
|------|--------|
| ⬜ | Not Started |
| 🔄 | In Progress |
| ✅ | Completed |
| ❌ | Blocked |
| ⏸️ | Deferred |

---

## Project Progress Summary

```
Phase 1: Foundation (tools)     [████████████████████]  100%  ✅
Phase 2: FairPlay Bypass        [████████████████████]  100%  ✅
Phase 3: Interceptor Suite      [████████████████████]  100%  ✅
Phase 4: LLM Runtime Bridge     [████████████████████]  100%  ✅  <- remaining work moved to Phase 13+14
Phase 5: App Testing Campaign   [░░░░░░░░░░░░░░░░░░░░]    0%  ⬜
Phase 6: CLI Automation         [████████████████████]  100%  ✅
Phase 7: Project Restructure    [████████████████████]  100%  ✅
Phase 8: Documentation          [████████████████████]  100%  ✅
Phase 9: Bug Fixes              [████████████████████]  100%  ✅
Phase 9.5: Linting & Code Quality [████████████████████]  100%  ✅
Phase 10: Test Suite            [████████████████████]  100%  ✅  <- COMPLETE
Phase 13: Bridge Capabilities   [████████████████████]  100%  ✅  <- COMPLETE — all 20 bridge capabilities implemented
Phase 14: LLM Autonomous Loop   [░░░░░░░░░░░░░░░░░░░░]    0%  ⬜  <- NEW (was Phase 4.3 placeholders)
——————————————————————————————————————————————————————————————
Overall Progress                [████████████████░░░░]   75%

Execution order: Phase 14 (LLM Autonomous Loop) → Phase 5 (App Testing Campaign)
```

---

## Phase 1: Foundation ✅

> Core pipeline tools. Built prior to formal project tracking.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 1.1 | Surgical Mach-O patcher — platform flags + encryption header zeroing | exploit-engineer |
| ✅ | 1.2 | ARM64 shellcode generator — entry point replacement via dlsym | exploit-engineer |
| ✅ | 1.3 | AppDelegate auto-detection — 4-tier (Swift mangled, variant, ObjC, SwiftUI detect) | exploit-engineer |
| ✅ | 1.4 | Full bundle patcher — main binary, frameworks, extensions, plists, re-sign | exploit-engineer |
| ✅ | 1.5 | Alternative stub generator — clang-compiled main() replacement | exploit-engineer |
| ✅ | 1.6 | Bootstrap dylib — Strategy B constructor + objc_getClassList interpose | mobile-engineer |
| ✅ | 1.7 | Monitor dylibs — basic injection verification + method swizzling hooks | mobile-engineer |
| ✅ | 1.8 | Full static analysis script — URLs, secrets, entitlements, SDKs, Mach-O | code-engineer |
| ✅ | 1.9 | App Store discovery scripts — search, category scan, installed app finder | ⬜ |
| ✅ | 1.10 | System pre-flight check script | ⬜ |
| ✅ | 1.11 | Memory dump utility (Mach task API) | exploit-engineer |

---

## Phase 2: FairPlay Simulator Decryption Bypass ✅

> Novel discovery: kernel transparently decrypts FairPlay pages for Simulator processes.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 2.1 | Reverse engineer iOS Simulator internals (dyld_sim, launchd_sim, amfid) | exploit-engineer |
| ✅ | 2.2 | Discover kernel page-in decryption path works for Simulator processes | exploit-engineer |
| ✅ | 2.3 | Build crypt region extraction dylib (darkmach-decrypt.dylib) | exploit-engineer |
| ✅ | 2.4 | Prove end-to-end: encrypted on disk -> decrypted in Simulator memory | exploit-engineer |
| ✅ | 2.5 | Document breakthrough in research paper | ⬜ |
| ✅ | 2.6 | Fix inside-out code signing for frameworks | exploit-engineer |

---

## Phase 3: Custom Instrumentation Suite ✅

> Modular DYLD-injected interceptors. Written in C, zero dependencies, undetectable.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 3.1 | `darkmach-core.h` — shared infrastructure (logging, JSON, ObjC helpers) | mobile-engineer |
| ✅ | 3.2 | `darkmach-net.dylib` — NSURLSession hooks, full HTTP request/response capture | mobile-engineer |
| ✅ | 3.3 | `darkmach-keychain.dylib` — SecItem CRUD hooks via DYLD interpose | mobile-engineer |
| ✅ | 3.4 | `darkmach-crypto.dylib` — CCCrypt + SHA hash hooks via DYLD interpose | mobile-engineer |
| ✅ | 3.5 | `darkmach-storage.dylib` — NSUserDefaults, pasteboard, cookies, file manager hooks | mobile-engineer |
| ✅ | 3.6 | `darkmach-ssl.dylib` — SecTrust evaluation, cert pinning bypass, challenge logging | mobile-engineer |
| ✅ | 3.7 | `darkmach-db.dylib` — sqlite3 API hooks (9 functions), query + row capture | mobile-engineer |
| ✅ | 3.8 | `darkmach-tls.dylib` — BoringSSL low-level TLS interception | mobile-engineer |
| ✅ | 3.9 | `darkmach-metal-fix.dylib` — GPU compatibility fix for Simulator | mobile-engineer |
| ✅ | 3.10 | All interceptors running simultaneously against OddsJam, zero crashes | mobile-engineer |
| ✅ | 3.11 | First live findings: API keys, auth tokens, database schemas from OddsJam | mobile-engineer |

---

## Phase 4: LLM Runtime Bridge ✅

> **CONFIDENTIAL** — Novel concept. No prior art exists. An LLM that autonomously explores a live iOS app's runtime.

### 4.1 Bridge Infrastructure

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 4.1.1 | `darkmach-bridge.dylib` — Unix domain socket listener inside injected process | mobile-engineer |
| ✅ | 4.1.2 | JSON command/response protocol — structured request/reply over socket | mobile-engineer |
| ✅ | 4.1.3 | Host-side client — `bridge.py` with interactive REPL + CLI modes | mobile-engineer |
| ✅ | 4.1.4 | LLM integration — direct bridge access via Python/Unix socket | mobile-engineer |

### 4.2 Bridge Command Set

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 4.2.1 | `enumerate_classes` — list all ObjC classes (with optional name filter) | mobile-engineer |
| ✅ | 4.2.2 | `get_methods` / `get_properties` / `get_ivars` — class introspection | mobile-engineer |
| ✅ | 4.2.3 | `read_property` — read live property value from an object instance | mobile-engineer |
| ✅ | 4.2.4 | `call_method` — invoke a method on a live object | mobile-engineer |
| ✅ | 4.2.5 | `hook_method` / `unhook_method` — dynamic swizzle install/remove | mobile-engineer |
| ✅ | 4.2.6 | `view_hierarchy` — dump UIKit view tree with classes, frames, labels | mobile-engineer |
| ✅ | 4.2.7 | `keychain_dump` / `userdefaults_dump` / `cookies_dump` — data extraction | mobile-engineer |
| ✅ | 4.2.8 | `heap_search` — find all instances of a given class on the heap | mobile-engineer |
| ✅ | 4.2.9 | `read_memory` — read N bytes at address | mobile-engineer |

### 4.3 Bridge Expansion & LLM Autonomous Exploration

> Bridge expansion (20 new capabilities) moved to Phase 13. LLM autonomous loop moved to Phase 14.
> Phase 4.3 placeholder tasks replaced by detailed phased implementation below.

---

## Phase 5: App Testing Campaign ⬜

> Validate the full pipeline (decryption + interceptors + bridge) across app categories.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 5.1 | Test 10+ apps across categories (native Swift, ObjC, React Native, Flutter, Unity) | all |
| ⬜ | 5.2 | Create app testing log format (app, bundle ID, strategy, outcome, findings) | code-engineer |
| ⬜ | 5.3 | Identify common failure patterns, file issues | code-engineer |
| ⬜ | 5.4 | SwiftUI `@main` app support — alternative entry strategy | exploit-engineer |
| ⬜ | 5.5 | Handle edge cases: FAT binaries, stripped symbols, arm64e, LC_VERSION_MIN | exploit-engineer |

---

## Phase 6: CLI Automation ✅

> Proper Python package installable via pip/pipx. Single `darkmach` command with 10 subcommands.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 6.1 | Design `darkmach` CLI — 10 subcommands: run, analyze, patch, launch, bridge, discover, hermes, keychain, list, status | ⬜ |
| ✅ | 6.2 | `darkmach run <app>` — full pipeline: analyze -> patch -> decrypt -> install -> launch with interceptors + bridge | ⬜ |
| ✅ | 6.3 | Two-pass FairPlay decryption — `simctl spawn` extraction + crypt dump caching | exploit-engineer |
| ✅ | 6.4 | Auto-boot Simulator if none running | ⬜ |
| ✅ | 6.5 | `darkmach analyze` — Python-native static analysis (ported from shell) | code-engineer |
| ✅ | 6.6 | `darkmach discover` — App Store discovery (ported from shell, iTunes API + amp-api) | ⬜ |
| ✅ | 6.7 | `darkmach hermes` — React Native / Hermes bytecode secret extraction | ⬜ |
| ✅ | 6.8 | `darkmach keychain` — Simulator keychain reader from host filesystem | ⬜ |
| ✅ | 6.9 | `darkmach list` — List installed iOS apps in /Applications | ⬜ |
| ✅ | 6.10 | `darkmach status` — System pre-flight check (Python-native, replaces shell) | ⬜ |
| ⬜ | 6.11 | Results aggregation — structured log of all findings per app | code-engineer |

---

## Phase 7: Project Restructure ✅

> Converted from scattered scripts to proper Python package with clean project layout.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 7.1 | Create `pyproject.toml` — setuptools build, `darkmach` console_scripts entry point | ⬜ |
| ✅ | 7.2 | Create `src/darkmach/` Python package with `__init__.py`, `cli.py`, `_paths.py` | ⬜ |
| ✅ | 7.3 | Move `dylibs/` and `patch/` under `src/` | ⬜ |
| ✅ | 7.4 | Create `Makefile` — builds all 10 dylibs + dump-region host tool | ⬜ |
| ✅ | 7.5 | Port `full-analysis.sh` -> `src/darkmach/analyze.py` (Python-native) | ⬜ |
| ✅ | 7.6 | Port `discover.sh` -> `src/darkmach/discover.py` (400-line shell -> Python) | ⬜ |
| ✅ | 7.7 | Port `check-system.sh` -> `darkmach status` command (Python-native) | ⬜ |
| ✅ | 7.8 | Migrate `darkmach-client.py` -> `src/darkmach/bridge.py` | ⬜ |
| ✅ | 7.9 | Migrate `hermes-extract.py` -> `src/darkmach/hermes.py` | ⬜ |
| ✅ | 7.10 | Migrate `keychain-reader.py` -> `src/darkmach/keychain.py` | ⬜ |
| ✅ | 7.11 | Per-app output organization: `output/<app>/static/`, `dynamic/`, `bundle/` | ⬜ |
| ✅ | 7.12 | `darkmach-core.h` updated to read `DARKMACH_OUTPUT_DIR` env var for dynamic log paths | mobile-engineer |
| ✅ | 7.13 | Delete superseded shell scripts, old `scripts/` dir, root `darkmach.py` | ⬜ |
| ✅ | 7.14 | Create `.gitignore` (dylibs, output, testing, venv, pycache) | ⬜ |
| ✅ | 7.15 | Create `testing/` directory as dev workbench (gitignored) | ⬜ |
| ✅ | 7.16 | Verify pip install + all subcommands working | ⬜ |

---

## Phase 8: Documentation ✅

> Comprehensive product and research documentation.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 8.1 | `docs/README.md` — Documentation landing page with badges and quick start | documentation-engineer |
| ✅ | 8.2 | `docs/installation.md` — Prerequisites, install, build, verify, troubleshoot | documentation-engineer |
| ✅ | 8.3 | `docs/cli-reference.md` — All 10 subcommands with args and examples | documentation-engineer |
| ✅ | 8.4 | `docs/architecture.md` — Project structure, pipeline, data flow | documentation-engineer |
| ✅ | 8.5 | `docs/interceptors.md` — All 10 dylibs, hooks, output format | documentation-engineer |
| ✅ | 8.6 | `docs/patching.md` — Two-pass FairPlay technique, all patch tools | documentation-engineer |
| ✅ | 8.7 | `docs/bridge.md` — Bridge protocol, command set, LLM exploration | documentation-engineer |
| ✅ | 8.8 | `docs/research/fairplay-bypass.md` — Novel discovery deep dive | documentation-engineer |
| ✅ | 8.9 | `docs/research/methodology.md` — Research approach, tool decisions | documentation-engineer |
| ✅ | 8.10 | `docs/research/findings.md` — OddsJam case study | documentation-engineer |
| ✅ | 8.11 | Root `README.md` rewritten for new CLI-based project structure | ⬜ |

---

## Phase 9: Bug Fixes ✅

> Bugs identified in independent assessment (2026-03-24). Fix before expanding features.

### 9.1 Medium Severity

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 9.1.1 | `bridge.py` + `cli.py` JSON framing — parse only first `\n`-delimited message via `data.split(b"\n", 1)[0]`. Fixed in both bridge.py and cli.py bridge_command. | mobile-engineer |
| ✅ | 9.1.2 | `discover.py` token override — added `DARKMACH_AMP_TOKEN` env var + `--token` CLI flag. Falls back to hardcoded default. `set_token()` API for programmatic use. | code-engineer |

### 9.2 Low Severity

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 9.2.1 | `hermes.py` type confusion — changed `.exists()` checks to truthiness checks (`if HBC_DECOMPILER:`) since `shutil.which` returns `str\|None`. | code-engineer |
| ✅ | 9.2.2 | `cli.py` input validation — added `validate_app_path()` checking existence, is-dir, .app suffix, Wrapper/ or Info.plist. Used in cmd_run, cmd_analyze, cmd_patch. | code-engineer |
| ✅ | 9.2.3 | `darkmach-tls.c` connection limit — added stderr warning when 512-slot table is full. Callers already had NULL checks (no crash risk). | mobile-engineer |
| ✅ | 9.2.4 | `darkmach-db.c` buffer limits — SQL buffer 512→2048, row columns 4KB→16KB, row data 8KB→24KB, sql_esc 2KB→4KB, bounds check margin 100→200. | mobile-engineer |
| ✅ | 9.2.5 | `darkmach-keychain.c` null guards — added `if (!orig_*)` early return on all 4 hooked functions. Returns `errSecUnimplemented`. (DYLD interpose makes NULL impossible, but now guarded.) | mobile-engineer |

---

## Phase 9.5: Linting & Code Quality ✅

> Strict ruff linting configured and enforced across all Python source. Zero violations.

| Status | Task | Description |
|--------|------|-------------|
| ✅ | 9.5.1 | Configured ruff in `pyproject.toml` — 26 rule groups, strict ignores only for intentional patterns (CLI print, subprocess, magic numbers). Per-file ignores for hermes.py, keychain.py, discover.py. |
| ✅ | 9.5.2 | Fixed 96 violations across 8 files — PLW1510 (subprocess check=False), PTH123 (pathlib), PERF401 (list comprehensions), E501 (line length), C401 (set comprehensions), RUF015 (next/iter), SIM105 (contextlib.suppress), B007 (unused loop vars), and more. |
| ✅ | 9.5.3 | Applied `ruff format` — consistent double quotes, space indent, auto line-ending across all source. |

---

## Phase 10: Test Suite ✅

> 581 pytest tests passing in 0.27s. Full coverage: Python CLI modules + patching pipeline (ARM64 encoders, Mach-O surgery, AppDelegate detection) + bridge formatters + type encoding parser + interpose safety.

### 10.1 Test Infrastructure

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 10.1.1 | pytest setup — `tests/` directory, `conftest.py`, `pyproject.toml` test config (`[tool.pytest.ini_options]`), markers for slow/integration | qa-engineer |
| ✅ | 10.1.2 | Test fixtures — `fake_app_bundle` (tmp_path .app with Info.plist + Wrapper), `mock_subprocess_run`, `mock_urlopen`, `make_completed_process` | qa-engineer |

### 10.2 Unit Tests — Patching Pipeline

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 10.2.1 | ARM64 instruction encoder tests — 111 tests: all 17 encoders verified against ISA spec (bit fields, opcodes, edge cases, alignment, boundaries) | exploit-engineer |
| ✅ | 10.2.2 | Mach-O patcher tests — 30 tests: platform patching, encryption zeroing, FAT 32/64-bit, thin binary, round-trip, idempotency, constants | exploit-engineer |
| ✅ | 10.2.3 | AppDelegate detection tests — 37 tests: 5-tier detection (Swift exact/variant/any, ObjC, nm, SwiftUI), SDK filtering, priority ordering, edge cases | exploit-engineer |
| ✅ | 10.2.4 | Shellcode generator tests — included in 10.2.1: end-to-end generate_main_patch, NOP sled, BRK/RET fill, string embedding, Strategy A/B | exploit-engineer |

### 10.3 Unit Tests — Python CLI

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 10.3.1 | Bridge protocol tests — 28 tests: JSON framing, UDS server integration, response formatting for all 15 command types, error paths | qa-engineer |
| ✅ | 10.3.2 | Static analysis tests — 44 tests: URL/secret/SDK extractors with edge cases, full `analyze_bundle` pipeline with mocked subprocess | qa-engineer |
| ✅ | 10.3.3 | Discovery tests — 22 tests: token validation (valid/expired/malformed), iTunes/amp-api parsing, all 5 Mac status outcomes, save/dedup | qa-engineer |
| ✅ | 10.3.4 | Hermes tests — 31 tests: bytecode detection, JS bundle finding, binary/JS string extraction, 14 secret pattern tests | qa-engineer |
| ✅ | 10.3.5 | Path resolution tests — 10 tests: ROOT, SRC_DIR, DYLIB_DIR, OUTPUT_DIR, BRIDGE_SOCKET, app output slug normalization | qa-engineer |

### 10.4 Integration Tests

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 10.4.1 | Patch pipeline integration — patch a test binary, verify with otool, confirm bootable in Simulator | exploit-engineer |
| ✅ | 10.4.2 | CLI smoke tests — 27 tests: `validate_app_path` (7 cases), arg parsing for all subcommands, `main()` dispatch error handling | qa-engineer |

---

---

## Phase 13: Bridge Capabilities ✅

> 20 new bridge commands organized into 7 sprints (13.0A restructure + 6 capability sprints). Transforms the bridge from an inspection tool into a full autonomous offensive platform.
>
> **Research references:**
> - `dev/frida-gum-study.md` — consolidated LOE report, sprint ordering, complexity estimates
> - `dev/frida-gum-interceptor-study.md` — exploit-engineer's ARM64 trampoline architecture study (sections 7-9 = design spec)
> - `dev/frida-gum-heap-study.md` — mobile-engineer's heap walking study (Analysis & Recommendations = design spec)
> - `.project/bridge-capabilities-brainstorm.md` — full capability descriptions, threat model, implementation concepts

### Conflict Zone Table

These files are touched by multiple agents and must NEVER be modified during parallel windows. Modifications happen only at gates between sprints.

| File | Risk | Resolution |
|------|------|------------|
| `src/dylibs/darkmach-core.h` | 🔴🔵 both may add helpers | Modify at sprint gates only. Sprint 13.0 pre-allocates all needed helpers. |
| `src/dylibs/bridge/darkmach-bridge.h` | 🔴🔵 shared types (ring buffers, hook table, response helpers) | Modify at sprint gates only. Created in Sprint 13.0A, settled at each gate. |
| `Makefile` | 🔴🔵 new assembly/dylib build rules | Modify at sprint gates only. Sprint 13.0A rewrites for modular structure, Sprint 13.0 adds remaining rules. |
| `src/darkmach/bridge.py` | 🔵🟣 C commands must sync with Python client | 🟣 code-engineer batches Python updates at sprint gates after C work is done. |

### Parallelization Map

```
Sprint 13.0A (Modular Restructure) — SEQUENTIAL, one agent restructures, all verify
    |
    v
Sprint 13.0 (Foundation Gate)  — SEQUENTIAL, all agents read, lead modifies shared files
    |
    v
Sprint 13.1 (Foundation)      — PARALLEL WINDOW 1
    |                            🔵 mobile-engineer: heap_dump, event_tap, db_inject in bridge/cmd-recon.c + bridge/cmd-events.c
    |                            🔵 mobile-engineer: env_dump in bridge/cmd-recon.c
    |                            🟣 code-engineer: ObjC type encoding parser in src/darkmach/typeenc.py (NEW file)
    |                            (No file conflicts — 🔵 owns bridge/cmd-*.c, 🟣 owns darkmach/)
    |
    v
Gate 13.1 → BUILD CHECK + Makefile update + bridge.py sync
    |
    v
Sprint 13.2 (Network Intel)   — PARALLEL WINDOW 2
    |                            🔵 mobile-engineer: net_tap, crypto_tap, auth_tap in bridge/cmd-network.c
    |                            🟣 code-engineer: bridge.py formatters for Sprint 13.1 + 13.2 commands
    |                            (No file conflicts)
    |
    v
Gate 13.2 → BUILD CHECK + bridge.py sync + test batch
    |
    v
Sprint 13.3 (The Trampoline)  — PARALLEL (true parallel, no sequential gate)
    |                            🔴 exploit-engineer: creates bridge/darkmach-trampoline.S + implements bridge/cmd-trace.c
    |                            🔵 mobile-engineer: bridge/darkmach-bridge.c dispatcher wiring for trace commands
    |                            🟣 code-engineer: bridge.py formatter for trace_log
    |                            🟢 qa-engineer: tests for Sprint 13.1-13.2 capabilities
    |                            (No file conflicts — 🔴 owns .S + cmd-trace.c, 🔵 owns darkmach-bridge.c, 🟣 owns darkmach/)
    |
    v
Gate 13.3 → BUILD CHECK + full regression test
    |
    v
Sprint 13.4 (Active)          — PARALLEL WINDOW 3
    |                            🔵 mobile-engineer: ui_interact in bridge/cmd-ui.c
    |                            🔴 exploit-engineer: stealth hooks (stealth/darkmach-stealth.c)
    |                            🟣 code-engineer: bridge.py formatters for Sprint 13.3 + 13.4 commands
    |                            (No file conflicts — 🔵 owns cmd-ui.c, 🔴 owns stealth/)
    |
    v
Gate 13.4 → BUILD CHECK + Makefile update for darkmach-stealth + bridge.py sync
    |
    v
Sprint 13.5 (Deep Analysis)   — PARALLEL WINDOW 4 (TRUE PARALLEL — no handoffs)
    |                            🔵 mobile-engineer: webview_extract in bridge/cmd-analysis.c, inject_class in bridge/cmd-inject.c, entitlement_scan in bridge/cmd-recon.c
    |                            🔴 exploit-engineer: pin_analyze in bridge/cmd-forensics.c (OWNS OUTRIGHT)
    |                            🟣 code-engineer: bridge.py formatters for all Sprint 13.5 commands
    |                            🟢 qa-engineer: tests for Sprint 13.3-13.4 capabilities
    |                            (No file conflicts — each agent owns separate files)
    |
    v
Gate 13.5 → BUILD CHECK + full regression test
    |
    v
Sprint 13.6 (Advanced)        — PARALLEL WINDOW 5 (TRUE PARALLEL — no handoffs)
    |                            🔵 mobile-engineer: block_inspect + proto_decode in bridge/cmd-analysis.c, sdk_map in bridge/cmd-recon.c
    |                            🔴 exploit-engineer: mem_forensics + timing_probe in bridge/cmd-forensics.c (OWNS OUTRIGHT)
    |                            🟣 code-engineer: bridge.py formatters for Sprint 13.6 commands
    |                            🟢 qa-engineer: tests for Sprint 13.5 capabilities
    |                            (No file conflicts — each agent owns separate files)
    |
    v
Gate 13.6 → FULL BUILD + ALL TESTS + bridge.py final sync + docs update
    |
    v
Phase 14 (LLM Autonomous Loop)
```

---

### 13.0A Modular Dylib Restructure (Sequential — Single Agent + All Verify)

> **CRITICAL PREREQUISITE**: The entire `src/dylibs/` directory is restructured into a modular layout BEFORE any capability work begins. This sprint is the foundation for all Phase 13 parallelism.
>
> **Why now:** `darkmach-bridge.c` is 1512 lines today and will grow to ~7000 lines with 20 new capabilities. A single monolithic file makes true parallel work impossible — every capability task touches the same file. The modular structure splits the bridge into a thin dispatcher (`darkmach-bridge.c`) plus domain-specific `cmd-*.c` files, each independently owned by a single engineer. This eliminates ALL handoff patterns from later sprints and enables true parallel development.
>
> **Estimated effort:** 1-2 days
> **This is SEQUENTIAL work** — one agent restructures, then everyone verifies.

#### New Directory Structure

```
src/dylibs/
├── darkmach-core.h                  # Shared header (stays at root — everyone includes it)
│
├── bridge/                        # LLM bridge + all command modules
│   ├── darkmach-bridge.c            # Main: UDS server, dispatcher, shared state
│   ├── darkmach-bridge.h            # Internal: ring buffers, hook table, response helpers
│   ├── cmd-recon.c                # heap_dump, env_dump, sdk_map, entitlement_scan
│   ├── cmd-network.c              # net_tap, crypto_tap, auth_tap
│   ├── cmd-trace.c                # trace, trace_class, trace_log
│   ├── cmd-ui.c                   # ui_tap, ui_type, ui_scroll, ui_back
│   ├── cmd-analysis.c             # webview_extract, block_inspect, proto_decode
│   ├── cmd-forensics.c            # mem_forensics, timing_probe, pin_analyze
│   ├── cmd-inject.c               # inject_class, inject_method, replace_delegate
│   ├── cmd-events.c               # event_tap, db_inject, db_queries
│   └── darkmach-trampoline.S        # ARM64 assembly for trace (created in Sprint 13.3)
│
├── interceptors/                  # Data capture dylibs (DYLD_INTERPOSE)
│   ├── darkmach-net.c               # NSURLSession hooks
│   ├── darkmach-crypto.c            # CommonCrypto hooks
│   ├── darkmach-keychain.c          # Security.framework hooks
│   ├── darkmach-db.c                # SQLite hooks
│   ├── darkmach-tls.c               # TLS connection tracking
│   ├── darkmach-ssl.c               # Cert pinning bypass
│   └── darkmach-storage.c           # NSUserDefaults/file hooks
│
├── stealth/                       # Anti-analysis evasion (created in Sprint 13.4)
│   └── darkmach-stealth.c           # sysctl/ptrace/dyld hiding
│
├── compat/                        # Simulator compatibility
│   ├── darkmach-metal-fix.c         # GPU framework stub
│   ├── darkmach-decrypt.c           # FairPlay analysis
│   └── darkmach-bootstrap.dylib     # Strategy B entry point
│
└── tools/                         # Host-side utilities (native macOS, not Simulator)
    └── dump-region.c              # Mach task memory reader
```

> **Build output decision**: All `.dylib` files are still output to `src/dylibs/` root. Source files live in subdirectories, but built artifacts stay flat at `src/dylibs/*.dylib`. This preserves all existing `DYLIB_DIR` references in `_paths.py` and `cli.py` with ZERO changes to Python code. The Makefile uses `VPATH` or explicit source paths to find `.c` files in subdirectories while outputting to the root.

#### File Ownership After Restructure

| Path | Owner | Notes |
|------|-------|-------|
| `src/dylibs/darkmach-core.h` | CONFLICT ZONE | Sequential only — both 🔵 and 🔴 may need to modify |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Main dispatcher only |
| `src/dylibs/bridge/darkmach-bridge.h` | CONFLICT ZONE | Shared types — settle at gates |
| `src/dylibs/bridge/cmd-recon.c` | 🔵 mobile-engineer | heap_dump, env_dump, sdk_map, entitlement_scan |
| `src/dylibs/bridge/cmd-network.c` | 🔵 mobile-engineer | net_tap, crypto_tap, auth_tap |
| `src/dylibs/bridge/cmd-events.c` | 🔵 mobile-engineer | event_tap, db_inject |
| `src/dylibs/bridge/cmd-ui.c` | 🔵 mobile-engineer | ui_interact commands |
| `src/dylibs/bridge/cmd-analysis.c` | 🔵 mobile-engineer | webview, block_inspect, proto_decode |
| `src/dylibs/bridge/cmd-inject.c` | 🔵 mobile-engineer | inject_class, replace_delegate |
| `src/dylibs/bridge/cmd-trace.c` | 🔴 exploit-engineer | trace integration — OWNS OUTRIGHT |
| `src/dylibs/bridge/cmd-forensics.c` | 🔴 exploit-engineer | mem_forensics, timing_probe, pin_analyze — OWNS OUTRIGHT |
| `src/dylibs/bridge/darkmach-trampoline.S` | 🔴 exploit-engineer | ARM64 assembly — OWNS OUTRIGHT |
| `src/dylibs/stealth/darkmach-stealth.c` | 🔴 exploit-engineer | OWNS OUTRIGHT |
| `src/dylibs/interceptors/*` | 🔵 mobile-engineer | Existing, minimal changes expected |
| `src/dylibs/compat/*` | 🔵 mobile-engineer | Existing, no changes expected |
| `src/dylibs/tools/*` | 🔴 exploit-engineer | Host tools |
| `Makefile` | CONFLICT ZONE | Major rewrite for new structure — modify at gates only |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.0A.1 | **Create directory structure** — Create subdirectories: `src/dylibs/bridge/`, `src/dylibs/interceptors/`, `src/dylibs/stealth/`, `src/dylibs/compat/`, `src/dylibs/tools/`. These are the domain folders for the modular layout. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.0A.2 | **Move interceptor dylibs** — Move existing interceptor source files to `src/dylibs/interceptors/`: `darkmach-net.c`, `darkmach-crypto.c`, `darkmach-keychain.c`, `darkmach-db.c`, `darkmach-tls.c`, `darkmach-ssl.c`, `darkmach-storage.c`. Update `#include` paths if they reference `darkmach-core.h` (now at `../darkmach-core.h` or use `-I` flag in Makefile). Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.0A.3 | **Move compat dylibs** — Move `darkmach-metal-fix.c` and `darkmach-decrypt.c` to `src/dylibs/compat/`. Move `darkmach-bootstrap.dylib` to `src/dylibs/compat/`. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.0A.4 | **Move host tools** — Move `dump-region.c` (and its compiled `dump-region` binary) to `src/dylibs/tools/`. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.0A.5 | **Split darkmach-bridge.c into modular files** — This is the critical task. (a) Move `darkmach-bridge.c` to `src/dylibs/bridge/darkmach-bridge.c`. (b) Extract shared types, ring buffer structs, hook table struct, response helper macros into `src/dylibs/bridge/darkmach-bridge.h`. The main file includes this header. (c) Extract existing bridge command implementations (the current 17 commands) into the appropriate `cmd-*.c` files: existing recon/inspection commands (enumerate_classes, get_methods, get_properties, get_ivars, read_property, call_method, heap_search, read_memory, view_hierarchy, info) go to `cmd-recon.c`; data extraction commands (keychain_dump, userdefaults_dump, cookies_dump, db_dump) go to `cmd-events.c`; hook commands (hook_method, unhook_method) go to `cmd-trace.c`. Each `cmd-*.c` file includes `darkmach-bridge.h` and `../darkmach-core.h`. (d) Create empty stub files with proper includes for future command files: `cmd-network.c`, `cmd-ui.c`, `cmd-analysis.c`, `cmd-forensics.c`, `cmd-inject.c`. Each stub has the boilerplate includes and a placeholder comment. (e) The main `darkmach-bridge.c` retains: UDS server code, JSON parsing, command dispatcher (switch/if-chain that calls into cmd-*.c functions), shared state (ring buffers, hook table), and `__attribute__((constructor))`. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.0A.6 | **Rewrite Makefile for modular structure** — Rewrite the Makefile to build from the new directory layout. Source files are in subdirectories; all `.dylib` outputs go to `src/dylibs/` root (preserving existing `DYLIB_DIR` paths). Key changes: (a) `darkmach-bridge.dylib` rule compiles `bridge/darkmach-bridge.c` + all `bridge/cmd-*.c` files + links them together (use `-x objective-c` for all bridge sources). (b) Interceptor dylib rules reference `interceptors/*.c`. (c) Compat dylib rules reference `compat/*.c`. (d) `dump-region` rule references `tools/dump-region.c`. (e) Add `-I` include path flags so `#include "darkmach-core.h"` and `#include "darkmach-bridge.h"` resolve correctly from subdirectories. (f) Keep `sign`, `clean`, `all` targets working. (g) Add placeholder rules for future files: `darkmach-trampoline.o` (commented out, activated in Sprint 13.0), `darkmach-stealth.dylib` (commented out, activated in Sprint 13.4). Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.0A.7 | **Verify build and runtime** — Run `make clean && make all` and confirm all dylibs build successfully. Run `pytest tests/` and confirm all tests pass. Verify dylib paths: all `.dylib` files are still at `src/dylibs/*.dylib` (not in subdirectories). If a live app is available, launch it with bridge injection and verify the bridge still responds to all existing commands. Check that `darkmach status` reports all dylibs present. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer + 🔴 exploit-engineer |
| ✅ | 13.0A.8 | **Update CLAUDE.md project structure** — Update the `src/dylibs/` section of `.claude/CLAUDE.md` to reflect the new modular directory layout. Update the DYLD Injection table with new file paths. This keeps documentation synchronized with the restructure. Execute as agent team with file-boundary isolation. | 📘 documentation-engineer |

**Gate 13.0A**: `make clean && make all` builds every dylib. All `.dylib` files are at `src/dylibs/*.dylib` (flat output). All existing tests pass (`pytest tests/`). `darkmach status` shows all dylibs present. Bridge injection works against a live app (if available). The codebase is now modular and ready for parallel capability development.

---

### 13.0 Foundation Gate (Sequential — Lead + All Agents Read)

> Pre-allocate all shared infrastructure changes before any parallel work begins. This gate prevents conflict zone collisions in all subsequent sprints.

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.0.1 | **darkmach-core.h shared helpers** — Added ring buffer infrastructure (`darkmach_ring_t` struct, `darkmach_ring_init`, `darkmach_ring_push`, `darkmach_ring_get`; capacity 500, entry size 4096), hook table struct (`darkmach_hook_t` with cls/sel/original_imp/class_name/sel_name/type_encoding/active/call_count; `DARKMACH_MAX_HOOKS` = 256), heap scan result structs (`darkmach_heap_candidate_t`, `darkmach_heap_scan_t`; max 10000 results), reentrancy guard comment spec (`pthread_key_t darkmach_guard_key` defined in cmd-trace.c). All 4 sections appended before `#endif`. Build verified: `make all` clean, 398 tests pass. | 🔵 mobile-engineer |
| ✅ | 13.0.2 | **Makefile build rules** — Activated `darkmach-trampoline.o` build rule (`$(CC) -target $(TARGET) -isysroot $(SDK) -c` from `bridge/darkmach-trampoline.S`). Updated `darkmach-bridge.dylib` to optionally link trampoline via `$(wildcard $(DYLIB_DIR)/darkmach-trampoline.o)` — expands to empty when `.o` absent, auto-includes when built. Added conditional `darkmach-stealth.dylib` rule via `ifneq ($(wildcard ...),)` — activates only when source exists. Clean target updated to remove `$(TRAMPOLINE_OBJ)`. Build verified: `make clean && make all` succeeds (10 dylibs + dump-region), 398 tests pass. | 🔴 exploit-engineer |
| ✅ | 13.0.3 | **Command protocol spec** — Created `dev/bridge-command-spec.md` with complete JSON command/response schemas for all 40 bridge commands (18 existing + 22 new across 6 sprints). Each command: name, sprint, file, args table with types/defaults, response data schema, wire-format example, implementation notes. Includes dispatcher registration template, C function signature convention, JSON parser limitation docs, Python client compatibility note. This is the contract that 🔵 and 🟣 both code against. | 🔵 mobile-engineer |

**Gate 13.0**: All agents verify shared files are correct. `make all` succeeds. Existing tests pass.

---

### 13.1 Foundation Sprint — Parallel Window 1

> Easiest high-impact capabilities. No dependencies. Maximum parallelism between 🔵 and 🟣.
>
> **Estimated effort:** 3-4 days
> **Estimated LOC:** ~600 (C) + ~300 (Python)

#### File Ownership — Window 1

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/cmd-recon.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/cmd-events.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring) |
| `src/dylibs/bridge/darkmach-bridge.h` | FROZEN | No modifications during this window |
| `src/dylibs/darkmach-core.h` | FROZEN | No modifications during this window |
| `src/darkmach/typeenc.py` (NEW) | 🟣 code-engineer | Read only |
| `Makefile` | FROZEN | No modifications during this window |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.1.1 | **`heap_dump` command** — Implement full malloc zone walking heap enumeration in `src/dylibs/bridge/cmd-recon.c`. Use `malloc_get_all_zones()` + `zone->introspect->enumerator` with `MALLOC_PTR_IN_USE_RANGE_TYPE` to collect all in-use allocations. Phase A: collect (address, size) pairs into pre-allocated buffer (no malloc during enumeration callback to avoid deadlock). Phase B: validate each candidate isa pointer against class set built from `objc_getClassList()`. Support optional `class` filter arg. Return paginated JSON: `{instances: [{addr, class, size}], total_scanned, time_ms}`. Wire dispatch entry in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `dev/frida-gum-heap-study.md` "Analysis & Recommendations" section for the 4-phase algorithm, thread safety mitigations, and the sketch in Appendix A. ~150 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.1.2 | **`event_tap` command** — Implement NSNotificationCenter event monitoring in `src/dylibs/bridge/cmd-events.c`. On `event_tap enable`: swizzle `-[NSNotificationCenter postNotificationName:object:userInfo:]` to capture all notification posts into a ring buffer (name, posting object class, userInfo keys, timestamp). On `event_tap recent` (or `event_tap` with no subcommand): return last N events. Support `name_filter` arg for pattern matching. Register catch-all observer via `addObserverForName:nil object:nil queue:nil usingBlock:` as secondary capture. Ring buffer capacity: 500 events. Wire dispatch entry in `src/dylibs/bridge/darkmach-bridge.c`. ~200 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.1.3 | **`env_dump` command** — Implement process environment extraction in `src/dylibs/bridge/cmd-recon.c`. Iterate `extern char **environ` for all environment variables. Read `[[NSProcessInfo processInfo] arguments]` for launch args. Iterate `_dyld_image_count()` / `_dyld_get_image_name()` / `_dyld_get_image_header()` for loaded image list with ASLR slide (`_dyld_get_image_vmaddr_slide()`). Iterate file descriptors 0-1024 via `fcntl(fd, F_GETFL)` and `fcntl(fd, F_GETPATH, buf)`. Return structured JSON with `{env, args, images, fds}` sections. Wire dispatch entry in `src/dylibs/bridge/darkmach-bridge.c`. ~100 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.1.4 | **`db_inject` command** — Extend existing db commands in `src/dylibs/bridge/cmd-events.c` to support write operations. Add `db_query` command accepting `{path, sql, params}` that calls `sqlite3_prepare_v2` + `sqlite3_step` for arbitrary SQL (INSERT/UPDATE/DELETE/SELECT). Interpose `sqlite3_prepare_v2` to log all live queries with bound parameters into a ring buffer. Add `db_queries` command returning recent intercepted queries. Reuse existing sqlite3 link flags. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. ~150 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.1.5 | **ObjC type encoding parser** — Create new file `src/darkmach/typeenc.py`. Parse ObjC type encoding strings (from `method_getTypeEncoding`) into structured Python types. Handle: `@` = ObjC object, `i`/`l`/`q`/`I`/`L`/`Q` = integers, `f`/`d` = float/double, `*` = C string, `#` = Class, `:` = SEL, `{Name=...}` = struct, `^` = pointer, `@?` = block, `B` = BOOL, `c`/`C`/`s`/`S` = char/short variants, `v` = void. Return list of `TypeInfo(encoding, python_name, size, is_object)`. Include utility to format argument values based on type (e.g., truncate long object descriptions, hex-format pointers, SELs as name). This parser is used by `trace` command formatting in Sprint 13.3. ~200 lines of Python. Write unit tests in `tests/test_typeenc.py`. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |
| ✅ | 13.1.6 | **Type encoding parser tests** — Create `tests/test_typeenc.py` with comprehensive tests for the ObjC type encoding parser from 13.1.5. Test all primitive types, object types, struct encodings, pointer types, block types, nested structs, method signature parsing (return type + args with offsets), edge cases (empty string, malformed encodings). Target: 30+ tests. Execute as agent team with file-boundary isolation. | 🟢 qa-engineer |

**Gate 13.1**: `make all` succeeds. All existing tests pass. New `heap_dump`, `event_tap`, `env_dump`, `db_inject` commands respond to bridge requests (verify via manual `darkmach bridge` session if app is available, or code review). `test_typeenc.py` passes.

**Gate 13.1 shared file updates** (sequential, lead executes):
- 🟣 code-engineer adds `format_response` handlers for `heap_dump`, `event_tap`, `env_dump`, `db_inject`, `db_query`, `db_queries` in `src/darkmach/bridge.py`
- 🟣 code-engineer adds argument parsing for new commands in `bridge.py:parse_cli_args()`
- Verify: `ruff check src/ tests/` clean

---

### 13.2 Network Intelligence Sprint — Parallel Window 2

> Wire existing interceptor dylibs into the bridge. The C intercept code already exists in darkmach-net.c and darkmach-crypto.c — this sprint exposes captured data through bridge commands.
>
> **Estimated effort:** 3-4 days
> **Estimated LOC:** ~1000 (C) + ~200 (Python)

#### File Ownership — Window 2

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/cmd-network.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring) |
| `src/darkmach/bridge.py` | 🟣 code-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.h` | FROZEN | No modifications during this window |
| `src/dylibs/darkmach-core.h` | FROZEN | No modifications during this window |
| `Makefile` | FROZEN | No modifications during this window |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| :white_check_mark: | 13.2.1 | **`net_tap` command** — Implement full HTTP request/response interception exposed through the bridge in `src/dylibs/bridge/cmd-network.c`. Swizzle `NSURLSession dataTaskWithRequest:completionHandler:` and delegate-based variants. Wrap completion handler blocks to capture response data. For each request/response pair, store in ring buffer (capacity 500): `{id, url, method, req_headers, req_body_preview, status, resp_headers, resp_body_preview, duration_ms, timestamp}`. Commands: `net_tap` (returns recent N entries), `net_filter {host, path, status}` (filtered view). Truncate bodies to 512B preview. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 1.2 for full implementation concept. ~400 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| :white_check_mark: | 13.2.2 | **`crypto_tap` command** — Implement live cryptographic key extraction in `src/dylibs/bridge/cmd-network.c`. DYLD_INTERPOSE on `CCCrypt`, `CCHmac`. For each operation, log to ring buffer: `{op, algorithm, encrypt, key_hex, iv_hex, input_len, output_preview, timestamp}`. Commands: `crypto_tap` (returns recent operations), `crypto_keys` (returns deduplicated key material with use_count). Detects darkmach-crypto.dylib coexistence via DYLD interpose resolution. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 1.1. ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| :white_check_mark: | 13.2.3 | **`auth_tap` command** — Implement OAuth/authentication flow recording in `src/dylibs/bridge/cmd-network.c`. Hook `LAContext evaluatePolicy:localizedReason:reply:` for biometric auth capture. Monitor `net_tap` ring buffer for OAuth-pattern URLs (`/oauth/token`, `/token`, `/.well-known/openid-configuration`). Parse JWT tokens inline (base64url-decode header+payload, report claims). Detect Bearer tokens in Authorization headers. Commands: `auth_tap` (returns authentication event timeline), `auth_tokens` (returns extracted/decoded tokens with claims). Depends on `net_tap` ring buffer from 13.2.1. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 2.1. ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| :white_check_mark: | 13.2.4 | **bridge.py Sprint 13.1 + 13.2 formatters** — Add `format_response` handlers in `src/darkmach/bridge.py` for all commands from Sprints 13.1 and 13.2: `heap_dump` (table of instances with address/class/size), `event_tap` (timestamped notification list), `env_dump` (sectioned env/args/images/fds), `db_inject`/`db_query`/`db_queries` (SQL results table), `net_tap`/`net_filter` (HTTP traffic summary with method/URL/status/duration), `crypto_tap`/`crypto_keys` (operation log with algorithms and key previews), `auth_tap`/`auth_tokens` (auth flow timeline with decoded JWT claims). Add corresponding `parse_cli_args` entries. Follow existing format_response pattern (switch on cmd string). Reference: `dev/bridge-command-spec.md` (created in 13.0.3) for response schemas. ~200 lines of Python. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |

**Gate 13.2**: `make all` succeeds. All tests pass (`pytest tests/`). `ruff check src/ tests/` clean. Bridge responds to `net_tap`, `crypto_tap`, `auth_tap` commands. Python formatters render clean output for all 7+ new commands.

---

### 13.3 The Trampoline Sprint — Parallel (True Parallel)

> The crown jewel: method tracing with full argument and return value capture. This is the highest-complexity capability. Requires ARM64 assembly from 🔴, C integration by 🔴 (owns cmd-trace.c), dispatcher wiring by 🔵, and Python formatting by 🟣.
>
> **Key change from pre-modular plan:** Because 🔴 exploit-engineer now OWNS `bridge/cmd-trace.c` outright, there is no sequential Phase A -> Phase B dependency. 🔴 works on the trampoline `.S` file AND `cmd-trace.c` simultaneously (or sequentially at their discretion). 🔵 only needs to wire the dispatch entry in `darkmach-bridge.c` — a 5-line change. All agents work in true parallel.
>
> **Estimated effort:** 4-5 days
> **Estimated LOC:** ~500 (C + ASM) + ~100 (Python)

#### File Ownership — Trampoline Sprint

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/darkmach-trampoline.S` | 🔴 exploit-engineer | Read only |
| `src/dylibs/bridge/cmd-trace.c` | 🔴 exploit-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring for trace commands) |
| `src/darkmach/bridge.py` | 🟣 code-engineer | Read only |
| `tests/` | 🟢 qa-engineer | Read only by others |
| `src/dylibs/bridge/darkmach-bridge.h` | FROZEN | No modifications during this window |
| `src/dylibs/darkmach-core.h` | FROZEN | No modifications during this window |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.3.1 | **`darkmach-trampoline.S` — ARM64 method tracing trampoline** — Create new file `src/dylibs/bridge/darkmach-trampoline.S`. Implement the shared trampoline that all traced methods dispatch through. The trampoline: (1) saves frame (STP FP, LR), (2) saves argument registers X0-X8 + Q0-Q7 to stack frame (208 bytes, 16-byte aligned), (3) calls `_darkmach_on_method_enter(hook_descriptor_ptr, saved_regs_ptr)` via BL, (4) restores all registers, (5) tail-calls original IMP via `LDR X16, [X17, #offset_to_original_imp]; BR X16`. X17 carries the `darkmach_hook_t*` pointer from per-hook stubs. Total: ~26 instructions. Reference: `dev/frida-gum-interceptor-study.md` sections 9.1 (strategy recommendation), 9.4 (exact register save layout and instruction sequence), 9.5 (per-hook stub generation). Also reference section 4 (Frida's glue.S) for the prolog/epilog pattern we simplify. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.3.2 | **Per-hook stub slots** — In `src/dylibs/bridge/darkmach-trampoline.S`, add 256 static stub slots. Each stub: `ADRP X17, hook_table@PAGE; ADD X17, X17, hook_table@PAGEOFF + (N * sizeof(darkmach_hook_t)); B _darkmach_method_trampoline`. These are the IMP replacements installed by `method_setImplementation`. Stubs are 12 bytes each (ADRP+ADD+B), 256 stubs = 3KB. Reference: `dev/frida-gum-interceptor-study.md` section 9.5 for static vs. dynamic stub approaches. The `hook_table` symbol is defined in `src/dylibs/bridge/cmd-trace.c` and resolved at link time. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.3.3 | **`trace` command — C integration** — Implement `cmd_trace` in `src/dylibs/bridge/cmd-trace.c`. On `trace {class, method}`: find the Method via `class_getInstanceMethod`, call `method_getTypeEncoding` to get type info, allocate a `darkmach_hook_t` slot from `hook_table`, store class/sel/original_imp, call `method_setImplementation(method, darkmach_stub_N)` to install the trampoline. Implement `_darkmach_on_method_enter(darkmach_hook_t *hook, void *saved_regs)` — the C handler called from the trampoline: check reentrancy guard (`pthread_getspecific`), read self (X0), _cmd (X1), and user args (X2-X7) from saved registers, format type-aware argument descriptions using `method_getTypeEncoding` (ObjC objects call `description`, integers format as decimal, pointers as hex, SELs as name). Log entry to per-hook ring buffer. Support `trace_class {class}` to hook ALL methods on a class. Support `trace_log` to query recent trace entries. Support `untrace` to remove hooks. Define `hook_table` global symbol (referenced by trampoline stubs). Reference: `dev/frida-gum-interceptor-study.md` sections 7.3-7.4 (what to implement), 8.1 (X17 convention), 9.2 (hook table design), 9.3 (reentrancy guard). ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.3.4 | **`trace` dispatcher wiring** — Wire `trace`, `trace_class`, `trace_log`, and `untrace` command dispatch entries in `src/dylibs/bridge/darkmach-bridge.c` to call the corresponding functions in `cmd-trace.c`. This is a thin wiring task — the dispatcher calls `cmd_trace()`, `cmd_trace_class()`, `cmd_trace_log()`, `cmd_untrace()` functions. ~20 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.3.5 | **Verify trampoline build** — Ensure `make all` builds `darkmach-trampoline.o` and links it into `darkmach-bridge.dylib`. Disassemble with `otool -tv src/dylibs/darkmach-bridge.dylib` to verify trampoline symbol is present and instructions are correct. Verify stub slots are addressable. Fix any linker issues. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.3.6 | **`trace` command — Python formatter** — Add `format_response` handler in `src/darkmach/bridge.py` for `trace`, `trace_class`, `trace_log`, `untrace` commands. `trace_log` output: timestamped table showing `[timestamp] -[ClassName method:arg1:] self=0x... args: {arg0_type: arg0_value, arg1_type: arg1_value, ...} -> return_value`. Use `src/darkmach/typeenc.py` (from 13.1.5) to render type names in the trace output. Add `parse_cli_args` entries. ~80 lines of Python. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |
| ✅ | 13.3.7 | **Sprint 13.1-13.2 test batch** — Write tests for bridge.py formatters added in Gate 13.1 and Sprint 13.2. Test `format_response` for: `heap_dump` (empty results, single instance, multiple instances), `event_tap` (empty, filtered, ring buffer full), `env_dump` (all sections present), `net_tap` (request/response rendering, body truncation), `crypto_tap` (key hex formatting), `auth_tap` (JWT decode display). Add to `tests/test_bridge.py`. Target: 20+ new tests. Execute as agent team with file-boundary isolation. | 🟢 qa-engineer |

**Gate 13.3**: `make all` succeeds. Full regression: `pytest tests/` passes (including new tests). The `trace` command installs a hook, the trampoline fires on method calls, `trace_log` returns captured invocations with decoded arguments. This is the most important verification point in the entire phase — trace is the hardest capability.

---

### 13.4 Active Capabilities Sprint — Parallel Window 3

> UI automation for the LLM and stealth mode for hardened apps. 🔵 and 🔴 work on separate files — zero conflicts.
>
> **Estimated effort:** 3-4 days
> **Estimated LOC:** ~700 (C) + ~150 (Python)

#### File Ownership — Window 3

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/cmd-ui.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring) |
| `src/dylibs/stealth/darkmach-stealth.c` | 🔴 exploit-engineer | Read only |
| `src/darkmach/bridge.py` | 🟣 code-engineer | Read only |
| `Makefile` | FROZEN | Updated at gate |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.4.1 | **`ui_interact` command** — Implement UI automation in `src/dylibs/bridge/cmd-ui.c`. `ui_tap {x, y}` or `ui_tap {accessibility_label}` or `ui_tap {class, text}`: synthesize UITouch events via `UIApplication sendEvent:` or invoke button target-action directly via `sendActionsForControlEvents:UIControlEventTouchUpInside`. `ui_type {text, field_address}`: call `becomeFirstResponder` then `insertText:` via UITextInput protocol. `ui_scroll {view_address, dx, dy}`: set contentOffset on UIScrollView. `ui_back`: pop navigation controller or dismiss presented VC. `ui_alert_dismiss {button_index}`: find UIAlertController on heap, tap specified button action. ALL actions dispatch to main thread via `dispatch_async(dispatch_get_main_queue(), ...)`. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 1.4 for full concept. ~350 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.4.2 | **`stealth` capability** — Create new file `src/dylibs/stealth/darkmach-stealth.c`. Implement anti-analysis evasion as a standalone DYLD-injectable dylib. DYLD_INTERPOSE on: `sysctl` (filter P_TRACED flag from kinfo_proc result), `ptrace` (no-op PT_DENY_ATTACH), `getenv` (return NULL for DYLD_INSERT_LIBRARIES). Swizzle `_dyld_image_count` and `_dyld_get_image_name` to filter out darkmach dylibs from the image list. Swizzle `NSFileManager fileExistsAtPath:` to return NO for jailbreak artifact paths (/bin/bash, /Applications/Cydia.app, etc). Hook `stat`, `access` for jailbreak paths. Add bridge integration: `stealth_scan` (detect which anti-analysis techniques the app uses by scanning class names and string table for known patterns: iXGuard, Arxan, etc), `stealth_enable` (activate all evasion hooks), `stealth_status` (report active bypasses). Reference: `.project/bridge-capabilities-brainstorm.md` section 3.5. ~350 lines of C. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.4.3 | **bridge.py Sprint 13.3 + 13.4 formatters** — Add `format_response` handlers in `src/darkmach/bridge.py` for: `trace`/`trace_class`/`trace_log`/`untrace` (from 13.3), `ui_tap`/`ui_type`/`ui_scroll`/`ui_back`/`ui_alert_dismiss` (from 13.4.1), `stealth_scan`/`stealth_enable`/`stealth_status` (from 13.4.2). Trace formatter uses `typeenc.py` for argument type display. UI formatters show action confirmation + result. Stealth formatter shows detection inventory + bypass status table. ~150 lines of Python. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |

**Gate 13.4** (sequential — lead executes):
- Activate `darkmach-stealth.dylib` build rule in `Makefile` (source: `src/dylibs/stealth/darkmach-stealth.c`, link: `-framework Foundation -framework Security -lobjc`, output: `src/dylibs/darkmach-stealth.dylib`)
- Add `darkmach-stealth.dylib` to `DYLIBS` list and `sign` target
- Wire `stealth_scan`/`stealth_enable`/`stealth_status` dispatch into `src/dylibs/bridge/darkmach-bridge.c` cmd_dispatch (if implemented as bridge commands rather than standalone dylib commands)
- `make all` succeeds. `pytest tests/` passes. `ruff check src/ tests/` clean.

---

### 13.5 Deep Analysis Sprint — Parallel Window 4 (True Parallel)

> WebView extraction, runtime class injection, entitlement scanning, SSL pin analysis. Four capabilities that significantly expand intelligence surface.
>
> **Key change from pre-modular plan:** The handoff pattern for `pin_analyze` is ELIMINATED. 🔴 exploit-engineer now owns `bridge/cmd-forensics.c` outright and implements `pin_analyze` directly in that file. No coordination with 🔵 needed for file access. 🔵 only wires the dispatch entry in `darkmach-bridge.c`.
>
> **Estimated effort:** 4-5 days
> **Estimated LOC:** ~1100 (C) + ~150 (Python)

#### File Ownership — Window 4

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/cmd-analysis.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/cmd-inject.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/cmd-recon.c` | 🔵 mobile-engineer | Read only (entitlement_scan) |
| `src/dylibs/bridge/cmd-forensics.c` | 🔴 exploit-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring) |
| `src/darkmach/bridge.py` | 🟣 code-engineer | Read only |
| `tests/` | 🟢 qa-engineer | Read only by others |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.5.1 | **`webview_extract` command** — Implement WKWebView discovery and extraction in `src/dylibs/bridge/cmd-analysis.c`. Use `heap_dump` infrastructure (from 13.1.1) to find all WKWebView instances. For each: read `configuration` -> `userContentController` -> enumerate `userScripts` and script message handlers (via `_scriptMessageHandlers` private API or known handler name probing). `webview_list`: returns all WebViews with URLs and bridge config. `webview_eval {address, js}`: calls `evaluateJavaScript:completionHandler:` on a specific WebView (dispatch to main thread). `webview_content {address}`: returns `document.documentElement.outerHTML`. `webview_bridge_map`: returns all registered WKScriptMessageHandlers. Requires heap_dump from 13.1.1. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 3.7. ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.5.2 | **`inject_class` command** — Implement runtime class synthesis in `src/dylibs/bridge/cmd-inject.c`. `inject_class {name, superclass, protocols}`: calls `objc_allocateClassPair`, adds protocol conformance via `class_addProtocol`, registers with `objc_registerClassPair`. `inject_method {class, selector, implementation}`: calls `class_addMethod` with a pre-built implementation from catalog (log_all_args, return_yes, return_no, return_nil, forward_to_original). `replace_delegate {object_address, delegate_property, new_class}`: instantiate the injected class, set as delegate, chain to original. Pre-built implementation catalog: 5 IMP functions compiled into the bridge. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 2.4. ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.5.3 | **`entitlement_scan` command** — Implement entitlement extraction in `src/dylibs/bridge/cmd-recon.c`. Parse LC_CODE_SIGNATURE from Mach-O headers to extract embedded entitlements plist. Enumerate all loaded images via `_dyld_image_count()` / `_dyld_get_image_header()`. Extract entitlements from each image's code signature. Parse app group IDs, keychain access groups, associated domains. Check for shared container at `~/Library/Group Containers/<group-id>/` and scan contents. Return structured JSON with risk annotations (overprivileged entitlements flagged). Wire dispatch entry in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 2.5. ~200 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.5.4 | **`pin_analyze` command** — Implement certificate pinning analysis directly in `src/dylibs/bridge/cmd-forensics.c`. Hook `SecTrustEvaluateWithError` and `SecTrustEvaluate` to capture trust evaluation results. Extract certificate chain via `SecTrustGetCertificateAtIndex` + `SecCertificateCopyData`. Extract public key hashes via `SecCertificateCopyKey` + `SecKeyCopyExternalRepresentation` + CC_SHA256. Detect TrustKit (check for `kTSKPinnedDomains` class/config). Detect ATS config from NSBundle Info.plist. `pin_analyze`: returns pinned hosts, pin types, pin values, bypass status. `pin_extract`: returns raw DER certificate data. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 2.2. ~250 lines of C. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.5.5 | **bridge.py Sprint 13.5 formatters** — Add `format_response` handlers in `src/darkmach/bridge.py` for: `webview_list`/`webview_eval`/`webview_content`/`webview_bridge_map`, `inject_class`/`inject_method`/`replace_delegate`, `entitlement_scan`/`shared_container_scan`, `pin_analyze`/`pin_extract`. ~100 lines of Python. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |
| ✅ | 13.5.6 | **Sprint 13.3-13.4 test batch** — Write tests for Sprint 13.3 and 13.4 formatters. Test trace_log formatting with type-aware argument display (verify typeenc.py integration). Test ui_interact command confirmation formatting. Test stealth_scan detection list rendering. Test stealth_status bypass table. Add to `tests/test_bridge.py`. Target: 15+ new tests. Execute as agent team with file-boundary isolation. | 🟢 qa-engineer |

**Gate 13.5**: `make all` succeeds. Full regression: `pytest tests/` passes. All Sprint 13.5 commands respond via bridge. `webview_extract` finds WKWebViews on heap. `entitlement_scan` parses code signatures. `pin_analyze` extracts certificate data. `inject_class` creates and registers new ObjC classes.

---

### 13.6 Advanced Sprint — Parallel Window 5 (True Parallel)

> High-complexity capabilities and protocol decoding. All agents work on separate files with zero conflicts.
>
> **Key change from pre-modular plan:** The handoff pattern for `mem_forensics` and `timing_probe` is ELIMINATED. 🔴 exploit-engineer now owns `bridge/cmd-forensics.c` outright and implements both capabilities directly. `sdk_map` is implemented by 🔵 in `bridge/cmd-recon.c`. No coordinated access to any shared file during the parallel window.
>
> **Estimated effort:** 5+ days
> **Estimated LOC:** ~1700 (C) + ~150 (Python)

#### File Ownership — Window 5

| Path | Owner | Others |
|------|-------|--------|
| `src/dylibs/bridge/cmd-analysis.c` | 🔵 mobile-engineer | Read only |
| `src/dylibs/bridge/cmd-recon.c` | 🔵 mobile-engineer | Read only (sdk_map) |
| `src/dylibs/bridge/cmd-forensics.c` | 🔴 exploit-engineer | Read only |
| `src/dylibs/bridge/darkmach-bridge.c` | 🔵 mobile-engineer | Read only (dispatcher wiring) |
| `src/darkmach/bridge.py` | 🟣 code-engineer | Read only |
| `tests/` | 🟢 qa-engineer | Read only by others |

#### Tasks

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ✅ | 13.6.1 | **`block_inspect` command** — Implement ObjC block introspection in `src/dylibs/bridge/cmd-analysis.c`. Parse Block_layout struct at given address: isa (identify stack/malloc/global block), flags, reserved, invoke function pointer, descriptor (size, signature). Extract captured variables by reading bytes after standard fields using descriptor size. `block_inspect {address}`: returns block metadata, signature string, invoke address, captured variable preview. `block_invoke {address, args}`: calls the block's invoke function with specified arguments (DANGEROUS — must validate block is still live). Integrate with trace: when a traced method receives a block argument (`@?` type encoding), auto-inspect. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 2.7. ~350 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.6.2 | **`proto_decode` command (protobuf-only first pass)** — Implement Protocol Buffer wire format parser in `src/dylibs/bridge/cmd-analysis.c`. Parse varint encoding, fixed32/fixed64, length-delimited fields. Recursively decode nested messages. For ObjC apps using Google's protobuf: resolve field names from `GPBDescriptor` runtime metadata (`+descriptor` method on `GPBMessage` subclasses, returns field names/types). `proto_decode {hex_or_base64}`: attempts protobuf decode, returns structured field tree. `proto_schema`: returns reconstructed schemas from accumulated decoded messages (grouped by net_tap URL). Auto-trigger on `net_tap` responses with `Content-Type: application/protobuf` or `application/grpc`. Defer MessagePack/CBOR/Thrift to a future sprint. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 1.6. ~400 lines of C (protobuf-only). Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.6.3 | **`mem_forensics` command** — Implement freed memory scanning directly in `src/dylibs/bridge/cmd-forensics.c`. Enumerate malloc zones via `malloc_get_all_zones`. For freed blocks: use zone introspect enumerator with `MALLOC_PTR_REGION_RANGE_TYPE`, then identify non-in-use blocks within regions. Scan freed blocks for: ObjC isa pointers (may still reference valid classes), UTF-8 string patterns (printable sequences > 8 chars), known token prefixes (`eyJ` for JWT, `Bearer`), URL patterns (`https://`). `mem_forensics`: scans freed memory for recoverable sensitive data. `mem_snapshot`: captures heap state for later diffing. `mem_diff {snapshot_a, snapshot_b}`: compares two snapshots. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 3.4 and `dev/frida-gum-heap-study.md` for zone walking mechanics (same API, different enumeration flags). ~300 lines of C. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.6.4 | **`timing_probe` command** — Implement method timing analysis directly in `src/dylibs/bridge/cmd-forensics.c`. `timing_probe {class, method, iterations, args}`: calls the method N times using the existing `call_method` infrastructure, records `mach_absolute_time()` before and after each call, computes mean/median/stddev/min/max. `timing_compare {class, method, args_a, args_b, iterations}`: runs both variants and reports timing differential with statistical significance. Discard first N iterations for JIT warmup. Detect constant-time vs variable-time implementations. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 3.3. ~150 lines of C. Execute as agent team with file-boundary isolation. | 🔴 exploit-engineer |
| ✅ | 13.6.5 | **`sdk_map` command** — Implement supply chain dependency mapping in `src/dylibs/bridge/cmd-recon.c`. Enumerate loaded images via `_dyld_image_count()` / `_dyld_get_image_name()` / `_dyld_get_image_header()`. Parse each image's Mach-O header for `LC_ID_DYLIB` (name, version). Build SDK fingerprint database: map class prefixes to SDKs (FIR* = Firebase, AMP* = Amplitude, MPT* = Mixpanel, ABK* = Braze, ADJ* = Adjust, BNC* = Branch, FBSDK* = Facebook). For identified SDKs, call known configuration accessors to extract API keys. `sdk_map`: returns full supply chain graph. `sdk_keys`: returns extracted credentials grouped by SDK. Wire dispatch entries in `src/dylibs/bridge/darkmach-bridge.c`. Reference: `.project/bridge-capabilities-brainstorm.md` section 3.2. ~400 lines of C. Execute as agent team with file-boundary isolation. | 🔵 mobile-engineer |
| ✅ | 13.6.6 | **bridge.py Sprint 13.6 formatters** — Add `format_response` handlers in `src/darkmach/bridge.py` for: `block_inspect`/`block_invoke`, `proto_decode`/`proto_schema`, `mem_forensics`/`mem_snapshot`/`mem_diff`, `timing_probe`/`timing_compare`, `sdk_map`/`sdk_keys`. Protobuf formatter renders nested field tree with indentation. Timing formatter shows stats table with significance markers. SDK formatter groups findings by SDK with confidence scores. ~150 lines of Python. Execute as agent team with file-boundary isolation. | 🟣 code-engineer |
| ✅ | 13.6.7 | **Sprint 13.5 test batch** — Write tests for Sprint 13.5 formatters. Test webview_list rendering, entitlement_scan risk annotation display, pin_analyze certificate table, inject_class confirmation. Add to `tests/test_bridge.py`. Target: 12+ new tests. Execute as agent team with file-boundary isolation. | 🟢 qa-engineer |

**Gate 13.6 — Phase 13 Completion Gate**:
- `make all` succeeds with all new build rules
- Full regression: `pytest tests/` passes (all existing + new tests)
- `ruff check src/ tests/` clean
- Manual verification: at least 3 new commands tested against a live app via `darkmach bridge`
- ✅ 📘 documentation-engineer updates `docs/bridge.md` with new command reference (all 20 capabilities) — COMPLETE 2026-03-26
- ⬜ 📘 documentation-engineer updates `README.md` tool reference
- ⬜ Lead updates `.claude/CLAUDE.md` Bridge Command Set table
- ⬜ Lead updates `.project/changelog.md` with Phase 13 milestone

### 13.V Live Validation — AP News (2026-03-26)

> All ~55 registered bridge commands tested against live AP News app in iOS Simulator. Full validation session.

**Results:**
- **Pass**: info, enumerate_classes, get_methods, get_properties, get_ivars, read_property, call_method, view_hierarchy, read_memory, heap_search, heap_dump, keychain_dump, userdefaults_dump, cookies_dump, db_dump, db_query, db_queries, event_tap, env_dump, net_tap, net_filter, crypto_tap, crypto_keys, auth_tap, auth_tokens, trace, trace_class, trace_log, trace_verbose, untrace, hook_method, unhook_method, ui_tap, ui_type, ui_scroll, ui_back, ui_alert_dismiss, stealth_scan, stealth_enable, stealth_status, webview_list, webview_eval, webview_content, webview_bridge_map, inject_class, inject_method, replace_delegate, entitlement_scan, pin_analyze, pin_extract, block_inspect, proto_decode, proto_schema, mem_forensics, mem_snapshot, sdk_map, sdk_keys, timing_probe, timing_compare
- **Notable findings**: Firebase API keys extracted via `sdk_keys`, protobuf schemas found via `proto_schema`, jailbreak detection + TrustKit SSL pinning detected via `stealth_scan`
- **Crash bugs found and fixed**:
  - `trace_class` crash on partially-constructed ObjC objects (commit `9acf614`)
  - `proto_schema` crash — `isKindOfClass:` sent to Class objects (metaclass) triggers SIGTRAP (commit `22e1ad5`)
  - Crash-on-launch and trace NULL pointer crash (commit `4789c0c`)
- **Known issues from testing**:
  - `deeplink` command registered but not implemented (returns error)
  - `fs_scan` returns binary data causing UTF-8 decode error in Python bridge client
  - `stealth_scan`/`stealth_enable`/`stealth_status` JSON responses have malformed structure (extra `{`)

---

### 13.D Deferred Capabilities

> These capabilities are deferred until Phase 13 is proven stable. Build when the need arises from real app testing.

| Capability | Why Deferred | Trigger to Build |
|-----------|-------------|-----------------|
| `diff_exec` (3.1) | Meta-capability requiring ALL other capabilities. Session recording across all subsystems + structured diff. | After Phase 14 LLM loop proves stable and needs differential analysis |
| `cloud_extract` (3.8) | CloudKit framework dependency, app-specific value. Many apps don't use CloudKit. | Encounter an app with significant CloudKit usage during Phase 5 |
| `persist` (3.10) | Session persistence is nice-to-have. Build when analysis sessions become multi-cycle. | When Phase 14 autonomous loop needs cross-session state |
| `deeplink_fuzz` (3.6) | Requires `ui_interact` (13.4.1). URL scheme fuzzing is straightforward once UI automation exists. | After Phase 5 identifies apps with complex URL scheme handlers |

---

## Phase 14: LLM Autonomous Exploration ⬜

> The defining capability of Darkmach. An LLM that autonomously explores a live iOS app's runtime.
> Depends on Phase 13 bridge capabilities — especially `trace`, `net_tap`, `heap_dump`, `ui_interact`.
>
> **Estimated effort:** 5-7 days
> **All tasks execute as agent teams with file-boundary isolation.**

### 14.1 Exploration Infrastructure

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 14.1.1 | **System prompt design** — Create `src/darkmach/prompts/exploration.md` (new directory + file). Define the LLM's exploration strategy: always start with `info` + `enumerate_classes` filtered by security-relevant patterns, prioritize high-value targets (Auth, Payment, Crypto, API, Token, Secret, Key, Wallet, Session, Credential, Certificate), use `trace` on interesting methods before `call_method`, combine `net_tap` with `ui_interact` to correlate actions to API calls, use `heap_dump` to find credential objects. Include output format specification and safety boundaries. | 🟣 code-engineer |
| ⬜ | 14.1.2 | **Target prioritization engine** — Implement in `src/darkmach/explorer.py` (new file). Given `enumerate_classes` output, score each class by security relevance using pattern matching on name (Auth=10, Payment=9, Crypto=8, API=7, Token=7, Secret=6, Key=6, Wallet=6, Session=5, Credential=5, etc). Return ranked list of exploration targets with suggested commands per target. | 🟣 code-engineer |
| ⬜ | 14.1.3 | **Exploration state tracker** — Implement in `src/darkmach/explorer.py`. Track: visited classes/methods, pending targets, installed hooks, captured findings, coverage metrics (classes inspected / total, methods traced / total on target classes). Support save/load to JSON for session resume. | 🟣 code-engineer |

### 14.2 Autonomous Loop

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 14.2.1 | **Exploration loop orchestrator** — Implement `autonomous_explore()` in `src/darkmach/explorer.py`. The loop: (1) `info` + `enumerate_classes` filtered by patterns, (2) `prioritize_targets()`, (3) for each target: `get_methods` + `get_properties` + `get_ivars`, (4) score methods by security relevance, (5) `trace` top methods, (6) `ui_interact` to trigger app flows, (7) `net_tap` to see API calls, (8) `heap_dump` for credential objects, (9) analyze findings, (10) decide next target. Uses bridge.py `send_command` as the bridge interface. Each iteration calls the LLM with current state + bridge results to decide next action. | 🟣 code-engineer |
| ⬜ | 14.2.2 | **Finding detection heuristics** — Implement in `src/darkmach/explorer.py`. Automated detection of security findings from bridge output: hardcoded keys (entropy analysis on string values), auth tokens (JWT pattern `eyJ`), PII (email/phone patterns), weak crypto (DES, MD5 in crypto_tap), insecure storage (credentials in UserDefaults), excessive entitlements (from entitlement_scan). Each finding gets a severity score and evidence snapshot. | 🟣 code-engineer |
| ⬜ | 14.2.3 | **Evidence collection** — Implement in `src/darkmach/explorer.py`. Capture structured evidence for each finding: bridge command output, method trace log, decoded values (JWT payload, base64, hex), screenshot context. Store in `output/<app>/findings/` directory. Each finding: `{title, severity, evidence[], reproduction_commands[], timestamp}`. | 🟣 code-engineer |

### 14.3 Report Generation and Validation

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 14.3.1 | **Report generator** — Implement in `src/darkmach/explorer.py`. Transform collected findings into structured reports following `.project/reports/` format: title, severity (CVSS 3.1), affected system, vulnerability type, reproduction steps (with Darkmach commands), proof of concept, impact, remediation. Auto-generate report files in `output/<app>/report.md`. | 🟣 code-engineer |
| ⬜ | 14.3.2 | **Session management** — Add save/resume to `src/darkmach/explorer.py`. On `darkmach explore --resume <app>`: reload state tracker, skip already-visited targets, continue from last position. On `darkmach explore --save <app>`: checkpoint current state to `output/<app>/session.json`. | 🟣 code-engineer |
| ⬜ | 14.3.3 | **CLI integration** — Add `darkmach explore <app>` subcommand to `src/darkmach/cli.py`. Options: `--auto` (full autonomous loop), `--targets <pattern>` (filter classes), `--max-findings <N>` (stop after N findings), `--timeout <minutes>`, `--resume`, `--save`. Wire into explorer.py. | 🟣 code-engineer |
| ⬜ | 14.3.4 | **End-to-end validation** — Run autonomous exploration against a real app. The LLM must: discover classes, identify security-relevant targets, trace methods, capture arguments, find a real security finding (hardcoded key, auth token, or insecure storage) without human guidance. Document the session transcript and findings. | 🟣 code-engineer + all |

### 14.4 Phase 14 Tests

| Status | Task | Description | Agent |
|--------|------|-------------|-------|
| ⬜ | 14.4.1 | **Explorer unit tests** — Create `tests/test_explorer.py`. Test target prioritization scoring, finding detection heuristics, state tracker save/load, evidence formatting. Mock bridge commands with synthetic responses. Target: 25+ tests. | 🟢 qa-engineer |
| ⬜ | 14.4.2 | **Sprint 13.6 + Phase 14 formatter tests** — Complete remaining bridge.py formatter tests for all Phase 13 capabilities. Test all format_response branches. Ensure 100% command coverage in test_bridge.py. Target: 15+ new tests. | 🟢 qa-engineer |

**Phase 14 Completion Gate**:
- All tests pass
- `darkmach explore <app>` runs end-to-end
- LLM finds at least one real security finding autonomously
- 📘 documentation-engineer updates `docs/bridge.md` with autonomous exploration guide

---

## Known Issues

- **SwiftUI `@main` apps** — detected but not yet patchable (no AppDelegate to call) → Phase 5.4
- **Some frameworks use legacy `LC_VERSION_MIN_IPHONEOS`** — requires manual vtool conversion → Phase 5.5
- **darkmach-keychain `SecItemCopyMatching` status -34018** — keychain access may need entitlement in Simulator context
- **App doesn't visually appear in Simulator** — launches and runs (interceptors capture data) but UI may not render for some apps
- **ObjC regex limitation** — `detect-delegate.py` regex `^[A-Z][A-Za-z0-9]*AppDelegate$` cannot match plain "AppDelegate" (requires prefix). Dead code at line 156/557. → Phase 5.5
- **darkmach-crypto.dylib DYLD_INTERPOSE conflict** — if `src/dylibs/interceptors/darkmach-crypto.c` is loaded alongside the bridge's new `crypto_tap`, the DYLD_INTERPOSE hooks may conflict. The bridge's `crypto_tap` (13.2.2) should detect if darkmach-crypto.dylib is already loaded and share its capture buffer rather than double-hooking. → Resolve in Sprint 13.2.
- ~~**`deeplink` bridge command not implemented**~~ — ✅ Fixed (ISSUE-002, 2026-03-26). Implemented `cmd_deeplink` in `cmd-inject.c`.
- ~~**`fs_scan` returns binary data**~~ — ✅ Fixed (ISSUE-003 + ISSUE-005, 2026-03-26). Added UTF-8 validator + binary hex preview, fixed leading comma in children arrays.
- ~~**`stealth_*` malformed JSON**~~ — ✅ Fixed (ISSUE-004, 2026-03-26). Stealth handlers now nest under `"data"` key inside bridge envelope.
- **Gate 13.6 remaining items** — README.md tool reference, CLAUDE.md Bridge Command Set table, and changelog.md Phase 13 milestone entry still need updating

---

## Architecture Decisions

- **Custom C dylibs over Frida** — zero dependencies, undetectable, DYLD interpose + method swizzling, no Python runtime. Frida blocked by SIP anyway.
- **Modular interceptors** — each dylib standalone, inject one or all, no inter-dylib dependencies.
- **DYLD interpose for C functions** (sqlite3, CCCrypt, SecItem, SecTrust) — kernel-level function replacement, works before app code runs.
- **Method swizzling for ObjC** (NSURLSession, NSUserDefaults, UIPasteboard, NSFileManager) — runtime method replacement via `method_setImplementation`.
- **JSON-lines logging** — structured, parseable, timestamp-correlated across all interceptors.
- **Python stdlib only for patching** — no LIEF, no external binary manipulation libs.
- **ARM64 instructions hand-encoded** — no assembler dependency.
- **Proper Python package** — `pip install -e .` with `src/` layout, `pyproject.toml`, console_scripts entry point.
- **Shell scripts ported to Python** — discovery, analysis, and system checks are now native Python modules callable via CLI.
- **Per-app output isolation** — `output/<app>/static/` + `dynamic/` + `bundle/` keeps results organized per target.
- **Project renamed Sphinx → Darkmach** (2026-03-26) — full sed rename across 62 tracked files. Domain: darkmach.dev. Package: `darkmach-re`. All 581 tests pass post-rename.
- **Static assembly trampoline over JIT** — the trace capability uses a pre-compiled `.S` file with 256 static stubs rather than mmap(MAP_JIT) dynamic code generation. Simpler, no JIT page management, works without code signing concerns. Reference: `dev/frida-gum-interceptor-study.md` section 9.1, Option A. Evolve to dynamic JIT stubs only if 256 simultaneous hooks is insufficient.
- **Separated heap enumeration from validation** — heap_dump collects addresses during zone enumeration (no malloc/ObjC calls in callback), then validates isa pointers after enumeration completes. Prevents deadlock and crashes. Reference: `dev/frida-gum-heap-study.md` "Recommended Implementation Approach".
- **Ring buffer pattern for all tap commands** — net_tap, crypto_tap, auth_tap, event_tap all use fixed-capacity ring buffers (500 entries) to bound memory usage while providing queryable recent history.
- **Modular dylib directory structure** — `src/dylibs/` restructured from flat layout into domain subdirectories (`bridge/`, `interceptors/`, `stealth/`, `compat/`, `tools/`) with the bridge split into a thin dispatcher (`darkmach-bridge.c`) plus domain-specific `cmd-*.c` files. Source files live in subdirectories; all `.dylib` build outputs remain flat at `src/dylibs/*.dylib` to preserve existing `DYLIB_DIR` references in `_paths.py` and `cli.py`. This enables true parallel development: 🔴 exploit-engineer owns `cmd-trace.c`, `cmd-forensics.c`, `darkmach-trampoline.S` outright while 🔵 mobile-engineer owns all other `cmd-*.c` files. Eliminates the handoff pattern where one agent writes code blocks for another to integrate. Decision made 2026-03-25 to support Phase 13 parallelism at scale.

---

---

## Future: Darkmach.app (macOS Application) — TBD

> **Status: Not decided.** GUI wrapper around the full pipeline. Would provide Simulator management via CoreSimulator.framework private APIs, embedded interceptor management, live log viewer, and LLM bridge chat UI. Large effort — evaluate after Phase 5 whether the CLI-based workflow is sufficient or if a GUI would meaningfully improve the research workflow.

| Capability | Description |
|------------|-------------|
| Simulator management | CoreSimulator.framework private APIs, possibly Virtualization.framework |
| App shell | SwiftUI macOS app with pipeline orchestration |
| Interceptor management | Build, inject, monitor dylibs from GUI |
| Live log viewer | JSONL stream → UI for interceptor output |
| LLM bridge UI | Chat interface for autonomous exploration |

---

*Last updated: 2026-03-26*
*Current Phase: Phase 14 (LLM Autonomous Loop) — Phase 13 COMPLETE*
*Execution order: Phase 14 (LLM Autonomous Loop) → Phase 5 (App Testing Campaign)*