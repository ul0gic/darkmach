# Darkmach

> First-of-its-kind iOS reverse engineering toolkit for Apple Silicon. Exploits the fact that iOS apps on Mac are stored fully decrypted — no jailbreak, no SIP bypass, standard user permissions. End-to-end pipeline from App Store discovery to binary patching to Simulator instrumentation.

## What Makes This Novel

iOS apps installed via the Mac App Store on Apple Silicon are stored **fully decrypted** on disk. `cryptid 1` is set but the binary is plaintext — Apple's FairPlay DRM simply doesn't encrypt the on-disk binary for Mac delivery. No one has built a complete toolkit around this gap before. Darkmach does:

- **Discovers** iOS apps available on Mac via App Store API
- **Analyzes** decrypted binaries for secrets, endpoints, SDKs, entitlements
- **Patches** Mach-O binaries at the byte level — platform flags, encryption headers, entry point shellcode
- **Launches** patched apps in the iOS Simulator (native arm64, not emulated)
- **Instruments** running apps with DYLD-injected dylibs

Every tool is hand-built. ARM64 shellcode encoded from the ISA spec. Mach-O surgery with Python stdlib only. No LIEF, no heavy dependencies.

## Before Any Work

- Read `README.md` — full pipeline documentation, tool reference, troubleshooting
- Read `.project/build-plan.md` — current priorities, task status, agent assignments
- Read `.project/changelog.md` — what's been done, significant decisions
- Read `.project/prd.md` — project vision, goals, success criteria

## Pipeline

```
Discovery -> Acquisition -> Static Analysis -> Patching -> Simulator Launch -> Dynamic Analysis -> Reporting
                                  ^                                                   |
                                  '----------------- iteration loop -----------------'
```

Static analysis and dynamic analysis each support parallel agent work. Patching is serial (exploit-engineer owns the binary).

## Project Structure

```
.Codex/
├── AGENTS.md                    # This file — central index
├── settings.local.json          # Permissions, team config, hooks
├── agents/                      # 7 specialist agents
│   ├── exploit-engineer.md      # Mach-O surgery, ARM64 shellcode, FairPlay bypass
│   ├── mobile-engineer.md       # Frida, DYLD injection, runtime analysis
│   ├── code-engineer.md         # Static analysis, secret extraction, toolkit QA
│   ├── qa-engineer.md           # Test architecture, pytest, coverage, regression prevention
│   ├── report-engineer.md       # Apple Security Bounty, research docs
│   ├── documentation-engineer.md # Product docs, research methodology
│   └── build-plan-architect.md  # Build plan design, parallelization, dependency chains, gates
├── hooks/                       # (available for future use)
├── rules/                       # Universal rules (always active)
└── skills/                      # (available for future use)

.project/
├── prd.md                       # Project vision, goals, success criteria
├── tech-stack.md                # Technology choices and rationale
├── build-plan.md                # Development roadmap, tasks, agent assignments, progress
├── changelog.md                 # Version history (Keep a Changelog format)
├── bridge-capabilities-brainstorm.md  # 20 bridge capabilities across 3 tiers
├── issues/                      # Bug/edge case tracking from app testing
│   ├── ISSUE_TEMPLATE.md
│   └── open/                    # ISSUE-002 (deeplink), ISSUE-003 (fs_scan), ISSUE-004 (stealth JSON)
└── reports/                     # Finding reports for Apple Security Bounty

src/
├── darkmach/                      # Python package — CLI, analysis, discovery, bridge
│   ├── cli.py                   # Main CLI entry point (argparse subcommands)
│   ├── analyze.py               # Static analysis — URLs, secrets, SDKs, entitlements
│   ├── bridge.py                # Bridge client — UDS/JSON-lines to darkmach-bridge.dylib
│   ├── discover.py              # App Store discovery — iTunes API + amp-api compatibility
│   ├── hermes.py                # Hermes bytecode analysis — JS bundle extraction, secrets
│   ├── keychain.py              # Keychain database reader — SQLite parsing
│   ├── typeenc.py               # ObjC type encoding parser — method signatures to Python types
│   └── _paths.py                # Path resolution — ROOT, SRC_DIR, OUTPUT_DIR, etc.
├── patch/                       # Binary patching — platform flags, encryption headers, shellcode
│   ├── patch-for-simulator.sh   # Full bundle patcher
│   ├── patch-macho-surgical.py  # Byte-level Mach-O patcher
│   ├── make-main-patch.py       # ARM64 shellcode generator
│   ├── make-main-stub.py        # Alternative clang-compiled stub
│   └── detect-delegate.py       # AppDelegate auto-detection
└── dylibs/                      # DYLD injection — modular architecture (Phase 13)
    ├── darkmach-core.h            # Shared types, logging macros, ring buffer
    ├── Makefile                 # Builds all dylibs from modular sources
    ├── bridge/                  # LLM bridge — dispatcher + command modules
    │   ├── darkmach-bridge.c      # Main dispatcher — UDS server, command routing
    │   ├── darkmach-bridge.h      # Shared bridge types, command registration
    │   ├── cmd-recon.c          # Recon commands — classes, methods, protocols, heap_dump, env_dump
    │   ├── cmd-network.c        # Network commands — net_tap, crypto_tap, auth_tap
    │   ├── cmd-trace.c          # Trace commands — ObjC method tracing via swizzling
    │   ├── cmd-ui.c             # UI commands — view hierarchy, ui_interact, screenshots
    │   ├── cmd-analysis.c       # Analysis commands — sdk_map, entitlements, proto_decode
    │   ├── cmd-forensics.c      # Forensics commands — mem_forensics, block_inspect, timing
    │   ├── cmd-inject.c         # Injection commands — inject_class, db_inject, deeplink
    │   ├── cmd-events.c         # Event commands — event_tap, notification monitoring
    │   └── darkmach-trampoline.S  # ARM64 trampoline — 26-instruction shared stub for trace
    ├── interceptors/            # DYLD_INTERPOSE-based C function hooks
    │   ├── darkmach-net.c         # Network call interception — NSURLSession, CFNetwork
    │   ├── darkmach-crypto.c      # CommonCrypto interception — encryption/hashing
    │   ├── darkmach-db.c          # SQLite query interception
    │   ├── darkmach-keychain.c    # Security.framework hooks
    │   ├── darkmach-tls.c         # TLS/SSL connection interception
    │   ├── darkmach-storage.c     # NSUserDefaults/file interception
    │   └── darkmach-ssl.c         # SSL certificate pinning bypass
    ├── stealth/                 # Anti-detection — jailbreak/debug/hook evasion
    │   └── darkmach-stealth.c     # Stealth module
    ├── compat/                  # Compatibility — Simulator environment fixes
    │   ├── darkmach-metal-fix.c   # Metal GPU framework stub
    │   ├── darkmach-decrypt.c     # FairPlay decryption analysis
    │   └── darkmach-bootstrap.c   # Strategy B bootstrap — UIApplicationMain caller
    └── tools/                   # Standalone utilities
        └── dump-region.c        # Memory region dumper

tests/                           # pytest suite — 581 tests, 0.27s
├── conftest.py                  # Shared fixtures — fake app bundles, subprocess mocks
├── test_analyze.py              # Static analysis extractors (44 tests)
├── test_bridge.py               # Bridge protocol + response formatting (127 tests)
├── test_cli.py                  # CLI arg parsing + validation (32 tests)
├── test_detect_delegate.py      # AppDelegate detection — 4-tier priority (37 tests)
├── test_discover.py             # Discovery API parsing + token handling (27 tests)
├── test_hermes.py               # Hermes bytecode + secret scanning (40 tests)
├── test_interpose_safety.py     # DYLD interpose symbol safety checks (15 tests)
├── test_keychain.py             # Keychain SQLite + timestamps (22 tests)
├── test_make_main_patch.py      # ARM64 shellcode + instruction encoders (111 tests)
├── test_patch_macho_surgical.py # Mach-O byte-level patching (30 tests)
├── test_paths.py                # Path resolution (16 tests)
└── test_typeenc.py              # ObjC type encoding parser (80 tests)

dev/                             # Development scratch space + reference studies
├── bridge-command-spec.md       # Complete JSON command/response schemas for all 40+ bridge commands
├── frida-gum/                   # Frida-gum source (shallow clone, reference only)
├── frida-gum-study.md           # Consolidated LOE report — all 20 capabilities, build order
├── frida-gum-interceptor-study.md  # ARM64 interception deep dive — trampoline design
└── frida-gum-heap-study.md      # Heap walking study — malloc zone enumeration

docs/                            # Documentation
output/                          # Runtime output (analysis results, patched bundles)
```

## Agents

| Agent | Domain | Owns | Deploy When |
|-------|--------|------|-------------|
| `exploit-engineer` | Mach-O surgery, ARM64 shellcode, FairPlay bypass, trampoline design | `src/patch/`, `bridge/cmd-trace.c`, `bridge/cmd-forensics.c`, `bridge/darkmach-trampoline.S`, `stealth/` | Binary-level problems, patching strategies, shellcode, trampoline, stealth |
| `mobile-engineer` | DYLD injection, method swizzling, ObjC runtime, interceptor hooks | `src/dylibs/` (all except exploit-engineer's files) | Runtime analysis, hook development, bridge capabilities, interceptors |
| `code-engineer` | Decrypted binary analysis, secret extraction, SDK fingerprinting, toolkit QA | `src/darkmach/` | Static analysis, secret scanning, reviewing toolkit code |
| `qa-engineer` | Test architecture, pytest, coverage, regression prevention | `tests/` | Test suite design, writing tests, coverage analysis |
| `report-engineer` | Apple Security Bounty submission, research documentation, finding reports | `.project/reports/` | Writing findings, scoring severity, compiling evidence |
| `documentation-engineer` | Product docs, research methodology, README | `docs/` | Documentation updates, research writeups |
| `build-plan-architect` | Build plan design, parallelization, dependency chains, gates, agent orchestration | `.project/build-plan.md` | New phases, restructuring work, maximizing parallel execution |

**Agent pairings for common work:**
- **exploit-engineer + mobile-engineer** — patching strategy + runtime verification (closest partners); shared dylib boundary in `bridge/`
- **code-engineer + mobile-engineer** — static findings become dynamic analysis targets
- **code-engineer + exploit-engineer** — binary edge cases that break the patcher
- **report-engineer + all** — compiles evidence from every agent into submissions
- **build-plan-architect + all** — designs execution plans that maximize parallelism across the team

**Phase 13 file ownership (bridge capabilities):**
- **exploit-engineer** (red): `cmd-trace.c`, `cmd-forensics.c`, `darkmach-trampoline.S`, `stealth/darkmach-stealth.c`
- **mobile-engineer** (blue): `cmd-recon.c`, `cmd-network.c`, `cmd-ui.c`, `cmd-analysis.c`, `cmd-inject.c`, `cmd-events.c`, all `interceptors/`

## Toolkit Components

### Patching Pipeline (`src/patch/`) — exploit-engineer

| Tool | Purpose |
|------|---------|
| `patch-macho-surgical.py` | Byte-level Mach-O patcher — platform flags (iOS→iOSSimulator) + encryption header zeroing |
| `make-main-patch.py` | ARM64 shellcode generator — replaces FairPlay-encrypted entry point with dlsym-based main() |
| `make-main-stub.py` | Alternative stub — compiles minimal main() replacement via clang |
| `detect-delegate.py` | Auto-detects AppDelegate class name from symbol table (4-tier: Swift mangled, Swift variant, ObjC, SwiftUI) |

**Patching strategies:**
- **Strategy A** — Crypt region contains only the entry point → replace with hand-crafted ARM64 shellcode
- **Strategy B** — Crypt region contains multiple functions → fill with RETs, inject bootstrap dylib

### DYLD Injection (`src/dylibs/`) — mobile-engineer + exploit-engineer

**Bridge (`bridge/`)** — LLM-accessible runtime introspection via UDS/JSON-lines protocol:

| Module | Purpose |
|--------|---------|
| `darkmach-bridge.c` | Main dispatcher — UDS server, command routing, response formatting |
| `cmd-recon.c` | Recon — classes, methods, protocols, heap_dump, env_dump, sdk_map |
| `cmd-network.c` | Network — net_tap, crypto_tap, auth_tap (ring buffer pattern) |
| `cmd-trace.c` | Trace — ObjC method tracing via swizzling + ARM64 trampoline |
| `cmd-ui.c` | UI — view hierarchy, ui_interact, screenshots |
| `cmd-analysis.c` | Analysis — entitlements, proto_decode, block_inspect |
| `cmd-forensics.c` | Forensics — mem_forensics, timing analysis |
| `cmd-inject.c` | Injection — inject_class, db_inject, deeplink triggering |
| `cmd-events.c` | Events — event_tap, notification monitoring |
| `darkmach-trampoline.S` | ARM64 trampoline — 26-instruction shared stub (200 bytes context save) |

**Interceptors (`interceptors/`)** — DYLD_INTERPOSE-based C function hooks:

| Dylib | Purpose |
|-------|---------|
| `darkmach-net.c/dylib` | Network call interception — NSURLSession, CFNetwork |
| `darkmach-crypto.c/dylib` | CommonCrypto interception — encryption/hashing operations |
| `darkmach-db.c/dylib` | SQLite query interception — captures all database operations |
| `darkmach-keychain.c/dylib` | Security.framework hooks — SecItemAdd/CopyMatching/Update/Delete |
| `darkmach-tls.c/dylib` | TLS/SSL connection interception — tracks connections, logs handshakes |
| `darkmach-storage.c/dylib` | NSUserDefaults + filesystem operation hooks |
| `darkmach-ssl.c/dylib` | SSL certificate pinning bypass |

**Stealth (`stealth/`)** — Anti-detection evasion for jailbreak/debug/hook checks

**Compat (`compat/`)** — Simulator environment compatibility:

| Dylib | Purpose |
|-------|---------|
| `darkmach-metal-fix.c/dylib` | Metal GPU framework stub for Simulator compatibility |
| `darkmach-decrypt.c/dylib` | FairPlay decryption analysis |
| `darkmach-bootstrap.c/dylib` | Strategy B bootstrap — UIApplicationMain caller |

### Python CLI (`src/darkmach/`) — code-engineer

| Module | Purpose |
|--------|---------|
| `cli.py` | Main CLI entry point — argparse subcommands: run, analyze, patch, discover, bridge, system, hermes, keychain |
| `analyze.py` | Static analysis — URL/secret/SDK extraction, entitlements, Mach-O structure |
| `bridge.py` | Bridge client — UDS/JSON-lines protocol to darkmach-bridge.dylib, interactive REPL |
| `discover.py` | App Store discovery — iTunes Search API + amp-api Mac compatibility check |
| `hermes.py` | Hermes bytecode analysis — JS bundle extraction, string/secret scanning |
| `keychain.py` | Keychain database reader — SQLite parsing, Apple timestamp conversion |
| `typeenc.py` | ObjC type encoding parser — method signatures to structured Python types |
| `_paths.py` | Path resolution — ROOT, SRC_DIR, DYLIB_DIR, OUTPUT_DIR, app output helpers |

### Reference Studies (`dev/`) — research material

| Study | Purpose |
|-------|---------|
| `bridge-command-spec.md` | Complete JSON command/response schemas for all 40+ bridge commands |
| `frida-gum-study.md` | Consolidated LOE report — 20 capabilities, ~23-27 days, ~6200 LoC, 6 sprints |
| `frida-gum-interceptor-study.md` | ARM64 interception deep dive — trampoline design, swizzling vs inline hooking |
| `frida-gum-heap-study.md` | Heap walking — malloc zone enumeration, isa validation, thread safety |
| `frida-gum/` | Frida-gum shallow clone — reference source for implementation patterns |

## Active Development — Phase 14: LLM Autonomous Exploration

**Phase 13 (Bridge Capabilities): COMPLETE** — 20 bridge capabilities implemented across 6 sprints + modular restructure. All ~55 commands validated against live AP News in Simulator (2026-03-26). 3 crash bugs found and fixed during validation.

**Current phase**: Phase 14 — LLM autonomous exploration loop. An LLM that autonomously explores a live iOS app's runtime using the bridge.

**Phase 14 tasks**:
1. Exploration infrastructure (system prompt, target prioritization, state tracker)
2. Autonomous loop (orchestrator, finding detection heuristics, evidence collection)
3. Report generation (auto-generate findings, session management, CLI `darkmach explore`)
4. End-to-end validation (LLM finds a real security finding without human guidance)

**Key design decisions (Phase 13, for reference):**
- ObjC method swizzling instead of Frida-style inline hooking (~500 lines vs ~4000)
- ARM64 trampoline: 26 instructions, 200-byte context save (vs Frida's 784 bytes)
- Ring buffer pattern (500 entries) for net_tap, crypto_tap, auth_tap, event_tap
- All `.dylib` outputs stay flat at `src/dylibs/` root — preserves existing `DYLIB_DIR` references

## Known Gaps

- **SwiftUI `@main` apps** — detected but not yet patchable (no AppDelegate to call). Needs alternative entry strategy.
- **No end-to-end CLI** — each phase is manual. A `darkmach run <app>` orchestrator would be a major force multiplier.
- **No results tracking** — no structured record of which apps have been tested, what strategy worked, what was found.
- **Pure Swift static dispatch** — swizzling covers ObjC message sends but not Swift direct calls. Upgrade path documented in `dev/frida-gum-interceptor-study.md`.

## Rules

All rules in `.Codex/rules/` are universal (always active):

- `context-management.md` — Read project files before work, use subagents for research, verify your own output
- `orchestration.md` — Agent roles, pipeline phases, parallel execution, file ownership
- `reporting-standards.md` — CVSS scoring, reproduction steps, evidence requirements
- `self-improvement.md` — Keep docs current, recognize patterns for new skills/rules

## Development Principles

- **No unnecessary dependencies** — Python stdlib, system tools (otool, vtool, codesign, plutil), clang for C. That's it.
- **Byte-level precision** — Mach-O surgery is struct.pack/unpack, not framework wrappers
- **Verify your own output** — disassemble shellcode after generation, otool -l after patching, launch after signing
- **Tests must pass** — 581 pytest tests in `tests/`, run with `.venv/bin/python -m pytest tests/`. Don't break them.
- **Lint-clean** — ruff configured in `pyproject.toml` (26 rule groups, strict). Run `.venv/bin/ruff check src/ tests/`
- **Work stays in project directories** — never dump files at project root
- **File ownership matters** — agents own their directories, coordinate before crossing boundaries
- **Update project docs** — build-plan.md after completing tasks, changelog.md at milestones
- **Reference frida-gum studies** — when implementing bridge capabilities, consult `dev/frida-gum-*.md` and `dev/frida-gum/` source
