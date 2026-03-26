![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# Architecture Overview

---

## Project Structure

```
darkmach/
├── pyproject.toml              # Package config, entry point: darkmach.cli:entrypoint
├── Makefile                    # Compiles all C dylibs against iOS Simulator SDK
├── src/
│   ├── darkmach/                 # Python CLI package
│   │   ├── cli.py              # 10 subcommands, pipeline orchestration
│   │   ├── analyze.py          # Static analysis (14-step, Python-native)
│   │   ├── discover.py         # App Store API: iTunes Search + amp-api
│   │   ├── bridge.py           # Bridge client: send_command(), interactive REPL
│   │   ├── hermes.py           # Hermes/React Native bytecode extraction
│   │   ├── keychain.py         # Host-side Simulator keychain SQLite reader
│   │   └── _paths.py           # Central path resolution (ROOT, DYLIB_DIR, etc.)
│   ├── dylibs/                 # C source files → Simulator-targeted .dylib
│   │   ├── darkmach-core.h       # Shared infrastructure header
│   │   ├── darkmach-bridge.c     # LLM runtime bridge (Unix socket, JSON protocol)
│   │   ├── darkmach-net.c        # NSURLSession hooks
│   │   ├── darkmach-keychain.c   # SecItem DYLD interpose
│   │   ├── darkmach-crypto.c     # CCCrypt + SHA DYLD interpose
│   │   ├── darkmach-storage.c    # NSUserDefaults, pasteboard, cookies, files
│   │   ├── darkmach-ssl.c        # SecTrust + pinning bypass
│   │   ├── darkmach-db.c         # sqlite3 DYLD interpose (9 functions)
│   │   ├── darkmach-decrypt.c    # FairPlay crypt region extractor
│   │   ├── darkmach-metal-fix.c  # Metal GPU compatibility shim
│   │   ├── darkmach-tls.c        # BoringSSL low-level TLS interception
│   │   └── dump-region.c       # Host-side Mach task API memory reader
│   └── patch/                  # Binary patching pipeline
│       ├── patch-for-simulator.sh    # Full bundle patcher (orchestrates all patching)
│       ├── patch-macho-surgical.py   # Byte-level Mach-O surgery (platform + encryption)
│       ├── make-main-patch.py        # ARM64 shellcode generator (Strategy A)
│       ├── make-main-stub.py         # clang-compiled stub (Strategy A alternative)
│       └── detect-delegate.py        # AppDelegate auto-detection (4-tier)
└── output/                     # Per-app results (created at runtime)
    ├── .cache/crypt/            # FairPlay decryption cache (per bundle ID)
    └── <app-slug>/
        ├── static/              # Static analysis output
        ├── dynamic/             # Runtime interceptor logs (JSONL)
        └── bundle/              # Patched app copy
```

---

## Pipeline Phases

The full pipeline runs 7 phases, all orchestrated by `darkmach run`:

```
Phase 1: Discovery
  darkmach discover — find iOS apps via App Store API
  darkmach list     — enumerate installed apps in /Applications

Phase 2: Acquisition
  App Store installation or manual bundle placement

Phase 3: Static Analysis                    Phase 4: Simulator Boot
  darkmach analyze                              xcrun simctl boot <device>
  └── 14 analysis steps                       └── auto-selects newest iPhone
      URLs, secrets, SDKs,
      entitlements, Mach-O structure

Phase 5: Patching + FairPlay Decryption
  1. Read cryptoff/cryptsize from original binary
  2. simctl spawn + darkmach-decrypt.dylib → extract decrypted bytes
  3. patch-for-simulator.sh → platform flags, encryption headers, plists, signing
  4. Write decrypted bytes into patched binary → re-sign

Phase 6: Simulator Launch                   Phase 7: Bridge Connect
  xcrun simctl install <device> <bundle>      Wait for /tmp/darkmach-bridge.sock
  xcrun simctl launch <device> <bundle-id>    Verify bridge info command
  └── SIMCTL_CHILD_DYLD_INSERT_LIBRARIES      darkmach bridge (interactive)
      = 8 interceptor dylibs
```

---

## Component Interactions

### Python CLI (`src/darkmach/`)

The CLI layer is the pipeline orchestrator. It delegates to shell scripts for bundle patching, uses Python `subprocess` for all system tool invocations, and communicates with the bridge via Unix domain sockets.

```
cli.py
  ├── cmd_run()          Full 7-step pipeline
  ├── cmd_analyze()      → analyze.py: analyze_bundle()
  ├── cmd_patch()        → stage_patch() → subprocess: patch-for-simulator.sh
  │                        + _extract_crypt_region() → simctl spawn
  ├── cmd_launch()       → stage_launch() → subprocess: simctl launch
  │                        + SIMCTL_CHILD_DYLD_INSERT_LIBRARIES
  ├── cmd_bridge()       → bridge.py: interactive_mode()
  ├── cmd_discover()     → discover.py: run_discover()
  ├── cmd_hermes()       → hermes.py: main()
  ├── cmd_keychain()     → keychain.py: main()
  ├── cmd_list()         Scans /Applications for iOS bundles
  └── cmd_status()       Checks architecture, tools, SDK, dylibs
```

### Dylib Injection

All interceptors are injected via `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES`. This environment variable prefix causes `xcrun simctl launch` and `xcrun simctl spawn` to set the specified variable inside the child process environment, where `dyld_sim` picks it up and injects the libraries before app code runs.

```
xcrun simctl launch <udid> <bundle-id>
  └── sets SIMCTL_CHILD_DYLD_INSERT_LIBRARIES in child env
      └── dyld_sim loads all listed dylibs at process start
          └── constructor functions run before main()
              ├── darkmach-bridge.dylib: opens Unix socket, starts listener
              ├── darkmach-net.dylib: installs NSURLSession method swizzles
              ├── darkmach-keychain.dylib: DYLD interposes SecItem* functions
              ├── darkmach-crypto.dylib: DYLD interposes CCCrypt, CC_SHA*
              ├── darkmach-storage.dylib: swizzles NSUserDefaults, pasteboard, etc.
              ├── darkmach-ssl.dylib: DYLD interposes SecTrustEvaluateWithError
              ├── darkmach-db.dylib: DYLD interposes sqlite3_* functions
              └── darkmach-metal-fix.dylib: Metal GPU compatibility patches
```

### FairPlay Decryption Flow

The two-pass decryption is the most complex piece of the pipeline:

```
Original binary (on disk):
  LC_ENCRYPTION_INFO_64: cryptoff=0x4000, cryptsize=0x8000, cryptid=1
  Bytes at offset 0x4000..0x8000: AES-encrypted by FairPlay

Pass 1 — Extract decrypted bytes:
  1. Copy bundle to /tmp/darkmach-decrypt/
  2. Run patch-for-simulator.sh on the copy (patches platform, zeroes crypt header)
  3. Restore cryptid=1 in the temp binary (so kernel will decrypt during page-in)
  4. Re-sign the temp binary
  5. simctl spawn <udid> <temp-binary>
       + SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=darkmach-decrypt.dylib
       + SIMCTL_CHILD_DARKMACH_CRYPTOFF=0x4000
       + SIMCTL_CHILD_DARKMACH_CRYPTSIZE=0x8000
       + SIMCTL_CHILD_DARKMACH_DECRYPT_OUT=output/.cache/crypt/<bundle-id>.bin
     → Kernel decrypts FairPlay pages during page-in
     → darkmach-decrypt.dylib reads bytes from process's own memory
     → Writes plaintext to cache file
  6. Clean up /tmp/darkmach-decrypt/

Pass 2 — Apply to final patched binary:
  1. Run patch-for-simulator.sh on the work copy (cryptid=0, platform=7)
  2. Write decrypted bytes from cache file into binary at cryptoff
  3. Re-sign binary and bundle
```

### Bridge Protocol

The bridge dylib and Python client communicate via newline-delimited JSON over a Unix domain socket:

```
Request (Python → C dylib):
  {"id": 1, "cmd": "enumerate_classes", "args": {"filter": "Auth"}}\n

Response (C dylib → Python):
  {"id": 1, "ok": true, "classes": [...], "count": 12}\n
```

---

## Data Flow: Output Layout

All output is organized per-app under `output/`:

```
output/
├── .cache/
│   └── crypt/
│       └── com.example.myapp.bin    # Cached FairPlay crypt region bytes
└── myapp/                           # Slug: lowercase, spaces → dashes
    ├── static/
    │   ├── urls.txt                 # All HTTP/HTTPS URLs
    │   ├── secrets.txt              # API key / token pattern matches
    │   ├── sdks.txt                 # SDK fingerprint strings
    │   ├── entitlements.txt         # Codesign entitlements
    │   ├── plists.txt               # All plist contents
    │   └── summary.json             # Structured analysis summary
    ├── dynamic/
    │   ├── darkmach-net.jsonl         # Network requests and responses
    │   ├── darkmach-keychain.jsonl    # Keychain read/write operations
    │   ├── darkmach-crypto.jsonl      # Crypto operations with keys
    │   ├── darkmach-storage.jsonl     # UserDefaults, pasteboard, files
    │   ├── darkmach-ssl.jsonl         # TLS trust evaluations
    │   ├── darkmach-db.jsonl          # SQL queries and results
    │   └── darkmach-bridge.jsonl      # Bridge command log
    └── bundle/
        └── MyApp.app/               # Patched bundle (Simulator-ready)
```

### JSONL Log Format

All interceptors write newline-delimited JSON via `darkmach-core.h`:

```json
{"ts":"2026-03-23T14:32:01.423","mod":"net","evt":"request","url":"https://api.example.com/v1/user","method":"GET","headers":{"Authorization":"Bearer eyJ..."}}
{"ts":"2026-03-23T14:32:01.891","mod":"net","evt":"response","url":"https://api.example.com/v1/user","status":200,"body":"{\"id\":\"...\""}
{"ts":"2026-03-23T14:32:02.011","mod":"keychain","evt":"copy","service":"com.example.myapp","account":"user@example.com","data":"s3cr3t-token"}
{"ts":"2026-03-23T14:32:02.234","mod":"db","evt":"query","db":"/var/mobile/.../Cache.db","sql":"SELECT * FROM Assets WHERE id=?","params":["42"]}
```

Fields common to all events:
- `ts` — ISO 8601 timestamp with millisecond precision
- `mod` — Module name (`net`, `keychain`, `crypto`, `storage`, `ssl`, `db`, `bridge`)
- `evt` — Event type specific to the module

---

## Path Resolution

Path resolution is centralized in `src/darkmach/_paths.py`. The module walks up from its own location to find `pyproject.toml`, establishing the project root. This ensures paths work correctly whether Darkmach is installed via `pip install -e .` or `pipx`.

| Constant | Resolved Path |
|----------|--------------|
| `ROOT` | Project root (contains `pyproject.toml`) |
| `SRC_DIR` | `ROOT/src/` |
| `DYLIB_DIR` | `ROOT/src/dylibs/` |
| `PATCH_DIR` | `ROOT/src/patch/` |
| `OUTPUT_DIR` | `ROOT/output/` |
| `CRYPT_CACHE` | `ROOT/output/.cache/crypt/` |
| `BRIDGE_SOCKET` | `/tmp/darkmach-bridge.sock` (fixed, shared with app process) |

---

## Architecture Decisions

**Custom C dylibs over Frida.** Frida is blocked by SIP on Apple Silicon. Even for Simulator processes, Frida's injection mechanism fails. Custom DYLD-injected C dylibs have no such restriction — `dyld_sim` loads them before app code runs, DYLD interpose replaces C function calls at the symbol table level, and ObjC method swizzling replaces implementations at runtime. The result is completely undetectable: no known signature or fingerprint exists for Darkmach interceptors.

**Python stdlib only for Python tools.** No LIEF, no external binary manipulation libraries. Mach-O surgery is done with `struct.pack` / `struct.unpack` directly on the binary bytes. This keeps the dependency surface minimal and makes the tools auditable.

**Modular interceptors.** Each dylib is fully standalone with zero inter-dylib dependencies. Inject one, several, or all. The full set of 8 (`INTERCEPTOR_DYLIBS` in `cli.py`) is the default for `darkmach run` and `darkmach launch`.

**ARM64 instructions hand-encoded.** The shellcode generator (`make-main-patch.py`) encodes ARM64 instructions from the ISA spec using Python `struct.pack`, with no assembler dependency.

**JSON-lines logging.** All interceptors write structured JSONL to per-module files. This format is timestamp-correlated across all interceptors, grep-friendly, and directly parseable by the bridge client and any downstream tooling.
