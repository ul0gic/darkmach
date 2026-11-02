![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# Architecture Overview

---

## Project Structure

```
darkmach/
├── pyproject.toml              # Package config, entry point: darkmach.cli:entrypoint
├── Makefile                    # Compiles all C dylibs against iOS Simulator SDK
├── src/                        # Python package — everything ships in the wheel
│   ├── cli.py                  # Parser, dispatch and console entry point
│   ├── commands.py             # 10 command handlers and workflow orchestration
│   ├── pipeline/               # Bundle, process, signing, patching and Simulator operations
│   ├── analysis/               # Bundle inspection, Hermes, keychain, SDK and secret analysis
│   ├── discover.py             # App Store API: iTunes Search + amp-api
│   ├── bridge/                 # JSON socket client, response rendering, shell, type encodings
│   ├── _paths.py               # Package paths, output locations and dylib inventory
│   ├── patch/                  # Importable binary transformations + standalone script wrappers
│   │   ├── surgical.py             # Byte-level Mach-O surgery (platform + encryption)
│   │   ├── main_patch.py           # ARM64 shellcode generator (Strategy A)
│   │   ├── main_stub.py            # clang-compiled stub (Strategy A alternative)
│   │   ├── objc_metadata.py        # ObjC method-list pointer neutralizer (Strategy A)
│   │   └── delegate.py             # AppDelegate auto-detection (6-tier)
│   └── dylibs/                 # C source → Simulator-targeted .dylib
│       ├── darkmach-core.h       # Shared infrastructure header
│       ├── build/                # Compiled .dylib outputs (shipped as package_data)
│       ├── bridge/               # Runtime bridge: dispatcher + 8 cmd-*.c modules
│       │                         #   + darkmach-trampoline.S (ARM64 trace stub)
│       ├── interceptors/         # DYLD_INTERPOSE hooks: net, crypto, db, keychain,
│       │                         #   tls, storage, ssl
│       ├── stealth/              # Jailbreak/debug/hook evasion
│       ├── compat/               # decrypt (FairPlay extractor), metal-fix, survival
│       └── tools/                # dump-region.c — host-side Mach task memory reader
└── output/                     # Per-app results (created at runtime; $PWD-relative)
    ├── .cache/crypt/            # FairPlay decryption cache (per bundle ID)
    └── <app-slug>/
        ├── static/              # Static analysis output
        ├── dynamic/             # Runtime interceptor logs (JSONL)
        └── bundle/              # Patched app copy
```

---

Darkmach and its subpackages use namespace packaging; product source contains no `__init__.py` files. Setuptools maps the import namespace `darkmach` directly to `src/`; no additional package-name directory is needed. Import bridge functions from `darkmach.bridge.client`, `darkmach.bridge.render` and `darkmach.bridge.shell`. The distribution version is declared in `pyproject.toml` and available through installed `darkmach-re` package metadata.

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
  stage_patch() → _detect_strategy() picks "extract" (Mac App Store) or
  "strategy_a" (iOS-channel IPA). The extract path:
  1. _read_crypt_info()      → cryptoff/cryptsize from the original binary
  2. _extract_crypt_region() → simctl spawn + darkmach-decrypt.dylib
  3. patch_bundle()          → platform flags, encryption headers, plists, signing
  4. _write_crypt_bytes()    → decrypted bytes into patched binary → re-sign

Phase 6: Simulator Launch                   Phase 7: Bridge Connect
  xcrun simctl install <device> <bundle>      Wait for /tmp/darkmach-bridge.sock
  xcrun simctl launch <device> <bundle-id>    Verify bridge info command
  └── SIMCTL_CHILD_DYLD_INSERT_LIBRARIES      darkmach bridge (interactive)
      = 8 interceptor dylibs
```

---

## Component Interactions

### Python CLI (`src/`)

The parser in `cli.py` dispatches to `commands.py`. Command handlers compose the focused modules in `pipeline/`: process execution, bundle discovery, signing, patching and Simulator operations. Bundle patching runs in process through `pipeline/patching.py` and `patch/surgical.py`; Strategy A additionally invokes the standalone Python patch scripts. System tools (`vtool`, `plutil`, `codesign`, `otool`, `xcrun simctl`) run as subprocesses. Both bridge client adapters share one Unix socket exchange in `bridge/client.py`, while retaining their existing response and error policies.

```
cli.py → commands.py
  ├── cmd_run()          Full 7-step pipeline
  ├── cmd_analyze()      → analysis/bundle.py: analyze_bundle()
  ├── cmd_patch()        → stage_patch() → _detect_strategy()
  │                        ├── "extract"    → _extract_crypt_region() (simctl spawn)
  │                        │                  → patch_bundle() → _write_crypt_bytes()
  │                        └── "strategy_a" → _patch_strategy_a()
  │                                           → patch_bundle(keep_framework_crypt=True)
  │                                           → make-main-patch.py, patch-objc-metadata.py
  ├── cmd_launch()       → stage_launch() → subprocess: simctl launch
  │                        + SIMCTL_CHILD_DYLD_INSERT_LIBRARIES
  ├── cmd_bridge()       → bridge/shell.py: interactive_mode()
  ├── cmd_discover()     → discover.py: run_discover()
  ├── cmd_hermes()       → analysis/hermes.py: main()
  ├── cmd_keychain()     → analysis/keychain.py: main()
  ├── cmd_list()         Scans /Applications for iOS bundles
  └── cmd_status()       Checks architecture, tools, SDK, dylibs
```

`patch_bundle()` walks the bundle (main binary → `Frameworks/` → `PlugIns/*.appex` → extension frameworks), patching each Mach-O and Info.plist, then re-signs inside-out. It imports `patch/surgical.py` and calls `patch_file()` directly. The original hyphenated script names remain available as thin command wrappers. The Strategy A tools — `make-main-patch.py` and `patch-objc-metadata.py` — are the only patch scripts still run as subprocesses, because they are invoked per binary with explicit crypt geometry.

**Discovery (`discover.py`) — amp-api token refresh:** Discovery is two-step —
the iTunes Search/RSS API (free, no auth) finds apps by keyword or category,
then a per-app amp-api lookup (Bearer token) checks `isIOSBinaryMacOSCompatible`.
The amp-api token is a JWT captured from the App Store web client. To refresh it:
visit apps.apple.com in Safari, open the Network tab, find any amp-api-edge
request, and copy the `Authorization: Bearer` token.

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

The two-pass decryption is the most complex piece of the pipeline. Both passes live in `pipeline/patching.py`; offsets below are from the verified AssetLabField run (`ca.assetlab.ios`, 2026-08-01).

```
Original binary (on disk):
  LC_ENCRYPTION_INFO_64: cryptoff=0x20000, cryptsize=0x1000, cryptid=1
  Bytes at offset 0x20000..0x21000: AES-encrypted by FairPlay

Pass 1 — _extract_crypt_region():
  1. Copy bundle to /tmp/darkmach-decrypt/
  2. patch_bundle() on the copy (patches platform, zeroes crypt header)
  3. Restore cryptid=1 + cryptoff/cryptsize in the temp binary
     (so the kernel decrypts during page-in)
  4. Re-sign the temp binary
  5. simctl spawn <udid> <temp-binary>
       + SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=darkmach-decrypt.dylib
       + SIMCTL_CHILD_DARKMACH_CRYPTOFF=0x20000
       + SIMCTL_CHILD_DARKMACH_CRYPTSIZE=0x1000
       + SIMCTL_CHILD_DARKMACH_DECRYPT_OUT=output/.cache/crypt/<bundle-id>.bin
     → Kernel decrypts FairPlay pages during page-in
     → darkmach-decrypt.dylib reads bytes from process's own memory
     → Writes plaintext to cache file
  6. Clean up /tmp/darkmach-decrypt/

Pass 2 — back in stage_patch():
  1. patch_bundle() on the work copy (cryptid=0, platform=7)
  2. _write_crypt_bytes() — cache file → binary at cryptoff
  3. Re-sign binary and bundle
```

The cache is keyed by bundle ID and reused when its size matches `cryptsize`, so re-patching the same app skips the spawn. A size mismatch or missing file raises `DarkmachError` rather than producing a silently wrong binary.

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

Path resolution is centralized in `src/_paths.py`. Asset paths are resolved relative to the installed package directory, so they work identically under `pip install -e .` and `pipx`. Output paths are resolved relative to the working directory, so results land where the operator ran the command.

| Constant | Resolved Path |
|----------|--------------|
| `DYLIB_DIR` | `<package>/dylibs/build/` — compiled dylibs, shipped as `package_data` |
| `PATCH_DIR` | `<package>/patch/` — patching tools |
| `OUTPUT_DIR` | `$PWD/output/`, overridden by `DARKMACH_OUTPUT` |
| `CRYPT_CACHE` | `OUTPUT_DIR/.cache/crypt/` |
| `BRIDGE_SOCKET` | `/tmp/darkmach-bridge.sock` (fixed, shared with app process) |

`app_output_dir()`, `app_static_dir()`, `app_dynamic_dir()`, and `app_bundle_dir()` derive the per-app tree from a slug (lowercased, spaces and underscores to dashes, `.app` stripped).

`DARKMACH_OUTPUT` sets the output root. It is distinct from `DARKMACH_OUTPUT_DIR`, which the CLI sets per-launch to point the injected dylibs' JSONL logs at that app's `dynamic/` subdirectory.

---

## Architecture Decisions

**Custom C dylibs over Frida.** Frida is blocked by SIP on Apple Silicon. Even for Simulator processes, Frida's injection mechanism fails. Custom DYLD-injected C dylibs have no such restriction — `dyld_sim` loads them before app code runs, DYLD interpose replaces C function calls at the symbol table level, and ObjC method swizzling replaces implementations at runtime. No public anti-tamper SDK is known to fingerprint Darkmach specifically, but the injection is not invisible: loaded dylibs are enumerable from inside the process via `_dyld_image_count` / `_dyld_get_image_name`, and swizzled `IMP`s are visible through the ObjC runtime. `darkmach-stealth.dylib` exists to blunt those checks — see `docs/interceptors.md`.

**Python stdlib only for Python tools.** No LIEF, no external binary manipulation libraries. Mach-O surgery is done with `struct.pack` / `struct.unpack` directly on the binary bytes. This keeps the dependency surface minimal and makes the tools auditable.

**Modular interceptors.** Each dylib is fully standalone with zero inter-dylib dependencies. Inject one, several, or all. The full set of 8 (`INTERCEPTOR_DYLIBS` in `_paths.py`) is the default for `darkmach run` and `darkmach launch`.

**ARM64 instructions hand-encoded.** The shellcode generator (`patch/main_patch.py`) encodes ARM64 instructions from the ISA spec using Python `struct.pack`, with no assembler dependency.

**JSON-lines logging.** All interceptors write structured JSONL to per-module files. This format is timestamp-correlated across all interceptors, grep-friendly, and directly parseable by the bridge client and any downstream tooling.
