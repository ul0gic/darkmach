![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)

# Darkmach

Operator-driven iOS reverse engineering toolkit for Apple Silicon. Darkmach turns Mac-installed iOS apps into Simulator-runnable, fully instrumentable analysis targets by patching bundle metadata, extracting FairPlay crypt regions through Simulator page-in decryption, and launching with DYLD-injected instrumentation. No jailbreak, no SIP bypass, no special entitlements.

## Current Status

- Core analyze -> patch -> decrypt -> install -> launch pipeline is implemented
- Runtime bridge and interceptor suite are implemented
- Manual validation has been carried out across roughly 15 real apps
- Autonomous LLM exploration remains optional and is not required for the current workflow

## Quick Start

```bash
# Install
pip install -e .

# Build interceptor dylibs
make

# Verify system
darkmach status

# See installed iOS apps
darkmach list

# Run full pipeline against an app
darkmach run /Applications/SomeApp.app
```

After `darkmach run`, connect to the runtime bridge:

```bash
darkmach bridge
```

## Prerequisites

- **Apple Silicon Mac** (M1/M2/M3/M4)
- **Xcode** with iOS Simulator runtime (`xcode-select --install`)
- **Python 3.11+**

See [docs/installation.md](docs/installation.md) for detailed setup.

## CLI

```
darkmach run <app>              Full pipeline: analyze -> patch -> decrypt -> install -> launch -> bridge
darkmach analyze <app>          Static analysis (URLs, secrets, SDKs, entitlements, Mach-O)
darkmach patch <app>            Patch bundle for Simulator (includes FairPlay decryption)
darkmach launch <bundle-id>     Launch installed app with all interceptors
darkmach bridge                 Connect to runtime bridge (interactive)
darkmach discover [search]      Find iOS apps available on Mac App Store
darkmach hermes <app>           Extract secrets from React Native / Hermes bytecode
darkmach keychain               Read Simulator keychain from host filesystem
darkmach list                   List installed iOS apps
darkmach status                 System pre-flight check
```

See [docs/cli-reference.md](docs/cli-reference.md) for full reference with arguments and examples.

## Pipeline

```
darkmach discover       Find iOS apps on Mac App Store
       |
darkmach list           See what's installed
       |
darkmach run            Full pipeline:
       |                1. Locate iOS bundle (resolves Wrapper/ structure)
       |                2. Copy to output/<app>/bundle/
       |                3. Static analysis -> output/<app>/static/
       |                4. Boot Simulator
       |                5. Patch for Simulator (two-pass FairPlay decryption)
       |                6. Install + launch with interceptors
       |                7. Connect runtime bridge
       |
darkmach bridge         Interactive operator-driven exploration of live app
```

## Project Structure

```
darkmach/
├── pyproject.toml              # Package config (pip install -e .)
├── Makefile                    # Builds all C dylibs
├── src/
│   ├── darkmach/                 # Python CLI package
│   │   ├── cli.py              # Pipeline orchestration + CLI commands
│   │   ├── analyze.py          # Static analysis engine
│   │   ├── discover.py         # App Store discovery
│   │   ├── bridge.py           # Runtime bridge client + formatter layer
│   │   ├── hermes.py           # React Native bytecode extraction
│   │   ├── keychain.py         # Simulator keychain reader
│   │   ├── typeenc.py          # ObjC type encoding parser
│   │   └── _paths.py           # Central path resolution
│   ├── patch/                  # Binary patching pipeline
│   │   ├── patch-macho-surgical.py   # Byte-level Mach-O patcher
│   │   ├── make-main-patch.py        # ARM64 shellcode generator
│   │   ├── make-main-stub.py         # Alternative clang-compiled stub
│   │   └── detect-delegate.py        # AppDelegate auto-detection
│   └── dylibs/                 # Injected C components
│       ├── bridge/             # Runtime bridge dispatcher + command modules
│       ├── interceptors/       # Passive network/crypto/db/keychain/storage/tls hooks
│       ├── compat/             # Simulator compatibility + decryption helpers
│       ├── stealth/            # Anti-detection support
│       ├── tools/              # Standalone host-side utilities
│       ├── darkmach-core.h       # Shared infrastructure
│       └── build/              # Compiled .dylib outputs
├── tests/                      # pytest suite (592 tests)
│   ├── conftest.py             # Shared fixtures
│   ├── test_analyze.py         # Static analysis tests
│   ├── test_bridge.py          # Bridge protocol tests
│   ├── test_cli.py             # CLI tests
│   ├── test_discover.py        # Discovery tests
│   ├── test_hermes.py          # Hermes bytecode tests
│   ├── test_keychain.py        # Keychain reader tests
│   ├── test_make_main_patch.py # ARM64 encoder + shellcode tests
│   ├── test_patch_macho_surgical.py  # Mach-O patcher tests
│   └── test_detect_delegate.py # AppDelegate detection tests
├── output/                     # Per-app results (gitignored)
│   └── <app>/
│       ├── static/             # Analysis output
│       ├── dynamic/            # Runtime JSONL logs
│       └── bundle/             # Patched app copy
└── docs/                       # Full documentation
```

## How It Works

**FairPlay bypass via kernel page-in decryption.** iOS apps on Mac have `cryptid=1` and genuine AES-encrypted crypt regions on disk. When a platform-patched binary runs in the Simulator, the macOS kernel decrypts these pages during page-in — the same mechanism used for normal execution, but without validation that the binary was modified. Darkmach spawns the binary in the Simulator with an extraction dylib that reads the decrypted bytes from its own memory.

**Custom C interceptors over Frida.** Darkmach uses DYLD-injected C dylibs that interpose C functions and swizzle ObjC methods. The stack stays lightweight, low-dependency, and inside the target process instead of depending on a heavier external instrumentation runtime.

**Runtime bridge.** An injected dylib opens a Unix domain socket inside the running app, exposing a JSON command protocol. A human operator can drive it interactively today through `darkmach bridge`, and the same protocol is compatible with future automation clients. The shipped workflow already supports live class enumeration, object inspection, method tracing, UI interaction, keychain/database inspection, and evidence collection from a running app.

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Prerequisites, install, building dylibs, verification |
| [CLI Reference](docs/cli-reference.md) | All 10 subcommands with args and examples |
| [Architecture](docs/architecture.md) | Project structure, pipeline, component interactions |
| [Interceptors](docs/interceptors.md) | All 10 dylibs — hooks, data captured, output format |
| [Patching](docs/patching.md) | Two-pass FairPlay technique, all patch tools |
| [Runtime Bridge](docs/bridge.md) | Bridge protocol, command set, operator workflow, and future autonomy notes |
| [FairPlay Bypass](docs/research/fairplay-bypass.md) | The novel discovery — kernel page-in decryption |
| [Methodology](docs/research/methodology.md) | Research approach and tool development decisions |
| [Findings](docs/research/findings.md) | OddsJam case study — first live app analysis |

## Troubleshooting

**App crashes on `simctl launch`**
- `darkmach patch` auto-converts `LC_VERSION_MIN_IPHONEOS` via vtool and re-signs inside-out
- If still crashing, check Simulator console for missing frameworks or entitlement errors

**`darkmach status` shows missing dylibs**
- Run `make` from project root to build all interceptors

**Bridge doesn't connect**
- The app must launch successfully first — check for crash in Simulator console
- Bridge socket is at `/tmp/darkmach-bridge.sock`

**App launches but blank screen**
- AppDelegate detection may have failed — check `python3 src/darkmach/patch/detect-delegate.py App.app/Binary`
- SwiftUI `@main` apps need alternative entry strategy (known limitation)

See [docs/installation.md](docs/installation.md) for more troubleshooting.
