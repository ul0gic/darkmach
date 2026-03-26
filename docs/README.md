![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Status](https://img.shields.io/badge/status-active%20development-orange)

# Sphinx Documentation

Sphinx is a first-of-its-kind iOS reverse engineering toolkit for Apple Silicon. It exploits a fundamental property of how the macOS kernel handles FairPlay DRM for iOS Simulator processes: iOS apps installed via the Mac App Store are stored fully decrypted on disk, and the kernel performs transparent page-in decryption for Simulator processes — enabling complete FairPlay bypass on a stock Mac with no jailbreak, no SIP bypass, and no special entitlements.

---

## Documentation Index

### Product Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](installation.md) | Prerequisites, install steps, building dylibs, verifying your setup |
| [CLI Reference](cli-reference.md) | Complete reference for all 10 subcommands |
| [Architecture Overview](architecture.md) | Project structure, pipeline phases, component interactions, data flow |
| [Interceptor Dylib Reference](interceptors.md) | All 10 interceptors, what they hook, output format, injection |
| [Binary Patching Guide](patching.md) | How patching works, the two-pass FairPlay technique, all patch tools |
| [LLM Runtime Bridge](bridge.md) | The bridge protocol, full command set, interactive and autonomous use |

### Research Documentation

| Document | Description |
|----------|-------------|
| [Research Index](research/README.md) | Overview of research documentation |
| [FairPlay DRM Bypass](research/fairplay-bypass.md) | Discovery of the kernel page-in decryption bypass — how it works and why |
| [Research Methodology](research/methodology.md) | How the project was built and how the pipeline was developed |
| [Example Findings](research/findings.md) | OddsJam case study — first full-pipeline live app analysis |

---

## Quick Start

From zero to a running instrumented app in 5 steps.

**Prerequisites:** Apple Silicon Mac, Xcode with Simulator, Python 3.11+

```bash
# 1. Install Sphinx
pip install -e /path/to/sphinx

# 2. Build the interceptor dylibs
cd /path/to/sphinx && make

# 3. Verify your system is ready
sphinx status

# 4. Find an iOS app to analyze
sphinx list

# 5. Run the full pipeline
sphinx run /Applications/SomeApp.app
```

After step 5, Sphinx will:
- Run static analysis (URLs, secrets, SDKs, entitlements)
- Boot a Simulator if none is running
- Patch the binary for Simulator execution (including FairPlay decryption)
- Install and launch with all interceptors active
- Connect to the LLM runtime bridge

Connect to the bridge for interactive or autonomous exploration:

```bash
sphinx bridge
```

---

## Pipeline Overview

```
sphinx discover          Find iOS apps available on Mac App Store
        |
sphinx list              See what's already installed
        |
sphinx analyze           Static analysis only (optional standalone use)
        |
sphinx run               Full pipeline:
        |                  1. Locate iOS bundle
        |                  2. Copy to output/<app>/bundle/
        |                  3. Static analysis → output/<app>/static/
        |                  4. Boot Simulator
        |                  5. Patch for Simulator (FairPlay decryption)
        |                  6. Install + launch with interceptors
        |                  7. Connect bridge
        |
sphinx bridge            Interactive LLM runtime bridge
```

---

## Key Concepts

**FairPlay bypass via kernel page-in decryption.** iOS apps on Mac have `cryptid=1` set in their Mach-O encryption headers, but the on-disk binary content in the crypt region is the real AES-encrypted code. When a process runs in the iOS Simulator, the macOS kernel decrypts these pages during page-in — the same mechanism used for regular execution, but without FairPlay enforcement. Sphinx exploits this to extract the decrypted bytes by spawning the binary in the Simulator with a DYLD-injected extraction library.

**Custom C interceptors over Frida.** SIP blocks Frida on Apple Silicon. Sphinx uses DYLD-injected C dylibs that interpose C functions and swizzle ObjC methods — undetectable, zero external dependencies, and running inside the Simulator process where SIP restrictions do not apply.

**LLM runtime bridge.** An injected dylib opens a Unix domain socket inside the running app, exposing a JSON command protocol. An LLM connects and can autonomously enumerate classes, read live object state, hook methods, dump keychain and databases, and compile security findings — all without human-directed scripting.

---

## Output Structure

All results are written to `output/` in the project directory:

```
output/
└── <app-slug>/
    ├── static/          # Static analysis: urls.txt, secrets.txt, sdks.txt,
    │                    #   entitlements.txt, plists.txt, summary.json
    ├── dynamic/         # Runtime logs: sphinx-net.jsonl, sphinx-keychain.jsonl,
    │                    #   sphinx-db.jsonl, sphinx-crypto.jsonl, sphinx-storage.jsonl,
    │                    #   sphinx-ssl.jsonl, sphinx-bridge.jsonl
    └── bundle/          # Patched app copy ready for Simulator
        └── <App>.app/
```
