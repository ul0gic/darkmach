![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-Proprietary-red)
![Status](https://img.shields.io/badge/status-active%20development-orange)

# Darkmach Documentation

Darkmach is a first-of-its-kind iOS reverse engineering toolkit for Apple Silicon. It exploits a fundamental property of how the macOS kernel handles FairPlay DRM for iOS Simulator processes: iOS apps installed via the Mac App Store ship FairPlay-encrypted on disk (`cryptid = 1`), and the macOS kernel transparently decrypts those pages during page-in for Simulator-targeted processes. Patching the platform flag to iOSSimulator and re-signing with empty entitlements is enough to engage this path — enabling complete FairPlay bypass on a stock Mac with no jailbreak, no SIP bypass, and no special entitlements.

---

## Documentation Index

### Product Documentation

| Document | Description |
|----------|-------------|
| [Capability Brief](darkmach-brief.md) | Current-state capability brief — pipeline, distinctives, validation |
| [Installation Guide](installation.md) | Prerequisites, install steps, building dylibs, verifying your setup |
| [CLI Reference](cli-reference.md) | Complete reference for all 10 subcommands |
| [Architecture Overview](architecture.md) | Project structure, pipeline phases, component interactions, data flow |
| [Interceptor Dylib Reference](interceptors.md) | The 12 injected dylibs, what they hook, output format, injection |
| [Binary Patching Guide](patching.md) | How patching works, the two-pass FairPlay technique, all patch tools |
| [Bridge Command Reference](bridge.md) | The bridge protocol, full 60-command surface, interactive use |
| [Engagement Pattern](engagement-pattern.md) | How an external engagement project wires Darkmach in via a `.tools/darkmach` symlink |

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
# 1. Build the dylibs (clang against the iOS Simulator SDK)
cd /path/to/darkmach && make

# 2. Install Darkmach as an isolated CLI
pipx install /path/to/darkmach

# 3. Verify your system is ready
darkmach status

# 4. Find an iOS app to analyze
darkmach list

# 5. Run the full pipeline
darkmach run /Applications/SomeApp.app
```

After step 5, Darkmach will:
- Run static analysis (URLs, secrets, SDKs, entitlements)
- Boot a Simulator if none is running
- Patch the binary for Simulator execution (including FairPlay decryption)
- Install and launch with all interceptors active
- Connect to the runtime bridge

Connect to the bridge for interactive operator-driven exploration:

```bash
darkmach bridge
```

---

## Pipeline Overview

```
darkmach discover          Find iOS apps available on Mac App Store
        |
darkmach list              See what's already installed
        |
darkmach analyze           Static analysis only (optional standalone use)
        |
darkmach run               Full pipeline:
        |                  1. Locate iOS bundle
        |                  2. Copy to output/<app>/bundle/
        |                  3. Static analysis → output/<app>/static/
        |                  4. Boot Simulator
        |                  5. Patch for Simulator (FairPlay decryption)
        |                  6. Install + launch with interceptors
        |                  7. Connect bridge
        |
darkmach bridge            Interactive LLM runtime bridge
```

---

## Key Concepts

**FairPlay bypass via kernel page-in decryption.** iOS apps on Mac have `cryptid=1` set in their Mach-O encryption headers and the on-disk crypt region is genuine AES-encrypted FairPlay ciphertext. When a process runs in the iOS Simulator, the macOS kernel decrypts these pages during page-in via the same `mremap_encrypted` / `IOTextEncryptionFamily` / `fairplayd` path used for regular execution. Darkmach engages this path by patching the platform flag, zeroing the encryption header, re-signing ad-hoc, and reading the decrypted bytes back from a DYLD-injected dylib inside the running Simulator process.

**Custom C interceptors over Frida.** SIP blocks Frida on Apple Silicon. Darkmach uses DYLD-injected C dylibs that interpose C functions and swizzle ObjC methods — no external runtime dependency, and running inside the Simulator process where SIP restrictions do not apply.

**Operator-driven runtime bridge.** An injected dylib opens a Unix-domain socket inside the running app, exposing a JSON command protocol. An operator (or automation client) connects and can enumerate classes, read live object state, hook methods, dump keychain and databases, capture network / crypto / auth tap streams, and compile evidence — all over a single socket.

---

## Output Structure

All results are written to `output/` in the project directory:

```
output/
└── <app-slug>/
    ├── static/          # Static analysis: urls.txt, secrets.txt, sdks.txt,
    │                    #   entitlements.txt, plists.txt, summary.json
    ├── dynamic/         # Runtime logs: darkmach-net.jsonl, darkmach-keychain.jsonl,
    │                    #   darkmach-db.jsonl, darkmach-crypto.jsonl, darkmach-storage.jsonl,
    │                    #   darkmach-ssl.jsonl, darkmach-bridge.jsonl
    └── bundle/          # Patched app copy ready for Simulator
        └── <App>.app/
```
