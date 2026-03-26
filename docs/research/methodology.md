![Classification](https://img.shields.io/badge/classification-security%20research-red)
![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)

# Research Methodology

---

## Problem Statement

iOS app security research has traditionally required a jailbroken iPhone. Jailbreaks require specific device/iOS version combinations, are difficult to maintain across iOS updates, and are detected by an increasing number of apps. The research question was: can iOS apps be analyzed on a stock Mac, without jailbreak, without SIP bypass, without any device modification?

The answer turned out to be yes — for all iOS apps delivered via the Mac App Store on Apple Silicon, without exception.

---

## Research Approach

### Phase 1: Understand the Attack Surface

The first question was: what does the Mac App Store actually deliver when you install an iOS app on Apple Silicon?

Investigation revealed:
- The app is installed at `/Applications/AppName.app/Wrapper/AppName.app/`
- The outer `.app` is a Mac wrapper; the inner `.app` is the real iOS bundle
- The binary is a standard iOS arm64 Mach-O with `LC_ENCRYPTION_INFO_64` (`cryptid=1`)
- The binary bytes in the crypt region are genuine AES-encrypted FairPlay ciphertext

This contradicts a common assumption that Mac App Store iOS app delivery leaves binaries unencrypted. The encryption is real. The decryption only happens at runtime.

### Phase 2: Enumerate Available Techniques

Standard approaches for iOS binary analysis were enumerated and tested against the Mac context:

| Technique | Requirement | Available on Mac? |
|-----------|-------------|------------------|
| Jailbreak + FLEX / Clutch | Jailbroken iOS device | No |
| debugserver + lldb | `task_for_pid`, no SIP | No — SIP blocks |
| Frida | `task_for_pid` | No — SIP blocks |
| posix_spawn with platform override | Private API, kernel entitlement | No — child killed |
| DYLD injection at launch | Must control the launch environment | **Yes, via simctl** |
| Memory read from within the process | Process can read itself | **Yes** |

The key insight from this enumeration: while the host cannot attach to a running process (SIP), the process can read its own memory. The challenge was getting a modified binary to run in the Simulator in the first place.

### Phase 3: Understand the Simulator

Extensive reverse engineering of the Simulator runtime (`dyld_sim`, `launchd_sim`, the simctl toolchain) revealed the properties documented in [FairPlay DRM Bypass](fairplay-bypass.md). The critical finding was that `dyld_sim` completely ignores `cryptid` — it doesn't attempt to decrypt anything. This suggested the kernel might be handling decryption transparently before `dyld_sim` ever sees the pages.

Testing confirmed: spawn a binary with `cryptid=1` and `platform=7` in the Simulator, inject a library that reads from the crypt region offset, and the bytes are decrypted ARM64 instructions — not ciphertext.

---

## Pipeline Methodology

The research is structured as a linear pipeline where each phase builds on the previous:

```
Discovery → Acquisition → Static Analysis → Patching → Launch → Instrumentation → Reporting
```

Each phase was built as a standalone tool before integration into the unified `sphinx` CLI.

### Discovery

**Goal:** Find iOS apps that are available on the Mac App Store — the target population for analysis.

**Approach:** Two-step API query:
1. iTunes Search API or RSS feeds (no auth) → search by keyword or category
2. Apple amp-api per-app lookup (Bearer JWT from App Store web client) → check `isIOSBinaryMacOSCompatible`

This produces a list of app IDs, names, bundle IDs, and file sizes. An app with `status: available` is an iOS binary that can be installed on Apple Silicon.

### Acquisition

Standard Mac App Store installation. No modifications to the acquisition process. The app is installed at `/Applications/AppName.app` exactly as it would be for a regular user.

### Static Analysis

**Goal:** Extract intelligence from the decrypted binary without execution.

**Approach:** Python-native analysis using system tools (`otool`, `lipo`, `codesign`, `plutil`, `strings`) with no external dependencies. The `analyze_bundle()` function runs 14 checks:

- Encryption status (verifies `cryptid`)
- Architecture (`lipo -info`)
- Linked frameworks (`otool -L`)
- Strings extraction — all printable strings from the binary
- URL extraction — regex filter on strings for `http://` and `https://` patterns
- Secret extraction — regex filter for API key, token, bearer, password, credential patterns
- SDK fingerprinting — regex filter for known SDK strings (Firebase, Stripe, Sentry, RevenueCat, etc.)
- Entitlements (`codesign -d --entitlements`)
- Plist contents (all `.plist` files in the bundle)
- URL schemes (`CFBundleURLSchemes` in `Info.plist`)
- App Transport Security configuration
- Embedded JSON files
- Embedded framework inventory
- Mach-O load command summary

For React Native apps, a second pass using `sphinx hermes` decompiles Hermes bytecode from `main.jsbundle` to extract secrets and API keys that live in the JavaScript layer.

### Patching

**Goal:** Modify the binary to run in the iOS Simulator while extracting the FairPlay-decrypted code.

**Approach:** Two-pass pipeline (see [Binary Patching Guide](../patching.md)):
1. Extract decrypted crypt region bytes via `simctl spawn` with `sphinx-decrypt.dylib`
2. Apply platform flag patches, plist patches, re-sign
3. Write decrypted bytes into crypt region

The patching is done on a copy in `output/<app>/bundle/` — the installed app in `/Applications` is never modified.

### Simulator Launch

**Goal:** Run the decrypted app in the Simulator with full instrumentation active.

**Approach:** `xcrun simctl launch` with `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES` set to all 8 interceptor dylibs. The Simulator auto-boots if none is running.

The interceptors are injected before app code runs (DYLD constructor execution order). The bridge socket is ready by the time `UIApplicationMain` is called.

### Instrumentation

**Goal:** Capture runtime behavior — network traffic, secrets accessed at runtime, database operations, cryptographic keys in use.

Two instrumentation modes run in parallel:

**Passive interceptors:** The 7 non-bridge dylibs (net, keychain, crypto, storage, ssl, db, metal-fix) write structured JSONL logs to `output/<app>/dynamic/`. These are always active and require no interaction.

**Interactive bridge:** `sphinx-bridge.dylib` exposes the JSON command protocol. Used interactively (`sphinx bridge`) or by an LLM agent for autonomous exploration.

### Reporting

Findings are compiled into structured reports following the format in `.project/issues/ISSUE_TEMPLATE.md` and `.claude/rules/reporting-standards.md`. Platform findings (the FairPlay bypass itself) are reported to Apple Security Bounty. App-specific findings (hardcoded credentials, excessive entitlements, etc.) are reported to the respective developers.

---

## Tool Development Approach

### Python stdlib only

Every Python tool uses only standard library modules. The decision was made early to avoid binary analysis frameworks like LIEF or angr. Reasons:

- LIEF makes it easy to write code that relies on LIEF's interpretation of the binary, which may differ from what the OS actually does
- `struct.pack` / `struct.unpack` on raw bytes is more explicit and auditable
- Fewer dependencies mean fewer breakage vectors
- The code is simpler to read and understand

The only Python dependency is `hermes-dec` for Hermes bytecode decompilation (a specialized task with no stdlib solution).

### Custom C dylibs over Frida

The decision to write custom C dylibs rather than use Frida was driven by:

1. **SIP blocks Frida** — This is the practical reason. Frida cannot attach to Simulator processes.
2. **Zero runtime dependencies** — The C dylibs have no Python runtime, no external agents. They compile to self-contained `.dylib` files.
3. **DYLD interpose for C functions** — DYLD interposition replaces C function implementations at the symbol resolution level, before any app code runs. This is more powerful than hooking at the call site.
4. **No detectable signature** — No known anti-tamper or anti-debugging tool has a signature for custom DYLD-injected C dylibs using standard ObjC runtime swizzling.
5. **Modularity** — Each dylib is standalone. Inject one or all.

### Byte-level binary surgery

All Mach-O modifications are byte-level operations. The patcher reads the binary into a `bytearray`, locates the target fields by walking the load command chain with `struct.unpack_from`, and modifies them with `struct.pack_into`. The modified bytes are written back.

This approach:
- Touches only the specific bytes that need changing
- Preserves everything else exactly as-is (checksums, padding, segment layout)
- Is transparent about exactly what changes
- Has no dependency on a binary framework's model of the file

### ARM64 instructions hand-encoded

The shellcode generator (`make-main-patch.py`) encodes ARM64 instructions from scratch using the ISA specification. Each instruction type has its own encoding function that takes the operand values and produces the correct 4-byte instruction word via `struct.pack`.

This avoids any assembler dependency while keeping the generated code auditable — the encoding functions document exactly which bits encode which operands.

---

## Agent-Based Development

The Sphinx toolkit was developed using a multi-agent collaboration model with four specialist agents:

| Agent | Domain |
|-------|--------|
| exploit-engineer | ARM64 shellcode, Mach-O surgery, FairPlay bypass, entry point reconstruction |
| mobile-engineer | Frida instrumentation, DYLD injection, method swizzling, runtime analysis |
| code-engineer | Decrypted binary analysis, secret extraction, SDK fingerprinting, toolkit QA |
| report-engineer | Apple Security Bounty submission, research documentation, finding reports |

The agents collaborate in two modes:

**Development mode:** Building, improving, and testing the toolkit. Agents work on their own domains but review each other's code. The exploit-engineer and mobile-engineer are the closest partners — one patches, the other instruments.

**Validation mode:** Running the toolkit against real apps. Static analysis and dynamic analysis run in parallel (code-engineer and exploit-engineer analyze the binary; mobile-engineer instruments the runtime). Patching is serial (exploit-engineer owns the binary modification pipeline).

### Iterative feedback loop

Every app test feeds back into toolkit development:
- Something doesn't patch correctly → exploit-engineer fixes the patcher
- A dylib crashes → mobile-engineer diagnoses and fixes
- A new SDK is found → code-engineer adds to fingerprint patterns
- A new edge case in binary structure → documented as a known issue

This tight loop between validation and development means the toolkit improves with each app analyzed.

---

## Known Limitations and Active Work

| Limitation | Status |
|------------|--------|
| SwiftUI `@main` apps without AppDelegate | Detected, not yet patchable via Strategy A. Two-pass decryption works. |
| Some frameworks use `LC_VERSION_MIN_IPHONEOS` | Handled by vtool conversion in `patch-for-simulator.sh` |
| App UI may not render visually in Simulator | App runs and interceptors capture data; UI rendering varies by app |
| `SecItemCopyMatching` may return -34018 in Simulator | Keychain entitlement may be needed in some Simulator contexts |
| No automated finding detection | Static analysis extracts data but doesn't flag what's interesting — requires review |
| No end-to-end test suite | No automated regression tests for the toolkit |
