![Classification](https://img.shields.io/badge/classification-security%20research-red)
![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)

# Research Documentation

This section documents the research behind Darkmach — the discovery of the FairPlay bypass technique, the methodology used to build the toolkit, and example findings from real iOS apps.

---

## Documents

| Document | Description |
|----------|-------------|
| [FairPlay DRM Bypass](fairplay-bypass.md) | The core technical discovery: how and why the macOS kernel decrypts FairPlay pages for iOS Simulator processes |
| [FairPlay Decryption Research](fairplay-decryption.md) | Deep investigation of macOS FairPlay infrastructure — mremap_encrypted syscall, fairplayd, kernel decryption chain, PoC results |
| [ipatool Protocol Study](ipatool-protocol-study.md) | How ipatool talks to the iOS App Store backend — kept as a protocol reference |
| [Research Methodology](methodology.md) | How the pipeline was developed, tool decisions, and the iterative research approach |
| [Example Findings](findings.md) | OddsJam case study — findings from the first full-pipeline live app analysis |
| [Frida-gum LOE Study](frida-gum-study.md) | Consolidated LOE report from the Phase 13 reference study — 20 capabilities, ~6200 LoC, six sprints |
| [Frida-gum Interceptor Study](frida-gum-interceptor-study.md) | ARM64 interception deep dive — trampoline design, swizzling vs inline hooking |
| [Frida-gum Heap Study](frida-gum-heap-study.md) | Heap walking — malloc zone enumeration, isa validation, thread safety |

---

## The Core Insight

iOS apps installed via the Mac App Store on Apple Silicon have `cryptid=1` set in their Mach-O `LC_ENCRYPTION_INFO_64` load command. The bytes in the declared crypt region are genuine AES-encrypted FairPlay ciphertext — not the actual executable code.

At runtime, the macOS kernel decrypts FairPlay-protected pages during page-in via the same mechanism used for regular device execution. **The key discovery:** the kernel performs this same transparent decryption for iOS Simulator processes — even when the binary has been modified to change the platform flag from iOS to iOSSimulator.

This means that by patching only the platform flag (a single byte change to `LC_BUILD_VERSION`), re-signing with an ad-hoc signature, and loading the binary in the iOS Simulator, the kernel will decrypt all FairPlay pages during execution. A DYLD-injected library can then read the decrypted bytes from the process's own memory — a capability every process has over itself.

**The result:** Complete FairPlay DRM bypass on a stock Apple Silicon Mac with:
- No jailbreak
- No SIP bypass
- No VM or hardware modification
- No special entitlements
- Standard user permissions only

No prior public documentation of this technique exists.

---

## Responsible Use

This research was conducted to document a systemic security issue in Apple's FairPlay DRM delivery model for Mac App Store iOS apps. The findings have been documented for responsible disclosure to Apple through the Apple Security Bounty program.

All research was conducted on apps the researcher had purchased. Findings from individual apps are disclosed to the respective developers through their security disclosure channels before public documentation.

The tools and techniques documented here are intended for:
- Security research on apps the researcher has purchased or is authorized to analyze
- Bug bounty programs with explicit authorization
- Defensive security assessment of the researcher's own applications
- Educational understanding of iOS app security on Apple Silicon

---

## Timeline

| Date | Milestone |
|------|-----------|
| 2026-03-23 | FairPlay Simulator decryption bypass discovered and proven end-to-end |
| 2026-03-23 | Custom instrumentation suite (6 interceptor dylibs) built and validated |
| 2026-03-23 | First live app analysis (OddsJam) — multiple security findings captured |
| 2026-03-23 | Full pipeline CLI automation (`darkmach run`) operational |
| 2026-03-26 | App Store opt-out flag located and decoded — `isIOSBinaryMacOSCompatible` boolean in amp-api, DMAP `aeSS` bitmask |
| 2026-03-26 | Simulator daemon stack investigated — full production URL bags served, storeUser.db unencrypted |
| 2026-03-26 | macOS FairPlay infrastructure confirmed — `mremap_encrypted` syscall 489, full kernel decryption chain mapped |
| 2026-03-26 | DoorDash PoC — ipatool IPA patched for Simulator, FairPlay chain engaged, failed on identity binding (error -42110) |
