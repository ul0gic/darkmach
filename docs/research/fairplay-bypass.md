![Classification](https://img.shields.io/badge/classification-security%20research-red)
![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Status](https://img.shields.io/badge/status-proven%20%E2%80%94%20end--to--end%20working-brightgreen)

# FairPlay DRM Bypass via Kernel Page-In Decryption

**Discovery date:** 2026-03-23
**Status:** Proven — end-to-end working on Apple Silicon Mac
**Scope:** All iOS apps delivered via Mac App Store on Apple Silicon

---

## The Core Insight

iOS apps installed via the Mac App Store on Apple Silicon Macs are protected by FairPlay DRM. The Mach-O binary contains `LC_ENCRYPTION_INFO_64` with `cryptid=1`, and the bytes in the declared crypt region (`cryptoff` to `cryptoff+cryptsize`) are genuine AES-encrypted FairPlay ciphertext on disk.

At runtime on a real iOS device, the kernel decrypts these pages during page-in via FairPlay's kernel extension. This is transparent to the running process — the code runs without any knowledge of having been encrypted.

**The discovery:** The macOS kernel performs this same transparent page-in decryption for iOS Simulator processes.

By patching only the platform flag in `LC_BUILD_VERSION` (changing `2` / iOS to `7` / iOSSimulator) and re-signing with an ad-hoc signature, an iOS binary can be loaded into the Simulator. When the Simulator process runs, the kernel decrypts the FairPlay crypt region during page-in exactly as it would for a real device — with no validation that the binary was modified.

A DYLD-injected library running inside the Simulator process can then read the decrypted bytes from its own memory space. Every process can read its own memory — this is not a privilege escalation.

The result is complete FairPlay DRM bypass without jailbreak, SIP bypass, VM, or special entitlements.

---

## Why This Works: Technical Analysis

### The Kernel Page-In Path

FairPlay DRM on macOS works at the virtual memory level. When a FairPlay-protected page is faulted in (the process attempts to access a page that is not yet resident in physical memory), the kernel intercepts the fault and:

1. Reads the encrypted page from disk
2. Decrypts it using the FairPlay key stored in the kernel
3. Maps the decrypted page into the process's virtual address space
4. Returns the fault — the process sees the decrypted code

This mechanism is implemented in the kernel's page fault handler and applies to any process that has a valid FairPlay entitlement in its binary.

### The Simulator Security Model

The iOS Simulator is not an emulator — it runs native arm64 code on the Mac's CPU. The Simulator provides a simulated iOS environment (SpringBoard, runtime libraries, sandboxing) but uses the real macOS kernel.

Key properties of the Simulator security model:

- **`dyld_sim` ignores `cryptid`** — The Simulator's `dyld` does not process `LC_ENCRYPTION_INFO_64`. It does not attempt to decrypt or validate the crypt region.
- **No `amfid` in the Simulator** — The Apple Mobile File Integrity daemon (`amfid`) that enforces code signing on real iOS devices does not run in the Simulator runtime.
- **`DYLD_AMFI_FAKE` exists in `dyld_sim`** — The Simulator can fake AMFI code signing responses.
- **Ad-hoc signatures accepted** — `codesign -s -` (no identity, ad-hoc) is sufficient for Simulator execution. No Apple Developer certificate required.
- **`mremap_encrypted` returns EINVAL in Simulator** — Syscall 489, which explicitly processes FairPlay mappings, is not available in the Simulator context. But this is not needed — the kernel page-in path already decrypts the pages.

### The Key Finding: FairPlay Page-In Without FairPlay Validation

The kernel's FairPlay page-in decryption path does not validate whether the binary has been modified. It checks whether the page falls within a declared crypt region and whether the process has FairPlay entitlement — and then decrypts.

When a platform-patched iOS binary (with `cryptid=1` and the original crypt region) runs in the Simulator:

1. The kernel sees `cryptid=1` — this binary has FairPlay-encrypted pages
2. On page fault for pages in the crypt region, the kernel decrypts them during page-in
3. `dyld_sim` does not re-validate the crypt region — it simply runs the binary
4. The process executes the decrypted code

The modification to `LC_BUILD_VERSION.platform` does not affect the FairPlay page-in path. The crypt region's `cryptoff`, `cryptsize`, and `cryptid` fields are what matter for FairPlay — and they are untouched in the pass-1 extraction binary.

### The Self-Read Technique

Once the process is running with decrypted pages, reading the crypt region is trivial. The process reads its own memory using `mach_vm_read`:

```c
// darkmach-decrypt.dylib constructor
__attribute__((constructor))
static void darkmach_extract(void) {
    uint64_t cryptoff  = strtoul(getenv("DARKMACH_CRYPTOFF"),  NULL, 16);
    uint64_t cryptsize = strtoul(getenv("DARKMACH_CRYPTSIZE"), NULL, 16);
    const char *outpath = getenv("DARKMACH_DECRYPT_OUT");

    // The process base address is available via _dyld_get_image_header(0)
    const uint8_t *base = (const uint8_t *)_dyld_get_image_header(0);

    // Read from our own memory — no privilege required
    // Pages in the crypt region are already decrypted by kernel page-in
    const uint8_t *crypt_bytes = base + cryptoff;

    // Write to file
    FILE *f = fopen(outpath, "wb");
    fwrite(crypt_bytes, 1, cryptsize, f);
    fclose(f);
}
```

A process always has read access to its own virtual address space. This is not a vulnerability — it is standard operation. The decryption happens transparently before the bytes are accessed.

---

## Discovery Timeline: What Was Tried and What Failed

### Approach 1: debugserver / lldb — BLOCKED BY SIP

The natural first approach to reading a running process's memory is a debugger. `debugserver` with the `com.apple.private.cs.debugger` entitlement can attach to iOS apps on a real device. On Mac, SIP blocks `task_for_pid` for App Store app processes — even for Apple-signed tools.

```
debugserver → task_for_pid denied (SIP)
lldb → task_for_pid denied (SIP)
```

SIP on Apple Silicon explicitly prevents host processes from obtaining task ports for iOS app processes, even with developer tools entitlements.

### Approach 2: Frida — BLOCKED BY SIP

Frida's injection mechanism relies on `task_for_pid` to inject a library into a running process. SIP blocks this.

```
frida → task_for_pid denied (SIP)
frida-server → same
objection → same (frida-based)
```

### Approach 3: `task_for_pid` from host side on Simulator processes — BLOCKED

Even for Simulator processes (which run as regular macOS processes), SIP prevents `task_for_pid` from the host side:

```
task_for_pid(simulator_pid) → KERN_FAILURE (SIP)
```

### Approach 4: `posix_spawn` with platform override — KILLED

The `posix_spawnattr_set_platform_np` private API can set the platform for a spawned process. However, without the `com.apple.private.security.no-sandbox` and related entitlements, the kernel kills the child:

```
posix_spawn with platform override → child receives SIGKILL
```

### Approach 5: Load iOS binary directly with DYLD_FORCE_PLATFORM — PARTIAL

`DYLD_FORCE_PLATFORM` exists in `dyld_sim`. Setting it to `7` (iOSSimulator) allows the Simulator's dyld to load a binary targeting iOS by overriding its platform check. However, this still had issues with FairPlay enforcement at the time this was tested.

### The Breakthrough: patch platform flag + simctl install

The key insight came from a different direction: what if the binary simply reported itself as targeting iOSSimulator? The `LC_BUILD_VERSION` platform field is a single 4-byte integer. Changing it from `2` to `7` is a one-instruction operation. After this change and an ad-hoc re-sign, `simctl install` accepts the bundle without complaint.

Then: does `simctl launch` work on an app with `cryptid=1`?

```
First attempt: simctl launch with cryptid=1 and ad-hoc signature
→ SpringBoard rejects the launch (SBMainWorkspace denial)
```

SpringBoard validates code signing more strictly. The fix: use `simctl spawn` instead of `simctl launch`. `simctl spawn` bypasses SpringBoard entirely and executes the binary directly.

```
simctl spawn + cryptid=1 + platform=7 + ad-hoc signature
→ Process starts
→ Pages in crypt region are decrypted by kernel page-in
→ DYLD-injected darkmach-decrypt.dylib reads decrypted bytes
→ SUCCESS
```

This confirmed the hypothesis: the kernel decrypts FairPlay pages for Simulator processes. The first successful extraction was of the OddsJam binary, in full, with all encrypted code regions decrypted to valid ARM64 instructions.

---

## Why This Matters

### For the FairPlay System

FairPlay DRM was designed to protect app intellectual property by preventing easy binary extraction. The current implementation creates a gap: Mac App Store delivery of iOS apps provides the same on-disk FairPlay protection as device delivery, but the Mac runtime decrypts these apps for any Simulator process — without validating that the binary has not been modified.

On a real iOS device, FairPlay enforcement involves:
- Kernel-level FairPlay validation tied to the device's hardware UID
- AMFI validation of the binary's FairPlay authorization
- Secure Enclave key derivation for decryption

In the Mac Simulator context, none of these device-specific checks are present. The kernel decrypts pages using the FairPlay key, but there is no mechanism to prevent a modified binary from loading in the Simulator and reading its own decrypted pages.

### For App Developers

Any iOS app distributed through the Mac App Store has its entire binary exposed to this technique. This means:

- Hardcoded secrets in the app binary are accessible
- Proprietary algorithms can be extracted and analyzed
- Certificate pinning can be studied and bypassed
- Authentication flows are fully observable
- API keys, tokens, and credentials are recoverable

Developers should not store secrets in the app binary and should treat the binary as readable by adversaries.

### For Apple

The inconsistency is architectural: the Mac App Store delivers iOS apps through the same FairPlay-protected channel as the iOS App Store, but the runtime environment (the iOS Simulator) does not enforce the same protections as a real iOS device. The on-disk encryption provides no protection once the binary can be loaded in the Simulator.

---

## Technical Details: Simulator Internals

These findings were documented during research into the Simulator's security model:

| Component | Finding |
|-----------|---------|
| `dyld_sim` | Does not process `LC_ENCRYPTION_INFO_64`. Completely ignores `cryptid`. |
| `DYLD_AMFI_FAKE` in `dyld_sim` | Allows faking AMFI code signing responses |
| `DYLD_FORCE_PLATFORM` in `dyld_sim` | Can override binary platform identity |
| `launchd_sim` | Has `com.apple.private.amfi.can-allow-non-platform` entitlement |
| `amfid` | Not present in Simulator runtime — no AMFI enforcement |
| `mremap_encrypted` (syscall 489) | Returns EINVAL in Simulator — but this is irrelevant as pages are already decrypted via page-in |
| `SecTrustEvaluateWithError` | Present and functional in Simulator, hooking works normally |
| `SIMCTL_CHILD_` prefix | Environment variables with this prefix are set in the child process by simctl (prefix stripped) |
| Ad-hoc code signing | `codesign -s -` is sufficient for all Simulator operations |

---

## Reproduction

The full bypass is reproducible on any Apple Silicon Mac with Xcode installed, using only the Darkmach toolkit:

```bash
# 1. Find an iOS app on Mac App Store
darkmach discover "finance" --category 6015

# 2. Install via Mac App Store (standard App Store download)

# 3. Run full pipeline — extracts FairPlay-decrypted binary, launches in Simulator
darkmach run /Applications/AppName.app

# 4. Verify: static analysis shows no cryptid in the extracted binary
darkmach analyze output/<app>/bundle/AppName.app
```

Detailed reproduction steps for the Apple Security Bounty submission are in `.project/reports/`.
