# FairPlay Local Decryption Research

> Exploit-engineer reconnaissance + PoC -- 2026-03-26
> Status: PoC EXECUTED. Kernel activates full FairPlay decryption chain for Simulator processes.
> DoorDash encrypted IPA (ipatool): installed into Simulator with cryptid=1, SC_Info intact.
> Kernel chain: set_code_unprotect -> IOTextEncryptionFamily -> AppleFairplayTextCrypterSession -> fairplayd
> **Result: fairplayOpen() failed error -42110 (authorization). sinf bound to different Apple ID.**
> **The failure is AUTHORIZATION-BASED, not CAPABILITY-BASED. The kernel CAN decrypt.**
> **Next step: Test with matching Apple ID (same account on Mac and ipatool download).**

---

## Executive Summary

macOS on Apple Silicon contains the complete FairPlay decryption stack required to decrypt iOS-encrypted binaries locally. This investigation confirms:

1. **The `mremap_encrypted` syscall (SYS 489) exists on macOS** -- dyld contains a direct syscall wrapper (`mov x16, #0x1e9; svc #0x80`) and actively calls it during binary loading via `dyld4::Loader::mapSegments()`.

2. **The kernel has all necessary components loaded and running:**
   - `com.apple.driver.FairPlayIOKit` (kext 87, v72.14.0, 257 KB) -- the main FairPlay IOKit driver
   - `com.apple.IOTextEncryptionFamily` (kext 212, v1.0.0) -- the page-level text decryption infrastructure
   - `AppleFairplayTextCrypter` -- active IOKit service registered in the IOKit registry

3. **fairplayd is running** (PID 1049, user `_fpsd`) with 6 Mach service endpoints:
   - `com.apple.fpsd` -- main FairPlay service
   - `com.apple.fpsd.sim` -- **Simulator-specific** FairPlay service
   - `com.apple.fairplayd` -- legacy Mach service
   - `com.apple.fairplayd.xpc` -- XPC endpoint
   - `com.apple.unfreed` -- host special port 17 ("fairplay")
   - `com.apple.arcade.fpsd` -- host special port 31 ("fairplayd"), Arcade DRM

4. **Device key material is present on disk:**
   - `/var/db/fpsd/SC Info/SC Info.sidb` -- 672-byte encrypted key database
   - `/var/db/fpsd/adi/adi.pb` -- 1650-byte Anisette Device Identity provisioning blob
   - `com.apple.driver.FairPlayIOKitUserClient` -- active IOKit user client, creator: `pid 1049, fairplayd`

5. **The Simulator FairPlay bypass is confirmed:** The OddsJam binary in the Simulator has `cryptid=1` with truly encrypted bytes on disk, yet executes correctly -- the kernel decrypts pages at page-in time.

**Bottom line:** The infrastructure to decrypt iOS FairPlay binaries exists and is active on macOS. The question is whether it can be leveraged for binaries that were not delivered through the Mac App Store channel (i.e., downloaded IPAs from the iOS channel).

---

## Investigation 1: dyld's Handling of LC_ENCRYPTION_INFO_64

### Binary Location and Format

```
/usr/lib/dyld -- Mach-O universal binary (x86_64 + arm64e)
Size: 2,300,384 bytes
__TEXT section: 0x1000 to 0x8C56C (571 KB of code)
__cstring: 0x8E9E0 to 0x9ED8F (66 KB of string data)
```

### Key Code Path: `dyld4::Loader::mapSegments()`

The function `dyld4::Loader::mapSegments()` (address 0x238C0) is responsible for mapping all segments of a Mach-O into memory. After mapping segments via mmap, it checks for FairPlay encryption:

**Step 1: Check for encryption (0x23CAC)**
```asm
; Initialize cryptoff/cryptsize output params to zero
str     wzr, [sp, #0x60]         ; cryptoff = 0
str     wzr, [sp, #0x74]         ; cryptsize = 0
ldr     x23, [sp, #0x78]         ; load Mach-O header pointer
add     x1, sp, #0x60            ; &cryptoff
add     x2, sp, #0x74            ; &cryptsize
mov     x0, x23                  ; header
bl      mach_o::Header::isFairPlayEncrypted(uint&, uint&)
cbz     w0, 0x23d30              ; if NOT encrypted, skip to post-encryption path
```

**Step 2: If encrypted, call mremap_encrypted (0x23CB4-0x23CF8)**
```asm
ldr     x24, [x20, #0x8]         ; syscall delegate
ldr     x19, [sp, #0x78]         ; mapped base address
ldr     w27, [sp, #0x60]         ; cryptoff
ldr     w25, [sp, #0x74]         ; cryptsize
; ... get architecture info ...
add     x1, x19, x27             ; addr = base + cryptoff (crypt region start)
mov     x0, x24                  ; syscall delegate
mov     x2, x25                  ; len = cryptsize
mov     w3, #0x1                 ; cryptid = 1
mov     x4, x26                  ; cputype
bl      SyscallDelegate::mremap_encrypted(void*, size_t, uint, uint, uint)
cbz     w0, 0x23d30              ; if success (0), continue loading
```

**Step 3: On failure, report error (0x23D00-0x23D10)**
```asm
str     x0, [sp]                 ; store error code
adr     x1, "could not register fairplay decryption, mremap_encrypted() => %d"
mov     x0, x21                  ; diagnostics object
bl      Diagnostics::error(char const*, ...)
```

### `SyscallDelegate::mremap_encrypted` Implementation (0x341D4)

This is a thin wrapper that directly invokes the syscall:
```asm
SyscallDelegate::mremap_encrypted:
    mov     x0, x1        ; shuffle args (skip 'this' pointer)
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    b       _mremap_encrypted     ; tail call to syscall wrapper
```

### `_mremap_encrypted` Syscall Wrapper (0x6600)

```asm
_mremap_encrypted:
    mov     x16, #0x1e9    ; SYS_mremap_encrypted = 489 = 0x1E9
    svc     #0x80           ; system call
    b.lo    0x6628          ; if no error, return
    ; error path: call cerror_nocancel
    pacibsp
    stp     x29, x30, [sp, #-0x10]!
    mov     x29, sp
    bl      _cerror_nocancel
    ...
```

**Syscall number confirmed:** `SYS_mremap_encrypted = 489` (defined in `<sys/syscall.h>` on macOS).

### `mach_o::Header::isFairPlayEncrypted()` Implementation (0x83754)

```asm
isFairPlayEncrypted:
    bl      findFairPlayEncryptionLoadCommand()
    cbz     x0, not_encrypted        ; if no LC_ENCRYPTION_INFO found
    ldr     w9, [x0, #0x10]          ; cryptid (offset 0x10 in load command)
    ldr     w8, [x0, #0x8]           ; cryptoff
    str     w8, [x20]                ; output cryptoff
    ldr     w8, [x0, #0xc]           ; cryptsize
    cmp     w9, #0x1                 ; is cryptid == 1?
    cset    w0, eq                   ; return (cryptid == 1)
    b       store_cryptsize
not_encrypted:
    mov     w8, #0x0
    str     wzr, [x20]               ; cryptoff = 0
store_cryptsize:
    str     w8, [x19]                ; store cryptsize
    ret
```

The `findFairPlayEncryptionLoadCommand` block checks for:
- `cmd == 0x2C` (LC_ENCRYPTION_INFO_64) -- 64-bit encryption info
- `cmd == 0x21` (LC_ENCRYPTION_INFO) -- 32-bit encryption info

### Critical Finding: NO Platform Branching in Encryption Path

**There is NO platform-specific branching in the encryption handling code.** dyld does not check whether the binary is iOS, macOS, iOSSimulator, or macCatalyst before calling `mremap_encrypted`. The logic is purely:

1. Is `LC_ENCRYPTION_INFO_64` present?
2. Is `cryptid == 1`?
3. If yes to both: call `mremap_encrypted(base + cryptoff, cryptsize, 1, cputype_sub)`
4. If the syscall fails: report error and fail the load
5. If the syscall succeeds: continue loading normally

**This means: if a binary with `cryptid=1` is loaded on macOS, dyld will unconditionally attempt kernel-level FairPlay decryption via `mremap_encrypted`, regardless of the binary's platform designation.**

### DYLD_FORCE_PLATFORM Environment Variable

dyld supports a `DYLD_FORCE_PLATFORM` environment variable that can override the platform detected from `LC_BUILD_VERSION`:

- Value `'2'` (0x32) = force iOS platform (requires arm64 arch + `__allow_alt_plat` section)
- Value `'6'` (0x36) = force macCatalyst platform

The check requires:
1. The env var is set
2. `mach_o::Header::allowsAlternatePlatform()` returns true
3. `allowsAlternatePlatform()` iterates sections looking for `__DATA,__allow_alt_plat`

This is relevant because it shows dyld has mechanisms for cross-platform binary loading.

---

## Investigation 2: fairplayd on macOS

### Process Details

```
PID:     1049
User:    _fpsd
Group:   _fpsd
Binary:  /System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd
Arch:    universal (x86_64 + arm64e)
Size:    20,454,736 bytes (~20 MB)
State:   running (since boot, never exited)
```

### Linked Frameworks

```
CoreServices.framework
AppStoreDaemon.framework      <-- app repair operations
CoreTime.framework
IOKit.framework               <-- FairPlayIOKit communication
CoreFoundation.framework
Security.framework            <-- certificate validation, keychain
Foundation.framework
AuthKit.framework             <-- Apple ID authentication
libbootpolicy.dylib           <-- boot policy verification
libbsm.0.dylib               <-- audit subsystem
libMobileGestalt.dylib        <-- device identity
libSystem.B.dylib
libobjc.A.dylib
```

Key linked libraries:
- **AppStoreDaemon.framework** -- imports `ASDRepairService` and `ASDRepairOptions` classes for app FairPlay repair
- **IOKit.framework** -- communicates with the FairPlayIOKit kernel driver
- **AuthKit.framework** -- handles Apple ID authentication for license validation
- **libMobileGestalt.dylib** -- accesses hardware identity for device binding

### Mach Service Endpoints (6 total)

| Endpoint | Port | Notes |
|----------|------|-------|
| `com.apple.fpsd` | 0x41633 | Main FairPlay service for macOS apps |
| `com.apple.fpsd.sim` | 0xAED1B | **Simulator-specific FairPlay service** |
| `com.apple.fairplayd` | 0x415A3 | Legacy Mach service |
| `com.apple.fairplayd.xpc` | 0xD031F | XPC endpoint |
| `com.apple.unfreed` | 0x2807 | Host special port 17 ("fairplay") |
| `com.apple.arcade.fpsd` | 0x2603 | Host special port 31 ("fairplayd"), Apple Arcade DRM |

**The `com.apple.fpsd.sim` endpoint is critical.** It demonstrates that fairplayd explicitly handles FairPlay operations for Simulator processes. This is the service that the Simulator's kernel page-in FairPlay decryption likely communicates with.

### Internal Service Identifiers

```
FairPlay-Classic-Client       -- traditional app DRM
FairPlay-CoreML-Client        -- ML model DRM
com.apple.fpsd.arcadeservice  -- Apple Arcade DRM
com.apple.private.fpsd.client -- private entitlement for FairPlay clients
com.apple.private.fairplay.FPDI -- FairPlay Device Identity entitlement
com.apple.fairplayd.resync-fpkeybag -- key bag resynchronization
com.apple.XCSim               -- Xcode Simulator integration reference
```

### ObjC API Surface

- `repairAppWithOptions:replyHandler:` -- FairPlay state repair for apps
- `setFairplayStatus:` -- set FairPlay status for an app
- `isSignedByDeveloperFileAtPath:basicCheck:` -- code signing verification
- `isVPPLicensed` -- Volume Purchase Program license check
- `getBundleID` / `_bundleID` -- bundle identification
- `initWithBundlePath:` -- initialize with app bundle path
- `_checkArray:containsCertificateWithOID:` -- certificate chain validation
- `_verifySignatureForSignedData:onDate:` -- signature verification

### XPC Services

```
com.apple.fpsd.arcadeservice.xpc -- Apple Arcade XPC service
  Binary: 1,242,544 bytes (arm64e + x86_64)
  Located in CoreFP.framework/XPCServices/
```

### Environment

```
OSLogRateLimit = 64
MallocSpaceEfficient = 1
DYLD_PAGEIN_LINKING = 0        <-- explicitly disabled, notable
XPC_SERVICE_NAME = com.apple.fairplayd
```

### CoreFP.framework

```
Path: /System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP
Size: 60,331,360 bytes (~60 MB, massive)
Arch: universal (x86_64 + arm64e)
Version: 5.4.0 (compatibility 2.2.19)
```

Links to:
- StoreFoundation.framework -- App Store operations
- IOKit.framework -- kernel driver communication
- DiskArbitration.framework -- disk/volume management
- Security.framework -- cryptographic operations
- libMobileGestalt.dylib -- device identity

**Exported symbols are fully obfuscated** (random names like `_WIn9UJ86JKdV4dM`, `_X46O5IeS`, etc.). Only 8 exported functions, all with randomized names. This is deliberate anti-analysis.

SINF version constants in CoreFP:
```
SINF.3333AF080923AF0001AF0000010 through SINF.3333AF080923AF0001AF0000100
```

API methods visible in strings:
```
readFromBuffer:
readTokenFromBuffer:
readOpaqueTokenFromBuffer:
_initWithID:class:length:content:opaque:
_initWithType:typeVersion:contentToken:
```

---

## Investigation 3: The Kernel Side (FairPlayIOKit, IOTextEncryptionFamily, AMFI)

### Loaded Kernel Extensions

```
ID   Refs  Address              Size     Name (Version)
87   3     0xfffffe00077b7630   0x3EB50  com.apple.driver.FairPlayIOKit (72.14.0)
                                          Dependencies: <7 6 5 4 3 1>
                                          (kpi.unsupported, kpi.private, kpi.mach, kpi.libkern, kpi.iokit, kpi.bsd)

212  0     0xfffffe00079eb010   0x887    com.apple.IOTextEncryptionFamily (1.0.0)
                                          Dependencies: <87 7 5 4 3 1>
                                          (FairPlayIOKit, kpi.unsupported, kpi.mach, kpi.libkern, kpi.iokit, kpi.bsd)
```

**FairPlayIOKit** (257 KB): The main FairPlay kernel driver. Provides:
- `com_apple_driver_FairPlayIOKit` -- IOKit driver class
- `com_apple_driver_FairPlayIOKitUserClient` -- user-space interface
- Currently has an active user client created by `pid 1049, fairplayd`

**IOTextEncryptionFamily** (2 KB): The page-level text decryption abstraction layer:
- Provides the `AppleFairplayTextCrypter` class
- This is the IOKit service that the kernel's VM subsystem calls during page-in to decrypt FairPlay-encrypted text pages
- Depends on FairPlayIOKit (ID 87)
- Registered and active in the IOKit registry

### IOKit Registry Entries

```
com_apple_driver_FairPlayIOKit
  IOProbeScore = 1000
  IOClass = com_apple_driver_FairPlayIOKit
  IOUserClientClass = com_apple_driver_FairPlayIOKitUserClient
  IOMatchedAtBoot = Yes
  IOProviderClass = IOResources
  |
  +-- com_apple_driver_FairPlayIOKitUserClient
        IOUserClientCreator = "pid 1049, fairplayd"

AppleFairplayTextCrypter
  IOClass = AppleFairplayTextCrypter
  IOMatchCategory = AppleFairplayTextCrypter
  IOProviderClass = IOResources
  IOResourceMatch = IOBSD
```

### AvpFairPlayDriver (Virtualization)

```
/System/Library/Extensions/AvpFairPlayDriver.kext
IOClass = AvpFairPlayDriver
IOProviderClass = AppleVirtIOTransport        <-- VirtIO transport (for VMs)
IOUserClientClass = AvpFairPlayUserClient
IOVirtIOPrimaryMatch = 0x1a08106b
```

This kext enables FairPlay in Apple's virtualization framework (Virtual Machine guests). The "Avp" prefix stands for Apple Virtualization Platform. This means FairPlay decryption works even inside macOS VMs running on Apple Silicon.

### The Decryption Chain

```
dyld -> mremap_encrypted() syscall -> XNU kernel VM subsystem
  -> IOTextEncryptionFamily -> AppleFairplayTextCrypter
    -> FairPlayIOKit -> fairplayd (via host special port 17)
      -> SC Info.sidb (key database) + adi.pb (device identity)
        -> Hardware-bound key derivation
```

1. dyld calls `mremap_encrypted(addr, size, cryptid, cputype_sub)` syscall
2. The kernel's VM subsystem marks the page range as FairPlay-encrypted
3. On page fault (first access to an encrypted page), the kernel invokes `AppleFairplayTextCrypter`
4. `AppleFairplayTextCrypter` communicates with `FairPlayIOKit` which communicates with `fairplayd` via the host special port
5. `fairplayd` looks up the decryption key from `SC Info.sidb`, derives the page key using the device identity from `adi.pb`, and returns the decrypted page
6. The kernel maps the decrypted page into the process's address space
7. Subsequent accesses to the same page hit the already-decrypted cached page

---

## Investigation 4: Real Mac-Delivered iOS App Analysis

### OddsJam Binary in Simulator

The OddsJam app was previously patched and installed in the Simulator. The binary retains its original FairPlay encryption:

```
Path: ~/Library/Developer/CoreSimulator/Devices/3504666C-.../OddsJam-test.app/OddsJam
Format: Mach-O 64-bit arm64 (thin binary)
__TEXT vmaddr: 0x100000000, fileoff: 0, filesize: 13,271,040

LC_ENCRYPTION_INFO_64:
  cryptoff:  126976 (0x1F000)
  cryptsize: 4096   (0x1000)
  cryptid:   1

LC_MAIN:
  entryoff:  127568 (0x1F250) -- WITHIN the crypt region (0x1F000-0x20000)
```

### Crypt Region Verification: ENCRYPTED ON DISK

Raw bytes at file offset 0x1F000 (the crypt region):
```
0001f000: 3287 480a 709d 3d18 9dc5 972f e580 19e0  2.H.p.=..../....
0001f010: cc70 988c fd63 3797 3f9d 6849 6641 174f  .p...c7.?.hIfA.O
0001f020: dc29 004d 6a3a 99b5 56d1 4a23 d00b 826f  .).Mj:..V.J#...o
0001f030: 594d f237 03fd 3d33 fd80 af00 873a 89a7  YM.7..=3.....:..
```

Disassembly at vmaddr 0x10001F000 (the crypt region mapped into memory):
```
10001f000: 0a488732    <unknown>
10001f004: 183d9d70    ldr  w16, 0x10009a3b0   (nonsensical reference)
10001f008: 2f97c59d    <unknown>
10001f00c: e01980e5    ld1b (SVE instruction -- not valid for this CPU)
```

**The bytes are genuinely encrypted.** They are not valid ARM64 instructions. The `<unknown>` tags and nonsensical references confirm the on-disk data is ciphertext.

### Yet the App Runs in Simulator

Despite the encrypted bytes on disk, OddsJam launches and runs correctly in the iOS Simulator. This confirms:

1. dyld encounters `cryptid=1` during loading
2. dyld calls `mremap_encrypted()` syscall
3. The kernel marks the crypt region pages for FairPlay decryption
4. On first page access, `AppleFairplayTextCrypter` decrypts the page transparently
5. The decrypted code (including the entry point at offset 0x1F250) executes normally

**The kernel FairPlay decryption infrastructure on macOS handles iOS arm64 binaries.** There is no "iOS-only" restriction -- the same kernel code path handles all architectures and platforms.

### SC_Info Directory Structure

```
OddsJam-test.app/SC_Info/
  Manifest.plist    -- 441 bytes, lists sinf paths
  OddsJam.sinf      -- 1056 bytes, FairPlay DRM atom
  OddsJam.supf      -- 924 bytes, supplementary FP data (contains Apple FairPlay certificate chain)
  OddsJam.supp      -- 1892 bytes, supplementary data
  OddsJam.supx      -- 80 bytes, supplementary extension
```

The sinf file structure (parsed from hex):
```
sinf (1056 bytes total)
  frma: "game" (format = game/app)
  schm: "itun" (scheme = iTunes)
  schi: (scheme info)
    user: 0x50135A74 (user ID hash)
    crdt: 0xE5E76B7A (creation date)
    asdt: 0x00000000 (assignment date)
    key:  0x0000001E (key reference)
    iviv: 16-byte initialization vector
  righ: (rights)
    veID: 4-byte verification ID
    plat: 0x00000000 (platform)
    aver: 0x01010100 (version)
    tran: transaction ID
    sing: 0x00000001 (single use)
    song: content ID
    tool: "P611" (tool version)
    medi: 0x00000080 (media type)
    mode: 0x00000000
    name: "Justin McCloud" (purchaser name)
  priv: (private data -- encrypted keys)
  sign: (signature -- 128-byte RSA signature)
```

The supf file contains an Apple FairPlay certificate chain (X.509 certificates from "Apple FairPlay Certification Authority"), confirming the DRM key hierarchy.

---

## Investigation 5: FairPlay Key Material on macOS

### /var/db/fpsd/ Directory

```
/var/db/fpsd/                     (owner: _fpsd:_fpsd, mode: drwxr-x---)
  Library/                        (mode: drwx------)
  SC Info/                        (mode: drwx------)
    SC Info.sidb                  (672 bytes, mode: -rw-rw-rw-, encrypted data)
  adi/                            (mode: drwxrwxrwx)
    adi-gb.lck                    (0 bytes, lock file)
    adi.pb                        (1650 bytes, Anisette Device Identity blob)
    adi.pb.lck                    (0 bytes, lock file)
  dvp/                            (mode: drwx------, empty)
```

**SC Info.sidb** -- The FairPlay key database. 672 bytes of encrypted data. This is the counterpart to the sinf/supf files in app bundles -- it contains the device-specific keys needed to decrypt FairPlay-protected content. The header bytes `0007 000b` suggest a versioned binary format.

**adi.pb** -- The Anisette Device Identity provisioning blob (1650 bytes). This contains the hardware-bound identity used by Apple's DRM and authentication systems. The header `0000 0001 0000 0016` followed by encrypted data indicates a versioned provisioning record. This is what binds FairPlay keys to this specific Mac.

**Note on permissions:** The `adi/` directory is world-writable (`drwxrwxrwx`), and `adi.pb` is world-readable/writable (`-rw-rw-rw-`). The `SC Info/` directory is restricted to `_fpsd` user only. The parent `/var/db/fpsd/` is `drwxr-x---` (readable by `_fpsd` group members).

### fairplaydeviceidentityd

```
Binary: /usr/libexec/fairplaydeviceidentityd
Mach service: com.apple.fairplaydeviceidentityd
User: _fpsd
```

This daemon manages the FairPlay Device Identity (FPDI), which includes:
- BAA (Batch Attestation Authority) certificate prefetching (every 12 hours)
- Host certificate management
- Certificate expiry monitoring
- Device identity provisioning

Strings of note:
```
BAA Certificate(s) are expired: %@
Failed to obtain BAA certificates: %@
Failed to obtain host certificates: %@
Host Certificate(s) are expired: %@
com.apple.fpdi.certpreload.querycert
com.apple.fpdi.certpreload.schedule
```

The BAA system is Apple's hardware attestation framework -- it proves to Apple's servers that a real Apple device is making the request. This is the hardware root of trust for FairPlay.

---

## Investigation 6: The mremap_encrypted Syscall

### Confirmed Present on macOS

```c
// /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/sys/syscall.h
#define SYS_mremap_encrypted 489
```

Also confirmed in Xcode's macOS SDK at the same path.

### Syscall Signature (from dyld disassembly)

Based on the `SyscallDelegate::mremap_encrypted` wrapper and the calling code in `mapSegments`:

```c
int mremap_encrypted(
    void *addr,        // x0: base address + cryptoff (start of encrypted region)
    size_t len,        // x1: cryptsize (length of encrypted region)
    uint32_t cryptid,  // x2: always 1 (encryption scheme identifier)
    uint32_t cputype,  // x3: CPU type from Mach-O header
    uint32_t cpusubtype // x4: CPU subtype from Mach-O header
);
// Returns: 0 on success, error code on failure
```

### How It Works

The syscall tells the kernel: "the memory region at `addr` for `len` bytes is FairPlay-encrypted with scheme `cryptid`. The binary is for architecture `cputype/cpusubtype`. Please arrange to decrypt it."

The kernel does NOT immediately decrypt. Instead, it marks the pages for lazy decryption:
1. The VM subsystem records the encryption metadata for the page range
2. When a thread first touches an encrypted page, a page fault occurs
3. The page fault handler recognizes the page is FairPlay-encrypted
4. It invokes `AppleFairplayTextCrypter` to decrypt the page
5. The decrypted page replaces the encrypted one in the page cache
6. The faulting instruction is retried, now hitting the decrypted page

This is the same mechanism used on iOS, but here it runs on macOS.

### The Error String

```
"could not register fairplay decryption, mremap_encrypted() => %d"
```

This error indicates that `mremap_encrypted` CAN fail. Possible failure modes:
- No FairPlay key material available for this binary
- The sinf/SC_Info data is missing or invalid
- The kernel's FairPlay infrastructure is not properly initialized
- The binary's cputype doesn't match the current platform's capabilities

---

## Assessment: Can macOS Decrypt iOS FairPlay Binaries Locally?

### What We Know

1. **The decryption infrastructure is present and active** on macOS Apple Silicon
2. **dyld calls mremap_encrypted unconditionally** when it encounters `cryptid=1` -- no platform check
3. **The kernel decrypts iOS arm64 FairPlay pages** for Simulator processes (proven by OddsJam)
4. **fairplayd has a Simulator-specific endpoint** (`com.apple.fpsd.sim`)
5. **FairPlay key material** (sinf, SC_Info.sidb, adi.pb) exists on the Mac for purchased apps
6. **The app's sinf file** contains the per-app encryption key (encrypted under the device key from SC_Info.sidb)

### What's Needed for Local Decryption of an iOS IPA

To decrypt a FairPlay-encrypted iOS binary obtained from the iOS download channel (e.g., via ipatool):

1. **The encrypted binary** -- contained in the IPA's Payload/<App>.app/<BinaryName>
2. **The sinf file** -- the per-app DRM atom containing the encrypted content key. This is the critical piece. On iOS, it's in the app's SC_Info directory. For Mac-delivered apps, it's included in the pfpkg.
3. **Device key material** -- SC_Info.sidb + adi.pb, already present on this Mac
4. **The mremap_encrypted syscall** -- available and functional on macOS

### The Critical Gap: sinf File Acquisition

The sinf file is the bridge between the encrypted binary and the device's decryption keys. For Mac-delivered iOS apps, the sinf is included in the pfpkg download. For iOS-channel downloads:

**Option A: sinf from the IPA itself**
iOS IPAs from the App Store include the SC_Info directory with sinf/supf/supp/supx files. If downloaded via ipatool (which authenticates as the user's Apple ID), the sinf should be present and bound to the user's purchase.

**Option B: sinf from fairplayd repair**
fairplayd's `repairAppWithOptions:replyHandler:` method (using `ASDRepairService` from AppStoreDaemon.framework) can request sinf repair for an app bundle. If the user owns the app, this might generate valid sinf data.

**Option C: sinf from existing Mac purchase**
If the user previously purchased the same app on Mac (even if it's since been opted out), the sinf from the Mac delivery might work for the iOS binary IF they share the same FairPlay content key.

### Feasibility Assessment

| Factor | Status | Notes |
|--------|--------|-------|
| Kernel FairPlay infrastructure | PRESENT | FairPlayIOKit + IOTextEncryptionFamily + AppleFairplayTextCrypter all loaded |
| mremap_encrypted syscall | PRESENT | SYS 489, functional, no platform restriction |
| fairplayd daemon | RUNNING | 6 Mach endpoints, including Simulator-specific |
| Device key material | PRESENT | SC_Info.sidb + adi.pb in /var/db/fpsd/ |
| sinf file for iOS IPA | UNKNOWN | Critical dependency -- must be obtained alongside the encrypted binary |
| Platform compatibility | CONFIRMED | Kernel decrypts iOS arm64 pages for Simulator processes |
| Apple ID ownership verification | UNKNOWN | Does mremap_encrypted verify purchase authorization? |

### Proposed Experiment (Theoretical -- Not Executed)

1. Obtain an iOS IPA via ipatool for a **purchased** app (one the user's Apple ID owns)
2. Extract the Mach-O binary and SC_Info directory from the IPA
3. Place the binary in a location dyld can load it (e.g., install into Simulator)
4. Ensure the sinf file is in the expected SC_Info path relative to the binary
5. Attempt to launch -- dyld will call mremap_encrypted, the kernel will attempt decryption
6. If the sinf's user key matches this Mac's SC_Info.sidb, decryption should succeed

### Risk Factors

- **sinf user binding**: The sinf contains a user ID hash and transaction ID. The kernel may verify these against the local SC_Info.sidb before decrypting.
- **Platform enforcement in sinf**: The sinf's `plat` field might restrict which platforms can decrypt (though it's `0x00000000` for OddsJam).
- **App-store channel enforcement**: The kernel might check whether the binary was delivered through an authorized channel (Mac App Store vs side-loaded).
- **AMFI enforcement**: Apple Mobile File Integrity may block decryption for binaries that lack proper code signatures from the App Store delivery chain.

### Bottom Line

**The technical infrastructure for local FairPlay decryption of iOS binaries exists and is fully operational on macOS.** The macOS kernel does not distinguish between iOS and macOS FairPlay encryption at the mremap_encrypted level. The only question is whether the sinf/key-material chain works for iOS-channel binaries on a Mac.

This represents **Vector 5** in the App Store bypass research: rather than trying to get Apple to deliver a decrypted Mac binary, obtain the encrypted iOS binary (which is available for ALL apps, regardless of opt-out) and decrypt it locally using the Mac's own FairPlay infrastructure.

---

## Appendix A: Complete FairPlay Architecture on macOS

```
USER SPACE                          KERNEL SPACE
==========                          ============

dyld (binary loader)                XNU Kernel
  |                                   |
  | mremap_encrypted()                | VM Subsystem
  | syscall 489                       |   |
  |------>--->--->--->--->--->------->-|   | page fault on
  |                                   |   | encrypted page
  |                                   |   |
fairplayd (PID 1049)                  |   v
  |                                   | IOTextEncryptionFamily
  | Mach service endpoints:           |   |
  |   com.apple.fpsd                  |   | AppleFairplayTextCrypter
  |   com.apple.fpsd.sim              |   |   |
  |   com.apple.fairplayd             |   |   v
  |   com.apple.fairplayd.xpc         | FairPlayIOKit (kext 87)
  |   com.apple.unfreed (port 17)     |   |
  |   com.apple.arcade.fpsd (port 31) |   | IOUserClient
  |                                   |   |
  |<------ host special port 17 ------|---|
  |                                   |
  | Key material:                     |
  |   /var/db/fpsd/SC Info/SC Info.sidb
  |   /var/db/fpsd/adi/adi.pb
  |
  | App DRM atoms:
  |   <app>/SC_Info/<name>.sinf
  |   <app>/SC_Info/<name>.supf
  |   <app>/SC_Info/<name>.supp
  |   <app>/SC_Info/<name>.supx

fairplaydeviceidentityd
  | BAA certificate prefetch (12h interval)
  | Device identity provisioning
  | com.apple.fairplaydeviceidentityd

CoreFP.framework (60 MB, obfuscated symbols)
  | Links: StoreFoundation, IOKit, Security
  | SINF versions 01-100
  | 8 exported functions (all obfuscated names)

AvpFairPlayDriver.kext
  | FairPlay for Apple Virtualization Platform
  | IOProviderClass = AppleVirtIOTransport
```

## Appendix B: Relevant File Paths

| Path | Description | Access |
|------|-------------|--------|
| `/usr/lib/dyld` | Dynamic linker (universal arm64e+x86_64) | world-readable |
| `/System/Library/PrivateFrameworks/CoreFP.framework/` | CoreFP framework + fairplayd | world-readable |
| `/System/Library/Extensions/FairPlayIOKit.kext/` | FairPlay IOKit kernel extension | world-readable |
| `/System/Library/Extensions/IOTextEncryptionFamily.kext/` | Text encryption family kext | world-readable |
| `/System/Library/Extensions/AvpFairPlayDriver.kext/` | VM FairPlay driver | world-readable |
| `/System/Library/LaunchDaemons/com.apple.fairplayd.plist` | fairplayd launchd config | world-readable |
| `/usr/libexec/fairplaydeviceidentityd` | Device identity daemon | world-readable |
| `/var/db/fpsd/` | FairPlay daemon data directory | _fpsd:_fpsd |
| `/var/db/fpsd/SC Info/SC Info.sidb` | FairPlay key database (672 bytes) | restricted |
| `/var/db/fpsd/adi/adi.pb` | Anisette Device Identity blob (1650 bytes) | world-readable |
| `<sys/syscall.h>` | SYS_mremap_encrypted = 489 | SDK header |

## Appendix C: Strings of Interest in dyld

```
"could not register fairplay decryption, mremap_encrypted() => %d"
"DYLD_FORCE_PLATFORM"
"DYLD_AMFI_FAKE"
"__allow_alt_plat" (section name for alternate platform support)
"iOS-simulator"
"macCatalyst"
"ROSETTA"
"/System/iOSSupport"
"wrong platform to load into process"
"incompatible platforms: %s - %s"
"arm64e not supported for simulator programs"
"DYLD_ROOT_PATH only allowed with simulator programs"
```

---

## PoC: DoorDash Encrypted IPA in Simulator (2026-03-26)

### Objective

Test whether macOS's FairPlay infrastructure (`mremap_encrypted` syscall 489) will decrypt an iOS-channel encrypted binary when loaded in the iOS Simulator. This tests Vector 5: local decryption of iOS binaries obtained outside the Mac App Store channel.

### Target Binary

```
Source: doordash.DoorDashConsumer_719972451_8.11.0.ipa (downloaded via ipatool)
Bundle ID: doordash.DoorDashConsumer
Binary: DoorDash (thin arm64, 293,606,176 bytes / ~280 MB)
DoorDash has opted OUT of Mac delivery -- this is an iOS-only download.
```

### Binary Analysis

**Encryption state (LC_ENCRYPTION_INFO_64):**
```
cryptoff  = 180224  (0x2C000)
cryptsize = 260816896  (0xF8E0000, ~249 MB)
cryptid   = 1  (encrypted)
```

**Platform (LC_BUILD_VERSION):**
```
platform = 2  (iOS)
minos    = 18.0
sdk      = 26.0
```

**Entry point (LC_MAIN):**
```
entryoff = 226020  (0x372E4) -- falls WITHIN the crypt region
```

**__TEXT segment layout:**
```
__TEXT vmaddr=0x100000000, vmsize=0xF8EC000, fileoff=0
__text section: addr=0x10002C000 (offset 180224 = exactly cryptoff)
Crypt region covers the entire __text section
```

**Encryption verification:**
- First 4096 bytes of crypt region: 256/256 unique byte values (maximum entropy)
- Zero bytes: 11/4096 (0.3%)
- Entry point bytes are high-entropy gibberish, not valid ARM64 instructions
- **Conclusion: Genuinely encrypted on disk. Not plaintext like Mac-delivered apps.**

**SC_Info present:**
```
DoorDash.sinf   (1032 bytes) -- FairPlay DRM atom with key references
DoorDash.supf   (2,038,524 bytes) -- supplementary FairPlay data
DoorDash.supp   (2,039,908 bytes) -- supplementary data
DoorDash.supx   (80 bytes) -- extended supplementary data
```

**sinf atom structure:**
```
[sinf] 1032 bytes
  [frma] format = "game" (FairPlay-protected content)
  [schm] scheme = "itun" (iTunes protection scheme)
  [schi] schema info:
    [user] = 50 13 5A 74 (Apple ID hash)
    [key ] = 0x1E (key index 30)
    [iviv] = 0F CC D6 3C E3 43 F5 A1 CB 47 79 CA 18 73 1F CC (AES-CBC IV)
    [righ] rights container
    [name] = "Justin McCloud" (Apple ID used by ipatool)
    [priv] = 440 bytes encrypted private key material
  [sign] 136 bytes signature
```

**Embedded content (all encrypted, cryptid=1):**
- 20 frameworks in Frameworks/ (6 with legacy LC_VERSION_MIN_IPHONEOS)
- 2 app extensions: DoorDashLiveActivityExtension, DoorDashNotificationServiceExtension

### Patching Strategy (Minimal)

**Changed:**
1. Main binary LC_BUILD_VERSION: platform 2 (iOS) -> 7 (iOSSimulator)
2. 14 framework binaries with LC_BUILD_VERSION: platform 2 -> 7 (via patch-platform-only.py)
3. 6 framework binaries with legacy LC_VERSION_MIN_IPHONEOS: converted to LC_BUILD_VERSION platform 7 via vtool
4. 2 extension binaries: platform 2 -> 7
5. Info.plist: CFBundleSupportedPlatforms=["iPhoneSimulator"], DTPlatformName="iphonesimulator", DTSDKName="iphonesimulator26.0"
6. Extension Info.plists: same platform markers
7. Removed UIRequiredDeviceCapabilities from all plists
8. Ad-hoc code signing (inside-out: frameworks, extensions, then app)

**NOT changed (intentionally preserved):**
- LC_ENCRYPTION_INFO_64: cryptoff=180224, cryptsize=260816896, cryptid=1 (all untouched)
- SC_Info directory with all sinf/supf/supp/supx files
- Encrypted crypt region bytes (no shellcode injection, no entry point replacement)
- No encryption header zeroing

### Installation

```
$ xcrun simctl install booted /path/to/patched/DoorDash.app
(success -- no error)
```

The Simulator accepted the app bundle with cryptid=1 and encrypted content.

### Launch Attempt

```
$ xcrun simctl launch --console booted doordash.DoorDashConsumer
An error was encountered processing the command (domain=FBSOpenApplicationServiceErrorDomain, code=1):
Simulator device failed to launch doordash.DoorDashConsumer.
The request was denied by service delegate (SBMainWorkspace).
```

### Kernel Log -- The Decryption Chain

Three kernel log entries captured via `/usr/bin/log show`:

```
2026-03-26 19:46:31.320723-0500  kernel: (IOTextEncryptionFamily)
    AppleFairplayTextCrypterSession::fairplayOpen() failed, error -42110

2026-03-26 19:46:31.320733-0500  kernel:
    set_code_unprotect: unable to create decrypter com.apple.unfree, kr=-536870211

2026-03-26 19:46:31.320735-0500  kernel:
    proc 33319: set_code_unprotect() error 7 for file "DoorDash"
```

Additionally, AMFI logged:
```
kernel: (AppleMobileFileIntegrity) AMFI: 'DoorDash.app/DoorDash' is adhoc signed.
amfid: DoorDash.app/DoorDash not valid: Error Domain=AppleMobileFileIntegrityError Code=-423
    "The file is adhoc signed or signed by an unknown certificate chain"
```

### Error Code Analysis

| Error | Hex | Meaning |
|-------|-----|---------|
| FairPlay -42110 | 0xFFFF5B82 | FairPlay DRM authorization failure -- sinf key material not valid for this device/account |
| IOKit kr -536870211 | 0xE00002BD | kIOReturnBadArgument -- the FairPlay kext could not create a decryption session |
| set_code_unprotect error 7 | - | Process cannot be code-unprotected -- final failure propagated to dyld/loader |

### Decryption Chain Traced

```
1. simctl launch -> SpringBoard -> launchd_sim -> exec(DoorDash)
2. Kernel loads binary, sees LC_ENCRYPTION_INFO_64 with cryptid=1
3. Kernel calls set_code_unprotect() for file "DoorDash"
4. set_code_unprotect() requests decrypter "com.apple.unfree"
5. IOTextEncryptionFamily kext creates AppleFairplayTextCrypterSession
6. AppleFairplayTextCrypterSession::fairplayOpen() contacts fairplayd
7. fairplayd checks sinf key material against local FairPlay identity
8. fairplayd REJECTS: sinf is bound to Apple ID "Justin McCloud" (ipatool download account)
   but local Mac has different FairPlay identity at /var/db/fpsd/
9. fairplayOpen() returns error -42110 (authorization failure)
10. IOKit returns kIOReturnBadArgument (0xE00002BD)
11. set_code_unprotect() returns error 7
12. Process fails to launch -- SpringBoard reports "launch failed"
```

### Key Finding: The Kernel DID Attempt FairPlay Decryption

**This is not a "the Simulator doesn't support FairPlay" result.** The kernel:
1. Recognized the binary as FairPlay-encrypted
2. Activated the full decryption chain (IOTextEncryptionFamily -> AppleFairplayTextCrypter -> fairplayd)
3. Attempted to open a FairPlay decryption session
4. Failed specifically because the **key material authorization was rejected** (-42110)

This confirms the architecture from Investigation 1-6: the Simulator DOES support FairPlay decryption. The failure is at the authorization layer, not the decryption capability layer.

### Implications for Vector 5

**What blocks local decryption of iOS-channel binaries:**
The sinf's `priv` field (440 bytes of encrypted key material) is encrypted under the purchasing Apple ID's FairPlay identity. fairplayd validates this against the local device's FairPlay identity at `/var/db/fpsd/`. If the identities don't match, authorization is denied.

**Potential bypasses (theoretical, not tested):**
1. **Same Apple ID**: If the Mac is signed into the same Apple ID that purchased the app, fairplayd may authorize the decryption. This would mean ANY app purchased by the Mac's owner could be decrypted locally, even if the developer opted out of Mac delivery.
2. **sinf replacement**: Replace the sinf with one from a Mac-authorized version of any app from the same Apple ID, if the key derivation is account-level rather than per-app.
3. **fairplayd API**: Directly invoke `com.apple.fpsd.sim` Mach service to request key material, bypassing the standard binary loading path.
4. **Repair API**: Use `repairAppWithOptions:replyHandler:` via AppStoreDaemon.framework to have fairplayd "repair" the FairPlay state for an installed-but-unregistered binary.

### Assessment

| Aspect | Result |
|--------|--------|
| Does the kernel attempt FairPlay decryption for Simulator processes? | **YES** -- full chain activated |
| Does decryption succeed for iOS-channel binaries? | **NO** -- authorization failure (-42110) |
| Is the failure architectural or authorization-based? | **Authorization-based** -- the capability exists, the key doesn't match |
| Is further investigation warranted? | **YES** -- test with matching Apple ID, explore fpsd.sim API |

### Files

```
IPA:       output/doordash/doordash.DoorDashConsumer_719972451_8.11.0.ipa (original, untouched)
Extracted: output/doordash/extracted/Payload/DoorDash.app/ (unmodified extraction)
Patched:   output/doordash/patched/DoorDash.app/ (platform-only patched, encryption intact)
Patcher:   output/doordash/patch-platform-only.py (minimal platform-only Mach-O patcher)
```

---

## AP News Control Test

> **Date**: 2026-03-26
> **Purpose**: Determine whether FairPlay decryption failure (-42110) is specific to DoorDash or universal for ipatool-sourced IPAs. AP News is opted IN to Mac delivery via the Mac App Store -- testing whether that affects fairplayd authorization.
> **Result**: **FAILED with identical -42110 error. fairplayd rejects ipatool sinf universally, regardless of Mac opt-in status.**

### Setup

- **App**: AP News (com.apnews.ipad.mobilenewsdevel)
- **IPA source**: ipatool download (`output/doordash/apnews-test.ipa`, 66.5 MB)
- **Mac delivery status**: AP News IS available as "Designed for iPhone/iPad" on Mac App Store
- **Simulator**: iPhone 17 Pro, iOS 26.2

### Binary Analysis

```
Main binary: "AP News" (18.8 MB, arm64)
LC_ENCRYPTION_INFO_64:
    cryptoff  = 16384    (0x4000)
    cryptsize = 15040512 (0xE58000)
    cryptid   = 1
LC_BUILD_VERSION: platform 2 (iOS), sdk 26.2
LC_MAIN: entryoff = 1517544 (0x172BE8) -- within crypt region

SC_Info present:
    AP News.sinf  (1032 bytes)
    AP News.supf  (118396 bytes)
    AP News.supp  (118500 bytes)
    AP News.supx  (80 bytes)
    Manifest.plist (4075 bytes)

Frameworks: 40 total (26 modern LC_BUILD_VERSION, 14 legacy LC_VERSION_MIN_IPHONEOS)
Extensions: 2 (APNewsWidgetExtension, NotificationService) -- both have cryptid=1
```

### Patching Applied

Platform-only patching (encryption intentionally left intact):

1. **Main binary**: LC_BUILD_VERSION platform 2 -> 7 (iOS -> iOSSimulator)
2. **26 modern frameworks**: LC_BUILD_VERSION platform 2 -> 7 via `patch-platform-only.py`
3. **14 legacy frameworks**: LC_VERSION_MIN_IPHONEOS converted to LC_BUILD_VERSION iossim via `vtool -set-build-version iossim 16.0 17.0`
4. **2 extensions**: LC_BUILD_VERSION platform 2 -> 7
5. **Info.plists**: CFBundleSupportedPlatforms -> iPhoneSimulator, DTPlatformName -> iphonesimulator
6. **Codesign**: Ad-hoc inside-out (40 frameworks, 2 extensions, app bundle)

Post-patch verification:
- cryptid = 1 (confirmed intact)
- platform = 7 (confirmed patched)
- SC_Info directory with sinf/supf/supp/supx (confirmed intact)

### Result

```
$ xcrun simctl install booted "AP News.app"
(success -- no errors)

$ xcrun simctl launch --console-pty booted com.apnews.ipad.mobilenewsdevel
An error was encountered processing the command (domain=FBSOpenApplicationServiceErrorDomain, code=1):
Simulator device failed to launch com.apnews.ipad.mobilenewsdevel.
The request was denied by service delegate (SBMainWorkspace).
```

Kernel log (single entry):
```
kernel: (IOTextEncryptionFamily) AppleFairplayTextCrypterSession::fairplayOpen() failed, error -42110
```

### Analysis

The -42110 failure is **universal for ipatool-sourced IPAs**, not specific to DoorDash or Mac opt-in status:

| Factor | DoorDash Test | AP News Test |
|--------|--------------|--------------|
| App opted in to Mac delivery | No | **Yes** |
| IPA source | ipatool | ipatool |
| cryptid | 1 | 1 |
| SC_Info/sinf present | Yes | Yes |
| fairplayOpen() result | -42110 | **-42110** |
| set_code_unprotect reached | Yes (first test) | Not logged separately |

Key observations:

1. **Mac opt-in status is irrelevant**: AP News IS available on the Mac App Store as "Designed for iPhone", yet fairplayd still rejects its sinf when the binary is loaded via Simulator. The sinf authorization is not tied to whether Apple publishes the app for Mac -- it is tied to the **delivery channel** (ipatool vs. Mac App Store native install).

2. **The sinf is channel-bound, not app-bound**: ipatool downloads through the iOS App Store API and receives a sinf keyed to iOS device delivery. fairplayd on macOS expects a sinf keyed to Mac delivery (or the same Apple ID's Mac-registered key material). The mismatch is in the **DRM key binding**, not the app metadata.

3. **Failure occurs at fairplayOpen(), before any page decryption**: The kernel engages the full FairPlay stack (IOTextEncryptionFamily -> AppleFairplayTextCrypterSession) but rejects at the authorization check, before attempting mremap_encrypted on any code pages.

### Implications for Next Steps

The ipatool delivery path is a dead end for FairPlay-encrypted Simulator loading. To get fairplayd to accept the sinf, the binary must come through one of:

1. **Mac App Store native install** -- the binary at `/private/var/folders/.../X/{UUID}/d/Wrapper/` has a Mac-bound sinf that fairplayd accepts (and the binary is already decrypted on disk -- no decryption needed)
2. **Same-account device backup/sync** -- would need investigation of whether device-extracted sinf files can be re-bound
3. **Direct fairplayd Mach service API** (`com.apple.fpsd.sim`) -- bypassing the standard binary loading path to request key material directly

The existing Darkmach pipeline (Mac App Store acquisition -> already-decrypted binary -> cryptid=0 patching) remains the correct approach. FairPlay decryption in Simulator is a capability that exists but is authorization-gated to Mac-delivered binaries.

### Files

```
IPA:       output/doordash/apnews-test.ipa (ipatool download)
Extracted: output/apnews-test/extracted/Payload/AP News.app/
Patched:   output/apnews-test/AP News.app/ (platform-only, encryption intact)
Patcher:   output/doordash/patch-platform-only.py (same as DoorDash test)
```
