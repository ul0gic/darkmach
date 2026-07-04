![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Language](https://img.shields.io/badge/language-Python%20%2B%20Bash-blue)

# Binary Patching Guide

---

## Why Patching Is Needed

iOS apps installed from the Mac App Store are built for `platform=2` (iOS) with ARM64 code. The iOS Simulator expects `platform=7` (iOSSimulator). If you attempt to install an unmodified iOS app into the Simulator, `simctl install` will reject it.

Two changes are required to make the Simulator accept an iOS binary:

1. **Platform flag** — Change `LC_BUILD_VERSION.platform` from `2` (iOS) to `7` (iOSSimulator) in every Mach-O binary in the bundle.
2. **Encryption header** — Zero out `LC_ENCRYPTION_INFO_64` fields (`cryptoff`, `cryptsize`, `cryptid`) so `dyld_sim` does not try to process the encryption header. `dyld_sim` ignores `cryptid` entirely, but the zeroing is required for clean loading.

A third step handles a legacy format issue:
3. **Legacy load commands** — Some binaries use `LC_VERSION_MIN_IPHONEOS` instead of `LC_BUILD_VERSION`. These must be converted with `vtool` before the surgical patcher can set the platform flag.

After all binary modifications, the bundle must be re-signed with ad-hoc signatures from the inside out (deepest components first).

---

## The Two-Pass FairPlay Decryption Technique

Simply zeroing the encryption header is not enough if the crypt region bytes are genuinely AES-encrypted on disk — which they are for Mac App Store downloads. After patching, the binary would have zero'd encryption markers but the code section would still contain ciphertext, causing immediate crashes.

Darkmach solves this with a two-pass approach that extracts the kernel-decrypted bytes before they are needed:

### Pass 1 — Extract decrypted bytes via simctl spawn

```
Original binary:
  LC_ENCRYPTION_INFO_64: cryptoff=0x4000, cryptsize=0x8000, cryptid=1
  Bytes at 0x4000..0x8000: AES-encrypted FairPlay ciphertext (on disk)

Steps:
  1. Copy bundle to /tmp/darkmach-decrypt/ (temp working copy)
  2. Run full bundle patcher on the temp copy (platform=7, cryptid=0, signed)
  3. Restore cryptid=1 in the temp binary so kernel will decrypt during page-in
  4. Re-sign the temp binary (cryptid=1, platform=7, ad-hoc)
  5. xcrun simctl spawn <udid> <temp-binary>
       with SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=darkmach-decrypt.dylib
       and SIMCTL_CHILD_DARKMACH_CRYPTOFF=0x4000
       and SIMCTL_CHILD_DARKMACH_CRYPTSIZE=0x8000
       and SIMCTL_CHILD_DARKMACH_DECRYPT_OUT=output/.cache/crypt/<bundle-id>.bin

What happens at step 5:
  - The Simulator kernel loads the binary
  - FairPlay pages are decrypted during page-in (kernel always does this for Simulator processes)
  - darkmach-decrypt.dylib constructor fires before main()
  - Reads <cryptsize> bytes from process memory at the mapped address of <cryptoff>
  - Writes decrypted bytes to DARKMACH_DECRYPT_OUT
  - Process exits

  6. Decrypted bytes cached at output/.cache/crypt/<bundle-id>.bin
  7. Temp directory cleaned up
```

### Pass 2 — Apply decrypted bytes to the final patched binary

```
  1. Run full bundle patcher on the work copy:
       LC_ENCRYPTION_INFO_64: cryptoff=0, cryptsize=0, cryptid=0
       LC_BUILD_VERSION.platform = 7 (iOSSimulator)
       All plists patched for Simulator
       Everything re-signed inside-out

  2. Write the cached decrypted bytes back into the binary at cryptoff:
       Binary[0x4000 .. 0x8000] = cached_decrypted_bytes
       The crypt header is zeroed, so dyld_sim won't process it
       The bytes are now the real ARM64 code

  3. Re-sign the modified binary, then re-sign the bundle

Result: A fully patched, fully decrypted binary ready for Simulator execution
```

The extracted bytes are cached per bundle ID at `output/.cache/crypt/<bundle-id>.bin`. Subsequent `darkmach patch` or `darkmach run` calls for the same app skip the extraction if the cache file exists and has the correct size.

---

## The Full Bundle Patcher: patch-for-simulator.sh

The shell script orchestrates patching across the entire bundle structure.

```bash
src/patch/patch-for-simulator.sh /path/to/App.app
```

### What It Patches

```
[1/4] Patching binaries
  Main binary                      → patch-macho-surgical.py (platform + encryption)
  Frameworks/*.framework           → patch-macho-surgical.py on each framework binary
  Frameworks/*.dylib               → patch-macho-surgical.py on each loose dylib
  PlugIns/*.appex                  → patch-macho-surgical.py on each extension binary
  PlugIns/*.appex/Frameworks/      → patch-macho-surgical.py on extension frameworks

  Legacy LC_VERSION_MIN_IPHONEOS   → vtool -set-build-version iossim 17.0 17.0
                                     (runs before surgical patcher if needed)

[2/4] Patching plists
  App.app/Info.plist               → CFBundleSupportedPlatforms[0] = "iPhoneSimulator"
                                     DTPlatformName = "iphonesimulator"
                                     DTSDKName: iphoneos<ver> → iphonesimulator<ver>
                                     UISupportedDevices removed
                                     UIRequiredDeviceCapabilities removed
  PlugIns/*.appex/Info.plist       → same transforms

[3/4] Re-signing (inside-out)
  Frameworks/*.framework           → codesign -s - --force (ad-hoc)
  Frameworks/*.dylib               → codesign -s - --force
  PlugIns/*.appex/Frameworks/      → codesign -s - --force
  PlugIns/*.appex                  → codesign -s - --force
  App.app                          → codesign -s - --force

[4/4] Verifying
  codesign -v App.app
  Platform check: otool -l binary | LC_BUILD_VERSION platform should be 7
```

> **Why inside-out signing?** The `--deep` flag on codesign does not correctly re-sign after binary modification. Each component must be signed individually from innermost to outermost, because each outer signature covers the inner components.

### Verification

After patching, the script checks:

```bash
# Platform should be 7 (iOSSimulator)
otool -l App.app/AppName | grep -A2 LC_BUILD_VERSION | grep platform
# Expected: platform 7

# Signature should be valid
codesign -v App.app
```

---

## Byte-Level Mach-O Surgery: patch-macho-surgical.py

The Python patcher performs the actual byte-level modifications to Mach-O binaries.

```bash
python3 src/patch/patch-macho-surgical.py /path/to/binary [/path/to/binary2 ...]
```

### What It Modifies

**`LC_BUILD_VERSION.platform`:**

```
Before: platform = 2 (PLATFORM_IOS)
After:  platform = 7 (PLATFORM_IOS_SIMULATOR)
```

The platform field is at byte offset `+8` from the start of the `LC_BUILD_VERSION` load command. The patcher walks all load commands to find it and performs an in-place `struct.pack_into`.

**`LC_ENCRYPTION_INFO_64`:**

```
Before: cryptoff = 0x4000, cryptsize = 0x8000, cryptid = 1
After:  cryptoff = 0x0,    cryptsize = 0x0,    cryptid = 0
```

All three fields are zeroed. The patcher finds `LC_ENCRYPTION_INFO_64` (command code `0x2C`) and writes zeros to offsets `+8`, `+12`, and `+16` from the command start.

### FAT Binary Support

The patcher handles thin (single-arch) and FAT (multi-arch) binaries:

- **Thin 64-bit** (`MH_MAGIC_64 = 0xFEEDFACF`): patches the single slice directly
- **FAT 32-bit** (`FAT_MAGIC = 0xCAFEBABE`): iterates `fat_arch` entries, patches each ARM64 slice
- **FAT 64-bit** (`FAT_MAGIC_64 = 0xCAFEBABF`): iterates `fat_arch_64` entries, patches each ARM64 slice
- Both big-endian and little-endian FAT cigam variants are handled

### No External Dependencies

The patcher uses only Python stdlib `struct` and `sys`. No LIEF, no binary parsing libraries. Every modification is a targeted byte write at a known offset within the binary's byte array.

---

## ARM64 Shellcode Generator: make-main-patch.py

Generates ARM64 shellcode to replace a FairPlay-encrypted entry point. This is **Strategy A** — used when the FairPlay crypt region contains only the entry point function and you want to replace it with a functional main().

```bash
python3 src/patch/make-main-patch.py \
    --binary /path/to/App.app/AppName \
    --delegate MyAppDelegate \
    --output /path/to/App.app/AppName.patched
```

The shellcode replaces the original entry point with a hand-encoded ARM64 sequence that:

1. Calls `dlsym(RTLD_DEFAULT, "UIApplicationMain")` to locate the function at runtime
2. Sets up the `argc`, `argv`, `principalClassName`, and `delegateClassName` arguments
3. Calls `UIApplicationMain` with the detected delegate class name

All ARM64 instructions are hand-encoded using `struct.pack` from the ISA spec — no assembler required.

> Note: With the two-pass FairPlay decryption technique now operational, Strategy A is no longer the primary approach for most apps. The shellcode generator is available for cases where direct crypt region replacement is preferred or where `simctl spawn` extraction is not feasible.

---

## Alternative Stub: make-main-stub.py

An alternative to the hand-encoded shellcode. Compiles a minimal `main()` replacement via clang and links it into the binary.

```bash
python3 src/patch/make-main-stub.py \
    --delegate MyAppDelegate \
    --output /tmp/main-stub.o
```

This approach uses clang to compile a small C file that calls `UIApplicationMain`, then injects the resulting object code at the entry point. Useful as a fallback when the hand-encoded shellcode approach is not suitable.

---

## AppDelegate Auto-Detection: detect-delegate.py

Before Strategy A patching can generate correct shellcode, the AppDelegate class name must be known. This tool auto-detects it from the app's symbol table.

```bash
python3 src/patch/detect-delegate.py /path/to/App.app/AppName
```

**Detection tiers (in priority order):**

1. **Swift mangled — exact module match** — finds `_TtC<module>11AppDelegate` style Swift mangled names where the module matches the executable name
2. **Swift variant** — finds other Swift-mangled AppDelegate names
3. **ObjC class name** — finds `AppDelegate` or `<AppName>AppDelegate` in the ObjC class list
4. **nm symbol-table fallback** — scans `nm` output for AppDelegate symbols the earlier tiers missed
5. **SwiftUI @main detection** — identifies apps that use `@main` instead of `AppDelegate` (these are flagged as not yet patchable via Strategy A)
6. **`__objc_classlist` walk (encrypted-symbol fallback)** — for iOS-channel IPAs whose symbol table and `__cstring`/`__objc_classname` sit inside the FairPlay crypt region. Walks unencrypted `__DATA_CONST,__objc_classlist`, follows chained-fixup pointers to each `class_t`, reads `class_ro_t.name`, and pattern-matches names that resolve *outside* the crypt range. Most apps retain at least one ObjC class with a readable name (extension classes, framework classes that landed in a different section). When every class name is in-crypt, it falls back to a convention guess (`_TtC<N><module>11AppDelegate`) that relies on the shellcode's cbz-to-nil tolerance.

The tool filters out SDK module names to avoid false positives from embedded frameworks.

---

## Strategy Decision Tree

```
Does the app have LC_ENCRYPTION_INFO_64 with cryptid=1?
│
├── No → No FairPlay encryption. Proceed with:
│         patch-for-simulator.sh (platform + plists + sign)
│
└── Yes → FairPlay encryption present.
          │
          └── Two-pass FairPlay decryption (primary approach):
              1. simctl spawn + darkmach-decrypt.dylib → extract decrypted bytes
              2. patch-for-simulator.sh → patch + sign
              3. Write decrypted bytes into crypt region → re-sign
              │
              └── Result: fully decrypted, Simulator-ready binary
```

Strategy A (shellcode) and Strategy B (bootstrap dylib) remain available for specialized use cases, but the two-pass kernel extraction approach is the default and handles all app structures correctly.

---

## Edge Cases

### `LC_VERSION_MIN_IPHONEOS` (legacy format)

Older apps use `LC_VERSION_MIN_IPHONEOS` instead of `LC_BUILD_VERSION`. The surgical patcher only modifies `LC_BUILD_VERSION`. `patch-for-simulator.sh` handles this by detecting the legacy command and converting with `vtool`:

```bash
vtool -set-build-version iossim 17.0 17.0 -replace -output binary binary
```

This replaces `LC_VERSION_MIN_IPHONEOS` with a new `LC_BUILD_VERSION` set to `iOSSimulator 17.0`, after which the surgical patcher can set the platform flag normally.

### Inside-out signing failures

Using `codesign --deep` after binary modification produces invalid signatures. The `patch-for-simulator.sh` script signs each component individually in the correct order. If you modify the bundle after running the patcher, re-sign using the same inside-out order:

```bash
# Sign frameworks first
for fw in App.app/Frameworks/*.framework; do
    codesign -s - --force "$fw"
done

# Sign extensions
for appex in App.app/PlugIns/*.appex; do
    codesign -s - --force "$appex"
done

# Sign the main bundle last
codesign -s - --force App.app
```

### SwiftUI `@main` apps

Apps that use SwiftUI's `@main` attribute have no traditional `AppDelegate`. `detect-delegate.py` identifies these apps but Strategy A is not applicable — there is no single entry point to replace. These apps are currently handled by the two-pass FairPlay decryption technique (which doesn't require entry point replacement), but SwiftUI `@main` apps may have UI rendering issues in the Simulator.

### FAT binaries with arm64 and x86_64

The surgical patcher handles FAT binaries correctly — it iterates all slices and patches each ARM64 slice. x86_64 slices are skipped. The Simulator on Apple Silicon uses the arm64 slice.
