![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Language](https://img.shields.io/badge/language-Python-blue)

# Binary Patching Guide

---

## Why Patching Is Needed

iOS apps installed from the Mac App Store are built for `platform=2` (iOS) with ARM64 code. The iOS Simulator expects `platform=7` (iOSSimulator). If you attempt to install an unmodified iOS app into the Simulator, `simctl install` will reject it.

Two changes are required to make the Simulator accept an iOS binary:

1. **Platform flag** — Change `LC_BUILD_VERSION.platform` from `2` (iOS) to `7` (iOSSimulator) in every Mach-O binary in the bundle.
2. **Encryption header** — Zero the `LC_ENCRYPTION_INFO_64` fields (`cryptoff`, `cryptsize`, `cryptid`) so `dyld_sim` maps the crypt region as ordinary code. Zeroing the header decrypts nothing — it is only safe once the decrypted bytes have been recovered and written back (see the two-pass technique below).

A third step handles a legacy format issue:
3. **Legacy load commands** — Some binaries use `LC_VERSION_MIN_IPHONEOS` instead of `LC_BUILD_VERSION`. These must be converted with `vtool` before the surgical patcher can set the platform flag.

After all binary modifications, the bundle must be re-signed with ad-hoc signatures from the inside out (deepest components first).

---

## The Two-Pass FairPlay Decryption Technique

Simply zeroing the encryption header is not enough if the crypt region bytes are genuinely AES-encrypted on disk — which they are for Mac App Store downloads. After patching, the binary would have zero'd encryption markers but the code section would still contain ciphertext, causing immediate crashes.

Darkmach solves this with a two-pass approach that extracts the kernel-decrypted bytes before they are needed. Both passes run inside `stage_patch()` in `src/pipeline/patching.py`; the offsets below are illustrative. Read actual offsets and lengths from your input’s Mach-O metadata.

### Pass 1 — Extract decrypted bytes via simctl spawn

`_extract_crypt_region()` in `pipeline/patching.py`:

```
Original binary:
  LC_ENCRYPTION_INFO_64: cryptoff=0x20000, cryptsize=0x1000, cryptid=1
  Bytes at 0x20000..0x21000: AES-encrypted FairPlay ciphertext (on disk)

Steps:
  1. Copy bundle to a unique /tmp/darkmach-decrypt-*/ workspace
  2. patch_bundle() on the temp copy (platform=7, cryptid=0, signed)
  3. Restore cryptid=1 + original cryptoff/cryptsize in the temp binary so the
     kernel decrypts during page-in
  4. Re-sign the temp binary (cryptid=1, platform=7, ad-hoc)
  5. xcrun simctl spawn <udid> <temp-binary>
       with SIMCTL_CHILD_DYLD_INSERT_LIBRARIES=darkmach-decrypt.dylib
       and SIMCTL_CHILD_DARKMACH_CRYPTOFF=0x20000
       and SIMCTL_CHILD_DARKMACH_CRYPTSIZE=0x1000
       and SIMCTL_CHILD_DARKMACH_DECRYPT_OUT=<unique-output-cache-temp-file>

What happens at step 5:
  - The host macOS kernel loads the Simulator-targeted binary
  - The extraction constructor reads the marked range from its process mapping;
    this is conditional on the host and input, not guaranteed for every Simulator process
  - darkmach-decrypt.dylib constructor fires before main()
  - Reads <cryptsize> bytes from process memory at the mapped address of <cryptoff>
  - Writes decrypted bytes to DARKMACH_DECRYPT_OUT
  - Process exits

  6. Verify recovered length/hash, publish the content-addressed dump and receipt
  7. Temp directory cleaned up
```

Spawn is capped at 30 seconds. Extraction fails loudly if the cache file is absent or its size does not match `cryptsize`.

### Pass 2 — Apply decrypted bytes to the final patched binary

```
  1. patch_bundle() on the work copy:
       LC_ENCRYPTION_INFO_64: cryptoff=0, cryptsize=0, cryptid=0
       LC_BUILD_VERSION.platform = 7 (iOSSimulator)
       All plists patched for Simulator
       Everything re-signed inside-out

  2. _write_crypt_bytes() writes the cached bytes back at the original cryptoff:
       Binary[0x20000 .. 0x21000] = cached_decrypted_bytes
       The crypt header is zeroed, so dyld_sim won't process it
       The bytes are now the real ARM64 code

  3. Re-sign the modified binary, then re-sign the bundle

Result: A fully patched, fully decrypted binary ready for Simulator execution
```

The cache path is `<output>/.cache/crypt/<input-main-SHA256>/<cryptoff-hex>-<cryptsize-hex>.bin`, with a `.json` sidecar. A hit requires matching schema, source hash, region geometry, recovered length and recovered-byte SHA-256. Missing or malformed metadata and mismatched bytes trigger extraction; filesystem access failures remain errors. Legacy bundle-ID-only entries are retained but not trusted. A hit is reuse, not fresh recovery.

The region is checked against the source file before extraction and against the destination before writing. The actual bytes consumed are hashed before mutation. Executable workspace traversal must be available to `launchd_sim`; recovered dumps and metadata remain mode 0600. The workspace is unique and removed after extraction.

### Compatible entitlement preservation

Default patching reads the original signed entitlement dictionary and keeps its existing Simulator-compatible allowlisted keys. It uses XML when that fits the available Mach-O section and binary plist otherwise; it does not grow the header. If the intact compatible set cannot fit or cannot be read/signed, patching fails before installation. `--strip-entitlements` explicitly omits the app-specific set for a control run. Dropped incompatible keys and the encoding are reported.

Runtime `entitlement_scan` distinguishes the encoded dictionary from selected OS readback. Neither observation proves every original service or capability-dependent operation.

Inspect the reconstructed binary with `otool -tV` and compare the original crypt range with its recovered dump. Coherent disassembly is one check, not a complete recovery oracle. Use the geometry and hashes in the cache/run metadata to attribute the bytes; the [walkthrough](walkthrough.md#read-the-artifacts) explains those artifacts.

---

## Bundle Patching: patch_bundle()

Bundle patching is in-process Python in `src/pipeline/patching.py` — there is no shell script and no subprocess boundary. The operator entry point is:

```bash
darkmach patch /path/to/App.app
```

`cmd_patch()` copies anything under `/Applications` into `output/<app>/bundle/` first, then calls `stage_patch()`, which selects a strategy and calls `patch_bundle()` for the bundle-wide work. Callers embedding Darkmach can invoke it directly:

```python
from pathlib import Path

from darkmach.pipeline.patching import patch_bundle

patch_bundle(Path("output/myapp/bundle/MyApp.app"))
```

### What It Patches

```
[1/4] Patching binaries — _patch_binary() per Mach-O
  Main binary                      → vtool (if legacy) + patch-macho-surgical.py
  Frameworks/*.framework           → same, on each framework binary
  Frameworks/*.dylib               → same, on each loose dylib
  PlugIns/*.appex                  → same, on each extension binary
  PlugIns/*.appex/Frameworks/      → same, on extension frameworks

  Legacy LC_VERSION_MIN_IPHONEOS   → vtool -set-build-version iossim 17.0 17.0
                                     (runs before the surgical patcher if present)

[2/4] Patching plists — _patch_plist() via plutil
  App.app/Info.plist               → CFBundleSupportedPlatforms[0] = "iPhoneSimulator"
                                     DTPlatformName = "iphonesimulator"
                                     DTSDKName: iphoneos<ver> → iphonesimulator<ver>
                                     UISupportedDevices removed
                                     UIRequiredDeviceCapabilities removed
  PlugIns/*.appex/Info.plist       → same transforms

[3/4] Re-signing (inside-out) — _sign_item() per component
  Frameworks/*.framework           → codesign -s - --force (ad-hoc)
  Frameworks/*.dylib               → codesign -s - --force
  PlugIns/*.appex/Frameworks/      → codesign -s - --force
  PlugIns/*.appex                  → codesign -s - --force
  App.app                          → codesign -s - --force

[4/4] Verifying
  codesign -v App.app
  otool -l binary → LC_BUILD_VERSION platform must be 7
```

`patch-macho-surgical.py` is loaded through `importlib` and its `patch_file()` called in-process — not shelled out. The only subprocesses are the system tools: `otool`, `vtool`, `plutil`, `codesign`.

> **Why inside-out signing?** The `--deep` flag on codesign does not correctly re-sign after binary modification. Each component must be signed individually from innermost to outermost, because each outer signature covers the inner components.

Verification failures are logged as warnings, not raised — `patch_bundle()` prints `WARNING: Signature verification failed` or `WARNING: Platform is <n>, expected 7` and returns. Check the output rather than the exit code.

### Manual verification

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

`patch_bundle()` imports this module via `importlib` and calls `patch_file()` directly, so bundle patching pays no subprocess cost per binary. The command line above is for patching a binary standalone.

---

## ARM64 Shellcode Generator: make-main-patch.py

Generates ARM64 shellcode to replace a FairPlay-encrypted entry point. This is **Strategy A** — used when the FairPlay crypt region contains only the entry point function and you want to replace it with a functional main().

```bash
python3 src/patch/make-main-patch.py /path/to/App.app/AppName \
    --app /path/to/App.app \
    --cryptoff 0x20000 \
    --cryptsize 0x1000
```

The binary is a positional argument and is overwritten in place unless `--output` is given. `--delegate` is optional: omitted, the tool auto-detects via `detect-delegate.py`. `--cryptoff` / `--cryptsize` override the header values, which is required after `patch-macho-surgical.py` has already zeroed them. `--detect-only` resolves the delegate and exits; `--bootstrap` selects Strategy B (fill the crypt region with RETs instead of BRKs).

The shellcode replaces the original entry point with a hand-encoded ARM64 sequence that calls
`objc_getClass`, `NSStringFromClass`, and `UIApplicationMain`, then invokes `UIApplicationMain`
with `argc`, `argv`, a nil `principalClassName`, and the detected delegate class name.

Each function pointer is loaded from its `__got` slot (`ADRP` + `LDR` + `BLR x16`) rather than through `__stubs`: Strategy A fills the crypt region with `BRK`, which destroys any stubs inside that range. The GOT-based strategy relies on usable slots outside the encrypted range; verify their location in the target's Mach-O layout rather than assuming every GOT is unencrypted.

One exception needs a runtime lookup. Swift-overlay apps import `UIKit.UIApplicationMain`, whose
Swift ABI is incompatible with the C entry point, so the C symbol is never bound and no `__got`
slot exists. When `_UIApplicationMain` is absent the shellcode falls back to
`dlsym(RTLD_DEFAULT, "UIApplicationMain")`, saving the delegate class name in `x22` across the
call. Generation fails loudly if neither the GOT slot nor `_dlsym` is available.

All ARM64 instructions are hand-encoded using `struct.pack` from the ISA spec — no assembler required.

> Note: With the two-pass FairPlay decryption technique now operational, Strategy A is no longer the primary approach for most apps. The shellcode generator is available for cases where direct crypt region replacement is preferred or where `simctl spawn` extraction is not feasible.

---

## Alternative Stub: make-main-stub.py

An alternative to the hand-encoded shellcode. Compiles a minimal `main()` replacement via clang and links it into the binary.

```bash
python3 src/patch/make-main-stub.py MyAppDelegate /tmp/main-stub.bin
```

Both arguments are positional: delegate class name, then output path. This approach uses clang to compile a small C file that calls `UIApplicationMain`, then injects the resulting object code at the entry point. Useful as a fallback when the hand-encoded shellcode approach is not suitable.

---

## AppDelegate Auto-Detection: detect-delegate.py

Before Strategy A patching can generate correct shellcode, the AppDelegate class name must be known. This tool auto-detects it from the app's symbol table.

```bash
python3 src/patch/detect-delegate.py /path/to/App.app/AppName --app /path/to/App.app
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

## ObjC Metadata Neutralizer: patch-objc-metadata.py

Strategy A leaves the crypt region as ciphertext, so any `class_ro_t.baseMethods` pointer reaching into that range makes libobjc's `fixupMethodList` dereference encrypted bytes and `SIGABRT` during dyld init. This tool zeroes those pointers.

```bash
python3 src/patch/patch-objc-metadata.py /path/to/binary \
    --cryptoff 0x20000 --cryptsize 0x1000
```

`--cryptoff` and `--cryptsize` are required and must be the *original* values, captured before `patch-macho-surgical.py` zeroed the header. `--dry-run` counts affected pointers without writing. `_patch_strategy_a()` runs this on the main binary and again on every embedded Mach-O, each with that binary's own crypt window.

---

## Strategy Decision Tree

`_detect_strategy()` in `pipeline/patching.py` checks the binaries enumerated by `_iter_bundle_binaries()`. It selects Strategy A if an encrypted binary lies beneath the main bundle's `Frameworks/` directory; otherwise it selects the extract path. This is a layout heuristic, not a count-based test or proof of acquisition channel.

```
Is an enumerated binary under the main Frameworks/ directory encrypted?
│
├── No    → "extract"  (includes the tested main-only encryption layouts
│            and already-decrypted bundles)
│            stage_patch():
│              1. _read_crypt_info()      → capture cryptoff/cryptsize
│              2. _extract_crypt_region() → simctl spawn + darkmach-decrypt.dylib
│              3. patch_bundle()          → platform + plists + inside-out sign
│              4. _write_crypt_bytes()    → decrypted bytes into crypt region
│              5. codesign binary, then bundle
│            Result: fully decrypted, Simulator-ready binary
│
└── Yes   → "strategy_a"  (an encrypted framework selects the experimental
           compatibility path)
           _patch_strategy_a():
             1. Remove SC_Info/ directories (ad-hoc signing cannot seal them)
             2. patch_bundle(keep_framework_crypt=True) → platform patched,
                cryptid=1 restored on embedded binaries
             3. make-main-patch.py      → GOT-based shellcode entry
             4. patch-objc-metadata.py  → main binary, then each framework
             5. Write .darkmach-strategy marker, re-sign binary then bundle
           Result: an injectable but hollow process — app code stays ciphertext
```

The supported acquisition workflow is installation through the Mac App Store on the research Mac. Historical extraction succeeded on that class of input. Strategy A is retained for compatibility and injection experiments; it does not establish that encrypted application logic was recovered. Strategy B (`make-main-patch.py --bootstrap`) remains in the patch tooling but is not auto-selected. See [the research article](how-it-works.md#strategy-selection-and-its-limits) for the distinction.

---

## Edge Cases

### `LC_VERSION_MIN_IPHONEOS` (legacy format)

Older apps use `LC_VERSION_MIN_IPHONEOS` instead of `LC_BUILD_VERSION`. The surgical patcher only modifies `LC_BUILD_VERSION`. `_patch_binary()` handles this: it greps `otool -l` output for the legacy command and converts with `vtool` before running the surgical patcher.

```bash
vtool -set-build-version iossim 17.0 17.0 -replace -output binary binary
```

This replaces `LC_VERSION_MIN_IPHONEOS` with a new `LC_BUILD_VERSION` set to `iOSSimulator 17.0`, after which the surgical patcher can set the platform flag normally.

### Inside-out signing failures

Using `codesign --deep` after binary modification produces invalid signatures. `patch_bundle()` signs each component individually in the correct order. If you modify the bundle after patching, re-sign using the same inside-out order:

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
