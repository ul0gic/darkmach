![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# Installation Guide

---

## Prerequisites

Darkmach runs exclusively on Apple Silicon Macs. The following must be installed and functional before proceeding.

### Required

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Apple Silicon Mac | M1 or later | The FairPlay bypass is architecture-specific |
| macOS | 13.0 (Ventura) or later | Earlier versions untested |
| Xcode | 15.0 or later | Full Xcode required, not just Command Line Tools |
| iOS Simulator | Included with Xcode | At least one iPhone simulator device configured |
| Python | 3.11 or later | Must be on `PATH` |
| clang | Included with Xcode | For building C dylibs |

### Xcode Setup

Install Xcode from the Mac App Store, then accept the license and install additional components:

```bash
sudo xcodebuild -license accept
xcode-select --install
```

Verify the iOS Simulator SDK is available:

```bash
xcrun --sdk iphonesimulator --show-sdk-path
```

This must return a valid path. If it fails, open Xcode, go to Settings > Platforms, and install the iOS platform.

### Python Setup

Verify your Python version:

```bash
python3 --version
# Python 3.11.x or later
```

If you need to install or upgrade Python, use the official installer from python.org or Homebrew:

```bash
brew install python@3.11
```

---

## Installing Darkmach

### Install with pipx (recommended)

pipx installs the tool in an isolated environment without affecting your system Python:

```bash
pipx install /path/to/darkmach
```

The compiled dylibs ship in the wheel via `package_data`, so a single install brings the full toolkit. After pulling new code:

```bash
pipx reinstall darkmach-re
```

### Development install (for toolkit work)

For an editable install where changes to Python source files take effect immediately:

```bash
cd /path/to/darkmach
pip install -e .
```

Use this only when actively editing Darkmach itself. Engagements should use pipx.

### Verify the Python install

```bash
darkmach status
```

You should see output like:

```
  [OK] Architecture: arm64
  [INFO] System Integrity Protection status: enabled.
  [OK] xcrun: /usr/bin/xcrun
  [OK] otool: /usr/bin/otool
  [OK] vtool: /usr/bin/vtool
  [OK] codesign: /usr/bin/codesign
  [OK] plutil: /usr/bin/plutil
  [OK] clang: /usr/bin/clang
  [OK] Simulator SDK: /Applications/Xcode.app/Contents/Developer/...
  [INFO] No Simulator booted (will auto-boot on launch)
  [MISSING] darkmach-net.dylib
  ...
```

The `MISSING` dylib entries are expected before the next step.

---

## Building the Interceptor Dylibs

All interceptors are C source files that must be compiled against the iOS Simulator SDK. The Makefile handles this.

From the project root:

```bash
make
```

This compiles 12 dylibs into `src/darkmach/dylibs/build/`:

```
src/darkmach/dylibs/build/darkmach-bridge.dylib       # Bridge: UDS server + 60-command dispatcher
src/darkmach/dylibs/build/darkmach-net.dylib          # Interceptor: NSURLSession / CFNetwork
src/darkmach/dylibs/build/darkmach-crypto.dylib       # Interceptor: CommonCrypto
src/darkmach/dylibs/build/darkmach-db.dylib           # Interceptor: SQLite
src/darkmach/dylibs/build/darkmach-keychain.dylib     # Interceptor: SecItem*
src/darkmach/dylibs/build/darkmach-tls.dylib          # Interceptor: TLS/SSL
src/darkmach/dylibs/build/darkmach-storage.dylib      # Interceptor: NSUserDefaults + filesystem
src/darkmach/dylibs/build/darkmach-ssl.dylib          # Interceptor: SSL certificate pinning bypass
src/darkmach/dylibs/build/darkmach-stealth.dylib      # Stealth: jailbreak/debug/hook evasion
src/darkmach/dylibs/build/darkmach-metal-fix.dylib    # Compat: Metal GPU framework Simulator shim
src/darkmach/dylibs/build/darkmach-decrypt.dylib      # Compat: FairPlay crypt-region capture
src/darkmach/dylibs/build/darkmach-survival.dylib     # Compat: app-specific survival kit
```

It also compiles a host-side utility:

```
src/darkmach/dylibs/build/dump-region     (native macOS binary, not Simulator-targeted)
```

### Verify dylibs were built

```bash
darkmach status
```

After a successful `make`, you should see:

```
  [OK] All 12 dylibs present
```

### Rebuild after source changes

```bash
make clean && make
```

### Sign dylibs (if needed)

The Makefile signs `darkmach-decrypt.dylib` automatically. If you need to re-sign all dylibs:

```bash
make sign
```

---

## Verifying Installation

Run `darkmach status` for a complete system check:

```bash
darkmach status
```

A fully ready system looks like:

```
  [OK] Architecture: arm64
  [INFO] System Integrity Protection status: enabled.
  [OK] xcrun: /usr/bin/xcrun
  [OK] otool: /usr/bin/otool
  [OK] vtool: /usr/bin/vtool
  [OK] codesign: /usr/bin/codesign
  [OK] plutil: /usr/bin/plutil
  [OK] clang: /usr/bin/clang
  [OK] Simulator SDK: /Applications/Xcode.app/Contents/Developer/Platforms/...
  [OK] Simulator booted: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  [OK] All 12 dylibs present
  [INFO] 12 iOS apps in /Applications

  System ready.
```

---

## Dependencies

Darkmach is designed to have minimal dependencies. The Python package has one runtime dependency:

| Package | Purpose |
|---------|---------|
| `hermes-dec` | Decompiling Hermes/React Native bytecode (`darkmach hermes`) |

The C dylibs have zero external dependencies — they link only against system frameworks (`Foundation`, `Security`) and system libraries (`sqlite3`, `objc`, `boringssl`).

---

## Troubleshooting

### "Architecture: x86_64" — FAIL

You are running on an Intel Mac. Darkmach requires Apple Silicon (arm64). The FairPlay bypass technique is architecture-specific.

### "xcrun: not found" or tool path shows "not found"

Xcode Command Line Tools are not installed or Xcode is not selected:

```bash
sudo xcode-select --switch /Applications/Xcode.app
xcode-select --install
```

### "Simulator SDK not found" — FAIL

The iOS platform is not installed in Xcode:

1. Open Xcode
2. Go to Settings (Cmd+,) > Platforms
3. Install the iOS platform

### Make fails with "SDK not found"

This is the same issue as the Simulator SDK not found. Ensure the iOS Simulator platform is installed in Xcode before running `make`.

### `darkmach-decrypt.dylib` fails to sign

Ad-hoc signing requires no developer account, but the binary must be a valid Mach-O:

```bash
codesign -s - --force src/dylibs/darkmach-decrypt.dylib
codesign -v src/dylibs/darkmach-decrypt.dylib
```

### `pip install -e .` fails

Ensure you are using Python 3.11 or later and that `setuptools` is installed:

```bash
python3 --version
pip install --upgrade pip setuptools
pip install -e .
```

### Simulator won't boot

Try from Xcode first: open the Simulator app manually and boot a device. If that works, `darkmach run` will auto-detect the booted device.

```bash
open -a Simulator
```

Then try:

```bash
darkmach status
```
