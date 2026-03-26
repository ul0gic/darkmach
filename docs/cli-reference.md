![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# CLI Reference

Sphinx exposes all pipeline functionality through a single `sphinx` command with 10 subcommands.

```
sphinx <subcommand> [arguments] [options]
```

---

## sphinx run

**Full pipeline**: analyze → patch → install → launch → bridge connect.

This is the primary entry point. Given a path to an installed iOS app, it runs the complete pipeline from static analysis through instrumented Simulator launch, including FairPlay decryption.

### Usage

```bash
sphinx run <app>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle. For apps installed from the Mac App Store, this is typically `/Applications/AppName.app`. |

### Pipeline Steps

The command executes 7 labeled steps:

1. **Locate iOS app bundle** — For Mac App Store apps, the iOS bundle lives inside `AppName.app/Wrapper/AppName.app`. Sphinx resolves this automatically.
2. **Copy to output directory** — The bundle is copied to `output/<app>/bundle/AppName.app` to avoid modifying the installed copy.
3. **Static analysis** — Runs `sphinx analyze` against the bundle. Output goes to `output/<app>/static/`.
4. **Boot Simulator** — If no Simulator is booted, Sphinx selects and boots the newest available iPhone Simulator.
5. **Patch for Simulator** — Patches platform flags, zeroes encryption headers, performs two-pass FairPlay decryption via `simctl spawn`, and re-signs the bundle.
6. **Install and launch** — Installs the patched bundle into the Simulator and launches with all 8 interceptors active.
7. **Connect bridge** — Waits for the `sphinx-bridge.dylib` socket to appear and verifies connectivity.

### Output

```
============================================================
  Sphinx Pipeline Complete
  App:       MyApp (com.example.myapp) v3.2.1
  PID:       12345
  Device:    XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  Bridge:    CONNECTED
  Socket:    /tmp/sphinx-bridge.sock
  Static:    /path/to/sphinx/output/myapp/static
  Dynamic:   /path/to/sphinx/output/myapp/dynamic
============================================================

  Bridge is ready. Connect with:
    sphinx bridge
```

### Examples

```bash
# Run against a Mac App Store iOS app
sphinx run /Applications/OddsJam.app

# The path can also point directly to an iOS .app bundle
sphinx run /path/to/extracted/MyApp.app
```

---

## sphinx analyze

**Static analysis only.** Extracts URLs, secrets, SDK fingerprints, entitlements, plist contents, and Mach-O structure from a decrypted bundle. Does not patch or launch.

### Usage

```bash
sphinx analyze <app> [-o OUTPUT]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle |

### Options

| Option | Description |
|--------|-------------|
| `-o OUTPUT`, `--output OUTPUT` | Output directory. Defaults to `output/<app>/static/` |

### Output Files

| File | Contents |
|------|---------|
| `urls.txt` | All HTTP/HTTPS URLs extracted from binary strings |
| `secrets.txt` | Strings matching API key, token, bearer, password, credential patterns |
| `sdks.txt` | SDK/service fingerprint strings (Firebase, AWS, Stripe, Sentry, etc.) |
| `entitlements.txt` | App entitlements from `codesign -d --entitlements` |
| `plists.txt` | Contents of all plist files in the bundle (excluding `.lproj` localization) |
| `summary.json` | Structured summary: app name, binary path, URL count, secret count, SDK count, architecture |

### Analysis Steps

The analyzer runs 14 checks:

1. Encryption check (cryptid status from `LC_ENCRYPTION_INFO_64`)
2. Architecture (via `lipo -info`)
3. Linked frameworks (via `otool -L`)
4. String extraction (all printable strings from the binary)
5. URL extraction
6. Secrets/API key extraction
7. SDK fingerprint extraction
8. Entitlements
9. Plist files
10. URL schemes (`CFBundleURLSchemes`)
11. App Transport Security configuration
12. Embedded JSON files
13. Embedded frameworks (`Frameworks/` directory)
14. Mach-O load command summary

### Examples

```bash
# Analyze to default output location
sphinx analyze /Applications/MyApp.app

# Analyze to a custom directory
sphinx analyze /Applications/MyApp.app -o /tmp/myapp-analysis

# Analyze a bundle you've already copied
sphinx analyze output/myapp/bundle/MyApp.app
```

---

## sphinx patch

**Patch a bundle for Simulator.** Applies the full patching pipeline — platform flags, encryption headers, FairPlay decryption — and re-signs. Does not install or launch.

This is useful when you want to inspect the patched bundle before launching, or when integrating Sphinx into your own pipeline.

### Usage

```bash
sphinx patch <app>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle |

### Behavior

If the path points to an app in `/Applications`, Sphinx first copies it to `output/<app>/bundle/` and patches the copy. If the path points to a bundle in `output/` or elsewhere, it patches in place.

The patching process:

1. Reads FairPlay crypt region info (`cryptoff`, `cryptsize`) from the original binary before any modification.
2. If encryption is present, boots a Simulator (auto-boots if needed) and runs `simctl spawn` with `sphinx-decrypt.dylib` to extract the decrypted bytes.
3. Runs `patch-for-simulator.sh` — patches all binaries, plists, and re-signs.
4. Writes the decrypted bytes back into the crypt region of the patched binary and re-signs.

### Output

```
Patched: /path/to/sphinx/output/myapp/bundle/MyApp.app
Install: xcrun simctl install booted /path/to/.../MyApp.app
Launch:  xcrun simctl launch booted com.example.myapp
```

### Examples

```bash
sphinx patch /Applications/MyApp.app
```

---

## sphinx launch

**Launch an already-installed app** with all interceptors active. Use this when you have already patched and installed the app and want to re-launch with fresh interceptor logs.

### Usage

```bash
sphinx launch <bundle_id> [--ssl-bypass]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `bundle_id` | The app's bundle identifier, e.g., `com.oddsjam.app` |

### Options

| Option | Description |
|--------|-------------|
| `--ssl-bypass` | Enable SSL pinning bypass by setting `SPHINX_SSL_BYPASS=1` inside the process. The `sphinx-ssl` interceptor will pass all `SecTrustEvaluateWithError` calls unconditionally. |

### Behavior

1. Terminates any existing instance of the app in the Simulator.
2. Removes the stale bridge socket at `/tmp/sphinx-bridge.sock`.
3. Launches the app via `xcrun simctl launch` with all 8 interceptor dylibs injected.
4. Sets `SPHINX_OUTPUT_DIR` to `output/<bundle-slug>/dynamic/` for interceptor log output.
5. Waits for the bridge socket to appear and connects.

### Examples

```bash
# Launch with interceptors
sphinx launch com.oddsjam.app

# Launch with SSL pinning bypass
sphinx launch com.example.myapp --ssl-bypass
```

---

## sphinx bridge

**Connect to a running bridge.** Opens an interactive REPL connected to the `sphinx-bridge.dylib` Unix domain socket inside the running app.

The bridge must already be running — meaning the app was launched with `sphinx-bridge.dylib` injected (which `sphinx run` and `sphinx launch` do automatically).

### Usage

```bash
sphinx bridge
```

### Interactive Mode

The REPL connects to `/tmp/sphinx-bridge.sock` and displays an `info` banner on startup:

```
sphinx-bridge client — type 'help' for commands, 'quit' to exit
Connecting to /tmp/sphinx-bridge.sock...
Bridge: sphinx-bridge v1.0
App: MyApp 3.2.1 (build 421)
Bundle: com.example.myapp
PID: 12345
Classes: 8432
Active hooks: 0
Commands: enumerate_classes, get_methods, get_properties, ...

sphinx>
```

Type `help` to see all available commands. See [LLM Runtime Bridge](bridge.md) for the full command reference.

### Examples

```bash
sphinx bridge

# Inside the REPL:
sphinx> enumerate_classes Auth
sphinx> get_methods AuthTokenManager
sphinx> heap_search AuthTokenManager
sphinx> keychain_dump
sphinx> view_hierarchy
```

---

## sphinx discover

**Find iOS apps available on the Mac App Store.** Uses the iTunes Search API and Apple's amp-api to identify apps that are iOS-only binaries marked as compatible with Apple Silicon Macs.

### Usage

```bash
sphinx discover [search] [--category CATEGORY] [--ids IDS] [--limit LIMIT] [-o OUTPUT]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `search` | Keyword search term (e.g., `sports betting`) |

### Options

| Option | Description |
|--------|-------------|
| `--category CATEGORY` | App Store category ID, or `all` to scan all major categories. See category table below. |
| `--ids IDS` | Comma-separated App Store app IDs for direct lookup |
| `--limit LIMIT` | Maximum number of results (default: 25) |
| `-o OUTPUT`, `--output OUTPUT` | Output file path. Defaults to `output/discover/<mode>-<date>.json` |

### Status Codes

| Code | Meaning |
|------|---------|
| `YES` | iOS binary available on Mac — can be installed and analyzed |
| `OUT` | Binary exists on Mac servers but developer opted out |
| `MAC` | This is a native Mac app, not an iOS binary |
| `--`  | Not available on Mac at all |

### Category IDs

| ID | Category |
|----|---------|
| 6001 | Weather |
| 6002 | Utilities |
| 6005 | Social Networking |
| 6007 | Productivity |
| 6008 | Photo & Video |
| 6012 | Lifestyle |
| 6013 | Health & Fitness |
| 6014 | Games |
| 6015 | Finance |
| 6016 | Entertainment |
| 6020 | Food & Drink |
| 6023 | Shopping |
| 6024 | Sports |
| 6026 | Business |

### Token Note

Discovery uses an Apple amp-api Bearer JWT token embedded in `src/sphinx/discover.py`. This token has an expiration date. When it expires, Sphinx will print a warning with refresh instructions: visit apps.apple.com in Safari, open DevTools Network tab, find any amp-api-edge request, and copy the `Authorization: Bearer` value.

### Output Format

Results are saved as JSON:

```json
{
  "available_count": 8,
  "opted_out_count": 3,
  "total_checked": 25,
  "apps": [
    {
      "id": "1234567890",
      "name": "MyApp",
      "bundle": "com.example.myapp",
      "category": "Sports",
      "status": "available",
      "size_mb": 42.3
    }
  ]
}
```

### Examples

```bash
# Search by keyword
sphinx discover "sports betting"

# Scan the Finance category
sphinx discover --category 6015

# Scan all major categories
sphinx discover --category all

# Look up specific app IDs
sphinx discover --ids 1234567890,9876543210

# Save to a specific file
sphinx discover "fitness" --limit 50 -o /tmp/fitness-apps.json
```

---

## sphinx hermes

**Extract secrets from Hermes/React Native bytecode.** Finds `main.jsbundle` files in React Native apps, detects Hermes bytecode (HBC format), decompiles them, and extracts secrets, API keys, URLs, and endpoints.

### Usage

```bash
sphinx hermes <app> [-o OUTPUT] [--json]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle or a `.jsbundle` file directly |

### Options

| Option | Description |
|--------|-------------|
| `-o OUTPUT`, `--output OUTPUT` | Output directory. Defaults to `output/<app>/static/hermes/` |
| `--json` | Output results as JSON instead of human-readable text |

### What It Finds

The Hermes extractor searches decompiled bytecode for:

- API keys (generic and service-specific: Stripe, AWS, Google, GitHub, Slack)
- Bearer tokens and JWTs
- Secrets and passwords
- API endpoints and backend URLs
- Firebase, Expo, and cloud service URLs

### Examples

```bash
# Analyze a React Native app
sphinx hermes /Applications/MyRNApp.app

# Analyze just the bundle file
sphinx hermes /path/to/main.jsbundle

# JSON output
sphinx hermes /Applications/MyRNApp.app --json
```

---

## sphinx keychain

**Read the Simulator keychain from the host filesystem.** The iOS Simulator stores its keychain as a SQLite database at a known path in `~/Library/Developer/CoreSimulator/`. This command reads it directly without needing to be inside the process.

This is a complement to the `sphinx-keychain.dylib` interceptor (which captures keychain operations at runtime) — the host-side reader gives you a snapshot of the entire keychain at any point.

### Usage

```bash
sphinx keychain [--udid UDID] [--json]
```

### Options

| Option | Description |
|--------|-------------|
| `--udid UDID` | Simulator UDID. Auto-detects the booted Simulator if not specified. |
| `--json` | Output as JSON instead of human-readable text |

### Database Location

```
~/Library/Developer/CoreSimulator/Devices/<UDID>/data/Library/Keychains/keychain-2-debug.db
```

### Examples

```bash
# Read keychain from the booted Simulator
sphinx keychain

# Read from a specific Simulator
sphinx keychain --udid XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

# JSON output for scripting
sphinx keychain --json
```

---

## sphinx list

**List installed iOS apps.** Scans `/Applications` for iOS app bundles (apps with a `Wrapper/` directory containing an inner `.app`).

### Usage

```bash
sphinx list
```

### Output

```
Name                           Bundle ID                                Version
--------------------------------------------------------------------------------
OddsJam                        com.oddsjam.app                          3.2.1
MyFitnessApp                   com.example.fitness                      8.1.0

2 iOS apps found
```

---

## sphinx status

**System pre-flight check.** Verifies that all required tools and conditions are met before running the pipeline.

### Usage

```bash
sphinx status
```

### Checks Performed

| Check | Pass Condition |
|-------|---------------|
| Architecture | Must be `arm64` (Apple Silicon) |
| SIP status | Informational — SIP can be enabled, Sphinx does not require SIP bypass |
| xcrun | Must be on PATH |
| otool | Must be on PATH |
| vtool | Must be on PATH |
| codesign | Must be on PATH |
| plutil | Must be on PATH |
| clang | Must be on PATH |
| Simulator SDK | `xcrun --sdk iphonesimulator --show-sdk-path` must succeed |
| Booted Simulator | Informational — will auto-boot if none found |
| Interceptor dylibs | All 8 dylibs in `src/dylibs/` must be present |
| iOS apps in /Applications | Informational count |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All required checks passed |
| 1 | One or more required checks failed |
