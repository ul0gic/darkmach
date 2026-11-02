![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# CLI Reference

Darkmach exposes all pipeline functionality through a single `darkmach` command with 10 subcommands.

```
darkmach <subcommand> [arguments] [options]
```

Every subcommand has offline `--help` with examples. `darkmach bridge --commands` prints the runtime command reference without connecting. `DARKMACH_OUTPUT` selects the output root (default `./output`). Exit codes are 0 for success, 1 for a reported operational failure, 2 for argument-parser errors and 130 for interruption. Progress and errors go to stderr; reports and summaries go to stdout.

Runtime commands accept `--udid UUID`. Automatic selection uses the only booted iOS device; when booting is needed and none is booted, exactly one available iPhone is required. Ambiguity requires an explicit UUID. `run`, `launch` and `bridge` also accept `--socket PATH`: an absolute Unix socket path shorter than 104 UTF-8 bytes. The default endpoint is `/tmp/darkmach-bridge-<UUID>.sock`; live endpoints are not replaced. Select a distinct endpoint for each simultaneous target on the same device.

`run`, `patch` and `launch` write per-invocation JSON receipts under `<output>/<app>/runs/`, including terminal failures after the receipt starts. Receipts report stage outcomes, input identity, selected device, patch/cache/entitlement results and bridge identity as those stages are reached. They exclude capture bodies and credentials. Completion does not validate UI flows or capture coverage.

---

## darkmach run

**Full pipeline**: analyze → patch → install → launch → bridge connect.

This is the primary entry point. Given a path to an installed iOS app, it runs the complete pipeline from static analysis through instrumented Simulator launch, including FairPlay decryption.

### Usage

```bash
darkmach run <app> [--udid UUID] [--socket PATH] [--strip-entitlements]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle. For apps installed from the Mac App Store, this is typically `/Applications/AppName.app`. |

### Options

| Option | Description |
|---|---|
| `--strip-entitlements` | Explicitly omit app-specific entitlements. Default preservation keeps the original Simulator-compatible set intact or fails. |
| `--udid UUID` | Select an available iOS Simulator; boot it if needed. |
| `--socket PATH` | Select the bridge endpoint instead of the device-derived default. |

See [environment isolation](research/methodology.md#record-the-environment-and-isolate-the-run) before running alongside another development project. Entitlement encoding/read/signing failures stop patching before installation; preserving keys does not guarantee every original Apple capability.

### Pipeline Steps

The command executes 7 labeled steps:

1. **Locate iOS app bundle** — For Mac App Store apps, the iOS bundle lives inside `AppName.app/Wrapper/AppName.app`. Darkmach resolves this automatically.
2. **Copy to output directory** — The bundle is copied to `output/<app>/bundle/AppName.app` to avoid modifying the installed copy.
3. **Static analysis** — Inspects the copied bundle before extraction. Output goes to `output/<app>/static/`; rerun `analyze` on the reconstructed copy when examining recovered code.
4. **Select Simulator** — Uses the explicit UUID or an unambiguous automatic selection and boots it if needed.
5. **Patch for Simulator** — Patches platform flags, zeroes encryption headers, performs two-pass FairPlay decryption via `simctl spawn`, and re-signs the bundle.
6. **Install and launch** — Installs the patched bundle into the Simulator and launches with all 8 interceptors active.
7. **Connect bridge** — Verifies the expected bundle and PID at the selected endpoint, then records entitlement readback. UI and capture-event validation remain separate.

### Output

```
============================================================
  Darkmach Pipeline Complete
  App:       MyApp (com.example.myapp) v3.2.1
  PID:       12345
  Device:    XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  Bridge:    CONNECTED
  Socket:    /tmp/darkmach-bridge-<UUID>.sock
  Static:    /path/to/darkmach/output/myapp/static
  Dynamic:   /path/to/darkmach/output/myapp/dynamic
============================================================

  Bridge is ready. Connect with:
    darkmach bridge --udid <UUID>
```

### Examples

```bash
# Run against a Mac App Store iOS app
darkmach run /Applications/OddsJam.app

# The path can also point directly to an iOS .app bundle
darkmach run /path/to/extracted/MyApp.app
```

---

## darkmach analyze

**Static analysis only.** Extracts URLs, secrets, SDK fingerprints, entitlements, plist contents, and Mach-O structure from a decrypted bundle. Does not patch or launch.

### Usage

```bash
darkmach analyze <app> [-o OUTPUT]
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
darkmach analyze /Applications/MyApp.app

# Analyze to a custom directory
darkmach analyze /Applications/MyApp.app -o /tmp/myapp-analysis

# Analyze a bundle you've already copied
darkmach analyze output/myapp/bundle/MyApp.app
```

---

## darkmach patch

**Patch a bundle for Simulator.** Applies platform, encryption-header and bundle transformations, performs extraction where applicable, and re-signs. It does not perform the final app installation or launch; extraction may boot a Simulator and spawn a temporary process.

This is useful when you want to inspect the patched bundle before launching, or when integrating Darkmach into your own pipeline.

### Usage

```bash
darkmach patch <app> [--udid UUID] [--strip-entitlements]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `app` | Path to the `.app` bundle |

### Options

| Option | Description |
|---|---|
| `--strip-entitlements` | Explicitly omit app-specific entitlements; default preservation fails if the compatible set cannot fit intact. |
| `--udid UUID` | Select the iOS Simulator used for extraction. |

### Behavior

If the path points to an app in `/Applications`, Darkmach first copies it to `output/<app>/bundle/` and patches the copy. If the path points to a bundle in `output/` or elsewhere, it patches in place.

The patching process (`stage_patch()` in `src/pipeline/patching.py`, in-process Python):

1. Selects Strategy A if an enumerated encrypted binary is beneath the main `Frameworks/` directory; otherwise selects the extract path below. This is a layout heuristic, not proof of the acquisition channel.
2. Reads FairPlay crypt region info (`cryptoff`, `cryptsize`) from the original binary before any modification.
3. If encryption is present, boots a Simulator (auto-boots if needed) and runs `simctl spawn` with `darkmach-decrypt.dylib` to extract the decrypted bytes.
4. Calls `patch_bundle()` — patches every binary and Info.plist, then re-signs inside-out.
5. Verifies and writes recovered bytes into the patched binary, preserves allowlisted original app entitlements using XML or binary plist unless explicitly stripped, and re-signs. Failure to preserve the compatible set is an error.

See [patching.md](patching.md) for the strategy decision tree and per-tool detail.

### Output

```
Patched: /path/to/darkmach/output/myapp/bundle/MyApp.app
Install and launch the patched copy on your explicitly selected Simulator.
```

### Examples

```bash
darkmach patch /Applications/MyApp.app
```

---

## darkmach launch

**Launch an already-installed app** with the default eight dylibs. Use this when you have already patched and installed the app. Interceptor logs append to their destination; relaunching does not create a fresh evidence directory automatically.

### Usage

```bash
darkmach launch <bundle_id> [--udid UUID] [--socket PATH] [--ssl-bypass]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `bundle_id` | The app's bundle identifier, e.g., `com.oddsjam.app` |

### Options

| Option | Description |
|--------|-------------|
| `--ssl-bypass` | Enable SSL pinning bypass by setting `DARKMACH_SSL_BYPASS=1` inside the process. The `darkmach-ssl` interceptor will pass all `SecTrustEvaluateWithError` calls unconditionally. |
| `--udid UUID` | Select the Simulator containing the installed patched bundle. |
| `--socket PATH` | Select a distinct bridge endpoint. |

### Behavior

1. Terminates any existing instance of the app in the Simulator.
2. Checks the selected endpoint. A live peer is refused; only an owned, unchanged stale socket is removed.
3. Launches the app via `xcrun simctl launch` with all 8 interceptor dylibs injected.
4. Resolves the installed bundle's identity and sets `DARKMACH_OUTPUT_DIR` to `output/<app-name-slug>/dynamic/`. Launch receipts remain under the invocation's bundle-ID-suffix directory; retain the printed receipt path and verify the actual log sink when attributing evidence.
5. Verifies the expected bundle/PID at the bridge endpoint and records a launch receipt. This is a relaunch, not fresh extraction.

### Examples

```bash
# Launch with interceptors
darkmach launch com.oddsjam.app

# Launch with SSL pinning bypass
darkmach launch com.example.myapp --ssl-bypass
```

---

## darkmach bridge

**Connect to a running bridge.** Opens an interactive REPL connected to the `darkmach-bridge.dylib` Unix domain socket inside the running app.

The bridge must already be running — meaning the app was launched with `darkmach-bridge.dylib` injected (which `darkmach run` and `darkmach launch` do automatically).

### Usage

```bash
darkmach bridge [--udid UUID] [--socket PATH] [--commands]
```

### Interactive Mode

The REPL uses the explicit socket, the selected device's endpoint, or the only booted device's endpoint. With no selected or booted device it falls back to legacy `/tmp/darkmach-bridge.sock`. Multiple booted devices require selection. It displays an `info` banner on startup:

```
darkmach-bridge client — type 'help' for commands, 'quit' to exit
Connecting to /tmp/darkmach-bridge.sock...
Bridge: darkmach-bridge v1.0
App: MyApp 3.2.1 (build 421)
Bundle: com.example.myapp
PID: 12345
Classes: 8432
Active hooks: 0
Commands: enumerate_classes, get_methods, get_properties, ...

darkmach>
```

Type `help` to see all available commands. See [LLM Runtime Bridge](bridge.md) for the full command reference.

`raw` accepts a complete JSON request object, for example `raw {"cmd":"info"}`. Numeric and JSON input errors are reported without ending the REPL. A command's success flag describes that command only; inspect its result before inferring a UI or application outcome.

### Examples

```bash
darkmach bridge

# Inside the REPL:
darkmach> enumerate_classes Auth
darkmach> get_methods AuthTokenManager
darkmach> heap_search AuthTokenManager
darkmach> keychain_dump
darkmach> view_hierarchy
```

---

## darkmach discover

**Find iOS apps available on the Mac App Store.** Uses the iTunes Search API and Apple's amp-api to identify apps that are iOS-only binaries marked as compatible with Apple Silicon Macs.

### Usage

```bash
darkmach discover [search] [--category CATEGORY] [--ids IDS] [--limit LIMIT] [-o OUTPUT] [--token TOKEN]
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
| `--token TOKEN` | Override the amp-api Bearer token; takes precedence over `DARKMACH_AMP_TOKEN` and the bundled fallback. |
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

Discovery accepts an amp-api Bearer token through `--token` or `DARKMACH_AMP_TOKEN`, with a bundled fallback in `src/discover.py`. Tokens expire; prefer an explicit override. The warning's refresh instructions describe obtaining the App Store web client's token through its network requests.

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
darkmach discover "sports betting"

# Scan the Finance category
darkmach discover --category 6015

# Scan all major categories
darkmach discover --category all

# Look up specific app IDs
darkmach discover --ids 1234567890,9876543210

# Save to a specific file
darkmach discover "fitness" --limit 50 -o /tmp/fitness-apps.json
```

---

## darkmach hermes

**Experimental Hermes/React Native inspection.** Finds bundle files, detects Hermes bytecode and attempts decompiler-assisted or fallback extraction. The current fallback can concatenate distinct HBC strings and produce fabricated URL or credential candidates. Do not treat those candidates as findings without independent boundary-aware validation; see [known limitations](research/findings.md#known-research-limitations).

### Usage

```bash
darkmach hermes <app> [-o OUTPUT] [--json]
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
darkmach hermes /Applications/MyRNApp.app

# Analyze just the bundle file
darkmach hermes /path/to/main.jsbundle

# JSON output
darkmach hermes /Applications/MyRNApp.app --json
```

---

## darkmach keychain

**Read the Simulator keychain from the host filesystem.** The iOS Simulator stores its keychain as a SQLite database at a known path in `~/Library/Developer/CoreSimulator/`. This command reads it directly without needing to be inside the process.

This is a complement to the `darkmach-keychain.dylib` interceptor (which captures keychain operations at runtime) — the host-side reader gives you a snapshot of the entire keychain at any point.

### Usage

```bash
darkmach keychain [--udid UDID] [--json]
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
darkmach keychain

# Read from a specific Simulator
darkmach keychain --udid XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX

# JSON output for scripting
darkmach keychain --json
```

---

## darkmach list

**List installed iOS apps.** Scans `/Applications` for iOS app bundles (apps with a `Wrapper/` directory containing an inner `.app`).

### Usage

```bash
darkmach list
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

## darkmach status

**System pre-flight check.** Verifies that all required tools and conditions are met before running the pipeline.

### Usage

```bash
darkmach status
```

### Checks Performed

| Check | Pass Condition |
|-------|---------------|
| Architecture | Must be `arm64` (Apple Silicon) |
| SIP status | Informational — SIP can be enabled, Darkmach does not require SIP bypass |
| xcrun | Must be on PATH |
| otool | Must be on PATH |
| vtool | Must be on PATH |
| codesign | Must be on PATH |
| plutil | Must be on PATH |
| clang | Must be on PATH |
| Simulator SDK | `xcrun --sdk iphonesimulator --show-sdk-path` must succeed |
| Booted Simulator | Informational — will auto-boot if none found |
| Interceptor dylibs | All 8 dylibs in `src/dylibs/build/` must be present |
| iOS apps in /Applications | Informational count |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All required checks passed |
| 1 | One or more required checks failed |
