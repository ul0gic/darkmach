# Darkmach -- Capability Brief

> A research toolkit for iOS reverse engineering on Apple Silicon. Discovers, decrypts,
> patches, instruments, and probes Mac-installable iOS apps with no jailbreak, no SIP
> bypass, and no dependence on Apple-internal infrastructure.

## At a Glance

Darkmach is a single-CLI pipeline for iOS app research on Apple Silicon. It takes a
FairPlay-encrypted iOS bundle delivered through the Mac App Store, produces a Simulator-runnable copy with the encryption
removed via kernel page-in, installs and launches it, injects a chain of cooperating
dylibs, and exposes the live process to operator queries through a JSON socket. The
result is a research workflow that traditionally requires a jailbroken device or a
leaked decrypted IPA, running entirely on a stock developer Mac.

## The Core Technical Contribution

The architectural insight at the center of Darkmach is that the macOS kernel's FairPlay
decryption path is reachable from the iOS Simulator. iOS apps installed on Apple
Silicon carry genuine FairPlay-encrypted crypt regions on disk (`cryptid = 1`); the
kernel decrypts those pages on demand during page-in via the `mremap_encrypted`
syscall, the `IOTextEncryptionFamily` kext, and `fairplayd`. The same decryption fires
for a Simulator-targeted process once the bundle is patched to identify as iOSSimulator
and re-signed with empty entitlements.

The technique reduces to a five-step procedure:

1. Rewrite the main binary's platform load command -- `LC_VERSION_MIN_IPHONEOS` to
   `LC_BUILD_VERSION` with platform `iOSSimulator`.
2. Zero the FairPlay encryption header (`cryptid = 0`) and inject Strategy A entry
   shellcode (or Strategy B bootstrap fill) into the cleared crypt region.
3. Re-sign the bundle ad-hoc with empty entitlements.
4. Install into the iOS Simulator and launch; the kernel decrypts crypt pages on
   page-in for the live process.
5. The injected `darkmach-decrypt.dylib` reads the decrypted pages from its own
   process memory and reconstructs a fully decrypted Mach-O bundle on disk.

Standard alternatives -- Frida, objection, Needle, r2frida -- require either a
jailbroken iOS device or a pre-decrypted IPA obtained from an untrusted source.
Darkmach reframes a documented kernel side-effect into a complete, reproducible
research workflow on a stock Apple Silicon Mac.

## The Pipeline

```
discover  ->  analyze  ->  patch  ->  decrypt  ->  install  ->  launch  ->  bridge
                                                                            |
                                                                            v
                                                                     dynamic analysis loop
```

Each stage is exposed as a `darkmach` subcommand and is independently runnable. The
`darkmach run` subcommand chains every stage end-to-end against a single bundle ID.

| Stage | Subcommand | Purpose |
|-------|-----------|---------|
| Discover | `darkmach discover` / `darkmach list` | Find iOS apps available on the Mac App Store; list locally installed apps |
| Static analysis | `darkmach analyze` | Extract URLs, secrets, SDKs, entitlements, and Mach-O structure from the bundle |
| Patch | `darkmach patch` | Mach-O surgery: rewrite platform flags, zero encryption headers, inject Strategy A/B entry shellcode |
| Decrypt | (within patch + launch) | Trigger kernel page-in decryption via the Simulator; capture decrypted crypt regions |
| Launch | `darkmach launch` | Boot the Simulator, install the patched bundle, inject the interceptor and bridge dylibs |
| Bridge | `darkmach bridge` | Connect to the running process through a UDS / JSON-lines socket; issue any of sixty introspection commands |
| Pre-flight | `darkmach status` | Verify the host environment, prerequisites, and dylib presence |

## Capability Detail

### Static Analysis

`darkmach analyze` runs against a decrypted `.app` bundle and emits a structured tree
to `output/<app>/static/`:

- URL inventory pulled from binary string tables.
- API key, token, and credential candidates from binary strings, plists, and embedded
  JSON.
- SDK fingerprinting against a curated signature table covering analytics, attribution,
  ad mediation, crash reporting, payments, push, and auth providers.
- Entitlement enumeration via `codesign -d --entitlements`.
- `Info.plist` policy posture: arbitrary loads, queried URL schemes, usage-description
  strings, privacy-manifest declarations.
- Linked frameworks (`otool -L`).
- Mach-O load-command summary (`otool -l`), including platform, architecture, and
  encryption state.

### Patching

The patch pipeline is a hand-rolled, byte-level Mach-O patcher built on the Python
standard library alone -- no LIEF, no external Mach-O libraries:

- Platform rewrite from `LC_VERSION_MIN_IPHONEOS` to `LC_BUILD_VERSION` with platform
  `iOSSimulator`.
- Encryption header zeroing: `cryptid`, `cryptsize`, `cryptoff` cleared.
- Strategy A entry-point shellcode: a hand-encoded ARM64 stub that resolves
  `objc_getClass`, `NSStringFromClass`, and `UIApplicationMain` through
  `dlsym(RTLD_DEFAULT, ...)` and transfers control into a detected AppDelegate.
- Strategy B bootstrap fill: ARM64 `RET` instructions across the full crypt region
  with a small bootstrap dylib for control transfer when the crypt region contains
  multiple functions.
- AppDelegate auto-detection: a four-tier resolver covering Swift-mangled,
  Swift-variant, Objective-C, and SwiftUI-declared application entry points, working
  directly from the symbol table.
- Re-signing: ad-hoc `codesign -s -` with empty entitlements to satisfy AMFI for
  Simulator launch.

### Decryption

Crypt-region decryption happens implicitly during Simulator launch. The injected
`darkmach-decrypt.dylib` reads decrypted pages back from its own process memory once
the kernel has paged them in, captures them to a snapshot under
`output/.cache/crypt/<bundle-id>.bin`, and from those bytes the toolkit reconstructs a
fully decrypted Mach-O bundle for downstream static and dynamic work.

### DYLD-Injected Instrumentation

Twelve compiled dylibs ship in the wheel under `src/darkmach/dylibs/build/` and are
injected at Simulator launch via `DYLD_INSERT_LIBRARIES`:

| Layer | Dylib | Purpose |
|-------|-------|---------|
| Bridge | `darkmach-bridge` | UDS server, command dispatcher, response formatter |
| Interceptors | `darkmach-net` | NSURLSession / CFNetwork interception |
| Interceptors | `darkmach-crypto` | CommonCrypto encryption / hashing capture |
| Interceptors | `darkmach-db` | SQLite query capture |
| Interceptors | `darkmach-keychain` | `SecItem*` call capture |
| Interceptors | `darkmach-tls` | TLS / SSL connection capture |
| Interceptors | `darkmach-storage` | NSUserDefaults and filesystem operation capture |
| Interceptors | `darkmach-ssl` | SSL certificate pinning bypass |
| Stealth | `darkmach-stealth` | Jailbreak / debugger / hook check evasion |
| Compat | `darkmach-metal-fix` | Metal GPU framework compatibility shim for the Simulator |
| Compat | `darkmach-decrypt` | FairPlay crypt-region capture |
| Compat | `darkmach-survival` | App-specific compatibility kit, promoted from real-app validation |

Interceptors use `DYLD_INTERPOSE`-based C function hooks; the bridge uses Objective-C
method swizzling. All twelve cooperate inside a single injected process. The bridge
owns the runtime control plane, while interceptors generate continuous tap streams
that the operator subscribes to over the same socket.

### Runtime Bridge

A single Unix-domain socket at `/tmp/darkmach-bridge.sock` carries JSON-lines requests
and responses between the operator and the injected dylib. Sixty commands are exposed
across nine modules (full request / response schemas in `docs/bridge.md`):

| Module | Count | Commands |
|--------|------:|----------|
| Core | 1 | `info` |
| Recon | 22 | `enumerate_classes`, `get_methods`, `get_properties`, `get_ivars`, `read_property`, `call_method`, `heap_search`, `heap_dump`, `read_memory`, `memory_scan`, `env_dump`, `fs_scan`, `db_dump`, `db_query`, `db_queries`, `keychain_dump`, `userdefaults_dump`, `cookies_dump`, `entitlement_scan`, `shared_container_scan`, `sdk_map`, `sdk_keys` |
| Network | 6 | `net_tap`, `net_filter`, `crypto_tap`, `crypto_keys`, `auth_tap`, `auth_tokens` |
| Trace | 7 | `hook_method`, `unhook_method`, `trace`, `trace_class`, `trace_log`, `trace_verbose`, `untrace` |
| UI | 6 | `view_hierarchy`, `ui_tap`, `ui_type`, `ui_scroll`, `ui_back`, `ui_alert_dismiss` |
| Analysis | 8 | `webview_list`, `webview_eval`, `webview_content`, `webview_bridge_map`, `block_inspect`, `block_invoke`, `proto_decode`, `proto_schema` |
| Forensics | 7 | `mem_forensics`, `mem_snapshot`, `mem_diff`, `pin_analyze`, `pin_extract`, `timing_probe`, `timing_compare` |
| Injection | 3 | `inject_class`, `inject_method`, `replace_delegate` |
| Events | 1 | `event_tap` |

Notable elements:

- `sdk_map` autonomously fingerprints embedded SDKs at runtime by class-prefix
  signature -- in validation against a Unity-based game it identified Fullstory,
  Optimizely, Mintegral, and Pangle without any operator prompting.
- `auth_tap` captures JWTs and bearer tokens from network response headers and bodies
  with no configuration.
- `trace` uses a 26-instruction ARM64 trampoline with a 200-byte context save --
  substantially smaller than the equivalent in comparable instrumentation frameworks --
  and decodes Objective-C type-encoded arguments into structured JSON.
- `mem_forensics` walks malloc zones and validates isa pointers against the live class
  list to surface live ObjC instances by class.

## Architectural Distinctives

- **No jailbreak.** Runs on a stock Apple Silicon Mac with only the developer
  toolchain.
- **No SIP bypass.** The technique uses Apple's own kernel decryption path through a
  documented platform side-effect; nothing on the host's protected state is touched.
- **Native arm64 execution.** Decrypted iOS code runs through the Simulator on Apple
  Silicon at native speed -- not emulated, not translated.
- **Hand-built, minimal-dependency.** Python standard library plus host tools
  (`otool`, `vtool`, `codesign`, `plutil`, `lipo`, `simctl`) plus `clang` for C. No
  LIEF, no Frida runtime dependency, no heavyweight framework.
- **Operator-driven by default.** Every stage is a callable subcommand; the bridge is
  an interactive REPL. Automation layers on top, not underneath.
- **Test-covered.** Approximately 580 pytest tests cover Mach-O patching, shellcode
  generation, static-analysis extractors, the bridge protocol, AppDelegate detection,
  DYLD interpose safety, and path resolution.

## Validation

The pipeline has been exercised end-to-end against approximately fifteen real iOS
apps delivered through the Mac App Store and the iOS channel. Two representative
runs:

- **Grok-X (xAI)** -- end-to-end validation that drove the promotion of the Strategy A
  survival kit (`darkmach-survival.dylib`) and the ObjC metadata patch
  (`patch-objc-metadata.py`) into the core toolkit.
- **Blackjack (Tripledot Studios)** -- a short independent research engagement that
  produced sixty catalogued findings, including server-pushed game-outcome rigging
  with the exact probability table extracted in plain JSON, an explicit click-injection
  primitive shipped in a major ad SDK, an IDFA-mock class shipped in production by a
  second ad SDK, and a fully decoded on-device ML CPM-floor model with feature schema.

## Where Darkmach Fits

| Approach | Requires | Static reach | Runtime reach |
|----------|----------|--------------|---------------|
| Frida / objection / Needle / r2frida | Jailbroken iOS device | Limited by what the device exposes | Full -- but only on jailbroken targets |
| MobSF / iMAS / static-only IPA scanners | None | Encrypted binary blocks deep static; a decrypted IPA from a gray-market source is required for full reach | None |
| Darkmach | Apple Silicon Mac, developer toolchain | Full decrypted bundle for any App-Store-deliverable iOS app | Full -- ObjC introspection, method tracing, network / crypto / auth capture, sandbox state extraction |

The differentiator is the no-jailbreak path to a decrypted-and-runnable bundle. Frida
on the Simulator with the decrypted real-app binary -- the workflow Darkmach makes
routine -- is the gap the toolkit occupies.

---

*Entry point: `darkmach` CLI. Installation: `pipx install darkmach-re`. Pre-flight:
`darkmach status`. End-to-end: `darkmach run <bundle-id>`. Test suite: `pytest tests/`.*
