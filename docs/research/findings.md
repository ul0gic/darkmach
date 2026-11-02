# Validation results and research findings

The recorded results establish useful extraction and instrumentation behavior on particular applications, with distinct limits for each stage. Historical extraction, current compatibility and detector accuracy are tracked separately.

Status: maintainer validation summary; independent full reproduction pending · Updated: 2026-11-02

## Evidence provenance

The historical cases below summarize structured local testing records dated 2026-08-01. The retained records are not a public, independently reproducible artifact package, and do not consistently record every host and runtime build. The earlier estimate of roughly fifteen tested apps has no complete structured inventory and is not used as a compatibility denominator here.

Application names and captured credentials are omitted from these cases. The results concern Darkmach's behavior; they are not vulnerability disclosures about the tested vendors.

## Historical validation

| Case | Extraction and execution | Instrumentation observations | Material limits |
|---|---|---|---|
| SwiftUI app with statically linked Swift | Recovered a 4,096-byte main-executable region at file offset `0x20000`; reconstructed app reached its sign-in UI. | Runtime bridge; app-owned ObjC classes; selected keychain, SDK and entitlement observations. | ObjC introspection reaches a small part of a predominantly Swift application; full host-build metadata and public raw artifact package remain unavailable. |
| Unity game with IL2CPP and embedded frameworks | Local record reports two-pass recovery and launch to a playable game. | Network, crypto, SQLite, auth, event and trace rings had recorded activity. | Primary game logic sits in UnityFramework; default static analysis of the small main executable does not cover it. IL2CPP logic is not exposed as an ObjC application model. |
| React Native app using Hermes | Recovered a 4,096-byte region at `0x40000`; patched and launched with bridge access. | Local record reports 23 HTTP exchanges, 448 SQLite statements and activity in the crypto and auth paths. | An attestation gate prevented access to the application's own backend; Hermes static extraction produced invalid combined strings. |

These cases show that runtime access and useful capture can coexist with incomplete static analysis or inaccessible application behavior. A successful launch is one stage of validation.

## Earlier patched-app compatibility check

The 2026-11-02 check used source revision `587a6e7`, macOS 27.0.1 build `26A434`, Xcode 27.2 build `27B52`, iOS Simulator SDK 27.2 and iOS runtime 27.0 build `24A434`. SIP was enabled.

| Check | Observation |
|---|---|
| Existing automated suite | 699 tests passed outside the agent sandbox. |
| Python lint | Ruff passed. |
| Forced native rebuild | All twelve dylibs and the host utility compiled; all twelve dylib signatures passed strict verification. |
| Simulator installation and launch | An existing patched SwiftUI app, version 1.0.3 build 7, installed and launched on a dedicated test device. |
| Launch path | Existing Python `stage_launch()` API, explicit device UDID, eight default dylibs and an isolated log directory; not a fresh `darkmach run` execution. |
| User interface | Sign-in screen observed through screenshot and accessibility snapshot. |
| Bridge | `info`, class enumeration, view hierarchy, network tap, crypto tap, SQLite queries, trust analysis and entitlement scan replied. |
| Class enumeration | 84,541 registered classes; 29 matched the application filter. |
| SQLite and trust | Query snapshot contained 23 captured statements and 2 captured trust evaluations. |
| Entitlements | Four app entitlements visible in the runtime scan. |
| Network and crypto | Recorders reported `capturing: true` with zero entries at the early query snapshot; later JSONL contained hash events. This does not establish completed network exchange or encryption/key capture coverage. |
| Fresh extraction | Not performed: no original encrypted target was installed. |

The [derived compatibility evidence](evidence/2026-11-02-compatibility.json) contains selected fields from the bridge replies and aggregate JSONL information. Raw application capture is retained privately. Sandbox denial of Unix sockets and CoreSimulator access was resolved by rerunning with access; it is not an Apple regression.

## Current CLI assessment and operator hardening

Subsequent work used the direct-src baseline `c6420fc` and local, uncommitted operator-hardening changes on the same host/toolchain/runtime versions. The assessment exercised the actual Darkmach CLI against original Mac App Store MaintainX 5.46 and ClickMaint 1.25 bundles. Both main executables marked a 4,096-byte crypt region at offset `0x5000`. Fresh recovered dumps matched reconstructed regions and differed from the encrypted originals; original main-executable SHA-256 values remained unchanged. These measurements cover the marked main regions, not every image or a whole-bundle integrity inventory.

ClickMaint reached sign-in. MaintainX initially remained on a blue splash screen after otherwise successful extraction and bridge connection; its compatible entitlement payload did not fit the original XML insertion path. Operator hardening preserves that four-key dictionary as binary plist, and independent process SecTask readback matched the original compatible values. A three-key XML ClickMaint control also matched. The updated MaintainX run reached its onboarding screen with Sign Up and Log In. This improves observed initial UI compatibility; it does not isolate entitlement loss as the sole earlier cause or validate authenticated application behavior.

Current changes add explicit device/socket selection, source/geometry/hash-bound cache receipts, per-invocation stage records, bounded native failures, typed zero-argument inspection and qualified UI action reporting. Raw target binaries, screenshots, replies and captures are retained privately rather than shipped as a public reproduction package. These observations do not establish universal Apple capability grants, complete hook coverage or physical-device fidelity.

## Research findings

### Reconstruction needs bytes as well as metadata

Platform and encryption-header changes are necessary transformations on the supported path, but clearing a marker does not recover code. The temporary extraction image and the final runnable image have different jobs and different encryption metadata. This distinction is central to [the mechanism](fairplay-bypass.md).

### Instrumentation needs an observable writer

Historical validation found bridge rings returning empty results even though a corresponding interceptor logged real events. The implemented correction lets the interceptor that owns a hook call an exported recorder in the bridge. A ring's existence is not proof that a hook writes to it; controlled events and a log cross-check are stronger evidence.

### Environment and access gates shape the result

Historical network tests encountered DNS blocking that prevented real HTTP responses. A separate React Native test reached an attestation gate and observed SDK traffic without reaching the app's own backend. Both produced useful observations, but neither supports a conclusion about unexercised protected behavior.

## Known research limitations

| Area | Current limitation | Consequence for a result |
|---|---|---|
| Extraction cache | Source/region-addressed entries verify recovered-byte hashes; legacy entries are ignored. | A verified cache hit still cannot establish fresh extraction. |
| Strategy selection | Encrypted frameworks beneath the main `Frameworks/` path select Strategy A. | Selection is a layout heuristic, not proof of acquisition channel or decryptability. |
| Extraction address | Reader uses mapped-header address plus file offset. | Layouts outside the tested text mapping need separate validation. |
| Swift and IL2CPP | ObjC runtime access does not cover all native application logic. | Class counts and method traces are not complete program coverage. |
| Hermes strings | Current fallback extraction can join distinct bytecode strings and fabricate candidate URLs or credentials. | Do not use its candidate output as research evidence without independent boundary-aware validation. |
| Static analysis of Unity | Default analysis focuses on the main executable. | Inspect the application framework separately when it contains the actual logic. |
| Method tracing | Selectors already swizzled by an interceptor had a recorded tracing blind spot. | An empty trace does not prove the selector was unused. |
| Heap enumeration | `heap_dump` limits returned rows, while zone traversal has no native deadline; a MaintainX CLI batch ending in `heap_dump limit=1` exceeded its 70-second budget without retained partial output. | This is not an isolated command timing or deadlock diagnosis. Client timeout does not cancel native work; complete inventory and general scan latency remain unverified. |
| Bridge success fields | Top-level errors and over-limit replies now return valid failures. | Success still describes only the command-specific operation. |
| Capture attribution | Launch resolves the installed app name for its dynamic sink; run receipts record session identity. | Log files append; verify the actual sink, process and observation window. |
| Parallel sessions | Device-specific or explicit bridge sockets and unique extraction workspaces reduce collisions. | The same target/output directory still requires one operator; these are not isolated concurrent evidence stores. |
| Physical-device fidelity | Simulator services differ from device services; attestation may block application access. | Findings about hardware-backed or protected flows require appropriate device validation. |
| Clean source build | Makefile does not create a missing dylib output directory. | Create that directory before building a clean checkout; current warm-tree rebuild success does not cover this setup step. |

The current record supports a useful, inspectable research workflow with bounded coverage. A public release should include a fresh extraction record and a self-built capture control so other researchers can test both halves independently.
