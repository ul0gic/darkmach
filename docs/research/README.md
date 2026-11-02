# Darkmach research manifest

Darkmach studies the path from a Mac App Store iOS installation to an instrumented iOS Simulator process on Apple Silicon. The research connects binary metadata, system-managed decryption, Simulator compatibility, and observable runtime behavior.

Status: publication draft · Updated: 2026-11-02

## Research question

Under what conditions can an iOS app delivered to an Apple Silicon Mac be copied, adapted for the Simulator, and inspected at runtime without a jailbroken device or disabling SIP?

Darkmach implements one workflow for investigating that question. Historical local runs recovered readable code from marked encryption regions and launched the reconstructed applications. Current checks confirm that an existing reconstructed application still launches with the default instrumentation on iOS 27.0. Fresh extraction on the current host remains an open validation task.

## Reading paths

| Reader's goal | Start here | Continue with |
|---|---|---|
| Understand the technical contribution | [Two-pass extraction](fairplay-bypass.md) | [Related work](related-work.md) |
| Reproduce or challenge a result | [Methodology](methodology.md) | [Validation and findings](findings.md) |
| Teach the mechanism | [Two-pass extraction](fairplay-bypass.md) | [Teaching sequence](methodology.md#teaching-sequence) |
| Use the toolkit | [Installation](../installation.md) | [CLI reference](../cli-reference.md), [bridge reference](../bridge.md) |
| Prepare a public release | [Publication plan](publication.md) | [Evidence requirements](methodology.md#evidence-record) |

## Claim register

The status applies to the stated scope. Implementation establishes what the tool attempts; a runtime observation establishes what happened in that particular run.

| ID | Claim | Evidence and scope |
|---|---|---|
| R1 | Platform rewriting and plaintext recovery are separate operations. | [Implementation analysis](fairplay-bypass.md#binary-state-transitions); clearing encryption metadata does not transform the region's bytes. |
| R2 | The extract path temporarily restores the original encryption metadata, spawns the binary with a self-reading dylib, then reconstructs a separate runnable copy. | Source-confirmed in `stage_patch()` and `_extract_crypt_region()`; [mechanism](fairplay-bypass.md#extraction-and-reconstruction). |
| R3 | Local historical runs recovered code and launched applications through this path. | Three structured cases dated 2026-08-01, summarized in [findings](findings.md#historical-validation). These are maintainer records; a public raw reproduction package is still needed. |
| R4 | An existing patched SwiftUI application launches with the eight default, rebuilt dylibs on iOS 27.0. | Local check dated 2026-11-02: live UI, bridge replies, SQLite capture, trust observations and four visible app entitlements; [derived evidence](evidence/2026-11-02-compatibility.json). |
| R5 | Fresh main-region recovery was observed on two Mac-delivered encrypted apps on macOS 27.0.1 with Xcode 27.2. | [CLI assessment and operator hardening](findings.md#current-cli-assessment-and-operator-hardening): two 4,096-byte regions matched reconstructed copies and differed from encrypted originals. Raw target artifacts remain private; broader encrypted-image coverage is unverified. |
| R6 | System-managed page decryption explains the historical extraction results. | Working interpretation consistent with the temporary header state and [XNU's loader source](related-work.md#apple-platform-and-loader-sources). An exact build-matched kernel and service call chain has not been established. |
| R7 | Runtime observations cover only the exercised hooks and application paths. | [Coverage limits](findings.md#known-research-limitations): pure Swift, IL2CPP, Hermes extraction, swizzle interactions and device-backed services constrain reach. |

## Scope of the contribution

The useful contribution is the integration of bundle transformation, a two-pass extraction path, cooperating native interceptors, and a queryable runtime bridge. The source exposes the details needed to inspect and challenge each stage.

This record does not establish priority over all prior research, universal App Store compatibility, or invisible instrumentation. [Related work](related-work.md) places the workflow beside existing platform and instrumentation techniques without treating those techniques as unavailable.

## Source map

| Research topic | Implementation |
|---|---|
| Command orchestration | [`commands.py`](../../src/commands.py) |
| Extraction, patching, signing and Simulator operations | [`pipeline/`](../../src/pipeline/) |
| Mach-O platform and encryption metadata changes | [`surgical.py`](../../src/patch/surgical.py) |
| Reading the mapped crypt region | [`darkmach-decrypt.c`](../../src/dylibs/compat/darkmach-decrypt.c) |
| Experimental entry-point replacement | [`main_patch.py`](../../src/patch/main_patch.py), [`objc_metadata.py`](../../src/patch/objc_metadata.py) |
| Bridge protocol and command registration | [`darkmach-bridge.c`](../../src/dylibs/bridge/darkmach-bridge.c) |
| Function interception and method swizzling | [`interceptors`](../../src/dylibs/interceptors), [`darkmach-core.h`](../../src/dylibs/darkmach-core.h) |

## Open research questions

- Does fresh extraction reproduce on the current host with an empty cache and a recorded original binary hash?
- Which distribution, account, host and bundle conditions determine extraction success?
- Which exact kernel and service paths participate on each tested OS build?
- Which binary layouts invalidate the extractor's current file-offset-to-memory-address assumption?
- How does instrumentation change the behavior being measured, especially when multiple mechanisms touch the same method?

These questions define the next experiments. They are separate from whether an existing patched app can launch.
