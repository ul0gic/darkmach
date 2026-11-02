# Research methodology and reproduction

A Darkmach result should show which input was transformed, what changed, which application paths executed, and which observations support the conclusion. This protocol separates acquisition, extraction, reconstruction and instrumentation so a failure in one stage cannot masquerade as success in another.

Status: reproduction protocol; current-host main-region extraction observed on two targets · Updated: 2026-11-02

## Choose the experiment

| Experiment | Input | Result it can establish |
|---|---|---|
| Build and parser validation | Source checkout and existing automated fixtures | The selected compiler and Python environment accept the implementation and its tested contracts. |
| Instrumentation control | A self-built, unencrypted Simulator app with known behavior | Injection, bridge and exercised hooks work without involving FairPlay. |
| Patched-app compatibility | An already reconstructed app | Installation, launch and selected observations work on the current runtime. |
| Fresh extraction | An original Mac-delivered encrypted app and empty cache | The extraction path can recover a region on the recorded host and target. |
| Full pipeline validation | Fresh extraction followed by reconstruction and an exercised app path | The stages work together for that exact target and environment. |

A self-built app is the best control for instrumentation because its expected network, crypto and database operations can be known in advance. It is not a substitute for the encrypted input in an extraction experiment.

## Record the environment and isolate the run

Record the source commit, Mac architecture, macOS version and build, SIP state, Xcode version and build, selected developer directory, SDK, Simulator runtime version and build, and device UDID. SDK and runtime versions are different inputs: the current local check used SDK 27.2 and runtime 27.0.

Use a dedicated research Simulator and pass its UUID through `--udid` to `run`, `patch`, `launch`, `status` and `bridge`. Automatic selection requires exactly one booted device, or, for commands that boot a device, exactly one available iPhone when none is booted. Ambiguous selection fails; do not use `booted` to identify a leased research device.

Set `DARKMACH_OUTPUT` to a new run directory before invoking the tool so extraction begins without a matching cache. This host-side output-root setting is distinct from `DARKMACH_OUTPUT_DIR`, which the launcher passes into the injected process for JSONL logs.

The default runtime endpoint is `/tmp/darkmach-bridge-<UUID>.sock`. Use a distinct absolute `--socket` for another target on the same device, and connect with that same endpoint. Live endpoints are not replaced. Extraction uses a unique temporary workspace. Keep a single operator per target and output directory; these changes do not isolate concurrent writes to the same app's evidence directory.

## Preserve and identify the input

Record the acquisition channel, app version, bundle identifier, main executable name, file hashes and relevant Mach-O metadata. Preserve the installed original and perform transformations on a copy. `run` copies its input; `patch` copies paths under `/Applications` but modifies other input paths in place.

Capture the main executable's original platform command and encryption geometry, and inventory encrypted embedded frameworks. This distinguishes a main-only extraction case from a layout that selects Strategy A. An encryption flag describes the image's declared state; the before-and-after byte comparison and execution checks establish what was recovered.

The supported acquisition workflow is the Mac App Store installation path. A downloadable iOS-channel IPA is not equivalent input merely because it has the same bundle ID or architecture.

## Validate extraction separately

Follow the [patching guide](../patching.md) and preserve the following observations in order:

1. The original main executable has a nonzero marked range, and no matching cached dump exists in the run directory.
2. The temporary copy has Simulator platform metadata and the original crypt geometry restored with `cryptid=1` before spawning.
3. A new dump appears during this run, has the expected size, and has a recorded hash and timestamp.
4. The recovered range is compared with the original file bytes and inspected for coherent instructions, references and control flow.
5. The final copy contains the recovered bytes at the original offset, has cleared encryption metadata, and passes signature checks.
6. An exercised application path depends on the reconstructed code and reaches an observable result.

The cache checks the input main-executable SHA-256, region geometry, recovered length and recovered-byte SHA-256. A verified cache hit is reuse, not fresh extraction. Receipts under `<output>/<app>/runs/` retain reached stages, cache and entitlement results, device/socket/PID and terminal outcome. They do not prove UI functionality or capture coverage. Preserve stdout and stderr alongside the receipt; signing or compatible-entitlement preservation failures stop patching before installation.

Do not fabricate a negative control by changing encryption metadata on arbitrary data and treating the resulting crash as a FairPlay finding. Use a known unencrypted app to test the instrumentation path, and use an independently prepared header-only copy if comparing reconstruction with metadata changes alone.

## Validate capture against known behavior

Start with bridge `info` and verify the expected bundle and process. Query a tap's `capturing` state before interpreting its count. That state indicates the recorder reports an installed source; it does not prove all API variants are observed.

Exercise one known operation at a time, then compare the raw bridge reply with the corresponding interceptor JSONL over the same time window. Bridge rings have bounded previews and may evict records; continuous logs have their own formatting and size constraints. A formatter is a presentation layer, so inspect raw JSON when a displayed count is unexpected.

For networking, distinguish an attempted request from a completed HTTP exchange. Record status, error, elapsed time, headers and body together. Historical local testing found DNS blocking could produce real outbound requests with no successful response; this was an environment failure, not a missing request hook.

For crypto, an observed hash call is not evidence that encryption or key capture works. For SQLite, a prepared statement, a returned row and a complete database inventory are distinct observations. For app access, reaching a sign-in or attestation gate does not establish that protected application behavior was exercised.

Top-level handler errors now return `ok: false`; oversized or invalid native replies return a bounded failure. A successful command still proves only its stated operation. In particular, `ui_tap` reports target/action dispatch, not physical touch delivery or focus, and entitlement readback does not establish every Apple capability.

## Evidence record

Keep one record per target, environment and run. Use a target alias in a public export when the application identity or underlying records cannot be shared.

| Field | Required content |
|---|---|
| Identity | Date, experiment type, source commit, app version and input hashes |
| Environment | Host, developer tools, SDK, runtime, architecture, SIP state and explicit device identity |
| Input | Acquisition channel, platform metadata, encryption ranges and original signature/entitlement inventory |
| Transformations | Strategy, metadata changes, entitlement keep/drop result and reconstructed hashes |
| Execution | Stage commands or API calls, exit results, warnings, process identity and observed app state |
| Capture | Raw replies, timestamped JSONL, expected operations, observed operations and errors |
| Conclusion | Precisely supported claim, unsupported paths, controls and reproducibility limits |

A summary exported from a private run should say which raw records are withheld. Hashes identify retained records but do not make unavailable artifacts independently inspectable. Do not redistribute third-party app binaries, captured credentials or user data as a teaching fixture.

## Teaching sequence

1. Inspect an original Mach-O's platform and encryption commands; predict the effect of changing metadata without changing bytes.
2. Walk the three image states in [two-pass extraction](fairplay-bypass.md#binary-state-transitions) and explain why the temporary and final headers differ.
3. Follow the small extraction constructor in source; distinguish self-memory access from debugger attachment.
4. Use a self-built app with one known SQLite, hash and network operation to establish expected capture.
5. Compare a bridge ring with the continuous JSONL and explain why an empty result cannot establish absence of behavior.
6. Read a partial case in [findings](findings.md), then state what additional experiment would support a stronger claim.

This sequence teaches both the mechanism and how to evaluate an instrument's output.
