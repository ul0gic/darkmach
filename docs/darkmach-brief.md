# Command and capability map

Darkmach combines Mac-compatible iOS app discovery, bundle inspection, Simulator reconstruction and native runtime instrumentation for iOS app security testing on Apple Silicon.

## The workflow

App Store discovery → manual installation → preserved working copy → temporary crypt-region recovery → reconstructed/signed Simulator bundle → native instrumentation → bridge and JSONL evidence.

The [walkthrough](walkthrough.md) covers the operator checkpoints. [Platform architecture](platform-architecture.md) explains why the temporary and final images differ; [Darkmach architecture](architecture.md) maps that model to the implementation.

## Interfaces

| Task | Interface | Boundary |
|---|---|---|
| Locate inputs | `list`, `discover` | Local wrappers versus remote App Store availability; neither downloads the input |
| Static analysis | `analyze`, `hermes` | Strings/metadata and candidates; Hermes fallback has a known boundary defect |
| Full workflow | `run` | Copy, inspect, reconstruct, install, launch and check bridge identity |
| Prepare only | `patch` | Final app is not installed/launched; encrypted input can spawn an extraction process |
| Relaunch | `launch` | Existing installed reconstructed target; not fresh extraction |
| Runtime inspection | `bridge` | In-process ObjC/query/capture/UI operations with command-specific limits |
| Host inspection | `keychain`, `status` | Selected Simulator database snapshot or host/tool/file checks |

The default final launch set has eight components: metal-fix, net, keychain, crypto, storage, ssl, db and bridge. Decrypt, TLS, survival and stealth have separate roles. [Interceptors](interceptors.md) names hooked APIs; [CLI](cli-reference.md) and [bridge](bridge.md) document exact options and results.

## Coverage

ObjC inspection does not expose all Swift/IL2CPP logic; selected hooks do not establish universal capture. Entitlement readback is not proof of every capability operation. UI target/action dispatch does not establish physical touch/focus. General `heap_dump` work is not bounded by returned-row limits. Cache reuse, application readiness and capture correctness remain separate evidence questions.

[How it works](how-it-works.md) explains the recovery sequence; the [walkthrough](walkthrough.md) shows the operator checkpoints.
