# Capabilities and limitations

## Supported workflow

Darkmach starts with an iOS app delivered through the Mac App Store to an Apple Silicon Mac. It copies and adapts the bundle for an iOS Simulator, then launches the reconstructed process with native instrumentation. Input layout, host/runtime compatibility and required app services affect the result.

An already reconstructed bundle is useful for instrumentation; it does not exercise fresh extraction. A self-built unencrypted Simulator app can provide known behavior for checking capture paths. Arbitrary iOS-only IPAs, physical-device operation and Intel Macs are outside this workflow.

## Coverage boundaries

| Area | Boundary | Practical consequence |
|---|---|---|
| Main-region recovery | The extract branch recovers the main executable's marked region, not every encrypted image recursively | Inspect frameworks and bundle layout separately |
| Address translation | The reader uses mapped-header address plus file offset | Arbitrary segment layouts and FAT containers require separate handling |
| Strategy selection | Encrypted binaries under the main Frameworks directory select the experimental branch | Layout selection does not establish decryptability or original app-code execution |
| Objective-C inspection | Pure Swift and IL2CPP logic is not a complete ObjC object model | Class inventories and traces cover only the reachable runtime surface |
| Network and other capture | Hooks observe selected API variants | Another transport or an unexercised hook can produce no records |
| Hermes analysis | Fallback string extraction can combine distinct bytecode strings | Treat URLs and credential matches as candidates requiring independent checks |
| Heap enumeration | Output limits do not bound all allocator traversal; the handler has no native deadline | Prefer bounded singleton lookup where applicable; client timeout does not cancel native work |
| UI tap | `ui_tap` dispatches target actions | An acknowledgement does not establish physical touch delivery, focus or the intended app state |
| Entitlements | Encoded values and selected OS readback are separate from actual service operations | Check capability-dependent behavior directly |
| Simulator services | Device services, attestation and hardware-backed behavior can differ | Simulator observations do not establish physical-device behavior |

## Interpret each result narrowly

- A verified crypt-cache hit is reuse, not a fresh extraction.
- A completed run confirms its reached stages and bridge identity, not authenticated workflows or complete application usability.
- Recorder readiness does not establish that an operation occurred or every API variant is captured.
- A zero count can mean no event, a different API path or eviction from a bounded ring.
- Runtime logs append across launches; use process identity and an observation window when reading them.

The [walkthrough](walkthrough.md) shows the checkpoints and artifacts. The [platform guide](platform-architecture.md) and [recovery sequence](how-it-works.md) explain the underlying distinctions.
