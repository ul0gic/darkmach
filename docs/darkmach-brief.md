# Darkmach capability brief

Darkmach is an operator-driven research toolkit for adapting selected Mac-delivered iOS applications to the iOS Simulator on Apple Silicon. It combines static inspection, bundle transformation, a two-pass crypt-region extraction path, native runtime capture and an interactive bridge.

Updated: 2026-11-02

## Supported workflow

The acquisition workflow begins with an iOS app installed through the Mac App Store on the research Mac. The pipeline copies the bundle, inspects it, selects a patch strategy, adapts it for the Simulator, and launches it with instrumentation. Historical local tests completed extraction and execution on several such apps. The [research manifest](research/README.md) records the claims and their evidence.

On the extract path, a temporary Simulator-targeted copy retains the original encryption geometry for system-managed decryption. An injected constructor reads the mapped region. A separate work copy receives those bytes, has its encryption metadata cleared, and is re-signed. Platform rewriting alone does not decrypt code. See [two-pass extraction](research/fairplay-bypass.md).

This workflow does not provide a general acquisition or decryption route for arbitrary iOS-only IPAs. Strategy A is retained for entry-point and compatibility experiments; a loadable process reached through replacement code is not proof of recovered application logic.

## Operational surface

| Task | Interface | Behavior |
|---|---|---|
| Discovery | `darkmach discover`, `darkmach list` | Check Mac availability and enumerate locally installed iOS bundles. |
| Static inspection | `darkmach analyze <app>` | Inspect strings, credential candidates, SDK evidence, entitlements, plists and Mach-O metadata. |
| Full pipeline | `darkmach run <app>` | Copy, analyze, patch/extract, install and launch the bundle, then check the bridge. |
| Bundle transformation | `darkmach patch <app>` | Prepare a bundle without the final application installation and launch; extraction may spawn a temporary process. |
| Instrumented launch | `darkmach launch <bundle-id>` | Relaunch an already installed target with the default interceptor set. |
| Runtime inspection | `darkmach bridge` | Query the live process using the registered JSON command surface. |
| Environment check | `darkmach status` | Check architecture, tools, SDK, Simulator state and expected interceptor files. |

`run` and `patch` accept paths to app bundles, not bundle identifiers. The [CLI reference](cli-reference.md) documents all ten subcommands.

## Runtime instrumentation

The default launch set contains eight dylibs: Metal compatibility, network, keychain, crypto, storage, trust evaluation, SQLite and the bridge. The build also provides TLS, decryption, survival and stealth components for specific paths or explicit use. Building twelve dylibs does not mean all twelve are injected on a normal launch.

C function interposition and Objective-C method swizzling observe the APIs they hook. The bridge exposes class and object inspection, method tracing, UI operations, captured network/crypto/database observations, and selected analysis tools over a Unix-domain socket. Its live `info.commands` list is the authoritative command inventory.

The implementation uses the Python standard library for binary transformations, Apple's developer tools, and custom native dylibs. The package also declares a Hermes-analysis dependency. Frida is not required by this implementation; this is not a claim that other instrumentation tools require a jailbreak or cannot operate in the Simulator.

## Validation and coverage

As of 2026-11-02, all 699 existing tests pass, Ruff is clean, all twelve dylibs rebuild under Xcode 27.2, and their signatures verify. A previously reconstructed SwiftUI application launched on iOS 27.0 with the default eight dylibs, a live bridge, observed UI, SQLite records and app entitlements. Fresh FairPlay extraction was not performed on that host. See [validation and findings](research/findings.md) for the environment and derived evidence.

Coverage depends on the application and exercised path. Pure Swift and IL2CPP code are not fully represented by ObjC introspection. Hermes string extraction has a known correctness defect. Existing swizzles can affect tracing; standalone launch can misattribute output directories; device attestation can prevent access to application behavior. A recorder reporting ready with zero observations does not establish that the behavior is absent.

Darkmach's contribution is an inspectable, integrated research workflow. Its public description should stay tied to specific inputs, environments and observations rather than universal compatibility, invisible instrumentation, or unsupported priority claims.
