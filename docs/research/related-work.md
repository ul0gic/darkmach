# Related work and technical sources

Darkmach combines platform adaptation, system-managed extraction and native instrumentation. The sources below explain the surrounding mechanisms and existing alternatives; they do not establish that Darkmach is the first implementation of this workflow.

Status: initial source review · Updated: 2026-11-02

## Apple platform and loader sources

| Source | Relevance | Boundary |
|---|---|---|
| [Apple: Running your iOS apps in macOS](https://developer.apple.com/documentation/apple-silicon/running-your-ios-apps-in-macos) | Describes unmodified iPhone and iPad applications running on Apple Silicon Macs. | iOS Apps on Mac is distinct from the Simulator execution environment Darkmach prepares. |
| [Apple: App availability on Macs with Apple silicon](https://developer.apple.com/help/app-store-connect/manage-your-apps-availability/manage-availability-of-iphone-and-ipad-apps-on-macs-with-apple-silicon) | Describes developer-controlled availability through the Mac App Store. | Availability is an input constraint, not a capability Darkmach overrides. |
| [XNU: Mach-O loader headers](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h) | Defines platform IDs, build-version commands and encryption-range fields. | A load-command definition does not prove a transformed app will execute. |
| [XNU: Mach-O kernel loader](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_loader.c) | `set_code_unprotect()` selects decryption behavior, prepares a decrypter and establishes a protected mapping. | Published source supports the mechanism's interpretation; a matching installed-kernel trace is needed to establish the exact path in a particular run. |
| [dyld: Process configuration](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp) | Separates policy for environment variables, library insertion and interposing. | Loader policy is conditional; broad claims that Simulator injection ignores every host protection are unwarranted. |

The links point to upstream reference trees as reviewed on 2026-11-02. A version-specific research release should pin the source revisions it analyzes and explain their relationship to the measured OS build.

## Existing instrumentation workflows

[Frida's iOS documentation](https://frida.re/docs/ios/) describes both jailbroken-device operation and instrumentation of debuggable apps without a jailbreak. [Frida Gadget](https://frida.re/docs/gadget/) provides an embedded instrumentation mode with code-signing-dependent capabilities. Those workflows make “Frida requires a jailbreak” an inaccurate comparison.

[OWASP MASTG's non-jailbroken-device technique](https://mas.owasp.org/MASTG/techniques/ios/MASTG-TECH-0146/) describes repackaging an unencrypted app with an instrumentation library, and distinguishes Simulator experiments from physical-device behavior. Darkmach's local attach restrictions motivated its custom injection path; they are not a general statement about what Frida can do on every Simulator or host configuration.

| Workflow | Research strength | What Darkmach addresses alongside it |
|---|---|---|
| Self-built Simulator app | Known source and expected behavior; straightforward instrumentation control. | Testing a transformed Mac-delivered app introduces acquisition, encryption and compatibility questions absent from the control. |
| Frida with a debuggable or repackaged app | Flexible instrumentation across supported environments. | Darkmach provides a specific extraction/transformation pipeline and cooperating native capture/bridge implementation. |
| Jailbroken physical device | Device behavior and broader process access in a suitable test environment. | Darkmach offers a Mac-hosted workflow for selected apps without requiring that device setup. |
| Static inspection | Reproducible inspection of artifacts without exercising a live app. | Recovered code and runtime observations can provide additional evidence, while static and dynamic coverage remain distinct. |

## Priority and attribution

This initial source review covers authoritative platform material and major instrumentation workflows. It is not an exhaustive survey of historical device-to-Simulator conversion, Mac-hosted FairPlay extraction, binary retargeting or academic work on these topics. No priority claim follows from it.

Before making a novelty claim, build a dated bibliography of those lines of work, compare the precise prerequisites and state transitions, and identify the specific contribution that remains. Credit component techniques separately from the integration implemented here.
