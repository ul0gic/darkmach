![Platform](https://img.shields.io/badge/platform-Apple%20Silicon-black)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

# Darkmach

Operator-driven iOS reverse engineering toolkit for Apple Silicon. Darkmach adapts selected iOS apps installed through the Mac App Store into Simulator research targets, using bundle patching, a two-pass crypt-region extraction path and DYLD-injected native instrumentation.

The workflow runs on a developer Mac without disabling SIP or requiring a jailbroken device. Supported inputs and tested environments matter: it is not a general decrypter for arbitrary IPAs.

## Research

The [research manifest](docs/research/README.md) connects the technical question to implementation, evidence and open questions.

- [How two-pass extraction works](docs/research/fairplay-bypass.md): why the temporary extraction image and final runnable image need different encryption metadata.
- [Methodology and reproduction](docs/research/methodology.md): controls, environment records, cache isolation and a teaching sequence.
- [Validation and findings](docs/research/findings.md): dated results and the limits of each observation.
- [Related work](docs/research/related-work.md): Apple loader sources and existing instrumentation workflows.

## Current validation

The 2026-11-02 assessment passed all 699 existing tests, Ruff, a forced rebuild of all twelve dylibs, and signature verification. Fresh main-region extraction was observed on MaintainX and ClickMaint on iOS 27.0 under macOS 27.0.1 and Xcode 27.2; reconstructed regions matched the recovered bytes and differed from the encrypted originals. Original main-executable hashes were unchanged.

Subsequent operator hardening added explicit device/socket selection, verified cache identity, stage receipts and intact compatible-entitlement preservation. MaintainX now reaches onboarding; ClickMaint reached sign-in in the assessment. These observations do not validate authenticated workflows or every encrypted image. Dated results and remaining limits are in the [validation record](docs/research/findings.md); raw third-party evidence remains private.

## Quick start

Use an Apple Silicon Mac, Python 3.11 or newer, full Xcode and an installed iOS Simulator runtime. Command Line Tools alone do not include the required Simulator environment.

For a source checkout, create `src/dylibs/build/` before running `make`; the current Makefile does not create a missing output directory. Install the Python package with `pip install -e .`, then build with `make` and check the environment with `darkmach status`. See [installation](docs/installation.md) for the complete setup.

Use `darkmach list` to find locally installed iOS apps and `darkmach run /Applications/SomeApp.app` for the full pipeline. Connect with `darkmach bridge` after the instrumented target is running.

Use `--udid` to select a dedicated research Simulator. Runtime commands default to a device-specific bridge socket; `--socket` selects a separate endpoint when needed. Ambiguous automatic device selection fails before app mutation. See the [methodology](docs/research/methodology.md#record-the-environment-and-isolate-the-run) for isolation and evidence handling.

## CLI

| Command | Purpose |
|---|---|
| `darkmach run <app>` | Copy, analyze, patch/extract, install, launch and connect to the bridge |
| `darkmach analyze <app>` | Static inspection of a bundle |
| `darkmach patch <app>` | Prepare a Simulator bundle, including extraction when applicable |
| `darkmach launch <bundle-id>` | Relaunch an installed target with the default eight dylibs |
| `darkmach bridge` | Interactive runtime bridge client |
| `darkmach discover [search]` | Discover iOS apps available on Mac |
| `darkmach hermes <app>` | Experimental Hermes inspection; candidate findings require independent validation |
| `darkmach keychain` | Read the selected Simulator keychain from the host |
| `darkmach list` | List installed iOS app bundles |
| `darkmach status` | Check the host environment and expected files |

Use `darkmach --help` or `darkmach <command> --help` for parser usage. The [CLI reference](docs/cli-reference.md) covers behavior, options and output.

## How the pieces fit

The Python package maps directly to `src/`. `cli.py` defines the command interface; `commands.py` orchestrates operations through `pipeline/`; `analysis/` owns static inspection; `bridge/` owns transport, rendering and the interactive shell; `patch/` contains importable Mach-O and entry-point tools plus stable standalone script names; `dylibs/` contains the native bridge, interceptors and compatibility components. `Makefile` builds the native outputs. `tests/` contains the existing pytest suite.

The extract path prepares a temporary copy with Simulator platform metadata and restored encryption geometry, reads its mapped crypt region through `darkmach-decrypt.dylib`, and writes the recovered bytes into a separate final copy. Clearing the encryption header alone does not recover code. [The technical article](docs/research/fairplay-bypass.md) separates the implementation from the interpretation of the system's decryption path.

The final target launches with a default set of eight dylibs. Interceptors observe selected APIs and feed bounded bridge rings alongside JSONL logs. A JSON socket supports inspection and operator queries. The [architecture guide](docs/architecture.md) maps the components and data flow.

Output defaults to `output/` under the current working directory; `DARKMACH_OUTPUT` overrides that root. Keep original bundles and run-specific evidence identified independently of a directory name, especially with the current standalone-launch attribution limitation.

## Documentation

| Document | Purpose |
|---|---|
| [Documentation index](docs/README.md) | Product and research reading paths |
| [Capability brief](docs/darkmach-brief.md) | Concise workflow and coverage summary |
| [Installation](docs/installation.md) | Setup, build and troubleshooting |
| [CLI reference](docs/cli-reference.md) | All ten subcommands |
| [Architecture](docs/architecture.md) | Source organization and component interactions |
| [Interceptors](docs/interceptors.md) | Native components and observed APIs |
| [Patching](docs/patching.md) | Binary transformations and strategy detail |
| [Runtime bridge](docs/bridge.md) | Protocol and command reference |
| [Publication plan](docs/research/publication.md) | Reproduction evidence and decisions remaining before release |

## Publication status

The research section is a local publication draft. License information needs reconciliation: package metadata declares MIT, previous documentation described the project as proprietary, and the repository has no root license file. No new license or public release is established by this documentation pass.
