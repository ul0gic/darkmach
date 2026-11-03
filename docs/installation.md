# Installation

Build from a source checkout on an Apple Silicon Mac. The Python CLI and native Simulator libraries have separate setup steps; an installed Python package alone does not supply a native build.

## Requirements

| Requirement | What to check |
|---|---|
| Apple Silicon | `uname -m` reports `arm64` |
| Python | Python 3.11+ |
| Full Xcode | Selected developer directory includes the iOS Simulator SDK and developer tools |
| iOS Simulator runtime | An available iOS device/runtime for target execution |
| Native tools | `clang`, `codesign`, `otool`, `vtool`, `plutil` and `xcrun` |
| Research input | A compatible iOS app installed through the Mac App Store for the extraction workflow |

Check the selected toolchain without changing it:

```sh
uname -m
python3 --version
xcode-select -p
xcrun --sdk iphonesimulator --show-sdk-path
```

If full Xcode or a runtime is missing, finish its installation/components setup first. Command Line Tools alone do not provide the full Simulator environment. Avoid changing an actively used Xcode selection merely to follow an example.

## Source checkout setup

Run from the repository root:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p src/dylibs/build
make
.venv/bin/python -m pip check
.venv/bin/darkmach --help
.venv/bin/darkmach bridge --commands
```

The editable install maps `darkmach` directly to `src/`. `make` builds twelve Simulator-targeted dylibs in `src/dylibs/build/` and the host utility at `src/dylibs/tools/dump-region`. Creating the output directory is necessary: the current Makefile does not create it on a clean checkout.

The help commands should exit zero without contacting a bridge. They are useful before installing or launching a target. Installation does not automatically launch an application or boot a Simulator.

### Native signing

The Makefile explicitly signs the extraction dylib. To ad-hoc sign all twelve native outputs, use its existing signing target:

```sh
make sign
```

No Apple developer account is required for that local ad-hoc operation. Native build/signing success is distinct from app compatibility and capture correctness.

### Non-editable installation

For a copied package or isolated non-editable installation, build native assets in the source checkout **before** installing the package. Packaging includes dylibs already present; it does not invoke Make. Building the checkout afterward does not replace assets already copied into another environment. The editable source workflow above avoids that stale-copy distinction during development.

## Check runtime readiness

After building, choose your dedicated device as described in the [walkthrough](walkthrough.md#choose-the-input-and-device), then check:

```sh
.venv/bin/darkmach status --udid "$DARKMACH_UDID"
```

The status command reports host tools, SDK, selected booted state and the **eight default interceptor files**. It does not report twelve default interceptors. An installed but shut-down selected device can appear as not booted; runtime commands can boot it later.

Inspect each status row, especially `[MISSING]`. The current implementation does not make missing dylibs affect its overall exit code, so `System ready` or exit zero is not enough to establish asset completeness. Also inspect the build result and the named files. A status pass does not validate fresh extraction, app UI or capture.

Proceed to [runtime workflow](walkthrough.md) for a complete operator sequence.

## Dependencies and asset paths

The Python runtime dependency is `hermes-dec`, used for Hermes/React Native analysis. Core binary transformations use the Python standard library and Apple tools. Native components link against system frameworks/libraries; no separate instrumentation runtime is required by the default path.

The package resolves native and patch assets relative to its own installation. Results default to `output/` under the working directory; `DARKMACH_OUTPUT` overrides that root. `DARKMACH_OUTPUT_DIR` is a separate setting passed by the launcher to native logging. See [architecture](architecture.md#evidence-and-storage).

## Development checks

Install the declared development extras when editing source:

```sh
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src
.venv/bin/python -m pytest -q -o addopts= --tb=short
```

The existing full suite includes two native/system-tool checks. The Python-only selection is:

```sh
.venv/bin/python -m pytest -q -o addopts= --tb=short -m 'not integration'
```

## Troubleshooting

| Symptom | Check / next action |
|---|---|
| `xcrun` or Simulator SDK missing | Check `xcode-select -p` and the full Xcode components/runtime installation |
| Make cannot write its output | Create `src/dylibs/build/` before building; inspect the actual compiler error |
| Python install succeeds but native files are missing | Run the native build; for non-editable installs, rebuild before reinstalling the package |
| Multiple booted candidates | Supply `--udid`; automatic selection deliberately refuses ambiguity |
| `status` reports missing dylibs but exits zero | Inspect the named `[MISSING]` rows; its current final status does not include that condition |
| Selected device is not booted | Confirm it is an available iOS device; `run`/`launch` can boot the explicit UUID |
| Bridge path is live or not a socket | Use the endpoint already printed for the intended session, or choose a different absolute `--socket`; live peers are not replaced |
| Bridge connects but the app stays on splash | Inspect the receipt, entitlement readback and independent UI state; connection alone does not establish application usability |

For failures after preparation starts, retain stderr and the printed run receipt. [CLI reference](cli-reference.md) describes exit/status behavior; [findings](limitations.md) explains runtime and detector limitations.
