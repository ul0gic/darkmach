# Runtime investigation workflow

This guide follows one target through Darkmach's public CLI. It explains the checkpoints and the artifacts rather than assuming that a completed pipeline proves the whole application works.

Complete [installation](installation.md) first. Runtime steps require your own installed app and a dedicated iOS Simulator. The commands use the generic path `/Applications/Example.app`; replace it with your own Mac-delivered iOS bundle. App availability and compatibility are input conditions.

## Choose the input and device

List Mac-installed iOS wrappers and available Simulator devices:

```sh
.venv/bin/darkmach list
xcrun simctl list devices available
```

Choose an available iOS Simulator that is reserved for this investigation. Copy its UUID, then read it into a shell variable:

```sh
read -r DARKMACH_UDID
```

Paste the UUID and press Return. This is your selected device, not the word `booted`. It may be shut down; `run` can boot it. Multiple booted devices cause automatic selection to refuse rather than silently choosing one.

The current `run` command reinstalls the selected bundle ID on that device, removing its existing installed target first. Use a research device where that app state is disposable. The original bundle in `/Applications` is copied before patching.

## Run the full path

Choose a new output directory for this experiment:

```sh
DARKMACH_OUTPUT="$PWD/output/target-study" .venv/bin/darkmach run /Applications/Example.app --udid "$DARKMACH_UDID"
```

A new output root has no matching crypt cache. Reusing the same root can reuse verified recovered bytes, replace the previous working bundle and append to existing runtime logs.

Follow the seven printed steps: locate, copy, analyze, device selection, patching, installation/launch and bridge check. Static analysis happens **before reconstruction** in this command. If you later inspect recovered code statically, run standalone `analyze` on the patched bundle rather than attributing the initial reports to decrypted code.

Completion prints the target name/bundle ID, PID, device UUID, socket, static directory, dynamic directory and an exact bridge-connect command. It also prints a per-invocation receipt path and explicitly leaves UI/capture-event validation unchecked. Failure retains the reached stage outcomes; interruption returns exit 130 and records failure.

## Inspect the actual process

Connect using the selected UUID, or copy the exact `--socket` command from the run summary:

```sh
.venv/bin/darkmach bridge --udid "$DARKMACH_UDID"
```

At the prompt, start with:

```text
info
view_hierarchy
entitlement_scan
raw {"cmd":"info"}
quit
```

| Checkpoint | What to inspect |
|---|---|
| Identity | `info` bundle/PID agree with the run summary and receipt |
| Initial UI | Hierarchy and an independent visual observation show whether the app progressed past launch content |
| Entitlements | Main encoded status and selected OS-readback result; matching values do not prove every capability-dependent operation |
| Raw protocol | A complete request object reaches the bridge; `ok` is a JSON boolean describing that command |

Use `help` inside the REPL or `darkmach bridge --commands` offline for the command catalog. `raw` takes a complete JSON object, including `cmd` and optional `args`; it is useful for strings containing spaces. Avoid treating an action acknowledgement as proof that the intended UI or application state changed.

For another target on the same device, select a distinct absolute `--socket` at launch and connect to that exact path. Separate endpoints do not make concurrent writes into the same output/app directory independent.

## Read the artifacts

| Artifact | Read it for |
|---|---|
| `<output>/<app>/bundle/` | The reconstructed copy; compare its original crypt range against the recovered dump |
| `<output>/<app>/static/` | Initial metadata/string reports; these precede recovery in a full run |
| `<output>/<app>/dynamic/` | Continuous per-module JSONL observations; files can contain earlier launches |
| Printed `<output>/<label>/runs/<run-id>.json` | Command, terminal outcome, stage timestamps, input hash, strategy, cache/entitlement result, device/socket/PID and injected-artifact hashes |
| `<output>/.cache/crypt/<input-main-sha256>/` | Recovered region plus sidecar binding offset/size, length and dump hash |

For a main region at offset `0x5000` with size `0x1000`, the cache basename is `5000-1000`. Do not identify a dump by length alone. The current cache also binds source and recovered-byte hashes; a verified hit remains reuse.

Retain the receipt path printed by each command. Receipt labels can come from an input basename or standalone launch's bundle-ID suffix, while bundle/log directories use the resolved app name. Raw captures are separate from receipts: receipts select metadata and exclude traffic bodies, whole environments and entitlement values. Keep raw captures private and export only what supports a particular result.

## Validate one capture path

Pick one operation whose expected behavior you know. Observe the recorder's readiness, perform the operation, then compare its bridge result and JSONL over the same time window. Use a self-built app with deterministic behavior when establishing a capture control.

Distinguish an attempted request from a completed response, a prepared SQLite statement from a returned row, and a hash operation from encryption/key capture. A zero count may mean no event, an unexercised hook, an evicted ring entry or a different transport. The bridge is a measurement instrument whose paths need validation too.

Use your own known-behavior app for capture checks; the [interceptor reference](interceptors.md) names the hooked APIs.

## Result checks

- Why does clearing `cryptid` without replacing bytes fail to establish recovery?
- Which artifact distinguishes a fresh extraction from a warm run?
- Why can a correct bridge identity coexist with a splash-only application?
- What additional observation would establish that a selected entitlement-dependent operation works?
- What would let you claim a missing capture is a tool defect rather than an unexercised path?

For the platform explanation, continue with [platform architecture](platform-architecture.md) and [two-pass extraction](how-it-works.md). For exact options and operations, use the [CLI](cli-reference.md) and [bridge](bridge.md) references.
