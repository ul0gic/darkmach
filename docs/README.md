# Darkmach documentation

## Setup and operation

1. [Install and build](installation.md): prerequisites, Python/native setup and troubleshooting.
2. [Runtime workflow](walkthrough.md): select an app and Simulator, inspect the process and read its output.
3. [Understand coverage](limitations.md): supported inputs, API reach and result semantics.

## Architecture

| Guide | What it explains |
|---|---|
| [Platform architecture](platform-architecture.md) | Mach-O metadata, mapped memory, loading, signing and entitlements |
| [How two-pass recovery works](how-it-works.md) | The temporary extraction image and reconstructed runnable copy |
| [Darkmach architecture](architecture.md) | CLI orchestration, process boundaries, native capture and storage |
| [Command and capability map](darkmach-brief.md) | A compact map of the operational surface |

External technical references are linked directly from the relevant explanations.

## Reference

| Reference | What it covers |
|---|---|
| [CLI](cli-reference.md) | All ten subcommands, arguments, outputs and failures |
| [Runtime bridge](bridge.md) | JSON protocol, runtime commands and result semantics |
| [Native interceptors](interceptors.md) | Component roles, hooked APIs and log formats |
| [Patching](patching.md) | Binary transformations, extraction and experimental strategies |
