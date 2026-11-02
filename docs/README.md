# Darkmach documentation

Darkmach adapts selected Mac-delivered iOS apps for Simulator research on Apple Silicon and exposes their runtime through native interceptors and a JSON bridge. Product guides explain how to operate the toolkit; the research section explains the mechanism, evidence and limits.

Updated: 2026-11-02

## Research documentation

| Document | Purpose |
|---|---|
| [Research manifest](research/README.md) | Research question, claim register, source map and reading paths |
| [Two-pass FairPlay extraction](research/fairplay-bypass.md) | Binary state transitions, extraction implementation and interpretation of system-managed decryption |
| [Methodology and reproduction](research/methodology.md) | Controls, environment isolation, evidence requirements and teaching sequence |
| [Validation and findings](research/findings.md) | Historical extraction results, current compatibility check and known limitations |
| [Related work](research/related-work.md) | Apple loader sources, existing instrumentation workflows and attribution boundaries |
| [Publication plan](research/publication.md) | Draft structure, missing reproduction evidence and release decisions |

## Product documentation

| Document | Purpose |
|---|---|
| [Capability brief](darkmach-brief.md) | Workflow, supported inputs, capabilities and validation boundary |
| [Installation](installation.md) | Full Xcode setup, source builds and preflight checks |
| [CLI reference](cli-reference.md) | All ten subcommands, arguments and operational behavior |
| [Architecture](architecture.md) | Source structure, pipeline stages and component interactions |
| [Interceptors](interceptors.md) | Dylib roles, hooked APIs, capture format and injection configuration |
| [Patching](patching.md) | Bundle transformations, extraction sequence and experimental strategies |
| [Runtime bridge](bridge.md) | JSON protocol, registered commands and operator workflow |
| [Engagement pattern](engagement-pattern.md) | Keep application research and captured data separate from toolkit development |

## Start with your question

For setup, start with [installation](installation.md) and then consult [CLI usage](cli-reference.md). For the mechanism, start with [two-pass extraction](research/fairplay-bypass.md). For a classroom session, follow the [teaching sequence](research/methodology.md#teaching-sequence). For a claim about compatibility, consult the dated [validation record](research/findings.md).

The 2026-11-02 check confirms a rebuild and launch of an existing patched app on iOS 27.0. Fresh extraction on the updated host remains untested. A successful bridge connection does not establish all hook coverage or access to protected app behavior.
