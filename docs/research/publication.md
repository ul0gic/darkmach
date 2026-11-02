# Research publication plan

The publication should let another researcher understand Darkmach's mechanism, reproduce a bounded result, inspect the evidence and identify its limits. The local draft is organized around those tasks.

Status: local draft; repository publication not authorized · Updated: 2026-11-02

## Publication structure

| Component | Purpose | Current home |
|---|---|---|
| Project entry | State the workflow, supported input and current validation boundary. | [Repository README](../../README.md) |
| Research manifest | Define questions, claims, source mapping and reading paths. | [Research manifest](README.md) |
| Technical article | Explain the temporary and final image states and the extraction mechanism. | [Two-pass extraction](fairplay-bypass.md) |
| Reproduction protocol | Specify inputs, controls, environment and evidence. | [Methodology](methodology.md) |
| Results and limitations | Present current and historical observations without conflating them. | [Validation and findings](findings.md) |
| Technical context | Credit platform mechanisms and existing instrumentation workflows. | [Related work](related-work.md) |
| Operational reference | Document installation, commands, patching and runtime queries. | [Documentation index](../README.md) |

## Evidence needed for the first public research release

The present compatibility evidence covers an already reconstructed app. The principal missing experiment is a fresh extraction on the current OS and Xcode combination with an empty cache, original input hashes, recovered-region comparison and dependent code execution recorded together.

A self-built demonstration app should provide deterministic network, hashing/encryption and SQLite operations. Its source can be shared, making instrumentation claims repeatable without distributing a third-party application. A separate encrypted-target record is still needed to support extraction claims.

Package a concise result summary with environment metadata, stage outcomes and sanitized observations. Keep original raw records locally when they contain application data. The public summary must identify that boundary; a digest of a private record does not provide independent access to its contents.

## Decisions before release

| Item | Present state | Decision or work remaining |
|---|---|---|
| Licensing | Previous documentation described proprietary licensing; `pyproject.toml` declares MIT; no root license file exists. | Reconcile the intended license, metadata and documentation. No license choice is made by this draft. |
| Author credit and citation | Package metadata names `darkmach`; no publication author identity or citation record is established here. | Choose public attribution and release identity before creating citation metadata. |
| Public target examples | Local records contain real app names, captured credentials and engagement-specific observations. | Select examples that can be shared and export only the evidence needed to substantiate the toolkit result. |
| Repository history | The current working tree and the full historical object set are different publication surfaces. | Inspect the actual release contents and history before changing visibility or pushing a public mirror. Ignored local output is not proof that history contains none. |
| Reproducible setup | Current-tree builds pass; a missing output directory breaks a clean build. | Repair or explicitly account for clean-checkout setup and verify it from a fresh source export. |
| Detector limitations | Hermes string extraction and several observation semantics have documented gaps. | Fix the relevant gap or keep the limitation prominent wherever the affected capability is described. |
| Compatibility | Fresh main-region recovery is observed on two targets; initial UI is observed, while broader images, authenticated flows and a shareable capture control remain open. | Publish the exact validated environment and experiment type, rather than a universal compatibility promise. |
| Priority claims | Initial related-work review only. | Complete a comparative literature/tool review before claiming a new or first technique. |

## Editorial standard

Describe transformations and observations concretely. Keep implementation intent, historical results, current reproduction and hypotheses distinguishable. A compelling research account includes what failed and what changed the interpretation, especially cache reuse, silent capture paths and environmental failures.

The first article can center on the two-pass state transition, followed by one controlled capture demonstration and a short account of the limits discovered in real applications. That gives researchers a mechanism to challenge and students a method to learn, while leaving the CLI and command reference available for deeper use.

Publication, repository visibility, releases, external disclosures and license changes remain separate owner decisions.
