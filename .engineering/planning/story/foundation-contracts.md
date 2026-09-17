---
format: aep.planning-md/1
id: story:foundation-contracts
kind: story
status: active
title: Stabilize combined ESS and foundation scaffold
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: docs/architecture
- confidence: cited
  path: systems/mandate
- confidence: cited
  path: xtask
revision: 9
---
# Stabilize combined ESS and foundation scaffold

## Acceptance

Given the combined foundation candidate, when task check evaluates it, then the gate exits zero with the review and source-provenance evidence retained for the same candidate tree.

## Required observations

task check validates all declared ESS, projections, dependency boundaries and source digests; the combined corpus explicitly covers all required security categories. Four critic verdicts and outcomes are recorded. Binaries accept help/version and reject runtime subcommands.

## Dependencies

None; this foundation milestone owns initial stabilization.

## Scope

- `systems/mandate` — cited planned scope in this story; shared path entries use canonical directory granularity.
- `docs/architecture` — cited planned scope in this story; shared path entries use canonical directory granularity.
- `xtask` — cited planned scope in this story; shared path entries use canonical directory granularity.
- `Cargo.toml` — cited planned scope in this story; shared path entries use canonical directory granularity.

## Validation and contract

`task check`; owner-specific runtime tests required above. `tests/security/cases.json` is a foundation contract corpus, not a runtime pass. ESS inputs: `systems/mandate/ess-inputs.yaml`. Addendum is mandatory, not optional hardening.

## Public documentation follow-up

The operator expanded this milestone to include a public outlook and a reusable contract viewer, with a local Brave review before website publication. README and docs/public now explain the architecture, contracts, roadmap and development boundary. The manifest selects 26 passive source files, including generated Markdown, four semantic OpenAPI references and ESS's existing ess-docs/1 projection. It excludes internal planning and review material from Website collection; those sources remain preserved in the repository.

`cargo xtask generate` and the deterministic gate now include docs-ir. Every generator receives generated/ as its output root. `task check` passed with 47 structural scenarios and all 48 planning records valid. The shared Docs System viewer is implemented separately and verified against complete Mandate and Connectors projections; Website owns its passive fetch and route adapter. No runtime security behavior was added. Source publication, exact public CI and final website review remain outstanding.

## Technical corrections and verification

The additional contract/design reviews retain their needs-revision verdicts and escalation evidence. docs/technical-review-disposition.md accounts for all 23 findings. Corrected shapes, ownership, per-command guards and command-linked corpus records pass task check (53 artifacts, 47 cases), deterministic ESS regeneration, and 27 positive/negative schema shape checks. Remaining epoch, conditional-reference, uniqueness, algorithm, audit and worker semantics have explicit UNMAPPED blockers. These are required later implementation decisions, not runtime claims or new independent approvals. Wave/Drive accepted type scope excludes incomplete epoch records and includes reviewed serialization dependency policy changes. Source publication and website review remain pending.
