---
format: aep.planning-md/3
id: story:ess-repin-0-59
kind: story
status: active
title: Move the specification and the ESS crates to ESS 0.59.0
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-12T16:02:13Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-12T16:02:14Z", actor: "human:timo", revision: 3}
---
# Move the specification and the ESS crates to ESS 0.59.0

## Acceptance

Given the workspace pins `ess-conformance`, `ess-primitives` and `ess-domain` at 0.26.0 (`Cargo.toml:24-26`) and `ess specify validate --path systems/mandate` under `ess 0.59.0` refuses the specification, when the pins move to 0.59.0 and the specification is corrected, then `ess specify validate --path systems/mandate` under 0.59.0 exits 0, `cargo xtask generate` reproduces `generated/` with no drift, and `task check` exits 0.

## The refusals this story owns

Read on 2026-10-12 with `ess 0.59.0`, `ess specify validate --path systems/mandate`:

- `[type_mismatch]` `mandate.credential.SigningKey.invariants[0]`: `not_before < expires_at` reads `expires_at` as a text literal (`domains/credential.yaml:78`). Comparing two fields needs one struct holding both.
- `[invariant_reads_unset_field]` `mandate.credential.RegisterSigningKey` outcome `accepted` creates `SigningKey` without setting `not_before` (`domains/credential.yaml:503`).
- `[invariant_reads_unset_field]` `mandate.delegation.CreateDelegation` outcome `accepted` creates `Delegation` without setting `transitive`, which the invariant `transitive == false` reads (`domains/delegation.yaml:271`).

Each correction states what the contract already meant; none adds a noun. The generated Rust shapes and the conformance suite follow from the corrected model, and every hand-written consumer of a changed shape is updated in the same unit.

## Scope

- `Cargo.toml`, `Cargo.lock` — cited, the three pins.
- `systems/mandate/domains/credential.yaml`, `systems/mandate/domains/delegation.yaml` — cited, the refusals.
- `generated/` — cited, regenerated, never hand-edited.
- `AGENTS.md`, `xtask/src/main.rs` — inferred, the text naming ESS 0.26.0 and its ownership note.
- Consumers of `SigningKey` and `Delegation` shapes in `crates/` and `services/` — inferred.

## Why now

The workspace rule is to use the newest ESS release, and the next story, `story:agent-authority-kernel`, is modelled in `domains/delegation.yaml`, which 0.59.0 refuses today.
