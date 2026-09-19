---
format: aep.planning-md/1
id: story:model-agreement
kind: story
status: draft
title: Model projections and canonical types agree with their generated shapes exactly
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-shapes
- depends_on: story:tenancy-graph-events
scope:
- confidence: inferred
  path: crates/mandate-model/src/lib.rs
- confidence: inferred
  path: crates/mandate-model/tests/contract_agreement.rs
- confidence: cited
  path: crates/mandate-model/tests/projections.rs
- confidence: inferred
  path: crates/mandate-types/src/inventory.rs
- confidence: cited
  path: crates/mandate-types/tests/conformance.rs
- confidence: inferred
  path: crates/mandate-types/tests/inventory.rs
revision: 8
---
## Acceptance

Given `mandate-model` and `mandate-types`, when each of the six projections, the `TenancyEvent`/`ResourceEvent` payloads and every one of the 36 `.State` enums is serialized, then it round-trips exactly into its generated contract shape, replacing the one-directional check at `crates/mandate-model/tests/projections.rs:172`.

## Scope

- `crates/mandate-model/tests/contract_agreement.rs` — inferred; round trips for Organization, OrganizationMembership, Team, TeamMembership, Space, Resource and the 12 event payloads into `mandate_contract::*`.
- `crates/mandate-model/tests/projections.rs` — cited; the one-directional check at `:172` retired in favour of the round trip.
- `crates/mandate-types/tests/conformance.rs` — cited; the 36 `.State` enums join the per-type schema account (today 6).
- `crates/mandate-model/src/lib.rs` — cited; `realizes!` registrations for the six entities and twelve events.

### Units

One agent; two units (`model`, `types`), disjoint files.

### Excluded

`crates/mandate-model/src/{tenancy,graph}.rs` (`story:tenancy-graph-events`), `crates/mandate-types/src/**` except through the coordinator, `generated/`, `Cargo.*`.

### Gate

`cargo test -p mandate-model -p mandate-types --locked`.

## Coordinator rulings at wave opening, 2026-09-19

- Dev-dependency on `mandate-contract` for `mandate-model` and `mandate-types` is pre-landed in the opening commit. The `realizes!` registrations for the six entities and twelve events go in `crates/mandate-model/src/lib.rs` (this story's, this wave).

## Coordinator rulings after critic round 1, 2026-09-19

- The `types` unit's account of the 36 `.State` enums needs `crates/mandate-types/src/inventory.rs` (`EXCLUDED_SEMANTICS`) and `crates/mandate-types/tests/inventory.rs`; both join this story's scope (parallel item 5); no other unit touches `mandate-types`.
