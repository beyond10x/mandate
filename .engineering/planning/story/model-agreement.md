---
format: aep.planning-md/1
id: story:model-agreement
kind: story
status: implemented
title: Model projections and canonical types agree with their generated shapes exactly
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-shapes
- depends_on: story:tenancy-graph-events
scope:
- confidence: inferred
  path: crates/mandate-model/src/graph.rs
- confidence: inferred
  path: crates/mandate-model/src/lib.rs
- confidence: inferred
  path: crates/mandate-model/tests/contract_agreement.rs
- confidence: cited
  path: crates/mandate-model/tests/projections.rs
- confidence: inferred
  path: crates/mandate-model/tests/replay.rs
- confidence: inferred
  path: crates/mandate-types/src/inventory.rs
- confidence: cited
  path: crates/mandate-types/tests/conformance.rs
- confidence: inferred
  path: crates/mandate-types/tests/inventory.rs
revision: 14
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

## Coordinator rulings after adversary pass 1, 2026-09-19

- Pairings are evidence, not typing (A1-1, A1-3): `payload!` and `state_enums!` assert that the generated type on the right is the one the ESS name on the left derives to (`std::any::type_name` ends with ESS's `declaration_name` derivation, the same rule `xtask/src/emit.rs` applies), and `ess_name()` equals the schema's `x-ess-name`; a wrong pairing is red.
- The account says what it covers (A1-4): six domain state enums decided against the contract through their generated enums; the other 30 accounted through the generated enum only, each named; the ten domain enums outside `mandate-model` that name a `.State` element are decided by the stories that own their crates — the five in `mandate-federation` and any in `mandate-identity` by `story:federation-identity-alignment` in this wave, those in `mandate-graph` and `mandate-policy` by `story:graph-policy-adapter` (recorded on both).
- `mandate-model` registers every element it implements (J2): the four `mandate.core` records join `realizes!` and the registry case pins 22; entity entries assert element-to-symbol correspondence by name derivation (J1), event-variant entries are documented as unverifiable by name.
- State loops carry an exhaustiveness guard (J3): a `match` over the domain enum in the test, so a variant added to the enum and not to the loop fails to compile.
- The stale `ResourceRegistered` sentences in `crates/mandate-model/src/graph.rs:133` and `tests/replay.rs:1085-1102` (A1-2, `story:tenancy-graph-events`' files, implemented) are corrected by this unit: the doc states the compiled payload, and the replay key check reads `required_keys(name)` like every other event. Scope extended for those two files, doc and oracle lines only.
