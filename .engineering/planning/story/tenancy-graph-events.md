---
format: aep.planning-md/1
id: story:tenancy-graph-events
kind: story
status: draft
title: Tenancy and resource commands emit their declared events and fold from them
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-model/src/graph.rs
- confidence: cited
  path: crates/mandate-model/src/lib.rs
- confidence: cited
  path: crates/mandate-model/src/tenancy.rs
- confidence: cited
  path: crates/mandate-model/tests/adversary_tenancy_topology.rs
- confidence: cited
  path: crates/mandate-model/tests/graph.rs
- confidence: inferred
  path: crates/mandate-model/tests/replay.rs
- confidence: cited
  path: crates/mandate-model/tests/tenancy.rs
revision: 4
---
## Acceptance

Given `crates/mandate-model`, when any of the ten tenancy commands or the two resource commands decides, then it returns the declared event (`TenancyEvent`, `ResourceEvent`, deriving `Serialize`) and `apply`/`fold` rebuild the projection from events alone; and when the replay test folds the captured events from an empty projection, the result equals the live projection field for field.

## Why

At `874a74f` the ten `Tenancy` methods (`crates/mandate-model/src/tenancy.rs:313-610`) and `Topology::register/deregister` (`graph.rs:149,193`) mutate projections directly and emit nothing. ADR 0009 makes the event the record; a projection the log cannot rebuild is a deployment blocker.

## Scope

- `crates/mandate-model/src/tenancy.rs` — cited; each method splits into `decide(&self, …) -> Result<TenancyEvent, Denied>`, `apply(&mut self, &TenancyEvent)`, `fold(&[TenancyEvent]) -> Result<Tenancy, Denied>`; the public read API (`admits`, `is_member`, `resolve_space`, `resolve_team`, `team_membership`, …) is unchanged (consumed by `mandate-authz`, `mandate-federation`).
- `crates/mandate-model/src/graph.rs` — cited; `ResourceEvent { Registered, Deregistered }`, the same split on `Topology`.
- `crates/mandate-model/src/lib.rs` — cited; re-exports.
- `crates/mandate-model/tests/tenancy.rs`, `tests/graph.rs` — cited; adjusted call sites.
- `crates/mandate-model/tests/replay.rs` — inferred; fold-from-empty replay for Organization, OrganizationMembership, Team, TeamMembership, Space, Resource, including every mutation.
- `crates/mandate-model/tests/adversary_tenancy_topology.rs` — cited; the "replay" test at `:229` re-executes commands today and is rewritten to fold events.

Event payloads follow the contract exactly (`generated/schema/events/mandate.tenancy.*.json`, `mandate.graph.Resource{Registered,Deregistered}`): `OrganizationCreated {context, organization_id, display_name}`, `TeamCreated`, `SpaceCreated`, `OrganizationMembershipAdded {context, organization_id, principal_id, membership_id}`, `OrganizationMembershipRemoved {context, id}`, `TeamMembershipAdded`, `TeamMembershipRemoved`, `OrganizationClosed`, `TeamRetired`, `SpaceRetired`, `ResourceRegistered {context, resource: ResourceRef, parent}` (plus `resource_id` once `story:contract-creates` lands — read the yaml at dispatch), `ResourceDeregistered {context, id}`.

### Units

| Unit | Owns | Test | Produces |
|---|---|---|---|
| `tenancy` | `src/tenancy.rs` | `tests/tenancy.rs` | `TenancyEvent`, decide/apply/fold |
| `graph` | `src/graph.rs` | `tests/graph.rs` | `ResourceEvent`, decide/apply/fold |
| `replay` | `src/lib.rs` | `tests/replay.rs`, `tests/adversary_tenancy_topology.rs` | fold-from-empty proofs |

One agent, serially.

### Excluded

Every other crate (`mandate-authz`, `mandate-federation` read `Tenancy` through its unchanged read API); `systems/`, `generated/`, `Cargo.*`.

### Gate

`cargo fmt -p mandate-model -- --check && cargo clippy -p mandate-model --all-targets --locked -- -D warnings && cargo test -p mandate-model --locked`; then `cargo check --workspace --all-targets --locked` (consumers still compile).

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).
