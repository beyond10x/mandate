---
format: aep.planning-md/1
id: story:tenancy-graph-events
kind: story
status: implemented
title: Tenancy and resource commands emit their declared events and fold from them
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-authz/tests/adversary_check.rs
- confidence: inferred
  path: crates/mandate-authz/tests/adversary_check_2.rs
- confidence: inferred
  path: crates/mandate-authz/tests/check_contract.rs
- confidence: inferred
  path: crates/mandate-authz/tests/context.rs
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
revision: 14
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

## Coordinator rulings at integration, 2026-09-19

- `create_organization`, `close_organization` and `add_organization_membership` take the `VerifiedContext` their payloads declare and return their event like the other nine; the context-less wrappers are removed. Their only callers outside the crate are four `mandate-authz` test files, which join this story's scope for E1 (no other E1 unit touches `mandate-authz`). Rationale: a public method that writes the projection without producing the event is the ADR 0009 violation this story exists to close.
- `ResourceRegistered` carries `{context, resource_id, resource, parent}`; `contract-creates` sources `resource_id` from the `RegisterResource` response (option b), so the ruled payload set matches the regenerated schema.
- Idempotence measured, not assumed: `fold(log ++ log) == fold(log)` holds because every `apply` is a keyed upsert or an absorbing state move.

## Coordinator rulings after adversary pass 1, 2026-09-19

```
unit: story:tenancy-graph-events — crates/mandate-model/src/{tenancy,graph,lib}.rs, tests/{tenancy,graph,replay,adversary_tenancy_topology}.rs, four mandate-authz test files, uncommitted on impl/tenancy-graph-events at base 9401ab9
verdict: needs-change
cases: executed 65 → 75, red 2 (adversary file crates/mandate-model/tests/adversary_events_1.rs, 10 cases: 8 held, 2 confirmed)
findings: 7 — 1 blocker, 3 warnings, 3 notes
```

```findings
- file: crates/mandate-model/src/graph.rs
  line: 153
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: ResourceEvent::Registered serializes an absent parent as "parent": null, which the compiled mandate.graph.ResourceRegistered refuses because parent is optional and typed as mandate.core.ResourceId, a string.
- file: crates/mandate-model/tests/replay.rs
  line: 704
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: resource_samples() only ever builds Registered with parent Some, so no case in the crate serializes the parent-less registration that carries the defect.
- file: crates/mandate-model/tests/replay.rs
  line: 724
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the payload oracle compares serialized key sets to required and never a value against its $ref, so a null, a wrong type or a malformed uuid in any of the twelve payloads is invisible to the suite.
- file: crates/mandate-model/tests/replay.rs
  line: 779
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: name checking is set-equality, so swapping ess_name() between two of the five payloads whose declared keys are exactly {context, id} survives every oracle in the workspace.
- file: crates/mandate-model/src/tenancy.rs
  line: 1225
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: apply writes a creation event as an unconditional keyed insert, so a creation replayed after its record reached a terminal state returns it to the initial state, which no decide path can produce and no wired consumer reaches today.
- file: .engineering/planning/story/tenancy-graph-events.md
  line: 27
  category: acceptance
  severity: note
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the story Scope declares fold returning Result<Tenancy, Denied> and the implementation returns Tenancy; the code is right and the story text is stale, and only the coordinator can amend it.
- file: crates/mandate-model/src/tenancy.rs
  line: 90
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: the module records the display-name admission as an unrealized denial clause but not RetireTeam's directory-mapping clause or RemoveTeamMembership's mapping-contribution clause, which are equally unrealized here.
```

Held under attack: fold equals live at every prefix of a 12-command interleaved history and of a 3-deep resource tree; 32 denied paths over all 12 commands leave the whole projection equal; every base guard survives the split and `add_organization_membership` is stricter; `apply` is total (a move for an absent record writes nothing); all 12 payloads validate structurally against their schemas except the ruled `resource_id`; the four `mandate-authz` hunks are argument-only with no assertion weakened; every projection exposes every required entity field including `state`. Evidence under the unit's scratch `adversary1/`.

## Coordinator rulings after adversary pass 2, 2026-09-19

- Guards live at decide; `apply` and `fold` are total (adversary pass 2, recharacterized): a fold that re-checks a guard is not a rebuild (ADR 0009), so `apply` writes what it is handed and re-checks nothing. The window between a decide call and its append is closed by the command path, which ADR 0009 makes one transaction under optimistic concurrency, not by this crate. The module doc and the `add_organization_membership` doc withdraw the sentence "a closure that lands between a decide call and its apply is refused rather than written" and state this contract instead. The adversary's four cases were amended by the coordinator to assert it (decide refuses in order; apply is total; decide never emits a divergent resource identity).
- The replay value oracle asserts `resource_id == resource.resource_id` on `ResourceRegistered` instead of deleting the key (A2-4); the pre-existing `adversary_tenancy_topology.rs` case whose doc names the decide-then-apply sequence drives that sequence (A2-5).
- Event-log deserialization is deferred: the enums stay `Serialize`-only because under `#[serde(untagged)]` the five `{context, id}` payloads are ambiguous to read back; the tagged envelope is the persistence story's, and `story:model-agreement` round-trips through the generated contract shapes (A2-6).
- `ResourceRegistered` is `{context, resource_id, resource, parent}` — the contract-creates pass-2 ruling removes the `space_id` that briefly joined it, so the ruled four-field payload stands.
