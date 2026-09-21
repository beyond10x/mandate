---
format: aep.planning-md/1
id: story:graph-policy-adapter
kind: story
status: draft
title: Attach the chosen graph and policy engines behind the ports
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:graph-policy
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: inferred
  path: crates/mandate-graph/src/adapter.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: inferred
  path: crates/mandate-graph/tests/adapter.rs
- confidence: inferred
  path: crates/mandate-policy/src/adapter.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: inferred
  path: crates/mandate-policy/tests/adapter.rs
- confidence: cited
  path: deny.toml
- confidence: cited
  path: dependency-boundaries.json
- confidence: inferred
  path: docs/adr/0010-graph-policy-backend.md
revision: 10
---
# Graph and policy adapters for the chosen backend

## Acceptance

Given the graph and policy engines named in `docs/adr/0010-graph-policy-backend.md`, when the `story:graph-policy` conformance suite runs under `cargo test -p mandate-graph -p mandate-policy` against the real adapters instead of the doubles, then it exits zero with a consistency token the engine issued.

## Required observations

Moved here from `story:graph-policy`, exactly as its moved-to sentence names them: choose graph and policy engine in ADR; concrete adapters; engine-issued consistency tokens; storage-level enforcement. Additionally, from `runtime-decisions.md` rows 5 and 7: `AuthzRevision` maps onto a real consistency token that survives Mandate's own API; storage-level exactly-one conditional reference and tenant-membership enforcement; a decision-latency target stated before load evidence means anything. "Backend types do not leak into domain" stays with `story:graph-policy`'s boundary check and is re-run, not re-owned, here. `graph-revocation` executes in `story:check-api`'s crate and is not this story's evidence.

## Why a separate story

`decision-blocker:backend` and `decision-blocker:subject-relations` are open and their clearance evidence is engine-specific. `story:graph-policy` delivers every port and pure function behind `pub` doubles; this story attaches the engines. Row 7 depends on row 2, so `decision-blocker:lifecycle` blocks this story for cascade semantics. No new crate may host an adapter (`xtask/src/main.rs:104`), so both land inside the two existing crates.

## Units

| Unit | Owns | Test file |
|---|---|---|
| coordinator, first | `crates/mandate-graph/src/lib.rs`; `crates/mandate-policy/src/lib.rs`; `Cargo.toml`; `Cargo.lock`; `dependency-boundaries.json`; `deny.toml`; `docs/adr/0010-graph-policy-backend.md` | — |
| `graph-adapter` | `crates/mandate-graph/src/adapter.rs` | `crates/mandate-graph/tests/adapter.rs` |
| `policy-adapter` | `crates/mandate-policy/src/adapter.rs` | `crates/mandate-policy/tests/adapter.rs` |

The four root config files are declared so the scheduler sees this story collide with every other claimant of `Cargo.lock`; it is ordered against `story:pkce-sessions` through `story:check-api`, which `depends_on` both.

## Scope

- `crates/mandate-graph/src/adapter.rs`, `tests/adapter.rs`; `crates/mandate-policy/src/adapter.rs`, `tests/adapter.rs` — inferred; do not exist.
- `docs/adr/0010-graph-policy-backend.md` — inferred; authored only on the operator's decision.
- `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml` — coordinator.

## Validation and contract

`cargo test -p mandate-graph -p mandate-policy --locked`, counts reported.

## Inherited from wave E1, 2026-09-19

- Surfaced by `contract-creates` adversary pass 2 (A2-8): four shipped records return `MutationOutcome::AlreadyRecorded` and document "Repeating it is accepted" for a state the contract now declares a `wrong-state` refusal (409): `crates/mandate-graph/src/record.rs:109` (`RemoveRelation`), `:168` (`RevokeGrant`), `crates/mandate-policy/src/record.rs:108` (`SupersedePolicy`), `:164` (`SupersedeAuthorizationModel`). Align them to the contract, or bring a spec change that declares the idempotent accept, before the conformance target maps their outcomes.

## Inherited from wave A, 2026-09-19

- From `model-agreement` adversary pass 1 (2026-09-19): the domain state enums in `crates/mandate-graph` and `crates/mandate-policy` that name a `.State` element are decided against the contract by nobody; this story decides each through its generated enum (`mandate_contract::entities::<Entity>State`) and registers it with `realizes!`.

## Findings routed here (2026-09-21, `review-result:wave-d-obligations-graph-adversary-1`)

- `RemoveRelation` / `RevokeGrant` "required graph revocation visibility cannot be satisfied": the `RevocationWriter` port takes no minimum revision and no implementor consults a `RevisionView`; `require_revision` is called only by `GraphDouble::check` (F1, F2). The adapter's writer must consult the view.
- `RegisterResource` "hierarchy admission fails": `GraphDouble::register_resource` never calls `ancestry`; a chain past `MAX_ANCESTRY_DEPTH` is recorded and every later `check` on it answers `CouldNotAnswer(HierarchyUnbounded)` (F4, case `register_resource_does_not_refuse_a_hierarchy_deeper_than_the_bound_it_declares`, pinned). The adapter refuses at registration.
- `WriteRelationship` "outside tenant membership": `GraphDouble::admits` answers `Denied(Denied)` where the contract's row fixes `TenantMismatch`; the only `TenantMismatch` today comes from a stub in `tests/relationship.rs` (F5, case `the_shipped_subject_admission_answers_a_different_reason_than_the_real_row_for_membership`, pinned).

- 2026-09-21, from `review-result:wave-d-obligations-policy-adversary-2` F4 — a limit on what a no-state-change comparison currently proves, for whoever builds the real adapter to decide. `crates/mandate-policy/tests/obligations.rs:36` says its by-value comparison of the whole `PolicyDouble` shows "no version, rule, role or trusted attribute moved". Three of those four dimensions are compared empty to empty: the fixture `published()` folds only `record_policy` and `record_model`, and neither no-state-change case calls `allow`, `deny`, `require_approval`, `trust_attribute` or `record_role`, so a mutant that cleared `rules`, `trusted` or `roles` would survive. The adversary stated this rather than constructing a case for it, correctly: the three fields are private with no accessor, so a test binary cannot assert on them without modelling the fold. When this story puts a store behind the port, deciding what a refusal must leave unmoved — and giving the fold's other dimensions a way to be observed — is part of the work.
