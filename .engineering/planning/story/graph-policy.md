---
format: aep.planning-md/1
id: story:graph-policy
kind: story
status: active
title: Implement graph and policy ports with test doubles
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
- depends_on: story:domain-runtime
scope:
- confidence: inferred
  path: crates/mandate-graph/src/double.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: inferred
  path: crates/mandate-graph/src/port.rs
- confidence: inferred
  path: crates/mandate-graph/src/record.rs
- confidence: inferred
  path: crates/mandate-graph/src/relationship.rs
- confidence: inferred
  path: crates/mandate-graph/src/revocation.rs
- confidence: inferred
  path: crates/mandate-graph/src/topology.rs
- confidence: inferred
  path: crates/mandate-graph/tests/boundary.rs
- confidence: inferred
  path: crates/mandate-graph/tests/double.rs
- confidence: inferred
  path: crates/mandate-graph/tests/port.rs
- confidence: inferred
  path: crates/mandate-graph/tests/record.rs
- confidence: inferred
  path: crates/mandate-graph/tests/relationship.rs
- confidence: inferred
  path: crates/mandate-graph/tests/revocation.rs
- confidence: inferred
  path: crates/mandate-graph/tests/topology.rs
- confidence: inferred
  path: crates/mandate-policy/src/double.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: inferred
  path: crates/mandate-policy/src/port.rs
- confidence: inferred
  path: crates/mandate-policy/src/precedence.rs
- confidence: inferred
  path: crates/mandate-policy/src/record.rs
- confidence: inferred
  path: crates/mandate-policy/tests/boundary.rs
- confidence: inferred
  path: crates/mandate-policy/tests/double.rs
- confidence: inferred
  path: crates/mandate-policy/tests/port.rs
- confidence: inferred
  path: crates/mandate-policy/tests/precedence.rs
- confidence: inferred
  path: crates/mandate-policy/tests/record.rs
revision: 13
---
# Implement graph and policy ports with test doubles

## Acceptance

Given a grant revoked at revision R, when the graph/policy conformance suite checks inherited access at minimum revision R, then the suite exits zero.

## Required observations

Inheritance, deny precedence, role expansion, revision/consistency and mutation idempotency tested behind ports; graph-revocation's revision-bound denial executes in this crate's suite; backend types do not leak into domain; the named conformance suite includes both revision-bound denial cases and a compile-time API boundary check, and both must execute and pass. Moved to `story:graph-policy-adapter`: choose graph and policy engine in ADR; concrete adapters; engine-issued consistency tokens; storage-level enforcement.

## Deliverable this wave, and the follow-on

Every canonical type the port signatures need is realized (`crates/mandate-types/src/inventory.rs:274,434,369,364,379`; `enumeration.rs:11`). The acceptance is the `revocation` unit's revision-bound denial suite exiting zero against the `graph-double`; on that evidence, with the boundary check compiling, the story moves to `implemented`. The engines, the adapters, `AuthzRevision`'s mapping onto a real consistency token, storage-level exactly-one enforcement and the latency target are `story:graph-policy-adapter`'s, which `depends_on` this story and carries the `backend`, `subject-relations` and `lifecycle` blockers. The one place a blocker reaches port-safe work: the `policy-port` unit's input parameter cannot be frozen until resource-attribute trust and distribution are decided (`original-design.md:3369`, `:738`); it takes an opaque attribute set and the adapter story revisits it.

## Sequencing

`depends_on story:domain-runtime`: the `policy-record` unit lands `Policy` and `AuthorizationModel` projections whose `State` enums that story's `lifecycle-a` unit first declares in `policy.yaml`, and `graph-record` likewise reads `graph.yaml`'s revised transitions.

## Records

`Relation` and `Grant` (`graph.yaml:30-105`) are projections of the graph fold in `crates/mandate-graph/src/record.rs`; `Policy` and `AuthorizationModel` (`policy.yaml:1-49`) in `crates/mandate-policy/src/record.rs`. Plain structs, no `serde` — neither crate may take it. `Resource` is `story:tenancy-topology`'s; this story reaches it only through a resource-lookup port and carries no edge to that story, so no ordering exists between the two. `ownership.md:11-12`'s assignment of these records to `mandate-model` is revised by `story:domain-runtime`'s coordinator row.

## Units

Two coordinator interface commits — one per crate root — then the units, all parallel within their crate. `policy.yaml` declares no commands; the policy units own none.

| Unit | Owns | Test file | Lands | ESS command |
|---|---|---|---|---|
| coordinator, first | `crates/mandate-graph/src/lib.rs`; `crates/mandate-policy/src/lib.rs` | `crates/mandate-graph/tests/boundary.rs`; `crates/mandate-policy/tests/boundary.rs` | `mod` lines, stubs, every port trait signature; the compile-time API boundary check on the pattern of `crates/mandate-model/src/lib.rs:23` | — |
| `graph-record` | `crates/mandate-graph/src/record.rs` | `tests/record.rs` | `Relation`, `Grant` projections and `State` enums | — |
| `graph-port` | `crates/mandate-graph/src/port.rs` | `tests/port.rs` | the required interfaces for all four graph commands; denied distinct from could-not-answer | — |
| `topology` | `crates/mandate-graph/src/topology.rs` | `tests/topology.rs` | parent-chain and inheritance traversal over a resource-lookup port | `RegisterResource` (`graph.yaml:146`), port half |
| `relationship` | `crates/mandate-graph/src/relationship.rs` | `tests/relationship.rs` | relationship write, subject admission, tenancy match; issues the revision | `WriteRelationship` (`:164`) |
| `revocation` | `crates/mandate-graph/src/revocation.rs` | `tests/revocation.rs` | relation removal, grant revocation, revision-bound reads; **the acceptance's suite** | `RemoveRelation` (`:110`), `RevokeGrant` (`:128`) |
| `graph-double` | `crates/mandate-graph/src/double.rs` | `tests/double.rs` | `pub` in-memory double; models "not caught up" as fail-closed | — |
| `policy-record` | `crates/mandate-policy/src/record.rs` | `tests/record.rs` | `Policy`, `AuthorizationModel` projections | — |
| `policy-port` | `crates/mandate-policy/src/port.rs` | `tests/port.rs` | evaluation port returning allow / deny / approval-required, `PolicyVersion`, challenge material; opaque attribute input | — |
| `precedence` | `crates/mandate-policy/src/precedence.rs` | `tests/precedence.rs` | **the deny-precedence combinator** — denies override grants (`combined.md:53`) — and role expansion over `Grant.role`; the single home of precedence, consumed by `story:check-api` | — |
| `policy-double` | `crates/mandate-policy/src/double.rs` | `tests/double.rs` | `pub` in-memory double | — |

Eleven units; five concurrent at most, so two dispatch rounds.

## Case ids

`graph-revocation` (`tests/security/cases.json:613-623`) names `mandate.authorization.Check` only; it executes in `story:check-api`'s crate against this story's ports. This story's own acceptance is the `revocation` unit's suite.

## What `story:check-api` needs from this story

Graph check `(VerifiedContext, AuthoritySubject, ResourceRef, relation, minimum AuthzRevision)` → allowed plus the revision observed, denied distinct from could-not-answer; ancestry expansion; policy evaluation returning components — never a `Decision` (`ownership.md:13`); the deny-precedence combinator; a fail-closed error mapping onto `DenialReason::{Denied, ApprovalRequired, TenantMismatch, Unavailable}`; publicly constructible doubles.

## Decisions that apply

`docs/adr/0009-event-sourced-persistence.md` — records are projections; the doubles are folds. `decision-blocker:backend`, `subject-relations`, `lifecycle` — moved to `story:graph-policy-adapter`; `runtime-decisions.md` rows 5 and 7 name the affected story and are refreshed by `story:domain-runtime`'s coordinator row.

## Dependency ceiling

Both crates: `mandate-types`, `mandate-model`, nothing else, dev-dependencies included. No `serde`. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

Any concrete adapter or engine name. `docs/adr/0010-*`. `crates/mandate-model`, `crates/mandate-authz`, `crates/mandate-testkit`. A new crate. A `Decision` returned from a port. "Role bundles" has no referent in the contract — `Grant.role` is a bare `String` (`graph.yaml:89-90`); the `precedence` unit expands over that string and names the gap in its report. `#[ignore]`.

## Scheduling hazard, recorded

`story:agent-authority-kernel` and `story:agent-security` scope `crates/mandate-policy` at directory level; refined before either is scheduled near this story.

## Gate per unit

`cargo fmt -p mandate-graph -p mandate-policy -- --check`; `cargo clippy -p mandate-graph -p mandate-policy --all-targets --locked -- -D warnings`; `cargo test -p mandate-graph -p mandate-policy --locked`, counts reported.

## Scope

- `crates/mandate-graph/src/lib.rs`, `crates/mandate-policy/src/lib.rs` — cited; 4-line scaffolds; coordinator.
- `systems/mandate/domains/graph.yaml`, `policy.yaml` — cited; read, not written.
- `crates/mandate-graph/src/record.rs`, `port.rs`, `topology.rs`, `relationship.rs`, `revocation.rs`, `double.rs`; `tests/boundary.rs`, `record.rs`, `port.rs`, `topology.rs`, `relationship.rs`, `revocation.rs`, `double.rs` — inferred; do not exist.
- `crates/mandate-policy/src/record.rs`, `port.rs`, `precedence.rs`, `double.rs`; `tests/boundary.rs`, `record.rs`, `port.rs`, `precedence.rs`, `double.rs` — inferred; do not exist.
- Would collide with: any unit touching either crate; `story:domain-runtime`, sequential by edge; `story:graph-policy-adapter`, `depends_on` this story.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
