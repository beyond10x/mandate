---
format: aep.planning-md/1
id: story:graph-policy
kind: story
status: implemented
title: Implement graph and policy ports with test doubles
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
- depends_on: story:domain-runtime
scope:
- confidence: cited
  path: crates/mandate-graph/src/double.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: cited
  path: crates/mandate-graph/src/port.rs
- confidence: cited
  path: crates/mandate-graph/src/record.rs
- confidence: cited
  path: crates/mandate-graph/src/relationship.rs
- confidence: cited
  path: crates/mandate-graph/src/revocation.rs
- confidence: cited
  path: crates/mandate-graph/src/topology.rs
- confidence: cited
  path: crates/mandate-graph/tests/adversary_double.rs
- confidence: cited
  path: crates/mandate-graph/tests/adversary_double_2.rs
- confidence: cited
  path: crates/mandate-graph/tests/boundary.rs
- confidence: cited
  path: crates/mandate-graph/tests/double.rs
- confidence: cited
  path: crates/mandate-graph/tests/port.rs
- confidence: cited
  path: crates/mandate-graph/tests/record.rs
- confidence: cited
  path: crates/mandate-graph/tests/relationship.rs
- confidence: cited
  path: crates/mandate-graph/tests/revocation.rs
- confidence: cited
  path: crates/mandate-graph/tests/topology.rs
- confidence: cited
  path: crates/mandate-policy/src/double.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: cited
  path: crates/mandate-policy/src/port.rs
- confidence: cited
  path: crates/mandate-policy/src/precedence.rs
- confidence: cited
  path: crates/mandate-policy/src/record.rs
- confidence: cited
  path: crates/mandate-policy/tests/adversary_precedence.rs
- confidence: cited
  path: crates/mandate-policy/tests/adversary_precedence_2.rs
- confidence: cited
  path: crates/mandate-policy/tests/boundary.rs
- confidence: cited
  path: crates/mandate-policy/tests/double.rs
- confidence: cited
  path: crates/mandate-policy/tests/port.rs
- confidence: cited
  path: crates/mandate-policy/tests/precedence.rs
- confidence: cited
  path: crates/mandate-policy/tests/record.rs
revision: 64
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

## Scope

Rewritten at wave-2 close from unit commit `92dd525e99d9eec22e5df2f0c5a27806fae38e5d`, merged as `5cf9fb9`.

- `crates/mandate-graph/src/lib.rs`, `src/record.rs`, `src/port.rs`, `src/topology.rs`, `src/relationship.rs`, `src/revocation.rs`, `src/double.rs` — cited.
- `crates/mandate-graph/tests/boundary.rs`, `tests/record.rs`, `tests/port.rs`, `tests/topology.rs`, `tests/relationship.rs`, `tests/revocation.rs`, `tests/double.rs` — cited; 66 cases plus 2 doctests.
- `crates/mandate-policy/src/lib.rs`, `src/record.rs`, `src/port.rs`, `src/precedence.rs`, `src/double.rs` — cited.
- `crates/mandate-policy/tests/boundary.rs`, `tests/record.rs`, `tests/port.rs`, `tests/precedence.rs`, `tests/double.rs` — cited; 55 cases plus 2 doctests.
- `crates/mandate-graph/tests/adversary_double.rs`, `tests/adversary_double_2.rs`, `crates/mandate-policy/tests/adversary_precedence.rs`, `tests/adversary_precedence_2.rs` — cited; the two adversary passes' 13 kept cases (`review-result:wave2-graph-policy-adversary-1`, `-2`).
- Read, not written: `systems/mandate/domains/{graph,policy}.yaml`, `generated/schema/**`, `docs/architecture/combined.md`.
- Untouched: `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`; the ceiling `mandate-types`, `mandate-model`, `std` held; no serde; no engine name.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Residue after wave 2

- `graph.yaml` declares no grant-creation command, so `record_grant` is the double's only grant path and admits a padded or empty role by design; the read path refuses the name instead — `story:declared-writers`.
- The relation-tenancy comparison in `GraphDouble::holds` is unreachable from outside the crate (`write_relationship` refuses a foreign resource first); kept as defence in depth, held by no case, both rounds' mutation probes agree.
- `Unanswered::SubjectUnresolved` was removed because no path of the double produces it; an adapter whose membership source is down answers `NotCaughtUp`. A future adapter that must distinguish the two brings the variant back with a path that produces it.
- `Combined::Nothing` has two readings — identity when composed, denial when decided — documented side by side; `story:check-api` composes at the top level and decides once.
- `GraphDouble` and `PolicyDouble` are `pub` by design; `story:testkit-doubles` is their home.
- The graph accept/deny channel on the globally keyed `ResourceId` is an existence oracle bounded by the UUID space, disclosed only inside the caller's organization.
