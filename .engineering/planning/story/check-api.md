---
format: aep.planning-md/1
id: story:check-api
kind: story
status: draft
title: Implement stable PEP check semantics
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:tenancy-topology
- depends_on: story:graph-policy
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-authz/src/availability.rs
- confidence: inferred
  path: crates/mandate-authz/src/ceilings.rs
- confidence: inferred
  path: crates/mandate-authz/src/challenge.rs
- confidence: inferred
  path: crates/mandate-authz/src/context.rs
- confidence: inferred
  path: crates/mandate-authz/src/dossier.rs
- confidence: cited
  path: crates/mandate-authz/src/lib.rs
- confidence: inferred
  path: crates/mandate-authz/src/port.rs
- confidence: inferred
  path: crates/mandate-authz/tests/approval_challenge.rs
- confidence: inferred
  path: crates/mandate-authz/tests/ceilings.rs
- confidence: inferred
  path: crates/mandate-authz/tests/check_contract.rs
- confidence: inferred
  path: crates/mandate-authz/tests/context_binding.rs
- confidence: inferred
  path: crates/mandate-authz/tests/dossier.rs
- confidence: inferred
  path: crates/mandate-authz/tests/outage.rs
- confidence: inferred
  path: crates/mandate-authz/tests/port_double.rs
revision: 11
---
# Implement stable PEP check semantics

## Acceptance

Given a protected request missing a required approval, when the PEP asks the PDP, then it receives allowed=false with a structured scoped challenge and decision identifier.

## Required observations

Validated context required; enforce tenant/space/resource/audience, ceilings and denial precedence. approval-required is allowed=false. PEP outage test denies; return decision correlation/model/policy/revision; runtime contract cases and property tests pass.

## Home: `crates/mandate-authz` alone

`services/authorization` is removed from scope. Package `mandate-authorization` is absent from `dependency-boundaries.json` `libraries`, so `xtask/src/main.rs:119` applies `["clap","serde_json","sha2"]` to it and it cannot name `mandate-authz`; `xtask/src/main.rs:270-272` requires its binary to fail on `serve`. `ownership.md:13` gives `mandate.authorization` to `mandate-authz` as the Rust owner; `components.yaml:55-68` assigns `Check` to the `mandate-authorization` deployment component, not the package.

## Not transitively blocked

`crates/mandate-graph` and `crates/mandate-policy` are 4-line scaffolds and `story:graph-policy` is blocked on `decision-blocker:backend` and `decision-blocker:subject-relations`. This story proceeds anyway: every type `Check` consumes and produces exists — `VerifiedContext` (`crates/mandate-types/src/record.rs:63`), `Decision` and `DecisionChallenge` (`crates/mandate-model/src/lib.rs:117,93`), `DecisionReason` (`crates/mandate-types/src/enumeration.rs`). Only authority lookup is missing, and the dependency arrow already points `mandate-authz → mandate-graph, mandate-policy`, so the consumer declares the required interfaces as traits and the test double lives in this crate. An adapter satisfies them later.

## Units

The coordinator interface commit lands `src/lib.rs` — crate doc, every `mod` line, the `Check` entry-point signature, the two port traits — and the six module stubs; six units then run in parallel.

| Unit | Owns | Test file | Discharges |
|---|---|---|---|
| coordinator, first | `crates/mandate-authz/src/lib.rs` | `crates/mandate-authz/tests/check_contract.rs` | the end-to-end acceptance once the six land: approval missing → `allowed=false`, scoped challenge, `decision_id` |
| `port` | `crates/mandate-authz/src/port.rs` | `tests/port_double.rs` | the graph and policy required interfaces and the deterministic in-crate double |
| `context` | `src/context.rs` | `tests/context_binding.rs` | validated context required; tenant/space/resource/audience binding |
| `ceilings` | `src/ceilings.rs` | `tests/ceilings.rs` | platform and tenant ceiling intersection applied to the combinator's output — **deny precedence itself is `story:graph-policy`'s `precedence` unit and is consumed through the port, not re-implemented** |
| `challenge` | `src/challenge.rs` | `tests/approval_challenge.rs` | `ApprovalRequired` → `allowed=false` with a scoped `DecisionChallenge` |
| `availability` | `src/availability.rs` | `tests/outage.rs` | fail closed when graph, policy or credential authority is unavailable (`combined.md:55`); case `pdp-outage` |
| `dossier` | `src/dossier.rs` | `tests/dossier.rs` | `Decision` assembly: `decision_id`, correlation from context, `revision`, `policy_version`, `model_version` |

## Case ids

`pdp-outage` — the single case with `story: story:check-api`. The "property tests" in the Required observations are hand-rolled deterministic generators on the pattern of `crates/mandate-types/tests/adversary.rs`: no property-testing crate is in `Cargo.lock` and none may be added.

## Contract facts

`authorization.yaml` declares exactly one command, `mandate.authorization.Check` (`:4`), one event `DecisionRecorded` (`:28`), one error `Denied` (`:35`), zero entities. `Explain` is declared nowhere in `systems/`, `generated/` or `docs/` — unmapped, an ESS change for `story:domain-runtime` if wanted, not this story's. The addendum's `CheckRequest { subject, actor, action, resource, context: AuthorizationContext }` (`architecture-addendum.md:685-691`) differs from the contract's `Check(context: VerifiedContext, action, resource)` (`authorization.yaml:5-11`), where `VerifiedContext` already carries subject and actor; `AuthorizationContext` exists nowhere. The contract is what the gate enforces and what this story implements.

## Decisions that apply

`docs/adr/0009-event-sourced-persistence.md` — decisions are events (`DecisionRecorded`); the double's state is a fold. `decision-blocker:backend` constrains the adapter, not this story.

## Dependency ceiling

`mandate-types`, `mandate-model`, `mandate-graph`, `mandate-policy` — already in `crates/mandate-authz/Cargo.toml`; nothing is added, dev-dependencies included. No `serde_json`, no `proptest`. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

`services/authorization`. `Explain`. Any edit to `crates/mandate-graph`, `crates/mandate-policy`, `crates/mandate-model`, `crates/mandate-types`, `systems/mandate`. A concrete backend. `#[ignore]`.

## Scheduling hazard, recorded

`story:agent-authority-kernel` and `story:agent-security` scope `crates/mandate-authz` at directory level. Once this story is at file level, `waves` no longer reports the collision. Both are refined to files before either is scheduled near this story.

## Gate per unit

`cargo fmt -p mandate-authz -- --check`; `cargo clippy -p mandate-authz --all-targets --locked -- -D warnings`; `cargo test -p mandate-authz --locked`, count reported.

## Scope

- `crates/mandate-authz/src/lib.rs` — cited; the crate's only file today; coordinator.
- `crates/mandate-authz/src/port.rs`, `context.rs`, `ceilings.rs`, `challenge.rs`, `availability.rs`, `dossier.rs` — inferred; do not exist.
- `crates/mandate-authz/tests/check_contract.rs`, `port_double.rs`, `context_binding.rs`, `ceilings.rs`, `approval_challenge.rs`, `outage.rs`, `dossier.rs` — inferred; do not exist.
- Removed: `services/authorization`, `crates/mandate-authz` (directory).
- Would collide with: any unit touching `crates/mandate-authz`.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
