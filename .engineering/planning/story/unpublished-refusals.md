---
format: aep.planning-md/1
id: story:unpublished-refusals
kind: story
status: draft
title: Every refusal a shipped decider makes has a published outcome the registry binds
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: inferred
  path: contracts/obligations/README.md
- confidence: cited
  path: contracts/obligations/model.json
- confidence: cited
  path: crates/mandate-model/src/tenancy.rs
- confidence: cited
  path: crates/mandate-model/tests/adversary_obligations_model_1.rs
- confidence: inferred
  path: generated/conformance/suite.json
- confidence: inferred
  path: generated/ir/system.json
- confidence: inferred
  path: generated/openapi
- confidence: inferred
  path: systems/mandate/domains/authorization.yaml
- confidence: inferred
  path: systems/mandate/domains/graph.yaml
- confidence: inferred
  path: systems/mandate/domains/policy.yaml
- confidence: cited
  path: systems/mandate/domains/tenancy.yaml
- confidence: cited
  path: xtask/src/obligations_registry.rs
- confidence: cited
  path: xtask/tests/obligations_registry.rs
revision: 9
---
## Why

The obligations registry (`contracts/obligations/README.md`) tiles each implemented command's `denied` cause into clauses and binds them to tests. It reads no other outcome and checks no direction from code to contract (`review-result:wave-d-obligations-model-adversary-1` F1–F3; `review-result:wave-d-obligations-sts-adversary-2` and the model implementor's note). Three consequences on the shipped fold: `decide_close_organization` (`crates/mandate-model/src/tenancy.rs:633`) and `decide_retire_team` (`:861`) refuse a second closure and an already-retired team — the commands' declared `wrong-state` outcomes in `generated/ir/system.json`, which no row binds; the three creators refuse an already-recorded identity (`:588`, `:821`, `:1010`) and declare no `wrong-state` outcome, so that refusal has no published home; and nothing checks that every `Denied` site in a shipped decider maps to a published outcome.

## Outcome

Every `wrong-state` outcome of an implemented command is an obligation row in `contracts/obligations/<crate>.json` bound to a real-path test; every refusal site in `crates/*/src` and `services/*/src` maps to a published outcome or clause, and `cargo xtask obligations-registry` refuses one that does not; the creators' already-recorded-identity refusal has a declared outcome in `systems/mandate/domains/tenancy.yaml` (specification corrected, never weakened).

## Acceptance

`crates/mandate-model/tests/adversary_obligations_model_1.rs` cases `close_organization_refuses_on_a_condition_no_clause_of_its_declared_cause_publishes`, `retire_team_refuses_a_team_inside_the_verified_organization_that_no_clause_publishes` and `the_creating_commands_refuse_although_the_document_defers_every_clause_they_publish` are flipped to assert a published home and are green; `cargo xtask obligations-registry` reports `wrong-state` rows per crate and exits non-zero on an unpublished refusal site (a case in `xtask/tests/obligations_registry.rs` shows the refusal).

- 2026-09-21, from `review-result:wave-d-obligations-graph-adversary-2` F2: `crates/mandate-graph/src/relationship.rs`'s `admit` refuses a relation name that `declared_name` does not recognise (`GraphError::Denied(DenialReason::Denied)`), and `mandate.graph.WriteRelationship`'s declared `condition.cause` publishes no clause for it. The crate's own module doc says so at `:8` — "a relation name that names nothing" is listed as decided here — while the cause enumerates the subject, the tenancy and the model admission and not the name. Two `declared_name` cases in `crates/mandate-graph/tests/obligations.rs` decide it and, after the ruling, name no clause: they are the evidence that the refusal exists and the contract does not publish it. This is the code → contract direction the model unit named on this story from the other side, now with a second instance.

- 2026-09-21, from `review-result:wave-d-obligations-policy-adversary-1` F3 — a third instance of the class, in `mandate-policy`. `crates/mandate-policy/src/double.rs:286`, the port's first branch, refuses an id it holds no record of with `PolicyError::Denied(Denied)` — the same error value that witnesses the clause `contracts/obligations/policy.json:30` publishes as decided — and neither `mandate.policy.SupersedePolicy`'s nor `mandate.policy.SupersedeAuthorizationModel`'s declared cause enumerates an unresolved id. `id` is caller input on both commands per the IR, and the unit's own `no_state_change` case drives that branch at `crates/mandate-policy/tests/obligations.rs:209`. So a document whose stated purpose is "the clause-level map from **every** external denial an implemented command can produce" publishes nothing for a refusal the shipped port produces on caller input.
- 2026-09-21, from the same pass F1 — the converse, and the sharper one: a refusal the contract **publishes** that the implementation does not make. `generated/openapi/mandate-authorization.yaml:251-256` publishes HTTP 409 for `SupersedePolicy` and `:903-912` fixes it to `error: mandate.policy.Denied`, `outcome: wrong-state`; the lifecycle gives `supersede` `from: ["Recorded"]`. The only implementor of `PolicyAdministration` answers an already-superseded subject with `Ok(Superseded { outcome: AlreadyRecorded })`, and `crates/mandate-policy/tests/double.rs:221` drives exactly that and asserts the accept. The crate's reason is at `crates/mandate-policy/src/port.rs:296-303`, citing ADR-0009, and it appears in neither generated document. Reconciling this is a `systems/mandate/domains/policy.yaml` decision — declare the outcome away, or answer `Denied` and move the idempotence claim to the caller — not a registry row, and the registry cannot see it either way because it reads the `denied` cause and not the `wrong-state` outcome.
- 2026-09-21, from the same pass F2, recorded as a property and not as work: `crates/mandate-policy/src/double.rs:262` decides "no later policy version is recorded for that organization" by **fold order**, searching `policies[position + 1..]`; `Policy::version` is compared nowhere. Folding `2026-09-18.2` before `2026-09-18.1` therefore supersedes the newer version and leaves the older current, with the newer in `Superseded` — whose own declaration at `crates/mandate-policy/src/record.rs:23-25` reads "a later version is current". The adversary reached it only through the `pub record_policy` in an order no shipped caller produces, so it is `INFEASIBLE` today and becomes reachable the moment a real adapter folds from a store.

- 2026-09-21, from `review-result:wave-d-obligations-authz-adversary-1` F1 — a fourth instance, in `mandate-authz`, and the one that reads most clearly. `mandate.authorization.Check`'s three rows for the clause "Credential-derived context is invalid/revoked/expired/stale" all drive the **`direct`** guard at `crates/mandate-authz/src/context.rs:109-111`: a delegated or execution-bearing context is refused closed. That refusal is real, is reached on the command's own path, and the declared cause publishes **no clause for it** — it is not any of `invalid`, `revoked`, `expired` or `stale`. So the registry named three tests for four conditions none of them decides, while the refusal those tests do decide had nowhere to be named. The adversary's mutant makes the point in one line: deleting the guard that decides `invalid` (`context.rs:103-105`) leaves all three rows green.

- 2026-09-21, the `mandate-authz` instance in its final form, after the clause split landed. `crates/mandate-authz/src/context.rs:109-111` refuses a delegated or execution-bearing context — `!direct(context)` → `DenialReason::Denied` — and `mandate.authorization.Check`'s declared cause names no condition for it: no verbatim substring of the cause says "not direct". Two tests decide that refusal on the command's own path (`context::a_delegated_request_is_refused_closed_and_reads_nothing` and `context::a_context_naming_a_delegation_or_an_execution_is_refused_closed`), and after the split they are **rows of nothing** — the correction rightly declined to invent a clause for them, because a clause is a verbatim substring of the declared cause and there is none to take. So the crate decides a refusal it does not publish, and two good tests have nowhere to be named. That is the same shape as `mandate-graph`'s `declared_name` and `mandate-policy`'s unresolved id, and it is the cleanest instance of the four: the tests exist, they pass, they drive the command, and the contract has no place for them.

- 2026-09-21, from `story:obligations-policy` correction 2, beside the fold-order entry above and sharpening it. The `current()` conjunct of both later-version guards (`crates/mandate-policy/src/double.rs:264` and `:301`) **can only decide a refusal on a fold the shipped writer cannot produce.** `crates/mandate-policy/src/record.rs:23-25` defines `Superseded` as "a later version is current and this one is kept for attribution", so a fold whose later same-organization records are all superseded contradicts its own projection — and that is the only shape in which `current() && organization_id == organization` answers differently from `organization_id == organization` alone. The unit's two cases now build it through the `pub` `record_policy` / `record_model` directly, which is the only way the conjunct decides anything today, and all four mutations of the two predicates now fell a case. What this leaves on the record is a guard that is real, load-bearing under test, and unreachable through any path a caller has: when a real adapter folds from a store, whether that adapter can produce the shape — and what it should answer if it does — is a question the adapter's story has to settle.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** obligations registry + specification — cited
- **Files:** `xtask/src/obligations_registry.rs`, `xtask/tests/obligations_registry.rs`, `crates/mandate-model/tests/adversary_obligations_model_1.rs:229,288,348`, `systems/mandate/domains/tenancy.yaml`, `contracts/obligations/model.json`, `crates/mandate-model/src/tenancy.rs` (deciders now at `:656,:698,:889,:929,:1078`) — cited
- **Also likely:** `generated/{ir/system.json,openapi,conformance/suite.json}`; `systems/mandate/domains/{graph,policy,authorization}.yaml` (the tree-wide scan reaches `relationship.rs:91`, `mandate-policy/src/double.rs:286`, `mandate-authz/src/context.rs:109`) — inferred
- **Confidence:** medium — the body names no mechanism for the code-to-contract refusal scan
