---
format: aep.planning-md/1
id: story:cross-crate-clauses
kind: story
status: active
title: A clause decided in another crate names that crate
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: inferred
  path: contracts/conformance/obligations-report.json
- confidence: cited
  path: contracts/obligations/README.md
- confidence: inferred
  path: contracts/obligations/authz.json
- confidence: cited
  path: contracts/obligations/federation.json
- confidence: inferred
  path: contracts/obligations/graph.json
- confidence: inferred
  path: contracts/obligations/identity.json
- confidence: inferred
  path: contracts/obligations/model.json
- confidence: inferred
  path: services/sts/tests
- confidence: cited
  path: xtask/src/obligations_registry.rs
- confidence: cited
  path: xtask/tests/obligations_registry.rs
revision: 14
---
## Why

`contracts/obligations/README.md` holds a clause row to the entry's crate. Two clauses of `mandate-federation` commands are decided in another crate: `AuthorizePublicClient` "STS code issuance/narrowing is refused" and `DisableOAuthClient` "disablement cannot stop the issuance of new authorization codes to it" are answered by `mandate-sts` code reached through the composition at `services/control-plane/src/adapters.rs:1046`. No test the binding story could write in `mandate-federation` binds them, and every story that owns the path is terminal, so the rows can only defer for ever (`review-result:wave-d-obligations-federation-adversary-1` F3).

## Outcome

A clause row may carry `decided_in: <crate>`; the same-crate rule then holds that row to the named crate, `xtask/src/obligations_registry.rs` refuses a `decided_in` naming a crate outside the workspace or equal to the entry's own, and the README describes the field.

## Acceptance

The two federation rows name `mandate-sts` tests under `decided_in` and `cargo xtask obligations-registry` counts both in `real_covered`; `cargo test -p xtask --locked --test obligations_registry` carries a case refusing `decided_in` equal to the entry's crate and one refusing a crate that is not a workspace member.

### Amended 2026-09-23, wave K

The two adversary passes on unit K1 (`review-result:wijk-k1-cross-crate-adversary-1`, `-2`) showed
that neither row, read closely, is decided by a `mandate-sts` test in full:

- `mandate.federation.AuthorizePublicClient`'s "STS code issuance/narrowing is refused" names two
  conditions. Nothing in `mandate-sts` narrows (`services/sts/src/code.rs:39-42`). The row is split:
  **"STS code issuance"** is decided in `mandate-sts` under `decided_in` and counted in
  `real_covered`; **"narrowing is refused"** is deferred to `story:agent-authority-kernel`, the story
  `contracts/obligations/sts.json` already defers authority narrowing to.
- `mandate.federation.DisableOAuthClient`'s "disablement cannot stop the issuance of new
  authorization codes to it" is a condition under which `DisableOAuthClient` itself is refused;
  `disable_oauth_client` (`crates/mandate-federation/src/disable.rs:197-226`) has no such refusal and
  no test decides it. It is deferred to `decision-blocker:epoch-atomicity`.

The step's refusals stand as first stated: `decided_in` equal to the entry's crate, and a crate that
is not a workspace member, are refused by cases in `xtask/tests/obligations_registry.rs`.

## Also in scope: one test id, one kind

`xtask/src/obligations_registry.rs:837` validates a row's kind against the obligation it sits in and never compares ids across obligations, so one case could discharge a clause's `denial` row and a command's `no-state-change` row (`review-result:wave-d-obligations-identity-adversary-1` F6; no live instance in the seven documents on 2026-09-21). The step refuses a test id named under two different kinds; the README states the rule.

- 2026-09-21, from `review-result:wave-d-obligations-graph-adversary-2` F4 — a second gap in the registry step, beside the one pass-1 F6 recorded. The step checks only that a `double` row's `double` field is **non-empty** (`xtask/src/obligations_registry.rs:880-887`); it never checks that the value is a path anything can resolve. `contracts/obligations/graph.json` shipped `"mandate-graph::relationship::Members"`, which is not a Rust path at all (a hyphen where a crate name needs an underscore) and which named a stub defined inside the test binary `crates/mandate-graph/tests/relationship.rs:85`. The rule the coordinator recorded and the graph unit now follows: **a `double` value is a `::`-separated Rust path into a library target**, because a stand-in nothing outside one test binary can name is not a stand-in a later reader can check the classification against. The step should refuse what it currently accepts.
- 2026-09-21, from the same pass F2: `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by the authorization model" defers here. `crates/mandate-graph/src/relationship.rs:10` says the refusal is `mandate-policy`'s, and `contracts/obligations/README.md` holds clause rows to the entry's own crate, so no row `graph.json` may carry can cover it — the same shape as the two STS-decided federation clauses this story already holds.

- 2026-09-21, a third step gap, measured by the `obligations-identity` correction while applying a coordinator ruling. `xtask/src/obligations_registry.rs:276-284` sends `cases` rows through the same `obligation()` as clause rows, so they inherit the one-path-per-obligation rule at `:906-918` — "a double row belongs where the real path does not cover; where two conditions of one clause have different deciders, the clause is split into them". That remedy has no counterpart for a case: a case is one id in `tests/security/cases.json`, the step refuses a case no document binds (`:314`) and one bound twice (`:318`), so `epoch-overflow` cannot be split into a real half and a double half the way `mandate.graph.RegisterResource` was. The consequence is on the record now: `mandate-identity::increment::epoch_overflow_an_increment_at_the_maximum_is_denied_and_the_generation_does_not_move` reads `path: double` in its clause, because it drives `<IdentityLog as SecurityEpochWrite>::increment`, and `path: real` in the `cases` section beside `mandate-identity::generation::epoch_overflow_the_maximum_generation_does_not_advance`, which is decided by shipped domain code. Both labels are true of their own row; the document cannot state them together, and the run that tried exits 1. One test id carrying two `path` labels in one document is the mislabelling class this half has been removing everywhere else, and here the step requires it.

- 2026-09-21, from `review-result:wave-d-obligations-model-adversary-2` F6 — the granularity rule and the substring rule pull against each other, and where they do the published contract loses. `contracts/obligations/README.md` asks for "one clause per condition the cause enumerates". `xtask/src/obligations_registry.rs:674-680` refuses a clause that is a substring of a sibling. `mandate.tenancy.AddTeamMembership`'s cause enumerates a condition whose name is `team`, and `team` lies inside three of its siblings, so the step refuses the honest text — measured by the model correction at three refusals, exit 1. The smallest text the step admits is `"team or"`, which is half a condition plus an admitted list joiner, and that is what `contracts/obligations/model.json` now publishes as the name of a refusal condition. No rule the step enforces is broken; a consumer reading the denial contract gets a condition called `team or`. The fix is in the pair of rules — the substring check needs to be about position in the cause, which is what the tiling walk already computes, rather than about text containment — and not in any document.

- 2026-09-21, a fourth step gap, from `review-result:wave-d-obligations-policy-adversary-1` F7 — and this one was caught being wrong in the same pass. `xtask/src/obligations_registry.rs:695-714` decides only that a double-backed clause's `blocked_on` is **not the crate's own binding story**. `contracts/obligations/README.md` states a stronger rule — it names the story that owns the port's real implementation, or the open `decision-blocker` holding the question — and nothing measures that, so any live story or open blocker exits 0 and a wrong owner is indistinguishable from a right one.
- The instance, recorded because it is the whole argument for closing the gap: this coordinator ruled on `review-result:wave-d-obligations-graph-adversary-2` F2 that `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by the authorization model" defers **here**, to `story:cross-crate-clauses`, on the strength of `crates/mandate-graph/src/relationship.rs:10` saying the refusal is `mandate-policy`'s. The step accepted it and the unit merged at `18ace4c`. The policy adversary then measured whether `mandate-policy` decides it: `AuthorizationModel::schema` (`crates/mandate-policy/src/record.rs:130-131`) is written by `record_model` and read by nothing, `evaluate` consults only `current_model(…).is_none()` (`crates/mandate-policy/src/double.rs:171`), and two folds with opposite schemas answer the same request identically. Nothing in `mandate-policy` admits or refuses by the authorization model, so a `decided_in: mandate-policy` row could never have bound the clause and this story was the wrong owner. Re-pointed to `story:graph-policy-adapter` in a coordinator alignment commit on the head. **A crate's module doc naming another crate is a hypothesis about where a decision lives, not a measurement of it** — that is twice this wave, and the step is what should have caught both.

- 2026-09-21, a fifth step-level gap and a new class, measured by the `obligations-authz` correction: **`xtask/tests/obligations_registry.rs` asserts on document content by restated literal**, so the step's own suite pins the wording of the documents it checks. `:349` hard-coded `"Credential-derived context is invalid/revoked/expired/stale"`; the moment that clause was legitimately split into its four conditions — the very correction the registry's own rules require — the step's suite went red for a reason that is not a defect. Measured, not inferred: with the pre-split text restored in `authz.json` the case prints `test result: ok. 1 passed`.
- Five more members of the class survive because nothing has moved them yet: `:645` and `:665` restate `mandate-graph` clause literals (`"hierarchy admission fails"`, `"parent is unresolved"`) and will fall the same way the next time `story:obligations-graph` splits a clause; `:508` and `:526` restate federation addendum step text; `:584` restates a federation test id. The fix has a shape and the authz correction demonstrated it on the instance that broke: **read the value out of the document the fixture just mutated**, rather than restating it in the test. A step whose own suite must be edited whenever a document it governs is corrected will, sooner or later, be the reason a correction is not made.

- 2026-09-21, from `review-result:wave-d-obligations-authz-adversary-2` F5 — the granularity conflict recorded above, now with a count and a worked instance. Nine of `contracts/obligations/authz.json`'s fifteen clause texts are **bare nouns whose predicate lives in a sibling clause**: `revoked`, `expired`, `stale`, `tenant`, `audience`, `resource`, `relationships`, `policy`, `graph`. That is what the positional tiling rule at `xtask/src/obligations_registry.rs:795-829` produces from a declared cause written as a slash-list, and the tiling itself re-derives clean — every character accounted for exactly once, no clause nested in a sibling. It is the same shape `mandate-model` had to publish as `"team or"`, at nine instances rather than one.
- The instance that shows the cost: a later binder reading the clause `revoked` cannot tell **credential** revocation, which this document defers to `decision-blocker:guards` because `VerifiedContext` carries no field for a guard to read, from **grant** revocation, which `mandate_graph::record::GrantState::Revoked` decides today and which this same document rows under `relationships`. The step compares clause text and nothing else, so both readings satisfy it. The fix is the one already named above — the substring check wants to be about position in the cause, which the tiling walk already computes — and until it is, a clause name is not a condition name.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `xtask` obligations-registry step — cited
- **Files:** `xtask/src/obligations_registry.rs` (the body's line numbers have drifted about 5; `fn obligation` is now `:842`); `xtask/tests/obligations_registry.rs` (`:349,:508,:526,:584,:645,:665`); `contracts/obligations/README.md`; `contracts/obligations/federation.json:221,:297` (the two `blocked_on: story:cross-crate-clauses` rows) — cited
- **Also likely:** `contracts/obligations/{model,authz,graph,identity}.json`; `services/sts/tests/*.rs` if no existing test decides the two clauses (candidates `issue.rs:279`, `code.rs:517`, `obligations.rs:317`); `contracts/conformance/obligations-report.json` — inferred
- **Symbols:** `decided_in` (not in the tree), `PATHS`, `obligation` — cited
- **Confidence:** high for the xtask step; medium for which contract files change
