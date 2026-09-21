---
format: aep.planning-md/1
id: story:obligations-authz
kind: story
status: implemented
title: Bind mandate-authz's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/authz.json
- confidence: cited
  path: crates/mandate-authz/tests/obligations.rs
revision: 7
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-authz` is one file this story owns: 1 command, ~5 clauses; denials as DenialReason (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-authz` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-authz/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-authz` command as `deferred` on this story, and `cargo test -p mandate-authz --locked --test obligations` is green.

- Result (2026-09-21, at merge): this story was carried into the coordinator handover as **already satisfied** — `mandate-authz 5 / 5 / 0 / 0`, guardrail 5, record it and archive it. It was not. The clause table counts neither `no_state_change` obligations nor `cases` rows, and three deferrals to this story were live in `contracts/obligations/authz.json`; moving the story to a terminal rung would have made `cargo xtask obligations-registry` refuse all three. Final table `mandate-authz 15 / 7 / 2 / 6` (coordinator verification 2026-09-21): **the crate that was published as fully covered decides 7 of 15 published conditions**, and the other eight were not visible because two clauses each bundled several conditions behind rows that decided fewer.
- What the splits found. `"Credential-derived context is invalid/revoked/expired/stale"` named three tests that all drive the `direct` guard at `crates/mandate-authz/src/context.rs:109-111` and decide none of the four conditions; the one test that decides `invalid` was named by no clause at all. `"the required PDP/graph/credential authority is unavailable"` named two rows that both take the policy port down. Split so every clause publishes exactly one condition — 5 clauses became 15 — and then two of the survivors fell on measurement: `"space binding mismatches"` is covered on a branch **no input can reach**, because `crates/mandate-model/src/graph.rs:250` writes `space_id: None` as a literal and is the only constructor of a `Resource`, so `context.rs:138` refuses every scoped request and two independent mutants survive the whole suite; and `"Credential-derived context is invalid"` was bound to a tenancy refusal, `VerifiedContext::credential` being read nowhere in `crates/mandate-authz/src` — four contexts differing only in that field give one identical `Err(InvalidCredential)`.
- Two `cases` rows were examined rather than deferred by default. `pdp-outage` is bound: its test drives `check` with a graph and catalogue that do allow and an unreachable evaluator, so deleting the guard returns `allowed: true` — the invented permission the corpus scenario forbids. `autonomous-ceiling` was bound, then **reverted by the unit on the adversary's evidence**: `mandate.delegation.AgentCapabilityCeiling` declares `agent_id` as its first field and `mandate_authz::evaluate::Ceiling` carries no agent, so the bound test's ceiling refuses every member of the organization equally and the corpus `given` is not driven. It defers to `story:agent-authority-kernel`. A `cases` row claims the named test decides the scenario end to end; binding one that drives something adjacent is worse than deferring it, because a deferral is visible and a wrong binding is not.
- A source comment routed a live gap to a finished story, for the third time this half: `crates/mandate-authz/tests/context.rs:266-269` names `story:event-payloads-for-folds` as the owner of the space gap and that story is `implemented`, so the registry step would have refused the deferral the code itself recommends. Re-pointed to `story:declared-writers` and recorded there beside `mandate.identity.SessionRefreshed` (rowed under an implemented `story:session-epochs`) and `mandate.authorization.DecisionRecorded` (pointed at an implemented `story:check-api`).
- The Acceptance — "no clause of a `mandate-authz` command is `deferred` on this story" — is met by re-pointing as well as by binding, and this unit met it both ways. Nine of the fifteen clause texts are bare nouns whose predicate lives in a sibling, the `"team or"` shape at nine instances; the tiling re-derives clean and the ambiguity is recorded on `story:cross-crate-clauses`.
