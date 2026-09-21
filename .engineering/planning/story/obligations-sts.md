---
format: aep.planning-md/1
id: story:obligations-sts
kind: story
status: implemented
title: Bind mandate-sts's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/sts.json
- confidence: inferred
  path: services/sts/tests/declared_denials.rs
- confidence: cited
  path: services/sts/tests/obligations.rs
revision: 10
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-sts` is one file this story owns: 11 commands, ~61 clauses (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-sts` for every unbound clause of this crate and the step stays green.

## Outcome

`services/sts/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-sts` command as `deferred` on this story, and `cargo test -p mandate-sts --locked --test obligations` is green.

- Implementor result (2026-09-21): of the 21 STS clauses deferred to this story, one is producible by a shipped handler (`RedeemAuthorizationCode` "atomic issuance validation fails" via `ExpiryUnbounded`, arranged through a profile `max_ttl` past the timeline) and is bound (`services/sts/tests/obligations.rs`, a denial case and a no-state-change case; green first, then falsified three ways); the other twenty cannot be produced by the shipped path and were re-pointed per the README rule — 14 authority/context clauses to `decision-blocker:guards`, 6 durable-commit clauses to `decision-blocker:epoch-atomicity` — plus 9 `exchange-*` case rows to `story:constrained-exchange` and one to `story:protocol-adapters`. Table: `mandate-sts` 32 real / 20 deferred; all 69 / 8 / 99. 201 `mandate-sts` tests; the step green. Class finding for the six peer documents (federation 20, model 38, graph 10, identity 8, policy 2 deferred to their own binding stories, of which 37 are authority/durability clauses): the same rule applies; relayed to the running federation unit. Adversary dispatched.

- Adversary 1 ruled (2026-09-21, `review-result:wave-d-obligations-sts-adversary-1`): the one clause bound is the `narrowing` half of "narrowing/atomic issuance validation fails" (`redemption.rs:343-348` narrows the expiry to `profile_bound.min(code_bound)`; `ExpiryUnbounded` is that narrowing failing); "atomic issuance validation fails" defers to `decision-blocker:epoch-atomicity`; the crate's own `declared_denials.rs` attribution follows (scope extended, inferred). F2 (a profile bound past the readable year is admitted and issues an expiry the crate reads back as `None`) → `story:sts-lifetime-bounds`. F4 → one README paragraph on blocker deferrals, by the coordinator.

- Result (2026-09-21, at merge): the Outcome above overstated what this story could reach. Of 52 `mandate-sts` clauses the unit **bound 1** on the real path (`RedeemAuthorizationCode` "narrowing", two cases after correction 2 added the zero-span profile bound) and **re-pointed 20** to the owner of the path that would have to produce the denial — 14 authority/context clauses to `decision-blocker:guards`, 6 durable-commit clauses to `decision-blocker:epoch-atomicity` — plus 9 `exchange-*` case rows to `story:constrained-exchange` and 1 to `story:protocol-adapters`. The remaining 31 were already real-covered by `services/sts/tests/declared_denials.rs`. Final table on the unit: `mandate-sts 52 / 32 / 0 / 20` (`cargo run -p xtask -- obligations-registry`, coordinator verification 2026-09-21). The Acceptance — "no clause of a `mandate-sts` command is `deferred` on this story" — is met by re-pointing as well as by binding, and the gate cannot distinguish the two; `review-result:wave-d-obligations-sts-adversary-1` F5 and `-adversary-2` F6 both say so.
- Adversary pass 2 ruled and corrected (`review-result:wave-d-obligations-sts-adversary-2`): 5 warnings, 2 notes, 0 blockers. Correction 2 added the zero-span case (`narrowing_refuses_a_zero_span_profile_bound_and_moves_nothing`), folded the tautological `fold(x) == fold(x)` no-state-change assertion into a seeded before/after comparison, and corrected the `:343-348` citation to `:343-350`. Four pre-existing findings were routed, not fixed here: the draw-before-refusal pair to `story:sts-lifetime-bounds`' sibling `story:sts-refusal-draws-nothing`. Mutation control: deleting `.filter(|span| *span > 0)` at `services/sts/src/redemption.rs:346` turned exactly the two zero-span cases red (2 of 207); `md5` of the source identical after restore.
