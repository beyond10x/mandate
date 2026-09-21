---
format: aep.planning-md/1
id: story:obligations-policy
kind: story
status: implemented
title: Bind mandate-policy's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/policy.json
- confidence: cited
  path: crates/mandate-policy/tests/obligations.rs
revision: 7
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-policy` is one file this story owns: 2 commands, ~8 clauses; denials as PolicyError (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-policy` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-policy/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-policy` command as `deferred` on this story, and `cargo test -p mandate-policy --locked --test obligations` is green.

- Result (2026-09-21, at merge): **`mandate-policy` decides none of its 10 published denial clauses on a shipped path.** The Outcome above said the crate's rows would move from `deferred` to `real_covered`; `real_covered` is 0 before and after. What moved is `double_only` and `deferred`, and in both directions for good reasons. Final table `mandate-policy 10 / 0 / 6 / 4` (`cargo run -p xtask -- obligations-registry`, coordinator verification 2026-09-21). The Acceptance — "no clause of a `mandate-policy` command is `deferred` on this story" — is met entirely by re-pointing and re-classification.
- Why nothing is real: `impl PolicyAdministration` exists exactly twice in the workspace — `mandate_policy::double::PolicyDouble` (`crates/mandate-policy/src/double.rs:239`) and a stub inside the test binary `crates/mandate-policy/tests/port.rs:203`, which is not an admissible `double` value — and no handler anywhere names either supersede command. `crates/mandate-conformance/src/commands/mod.rs:200-209` says the same thing independently, rowing both commands unsupported because "policy administration is a double", and both declared events are `deferred` in `contracts/coverage.json`. Two adversary passes attacked that enumeration and could not break it.
- The unit's own finding, and the reason `double_only` first **fell** from 6 to 4: two of the six `double` rows it inherited named cases that never call the command they were cited for — `an_answer_whose_model_version_is_not_observable_is_refused` and `an_answer_that_cannot_be_attributed_to_a_version_is_refused` both enter `PolicyEvaluator::evaluate`, not a supersede path. Withdrawn, and proved by mutation: deleting each guard left those cases green. The fall is the finding.
- Then `double_only` rose to 6 again for a different reason: adversary pass 2 and ruling (a) split both "no later X version is recorded for that organization" clauses into their two conditions, because `contracts/obligations/README.md` states "one clause per condition the cause enumerates" and `story:obligations-authz` had applied that rule the same week (9 clauses to 15). Two documents applying one named rule at different granularities make the registry's counts incomparable.
- **A claim that a mutation fells a case is worth exactly what the mutation says.** Correction 1's paragraph stated that dropping either half of the later-version predicate fells its two new cases; adversary 2 ran all four mutations and dropping the `current()` half left all 76 cases green. The ruling took the fix that closes the gap rather than the one that softens the sentence: correction 2 folded an already-superseded later record into each case, and all four mutations now fell a case. The guard is real, load-bearing under test, and unreachable through any path a caller has — recorded on `story:unpublished-refusals`.
- Four findings routed rather than fixed, all pre-existing and all measured: a published 409 `wrong-state` refusal the only implementor answers as an accepted repeat; a port refusing caller input with no clause published for it; a later-version guard deciding by fold order with `Policy::version` compared nowhere; and the finding that overturned a coordinator ruling — `mandate-policy` does not decide `mandate.graph.WriteRelationship`'s authorization-model clause either, because `AuthorizationModel::schema` is written by `record_model` and read by nothing.
