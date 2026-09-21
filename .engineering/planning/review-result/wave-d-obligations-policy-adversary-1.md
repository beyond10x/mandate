---
format: aep.planning-md/1
id: review-result:wave-d-obligations-policy-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-policy
relations:
- reviews: story:obligations-policy
revision: 1
---
```
unit: story:obligations-policy — mandate-wd-obl-policy, branch impl/obligations-policy, base a2a55c3 (unit uncommitted in the tree)
verdict: CONFIRMED (0 blockers, 4 warnings, 3 notes)
cases: 68 → 74 executed, 4 red when written (crates/mandate-policy/tests/adversary_obligations_policy_1.rs, 6 cases)
origin: introduced 2 / pre-existing 5 / undecided 0
suite: cargo test -p mandate-policy --locked --no-fail-fast → 74 executed / 13 result-targets, 4 failed, exit 101; with the adversary file deselected 68 executed, 0 failed — the implementor's number reproduced; fmt 0; clippy all-targets 0; obligations-registry exit 0 `mandate-policy 8 0 4 4` / `all 176 77 9 90`; xtask obligations_registry 24 passed
mutation probe (scratch copy, worktree never mutated; src/double.rs md5 ec752a394daef9d57b9a77beb3c8c823 unchanged): dropping the organization predicate from both later-version guards leaves the whole 68-case suite green and fells only the adversary's own two cases
attacked and unbroken: `impl PolicyAdministration` is exactly two and no handler names either supersede command, so real_covered 0 is by construction; the two withdrawn double rows both call PolicyEvaluator::evaluate and never a supersede path; the four surviving double rows each drive the command they are cited for; clause tiling walked by hand against generated/ir/system.json for both commands; `cases: []` and `addendum: []` re-measured over the whole directory with the adversary's own counter (50 ids, 50 rows, each bound once; all nine §5.2 steps named); every cited span read and holding what it is cited for; both re-point targets live and independently corroborated by contracts/conformance/injections.json:1076-1087, which routes both commands' denied outcome to story:graph-policy-adapter as unrealized-command; report arithmetic recomputed by hand
```

```findings
- file: crates/mandate-policy/src/double.rs
  line: 254
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the generated OpenAPI publishes a 409 wrong-state refusal carrying error mandate.policy.Denied for SupersedePolicy, and the only implementor of the port answers an already-superseded subject with Ok(Superseded{AlreadyRecorded}); the crate''s ADR-0009 reason at port.rs:296-303 appears in neither generated document'
- file: crates/mandate-policy/src/double.rs
  line: 262
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'the clause "no later policy version is recorded for that organization" is decided by fold order and Policy::version is compared nowhere, so folding a newer version before an older one supersedes the newer; reached only through the pub record_policy in an order no shipped caller produces'
- file: crates/mandate-policy/src/double.rs
  line: 286
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the port''s first branch refuses an id it holds no record of with the same Denied(Denied) that witnesses the newly bound clause at policy.json:30, and no clause of either declared cause enumerates that condition, so the registry publishes nothing for a refusal the shipped port produces'
- file: crates/mandate-graph/src/relationship.rs
  line: 10
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the graph clause "the relationship is not admitted by the authorization model" was routed to story:cross-crate-clauses on this line''s attribution to mandate-policy, but mandate-policy does not decide it — AuthorizationModel::schema is read by nothing and two folds with opposite schemas answer identically — so a decided_in: mandate-policy row cannot bind it'
- file: crates/mandate-policy/src/double.rs
  line: 301
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'dropping the organization predicate from both later-version guards leaves all 68 cases green including the unit''s four new ones, so the "for that organization" half of the clause this unit newly bound is decided by nothing in the workspace'
- file: .engineering/planning/story/obligations-policy.md
  line: 25
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the Outcome says the crate''s rows move from deferred to real_covered; real_covered is 0 before and after, double_only fell 6 to 4 and deferred rose 2 to 4, and the Acceptance sentence still holds because no clause is deferred on this story'
- file: xtask/src/obligations_registry.rs
  line: 704
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the step decides only that a double-backed clause''s blocked_on is not the crate''s binding story, so the README rule that it names the story owning the port''s real implementation is unmeasured and a wrong owner would exit 0'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Confirmed, pre-existing, routed.** The generated OpenAPI publishes a 409 `wrong-state` refusal for `SupersedePolicy` and the only implementor answers an already-superseded subject `Ok(Superseded{AlreadyRecorded})`. The registry cannot see this — it reads the `denied` cause, not the `wrong-state` outcome — which is exactly the gap `story:unpublished-refusals` was created for on the model pass, from the other direction. Appended there with the two generated spans and the crate's own ADR-0009 reason at `src/port.rs:296-303`, which appears in neither generated document. The unit does not change the contract: reconciling a published outcome with a shipped answer is a `policy.yaml` decision, not a registry row. | story |
| F2 | **Noted, infeasible, no action.** The adversary reached it only by folding a newer version before an older one through the `pub record_policy`, an order no shipped caller produces; it says so itself. Recorded on `story:unpublished-refusals` beside F1 as a property of the fold, not as work. The case stays in the adversary file as the standing record. | story |
| F3 | **Confirmed, pre-existing, routed.** The port's first branch refuses an unresolved id with the same `Denied(Denied)` that witnesses the clause at `policy.json:30`, and neither declared cause enumerates that condition — so a document whose whole purpose is "every external denial an implemented command can produce" publishes nothing for a refusal the shipped port does produce. Third instance of the class this half (`mandate-graph`'s `declared_name`, `mandate-model`'s two `wrong-state` refusals and the creators' already-recorded identity). Appended to `story:unpublished-refusals`. | story |
| F4 | **Confirmed, and it overturns the premise of a ruling I had already taken.** I ruled on `review-result:wave-d-obligations-graph-adversary-2` F2 that `mandate.graph.WriteRelationship`'s clause "the relationship is not admitted by the authorization model" defers to `story:cross-crate-clauses`, on the strength of `crates/mandate-graph/src/relationship.rs:10` saying the refusal is `mandate-policy`'s. The adversary asked whether `mandate-policy` decides it and measured that it does not: `AuthorizationModel::schema` (`crates/mandate-policy/src/record.rs:130-131`) is written by `record_model` and read by nothing, `evaluate` consults only `current_model(…).is_none()` (`src/double.rs:171`), and two folds with opposite schemas answer the same request identically. So the clause is not another crate's to bind — it is nobody's until a real policy engine exists, which is `story:graph-policy-adapter`'s Acceptance in terms ("against the real adapters instead of the doubles"). **The graph document is already merged at `18ace4c`; the coordinator re-points that one clause on the head in an alignment commit.** A crate's own module doc naming another crate is a hypothesis about where a decision lives, not a measurement of it, and this is the second time this wave that reading a comment gave the wrong owner. | coordinator |
| F5 | **Confirmed, introduced, and the only thing correction 1 must change.** The clause the unit newly bound reads "no later model version is recorded **for that organization**", and dropping `model.organization_id == organization` from both later-version guards leaves the whole 68-case suite green — so the organization half is bound by nothing. Correction 1 adds, for each of the two commands, a case that records a later version **under another organization** and asserts the supersede is still refused, and shows it red under that mutation. The adversary's own two cases already demonstrate the shape; the unit needs its own, because an adversary case is not the unit's evidence. | correction 1 |
| F6 | **Confirmed.** Result line on the story at merge. `real_covered` is 0 before and after; what moved is `double_only` 6 → 4 and `deferred` 2 → 4, and the fall is the unit's finding, not a regression. | coordinator |
| F7 | **Confirmed, pre-existing, routed.** `xtask/src/obligations_registry.rs:695-714` decides only that a double-backed clause's `blocked_on` is not the crate's own binding story; the README's actual rule — that it names the owner of the port's real implementation — is unmeasured, and a wrong owner exits 0. F4 above is precisely a wrong owner that the step accepted. Appended to `story:cross-crate-clauses` with the three step gaps already recorded there. | story |
