---
format: aep.planning-md/1
id: review-result:wave-d-obligations-authz-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-authz
relations:
- reviews: story:obligations-authz
revision: 1
---
```
unit: story:obligations-authz — mandate-wd-obl-authz, branch impl/obligations-authz, base a2a55c3 (unit uncommitted in the tree)
verdict: NEEDS-CHANGE (1 blocker, 3 warnings, 3 notes)
cases: 78 → 81 executed, 3 red when written (crates/mandate-authz/tests/adversary_obligations_authz_1.rs)
origin: introduced 3 / pre-existing 4 / undecided 0
suite: cargo test -p mandate-authz --locked --no-fail-fast → 81 executed / 11 targets, 3 failed, exit 101; the 10 pre-existing targets 78/78 green; fmt 0; clippy all-targets 0; obligations-registry exit 0 `mandate-authz 9 7 2 0` / `all 180 79 13 88`; xtask obligations_registry 24 passed
mutation probes (scratch copy, deleted; worktree never mutated): deleting the tenancy.admits guard at context.rs:103-105 kills one case that no clause names and leaves all three rows of the credential clause green; deleting the direct guard at context.rs:109-111 leaves a_context_that_is_not_direct_is_refused green; dropping Ceiling::admits' denied_actions half leaves a_ceiling_that_does_not_admit_the_action_refuses_an_otherwise_allowed_request green
attacked and unbroken: the forwarding-site enumeration is exactly three (decision.rs:196 is the precedence fold's own and lib.rs:251 is the second hop of context.rs:118); the discriminator applied consistently across all nine clauses; clause tiling re-derived by hand and against tiles(), 5 → 9 confirmed, every half a verbatim substring and none inside a sibling; pdp-outage drives its corpus given, action and expected; both double values are library paths and neither defers to the binding story; 2 of 2 line-carrying citations resolve to spans holding the cited phrase — no stale span in this unit
```

```findings
- file: contracts/obligations/authz.json
  line: 14
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the clause ''Credential-derived context is invalid/revoked/expired/stale'' is counted real_covered on three rows that all drive the direct guard at context.rs:109-111 and decide none of the four conditions it publishes; the only test deciding ''invalid'' is named by no clause, and deleting the invalid guard leaves all three rows green'
- file: contracts/obligations/authz.json
  line: 218
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the autonomous-ceiling cases row claims a scenario the crate cannot express: mandate.delegation.AgentCapabilityCeiling is identified by agent_id and mandate_authz::evaluate::Ceiling carries no agent, so the bound test''s installation ceiling refuses every member of the organization equally and does not drive the corpus given'
- file: contracts/obligations/authz.json
  line: 128
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the clause ''the required PDP/graph/credential authority is unavailable'' publishes three authorities and both rows it names take the policy port down; the graph outage reaches the same declared reason through evaluate.rs:273 and is asserted by no named row, and the credential authority by nothing at all'
- file: crates/mandate-authz/tests/context.rs
  line: 340
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'a_context_that_is_not_direct_is_refused asserts on the direct() predicate and never calls bind or check, so deleting the guard at context.rs:109-111 leaves it green; it is row 1 of a clause and is not evidence that mandate.authorization.Check refuses anything'
- file: contracts/obligations/authz.json
  line: 144
  category: judgement
  severity: note
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the no_state_change re-point to story:declared-writers has all four cited facts holding, but that story''s scope lists 21 paths and none under crates/mandate-authz, so the obligation waits on work whose declared scope cannot reach it'
- file: .engineering/planning/story/obligations-authz.md
  line: 25
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the Outcome says every clause is decided on the real path and promises one no-state-change case per command; two of nine clauses are double_only and no_state_change is empty'
- file: crates/mandate-authz/tests/obligations.rs
  line: 1
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the module doc opens mid-sentence — a leading clause was lost, leaving ''The security-corpus scenario ... binds to this crate and that no test already here decides end to end'''
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Confirmed, and the clause is split — the same remedy the unit already applied twice.** Four conditions are published and three rows all drive one guard. Split `"Credential-derived context is invalid"` / `"revoked"` / `"expired"` / `"stale"` as far as the step admits (walk the cause; if a half lies inside a sibling, take the smallest admitted text, as `mandate-model` had to for `"team or"`). `invalid` takes `context::an_organization_that_admits_no_authority_refuses_the_context`, which decides it at `crates/mandate-authz/src/context.rs:103-105` and which no clause currently names — that is the row the document was missing, not one it should have invented. `revoked`, `expired` and `stale` are decided by nothing in the crate: re-point them with the source line that shows the guard does not exist. This is a pre-existing defect the unit inherited and is now the first to be able to see. | correction 1 |
| F1b | **Coordinator's addition, same measurement.** What those three rows *do* decide — `!direct(context)`, a delegated or execution-bearing context refused closed — is a refusal `mandate.authorization.Check`'s declared cause publishes **no** clause for. Fourth instance of that class this half. Appended to `story:unpublished-refusals`. | story |
| F2 | **Upheld, blocker. Revert the row.** `mandate.delegation.AgentCapabilityCeiling` is identified by `agent_id` in `generated/ir/system.json`; `mandate_authz::evaluate::Ceiling` has no agent field and `applies()` keys on organization alone, so the bound test's "installation ceiling" refuses every member of the organization equally and the corpus `given` — *an agent's* grant against *an agent's* ceiling — is never driven. `crates/mandate-authz/src/lib.rs:46-49` already says the `agent_id` binding is `story:agent-authority-kernel`'s, and that story is `draft`, so it can hold the deferral. `autonomous-ceiling` goes back to `"tests": []`, `"blocked_on": "story:agent-authority-kernel"`. A `cases` row is a claim that the named test decides the corpus scenario end to end; binding one that drives something adjacent is worse than deferring it, because the deferral is visible and the binding is not. The unit was right to look for a binding and right to be refused one. | correction 1 |
| F3 | **Confirmed; split.** Three authorities published, both named rows take the policy port down. Split into the PDP half, the graph half and the credential half. The graph half is decidable and the adversary drove it end to end — `AuthzRevision::new("never-issued")` → `CouldNotAnswer(NotCaughtUp)` → `crates/mandate-authz/src/evaluate.rs:273` → `DenialReason::Unavailable` — so bind it with a case of the unit's own. The credential half is decided by nothing; re-point it. | correction 1 |
| F4 | **Confirmed; withdraw the row.** `a_context_that_is_not_direct_is_refused` asserts on the `direct()` predicate and never calls `bind` or `check`, and the mutant proves it: deleting the only place the command's path calls that predicate leaves the test green. Under the recorded rule — a row is evidence of a command only when the command's own path calls the deciding function — it is not evidence and must not be a row. Withdrawing it is subsumed by F1's split; make sure the split does not carry it forward. The test itself stays where it is; it is a fine unit test of a predicate and a bad row in a denial registry. | correction 1 |
| F5 | **Upheld, and the fix is the coordinator's.** The four cited facts hold and the routing is right; what is wrong is that `story:declared-writers`' `scope:` lists 21 paths and none under `crates/mandate-authz/`, so the obligation waits on work whose declared scope cannot reach it. The coordinator adds `crates/mandate-authz/src/lib.rs` to that story's scope as `inferred`. This is the store's own consistency check working as intended — a deferral is only as good as the scope of the story it names, and nothing else in the wave would have caught it. | coordinator |
| F6 | **Confirmed.** Result line at merge. | coordinator |
| F7 | **Confirmed.** Restore the lost leading clause of the module doc. | correction 1 |
