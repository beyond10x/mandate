---
format: aep.planning-md/1
id: review-result:wave-d-obligations-authz-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-authz
relations:
- reviews: story:obligations-authz
revision: 1
---
```
unit: story:obligations-authz — mandate-wd-obl-authz, branch impl/obligations-authz, base a2a55c3, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 1 warning, 2 notes)
cases: 82 → 86 executed, 4 red when written (crates/mandate-authz/tests/adversary_obligations_authz_2.rs, 581 lines)
origin: introduced 5 / pre-existing 0 / undecided 0
suite: cargo test -p mandate-authz --locked --no-fail-fast → 86 executed / 12 targets, 4 failed, exit 101; with the adversary's four skipped 82 executed 0 failed, reproducing correction 1's number; fmt 0; clippy all-targets 0 for mandate-authz and for xtask; obligations-registry exit 0 `mandate-authz 15 9 2 4` / `all 186 81 13 92`; xtask obligations_registry 24 passed
no src file mutated, transiently or otherwise; every source the cases measure byte-identical to a2a55c3
attacked and unbroken: the tiling re-derived from generated/ir/system.json independently of xtask — complete, no uncovered or double-covered character, no nesting, counts matching the report exactly; all four deferrals' cited spans read and holding; the graph row load-bearing through evaluate.rs:273 with a working control and the only assertion that decision.revision is None through check; story:agent-authority-kernel live and its Required observations naming platform/tenant ceiling intersection, so it can discharge autonomous-ceiling; ruling 1 re-enumerated over all 19 rows, class empty; all three resolvable citations in tests/obligations.rs holding their statement; the no_state_change re-pointing; Ceiling::applies, whose organization key is tested at tests/evaluate.rs:447-451
```

```findings
- file: contracts/obligations/authz.json
  line: 71
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the clause "space binding mismatches" is counted real_covered on two rows whose guard no input reaches — Topology::apply writes space_id as a literal None (crates/mandate-model/src/graph.rs:250), so context.rs:138 refuses every scoped request and deleting the resolve_space guard at context.rs:126-128 leaves both rows green; the crate''s own test comment at tests/context.rs:266-269 calls the condition a contract gap owned by story:event-payloads-for-folds, and a covered obligation is not also a gap'
- file: contracts/obligations/authz.json
  line: 14
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the clause "Credential-derived context is invalid" is bound real to a row that closes an organization and drives Tenancy::admits, and VerifiedContext::credential is read nowhere in crates/mandate-authz/src — four contexts differing only in credential give one identical Err(InvalidCredential), so the fourth condition of the slash-list is counted real_covered on exactly the evidence revoked, expired and stale were deferred to decision-blocker:guards for'
- file: crates/mandate-authz/tests/obligations.rs
  line: 15
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the file states that mandate.delegation.AgentCapabilityCeiling "is identified by agent_id in generated/ir/system.json" and the cited document declares its identity as id (generated/ir/system.json:3128-3135) with agent_id as the first field (:3138); that sentence carries the whole argument for deferring autonomous-ceiling, and pass 1 had written the correct form'
- file: contracts/obligations/authz.json
  line: 121
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the row obligations::a_ceiling_recorded_for_the_organization_refuses_an_action_the_grant_carries returns a byte-identical Denied when the ceiling''s organization field is changed from Some(organization()) to None, so it does not decide the condition its name states; the clause was already real-covered, the command-level ceiling wiring is covered by check_contract.rs:318-337, and the discrimination the name claims is decided by evaluate::every_applicable_ceiling_intersects (tests/evaluate.rs:431-451), which no row names'
- file: contracts/obligations/authz.json
  line: 24
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'nine of the fifteen clause texts are bare nouns whose predicate lives in a sibling clause (revoked, expired, stale, tenant, audience, resource, relationships, policy, graph) — the "team or" shape at nine instances; the tiling itself re-derives clean, but a later binder reading the clause "revoked" cannot tell credential revocation, which is deferred, from grant revocation, which mandate-graph decides today and the document rows under "relationships"'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Upheld, blocker — and the owner the adversary proposed cannot hold it.** The measurement stands: `crates/mandate-model/src/graph.rs:250` writes `space_id: None` as a literal, it is the only constructor of a `Resource`, so `crates/mandate-authz/src/context.rs:138` refuses every scoped request and two independent mutants survive the whole suite. A clause whose guard no input reaches is not `real_covered`. But `story:event-payloads-for-folds`, which `crates/mandate-authz/tests/context.rs:266-269` names as the owner, is **`implemented`** — a terminal rung the step refuses, so the deferral would exit 1. The live owner is `story:declared-writers`: the gap is a declared element of the contract that no code writes, which is that story's subject, and it already carries `mandate.identity.SessionRefreshed` and `mandate.authorization.DecisionRecorded` in the same family. Defer the clause there with `crates/mandate-model/src/graph.rs:250` cited. Expect `real_covered` 9 → 8. That a shipped source comment routes a live gap to a finished story is the third instance of that class this half and is appended to the same story. | correction 2 + story |
| F2 | **Upheld, blocker. Defer `invalid` beside its three siblings.** The question put to the coordinator has a measured answer and it is not close: `VerifiedContext::credential` is read nowhere in `crates/mandate-authz/src` — thirteen occurrences of the word, every one a doc comment — and four contexts differing only in that field produce one identical `Err(InvalidCredential)`. The refusal the row drives is `Tenancy::admits(context.organization)`, decided from the same field the sibling clause `tenant` is bound through. So the argument that closing an organization invalidates the credential-derived context is an argument about a different field; taking it would mean the crate publishes one refusal as two conditions and counts both. `invalid` defers to `decision-blocker:guards` with the same citation its three siblings carry, and `context::an_organization_that_admits_no_authority_refuses_the_context` stops being a row of this clause. Expect `real_covered` 8 → 7, `deferred` 4 → 6. | correction 2 |
| F3 | **Upheld.** `generated/ir/system.json:3128-3135` declares the identity as `id`; `agent_id` is the first field at `:3138`. Pass 1 wrote it correctly and the correction restated it wrongly, in the sentence that carries the whole argument for deferring `autonomous-ceiling`. Correct it to the form pass 1 used. The deferral's substance is untouched — `mandate_authz::evaluate::Ceiling` carries no agent field either way. | correction 2 |
| F4 | **Confirmed. Make the case decide what its name says, or withdraw the row.** Changing the ceiling's `organization` from `Some(organization())` to `None` returns a byte-identical `Denied`, so the row is not evidence of the condition it names. The preferred fix adds evidence rather than removing it: give the case the foreign-organization ceiling that `crates/mandate-authz/tests/evaluate.rs:447-451` uses, so that the `organization` field changes the answer and the row becomes true at the `check` entry point, which `evaluate.rs` does not exercise. If that cannot be made to discriminate, withdraw the row — the clause keeps its existing real row and nothing is lost but a claim that was not earned. Either way, report the mutation. | correction 2 |
| F5 | **Confirmed, note, no action on the document.** Nine bare-noun clause texts are what the positional tiling rule produces from a slash-list, the same shape `mandate-model` had to publish as `"team or"`, and the tiling itself re-derives clean. The ambiguity the adversary names is real and worth the record: a later binder reading the clause `revoked` cannot tell credential revocation, which this document defers, from grant revocation, which `mandate-graph` decides today and which this document rows under `relationships`. Appended to `story:cross-crate-clauses` beside the granularity conflict already recorded there, with the count. | story |
