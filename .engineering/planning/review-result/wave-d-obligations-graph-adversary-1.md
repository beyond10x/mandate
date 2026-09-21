---
format: aep.planning-md/1
id: review-result:wave-d-obligations-graph-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-graph
relations:
- reviews: story:obligations-graph
revision: 1
---
```
unit: story:obligations-graph — impl/obligations-graph on 181e6c0, the unit's three files uncommitted
verdict: NEEDS-CHANGE (3 blockers, 3 warnings, 3 notes)
cases: 89 → 93 executed, 4 red when written (crates/mandate-graph/tests/adversary_obligations_graph_1.rs)
origin: introduced 4 / pre-existing 4 (one row: :242 note) / undecided 0
```

```findings
- file: contracts/obligations/graph.json
  line: 146
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'mandate.graph.RemoveRelation''s visibility clause is counted in real_covered, but the port realizing the command takes no minimum revision and no implementor consults a RevisionView, so the shipped path cannot produce the declared denial.'
- file: contracts/obligations/graph.json
  line: 191
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'mandate.graph.RevokeGrant''s visibility clause is counted in real_covered on the same free function, which revoke_grant never calls.'
- file: contracts/obligations/graph.json
  line: 156
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the path-real no_state_change rows for RemoveRelation and RevokeGrant assert that a function taking an immutable reference did not mutate, so a refusal that moves the fold leaves tests/obligations.rs 9 of 9 green, and those rows are what dropped both commands'' command-level blocked_on.'
- file: contracts/obligations/graph.json
  line: 94
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'RegisterResource''s "hierarchy admission fails" is real_covered by ancestry cases, but register_resource never calls ancestry and records a chain past MAX_ANCESTRY_DEPTH that the read path can then never answer for.'
- file: contracts/obligations/graph.json
  line: 229
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: '"outside tenant membership" is real_covered by a case whose TenantMismatch comes from a stub declared in the test file, while the only other implementor of the deciding port answers Denied.'
- file: contracts/obligations/README.md
  line: 116
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the README still states eight double-backed clauses deferring to story:graph-policy-adapter; this unit took double_only to eleven.'
- file: contracts/obligations/README.md
  line: 132
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the blocked_on section describes story-valued deferrals only, and this unit introduced the directory''s first six clause-level decision-blocker deferrals, which the validator permits and the README does not describe.'
- file: .engineering/planning/story/obligations-graph.md
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the acceptance statement is discharged by relabelling: of sixteen deferrals to the binding story exactly two became real_covered, and both of those are the falsified visibility rows.'
- file: contracts/obligations/graph.json
  line: 242
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: '"the relationship is not admitted by the authorization model" is bound to relation-name-format cases, while relationship.rs:10 says that refusal belongs to mandate-policy.'
```

## Rulings (coordinator, 2026-09-21)

Rule stated for every binding unit: **a clause decided by store or adapter code — commit, durability, visibility, membership lookup — is `double` when only an in-memory stand-in implements it, and `real` only when handler code over the fold decides it.** `require_revision` and `admit` are load-bearing free functions, but a row is evidence of a *command* only when the command's path calls the function.

| # | ruling | route |
|---|---|---|
| F1, F2 | accepted. `RemoveRelation` and `RevokeGrant` "required graph revocation visibility cannot be satisfied" return to `tests: []`, `blocked_on: story:graph-policy-adapter` (the writer that would consult the view is the adapter's). | correction 1 |
| F3 | accepted. Both `path: real` no-state-change rows are withdrawn. In their place, `path: double` no-state-change rows drive `GraphDouble::remove_relation` / `revoke_grant` under a tenancy refusal and assert the whole fold unmoved (the mutant that advances the fold before the tenancy check must be red); command-level `blocked_on: story:graph-policy-adapter` restored on both commands, the pattern the unit already used for `RegisterResource` / `DeregisterResource`. | correction 1 |
| F4 | confirmed, pre-existing row. The shipped registry cannot produce "hierarchy admission fails" at registration; the row moves to `tests: []`, `blocked_on: story:graph-policy-adapter`, and the defect (an over-deep chain is recorded and is then unanswerable) is appended to that story. Adversary case pinned by the coordinator. | correction 1 + story |
| F5 | accepted, pre-existing row. A stub declared in the test file is a double; the row becomes `path: double`, `blocked_on: story:graph-policy-adapter`; the disagreement between `GraphDouble::admits` (`Denied`) and the declared `TenantMismatch` is appended to that story. Case pinned. | correction 1 + story |
| F6 | accepted. The README sentence loses its count. | coordinator |
| F7 | already answered by the coordinator's blocker-deferral paragraph (sts F4). | — |
| F8 | confirmed. The story body carries the measured result at merge; the Acceptance of the remaining binding stories reads "no clause deferred on this story" by design — re-pointing with a cited source line is the intended discharge for a clause the crate cannot decide. | coordinator |
| F9 | noted; `admit`'s declared-name check is the model's admission of the relation; no change. | — |

Adversary cases 1–4 pinned by the coordinator to the shipped behaviour, each naming `story:graph-policy-adapter` (deviation 12 class).
