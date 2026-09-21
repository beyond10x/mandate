---
format: aep.planning-md/1
id: review-result:wave-d-obligations-identity-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-identity
relations:
- reviews: story:obligations-identity
revision: 1
---
```
unit: story:obligations-identity — impl/obligations-identity on 181e6c0, the unit's three files uncommitted
verdict: NEEDS-CHANGE (1 blocker, 4 warnings, 2 notes)
cases: 124 → 127 executed, 3 red when written (crates/mandate-identity/tests/adversary_obligations_identity_1.rs)
origin: introduced 5 / pre-existing 1
```

```findings
- file: contracts/obligations/identity.json
  line: 22
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '''tenant containment fails'' is deferred to decision-blocker:guards, a blocker about external cryptographic/graph/policy validation, while the same crate decides the identical organization comparison at src/session.rs:369 and a caller verified in one organization advances another''s security-epoch generation with no refusal'
- file: contracts/obligations/identity.json
  line: 143
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the new no_state_change row for RefreshSession cannot fail: refresh_session takes &R and the accepted outcome appends nothing either, so the declared mandate.identity.SessionRefreshed is never folded and refused and accepted leave byte-identical logs'
- file: crates/mandate-identity/tests/obligations.rs
  line: 35
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'src/session.rs:290-291 is cited as stating that proof verification is the credential domain''s and holds the expiry comparison instead; the statement is at src/session.rs:267'
- file: crates/mandate-identity/tests/obligations.rs
  line: 43
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'src/session.rs:339-341 is cited as stating that the caller''s authority is not decided here and holds the decide-then-append sentence instead; the statement is at src/session.rs:351'
- file: contracts/obligations/identity.json
  line: 45
  category: judgement
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '''atomic increment cannot commit'' is rowed real against the in-memory IdentityLog while all six sibling commit/durability clauses in sts.json and federation.json, and RevokeSession''s own durability clause in this same document, defer to decision-blocker:epoch-atomicity, which src/port.rs:29-30 and src/increment.rs:5-7 both name as owning that compare-and-set'
- file: .engineering/planning/story/obligations-identity.md
  line: 24
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the story''s Outcome says every clause is decided on the real path and six of twelve are still deferred; the Acceptance is satisfied by re-pointing a deferral as well as by deciding a clause, and the gate cannot distinguish the two'
- file: xtask/src/obligations_registry.rs
  line: 837
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'the step never compares test ids across obligations, so one case could discharge a clause''s denial row and a command''s no-state-change row; no live instance exists in any of the seven documents today, so the gap could not be shown in a state anybody reaches'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | accepted. The behaviour is pre-existing and the routing is the unit's. The comparison belongs in `mandate-identity`'s increment path, not behind `decision-blocker:guards`: home `story:identity-tenant-containment` (draft); the clause defers to it. Case pinned by the coordinator (the increment is accepted; the other organization's generation advances). | correction 1 + story |
| F2 | accepted. The `no_state_change` row for `RefreshSession` is withdrawn and the command carries `blocked_on: story:declared-writers` (active), which folds the declared `SessionRefreshed`; the unfalsifiable case is removed from `obligations.rs`. The conformance target reporting `SessionRefreshed` as emitted with nothing appended is appended to that story. Case pinned. | correction 1 + story |
| F3 | accepted: cite `src/session.rs:267` and `:351`. | correction 1 |
| F4 | accepted under the cross-crate rule stated on the graph pass: a clause decided by store code that only an in-memory stand-in implements is `double`. Both rows of "atomic increment cannot commit" become `path: double`, `blocked_on: decision-blocker:epoch-atomicity` (`src/session.rs:341-342` calls `IdentityLog` the in-memory double of the adapter). | correction 1 |
| F5 | confirmed; the story body carries the measured result at merge (same as graph F8). | coordinator |
| F6 | noted, pre-existing registry gap: one test id must not discharge rows of two kinds; appended to `story:cross-crate-clauses`, the registry follow-up. | story |
