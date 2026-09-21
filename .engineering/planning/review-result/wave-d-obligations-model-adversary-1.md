---
format: aep.planning-md/1
id: review-result:wave-d-obligations-model-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-model
relations:
- reviews: story:obligations-model
revision: 1
---
```
unit: story:obligations-model — mandate-wd-obl-model on eb22b1c, the unit's three files uncommitted
verdict: NEEDS-CHANGE (2 blockers, 3 pre-existing warnings, 2 notes)
cases: 107 → 112 executed, 5 red when written (crates/mandate-model/tests/adversary_obligations_model_1.rs)
origin: introduced 2 / pre-existing 3 (+2 notes)
```

```findings
- file: crates/mandate-model/src/tenancy.rs
  line: 633
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'decide_close_organization refuses a second closure of an organization the fold resolves, and no clause of mandate.tenancy.CloseOrganization''s declared cause publishes that condition, so the registry maps it to nothing and counts it nowhere'
- file: crates/mandate-model/src/tenancy.rs
  line: 861
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'decide_retire_team refuses an already-retired team inside the verified organization, a condition no clause of the command''s cause publishes, while the one clause the document marks real is "the team is outside the verified organization"'
- file: contracts/obligations/model.json
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'CreateOrganization, CreateTeam and CreateSpace are implemented with real_covered 0 — every clause deferred — while their shipped decide halves do refuse; the CreateTeam and CreateSpace admits branch is reached from request input, the already-recorded-identity branch is not reached by the conformance target because it mints the id'
- file: contracts/obligations/model.json
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the diff re-points 28 clauses off the binding story into positive claims that this crate ships no decider for them, while crates/mandate-model/src/tenancy.rs:107-132 still enumerates five and says "These are all of them"; 23 clauses are unaccounted and the two documents were consistent at eb22b1c'
- file: contracts/obligations/model.json
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the AddTeamMembership clause "team or principal is unresolved or outside the verified organization" carries a path real row whose own case disclaims the principal half in writing, and the fold holds no principal projection, so real_covered counts a condition with no decider; the registry README requires splitting a clause whose conditions have different deciders'
- file: crates/mandate-conformance/src/commands/tenancy.rs
  line: 169
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the control for the AddOrganizationMembership authority clause passes MembershipAuthority::PlatformOrganizationAdministration, a value the only shipped command path never constructs — it hardcodes VerifiedOrganization and calls the choice a standing double — so the attribution rests on an input outside the command path even though the denial half is reachable'
- file: contracts/obligations/model.json
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the three "cannot be created without implying …" clauses are deferred to decision-blocker:epoch-atomicity, whose text is about cross-record transactional behaviour, while the property is structural to a single-entity transition that decide_create_* already satisfies; routing over blocker scope is the coordinator''s call, same shape as the unit''s own flag on the RetireSpace and RetireTeam grants clauses'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1, F2 | confirmed, pre-existing, and narrower than stated: `generated/ir/system.json` declares a `wrong-state` outcome for `CloseOrganization` and `RetireTeam`, so a second closure and an already-retired team are published refusals — under an outcome the registry does not read (it tiles the `denied` cause only). Home: `story:unpublished-refusals` (draft): `wrong-state` outcomes become registry obligations, and a code → contract check maps every refusal site to a published outcome. Cases pinned to the shipped record. | story |
| F3 | confirmed, pre-existing: the creators declare no `wrong-state` outcome, so an already-recorded identity is a refusal with no published home — a specification gap the same story owns. Case pinned. | story |
| F4 | accepted. The crate's own record of what it does not decide (`src/tenancy.rs:107-132`) must equal the registry's deferred set; the section is rewritten to enumerate every clause `model.json` defers, verbatim, and to name `contracts/obligations/model.json` as the record. The adversary's case stays as the drift check between the two documents. `crates/mandate-model/src/tenancy.rs` (that doc section only) is added to the unit's scope as inferred. | correction 1 |
| F5 | accepted: the clause is split into `team` / `principal is unresolved or outside the verified organization` (`or` an admitted joiner); the team half keeps the real row, the principal half defers to `story:declared-writers` beside "the principal is disabled". | correction 1 |
| F6 | noted, pre-existing; no change. | — |
| F7 | ruled: `decision-blocker:epoch-atomicity` stays the home. The clause names the boundary of the creation transaction (a creation that would also write membership, grants or authority); today's single-record `decide_create_*` cannot cross it, and the store that could is the blocker's subject. Same for the `RetireSpace` / `RetireTeam` grants clauses. | — |

Not broken: all ten real rows drive the command's own `decide_*` half (the conformance target dispatches to the same functions); guard ordering; nine of ten controls repair only the named condition; "already a member" is active-scoped; the seven `cases` re-pointings match their own `story` field; `decision-blocker:lifecycle` covers the closure clause; every `blocked_on` live; the report arithmetic.
