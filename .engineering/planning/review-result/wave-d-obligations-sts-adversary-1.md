---
format: aep.planning-md/1
id: review-result:wave-d-obligations-sts-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-sts
relations:
- reviews: story:obligations-sts
revision: 1
---
```
unit: story:obligations-sts — impl/obligations-sts on 0ecccae, the unit's three files uncommitted
verdict: NEEDS-CHANGE (1 blocker, 2 warnings, 1 note)
cases: 201 → 203 executed, 2 red when written (services/sts/tests/adversary_obligations_sts_1.rs)
origin: introduced 3 / pre-existing 1
```

```findings
- file: contracts/obligations/sts.json
  line: 381
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the one clause this unit moves to real_covered is the only one of the crate''s 32 with no phrase of services/sts/tests/declared_denials.rs ROWS inside its span — the sole row reaching it, "narrowing/atomic issuance validation fails", spans the neighbouring "narrowing" clause the same commit defers to decision-blocker:guards, and the refusal it names is the expiry narrowing at services/sts/src/redemption.rs:343-348, not the atomicity decision-blocker:epoch-atomicity owns'
- file: services/sts/src/issue.rs
  line: 290
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'admits_profile admits max_ttl PT99999999H and issue_reference_credential then accepts, mints a secret and issues expires_at "13434-08-30T15:00:00Z" — an instant the crate''s own reader answers None for, so the credential is not live at the instant it was minted and the declared clause "expiry cannot be bounded" refuses nothing, while the control-plane refuses the identical span at startup via renders_readably'
- file: services/sts/tests/obligations.rs
  line: 48
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the file''s stated reason for its binding — that the refusal follows from an expiry "past the end of the timeline this crate can render" — is falsified by the same red case: past the renderable end nothing refuses, and only i64 overflow in checked_add does'
- file: contracts/obligations/sts.json
  line: 378
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'twenty clauses now defer to a decision-blocker id, a form contracts/obligations/README.md:132 does not describe — it says a deferral names a story the store holds, and for an unproducible path the story that owns it, which services/sts/src/registry.rs:165-167 names as story:product-listener / story:port-adapters — so only step rule 9 admits the rows and the two documents disagree'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | accepted. `redemption.rs:343-348` computes `expires_at = profile_bound.min(code_bound)`; its failure is the narrowing of the credential expiry. The `narrowing` clause binds to `atomic_issuance_validation_refuses_a_credential_whose_expiry_cannot_be_bounded` (renamed to say narrowing) on the real path; `atomic issuance validation fails` defers to `decision-blocker:epoch-atomicity`. The crate's own attribution, `declared_denials.rs` `ROWS` `Source::DenialPhrase("narrowing/atomic issuance validation fails")`, becomes `"narrowing"` so the two documents agree; that file is added to the unit's scope as inferred. | correction 1 |
| F2 | confirmed, pre-existing, out of the unit's scope. Home: `story:sts-lifetime-bounds` (draft). The adversary case is pinned by the coordinator to the shipped behaviour and names the story. | story |
| F3 | accepted: the doc comment states the `i64` overflow bound that refuses, not the renderable timeline. | correction 1 |
| F4 | accepted as a README gap: rule 9 (`xtask/src/obligations_registry.rs:38`) admits an open blocker and the README does not say so. One README line under `blocked_on`, by the coordinator at integration (the README belongs to `story:obligation-registry`, implemented). | coordinator |

Not broken: the other 19 re-pointed clauses, the 10 `cases` re-pointings, rule 9 resolution, the report arithmetic, the arrangement's reachability from a request payload, the no-state-change case.
