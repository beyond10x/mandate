---
format: aep.planning-md/1
id: review-result:wave-d-obligations-sts-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-sts
relations:
- reviews: story:obligations-sts
revision: 1
---
```
unit: story:obligations-sts — impl/obligations-sts on 0ecccae, after correction 1
verdict: NEEDS-CHANGE (4 pre-existing warnings, 1 introduced warning, 2 notes)
cases: 203 → 206 executed, 2 red when written (services/sts/tests/adversary_obligations_sts_2.rs)
origin: introduced 2 / pre-existing 4
```

```findings
- file: services/sts/src/redemption.rs
  line: 436
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the losing half of two concurrent redemptions draws a credential secret and a credential identity at :354-357 before the compare-and-set refuses at :436, so a transaction that wrote nothing still moved the deployment''s secret source and allocator, against credential.yaml:245 and against the standard the unit''s own no_state_change row asserts'
- file: services/sts/src/issue.rs
  line: 424
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'issue_self_contained_credential is the one handler in this crate that draws a credential identity before a refusal it can still make — SigningRefused at :436 — and the no_state_change row cited for that command refuses above the draw and inspects no allocator'
- file: services/sts/src/redemption.rs
  line: 346
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'deleting the .filter(|span| *span > 0) that decides one of the three conditions of the clause this unit publishes as real_covered leaves all 203 pre-existing cases green while the handler issues a credential dated at its own issuance instant; no case in the suite builds a zero span against a redemption'
- file: services/sts/tests/obligations.rs
  line: 400
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the credential-fold assertion is unfalsifiable — credential_log is a local the function under test never receives, so it reads fold(x) == fold(x) and holds for every possible implementation, while the registry cites this case as no-state-change evidence'
- file: services/sts/tests/declared_denials.rs
  line: 467
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the correction''s comment cites redemption.rs:343-348 for min(issued_at + max_ttl, code.expires_at), but code_bound is :349 and the min is :350, both outside the cited range; obligations.rs:16 and :288 repeat the same citation'
- file: .engineering/planning/story/obligations-sts.md
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the story''s Outcome promises one denial case per clause and one no-state-change case per command; one of each was delivered and 20 clauses were re-pointed to two open blockers, which the Acceptance sentence cannot detect because it is satisfied by the re-pointing alone — the deferrals are correct on the merits, so the Outcome paragraph is what needs correcting'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1, F2 | confirmed, pre-existing, out of the unit's scope. Home: `story:sts-refusal-draws-nothing` (draft): every refusal a handler can still make happens before any draw from the secret source or the allocator. The two adversary cases are pinned by the coordinator to the shipped behaviour and name the story. | story |
| F3 | accepted: the `narrowing` row's evidence gains a zero-span case in `obligations.rs` (a profile `max_ttl` of `PT0S` admitted by a registration record another writer put in the log refuses the redemption with `ExpiryUnbounded`); the adversary's case 3 stays as the mutation witness. | correction 2 |
| F4 | accepted: the `fold(x) == fold(x)` line is deleted, or the credential log the writer seeds through `AuthorizationCodeEvent::credential_event` is folded and compared. | correction 2 |
| F5 | accepted: `:343-350` in the three places. | correction 2 |
| F6 | confirmed; the story body carries the measured result at merge (same class as graph F8, identity F5). | coordinator |

Not broken: the `narrowing` binding (m1 killed by both new cases; the arrangement traced by hand), the no-state-change row otherwise, the 20 blocker deferrals ("code redemption" is named in `decision-blocker:epoch-atomicity`), six base guard deletions all killed, `ROWS` shown to be real-path evidence, 67 rows laid over the clause list with none spanning two clauses, the report arithmetic.

Correction 2 is the last correction this unit gets; the coordinator verifies it by running the unit gate and the adversary targets in the tree.
