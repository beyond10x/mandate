---
format: aep.planning-md/1
id: review-result:wave-a-alignment-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — federation-identity-alignment
relations:
- reviews: story:federation-identity-alignment
revision: 1
---
```
unit: story:federation-identity-alignment — crates/mandate-federation and crates/mandate-identity, uncommitted on impl/alignment at base b1d6297, after correction round 1
verdict: needs-change
cases: executed 276 → 280, red 4 (adversary files tests/adversary_alignment_2.rs: federation 2 cases, identity 2 cases, all confirmed); pass-1 files 6/6 green
findings: 5 — 1 blocker, 1 warning, 3 notes; pass-1 findings held (A1-2 and A1-3 held for their instance, not as a class)
```

```findings
- file: crates/mandate-federation/src/record.rs
  line: 601
  category: concurrency
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'one race every handler accepted resolves the composite external key to the second writer link or to no link at all depending on which of two unordered aggregate appends lands first, so a rebuild decides which principal a federated login authenticates, against record_link own claim that first is a property of the events.'
- file: crates/mandate-identity/src/port.rs
  line: 456
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the SessionOpened arm of the append guard decides no lexical form, so try_record appends an opening whose expires_at the closed schema refuses and the fold materializes a Session from it.'
- file: crates/mandate-federation/src/record.rs
  line: 333
  category: acceptance
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'disable_oauth_client accepted event always aborts the fold, but no declared command creates an OAuthClient so no store this domain fills reaches the accepted outcome; the class statement is narrowed.'
- file: crates/mandate-identity/src/port.rs
  line: 337
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'IdentityLog documents two host ordering obligations and the append guard enforces only the snapshot one; the other fails closed as a permanent StaleEpoch.'
- file: crates/mandate-federation/src/record.rs
  line: 762
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'external_principal reads links only while organization_of also reads conflicts, so a displaced link is unnameable by its own lifecycle command.'
```

Held: `wrong-state` returned at exactly four sites, each from the terminal state on a command that declares it; the registry union equals the declared set with realized and unrealized disjoint (the pass-1 ruling's "15" was wrong; 12 is right); every legitimate interleaving folds; the epoch mechanism cannot fail open; `instant::parse` admits nothing the schema refuses. Evidence under the unit's scratch `adversary2/`.
