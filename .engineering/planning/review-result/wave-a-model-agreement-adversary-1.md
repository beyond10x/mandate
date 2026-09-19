---
format: aep.planning-md/1
id: review-result:wave-a-model-agreement-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — model-agreement
relations:
- reviews: story:model-agreement
revision: 1
---
```
unit: story:model-agreement — crates/mandate-model/{tests/contract_agreement.rs,tests/projections.rs,src/lib.rs}, crates/mandate-types/{src/inventory.rs,tests/conformance.rs,tests/inventory.rs}, uncommitted on impl/model-agreement at base b1d6297
verdict: needs-change
cases: executed 154 → 163, red 4 (adversary files crates/mandate-model/tests/adversary_agreement_1.rs 5 cases: 3 held, 2 confirmed; crates/mandate-types/tests/adversary_states_1.rs 4 cases: 2 held, 2 confirmed)
findings: 7 — 3 warnings, 4 notes (one pre-existing)
```

```findings
- file: crates/mandate-model/tests/contract_agreement.rs
  line: 157
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the payload! macro pairs a hand-typed generated shape with an ess_name() read off the domain and nothing compares the two, so all 30 cross-pairings among the six context-id payloads survive the whole round-trip procedure.'
- file: crates/mandate-model/src/graph.rs
  line: 133
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'graph.rs:133 and replay.rs:1085 both state the compiled ResourceRegistered declares no resource_id, while the compiled payload requires it and replay.rs:1090 weakens that event key check to a ruled literal on that now-false ground.'
- file: crates/mandate-types/tests/conformance.rs
  line: 17
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the state_enums! table carries no evidence of its pairing, so 72 of the 1260 ordered wrong pairings pass the account unchanged.'
- file: crates/mandate-types/tests/conformance.rs
  line: 22
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the account states the six in mandate-model are the only domain enums for a derived state element, but ten more exist across federation, policy, graph and identity and nothing decides any of them against the contract; 30 of the 36 are decided only by the generated crate against its own schema.'
- file: crates/mandate-model/tests/contract_agreement.rs
  line: 604
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the registry case asserts the element set and that each symbol starts with crate:: but never that an element and its symbol correspond.'
- file: crates/mandate-model/src/lib.rs
  line: 455
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'mandate-model registers 18 of the 22 elements it implements (the four mandate.core records are missing) and the new case pins the registry at 18, so a later coverage step will report the four as realized by nothing.'
- file: crates/mandate-model/tests/contract_agreement.rs
  line: 181
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'every state each projection holds is the hand-written sample loops rather than the domain enum variants, with no compile-time exhaustiveness guard.'
```

Held: the log-reader direction for all six projections (16 generated-side documents read back and re-emit identically); declared-key coverage with every optional set; `deny_unknown_fields` and `Presence` null refusal at every depth; state-string boundaries refused on both sides; the six model state enums and the ten sibling enums agree variant-for-variant with the contract today; `DERIVED_STATE_ENUMS` rebuilt independently equals the 36 with 70 variants; the payload filter selects exactly the 12; `ACCEPTED` unchanged and `mandate-proto`/`mandate-token` green (28). Evidence under the unit's scratch `adversary1/`.
