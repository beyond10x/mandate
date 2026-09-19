---
format: aep.planning-md/1
id: review-result:wave-a-model-agreement-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — model-agreement
relations:
- reviews: story:model-agreement
revision: 1
---
```
unit: story:model-agreement — crates/mandate-model and crates/mandate-types tests, src/lib.rs, src/graph.rs doc, src/inventory.rs; uncommitted on impl/model-agreement at base b1d6297, after correction round 1
verdict: needs-change
cases: executed 164 → 170, red 2 (adversary files tests/adversary_agreement_2.rs 4 cases: 3 held, 1 confirmed; tests/adversary_states_2.rs 2 cases: 1 held, 1 confirmed)
findings: 5 — 3 warnings (one miscount in three prose sites), 2 notes; pass-1 findings all held
```

```findings
- file: crates/mandate-types/src/inventory.rs
  line: 474
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the DERIVED_STATE_ENUMS account states 22 of the 36 derived declarations share a variant list with another, and generated/schema/types declares 23 that do.'
- file: crates/mandate-types/tests/conformance.rs
  line: 56
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the same miscount in the module prose that justifies why the state_enums! pairing needs a derivation check.'
- file: crates/mandate-model/tests/contract_agreement.rs
  line: 675
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the same miscount in the prose that justifies every_pairing_is_the_generated_shape_its_element_name_derives_to.'
- file: crates/mandate-model/tests/contract_agreement.rs
  line: 663
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the null-and-absent-optional case guards its sample count with a lower bound, so losing a sample crossing is silent; pinned to the measured count (42).'
- file: crates/mandate-graph/src/double.rs
  line: 37
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'a private second hand-written ResourceState for mandate.graph.Resource.State in the in-memory double that the account claim of six domain enums in mandate-model does not admit; story:graph-policy-adapter.'
```

Held: the derivation rule agrees character for character with ESS 0.26.0 and `xtask/src/emit.rs` on every name; the 22 registry entries decided by derivation and compile-time existence; the replay oracle reads `required_keys` for both resource events and keeps the identity assertion; all 12 payloads pass `check_event_conforms` in both context forms; every generated shape refuses a document missing a required key; the variant-to-element edge pinned literal-free; no eleventh public domain state enum in the workspace. Coordinator applied the four pins (23 in three sites, the count pinned at 42). Evidence under the unit's scratch `adversary2/`.
