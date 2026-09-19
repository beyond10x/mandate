---
format: aep.planning-md/1
id: review-result:wave-e-event-validation-harness-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — event-validation-harness
relations:
- reviews: story:event-validation-harness
revision: 1
---
```
unit: story:event-validation-harness — crates/mandate-testkit/{src/contract.rs, src/lib.rs, tests/contract.rs}, uncommitted on impl/event-validation-harness at base 9401ab9, after correction round 1
verdict: needs-change
cases: executed 45 → 58, red 5 (adversary file tests/adversary_contract_2.rs, 13 cases: 8 held, 5 confirmed); pass-1 file 13/13 green
findings: 8 — 1 blocker, 6 warnings, 1 note; pass-1 findings all held
```

```findings
- file: crates/mandate-testkit/src/contract.rs
  line: 469
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'absent() lets an absent source excuse an absent target unconditionally, so all 154 required value-sourced targets are accepted when the event omits them and the caller input omits the source, while check_event_conforms refuses the same payload; the IR declares target_type.kind on all 183 fields and the code never reads it.'
- file: crates/mandate-testkit/src/contract.rs
  line: 184
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the doc and tests/contract.rs:359 both say the contract declares three optional-to-optional mappings, but generated/ir/system.json declares four, and the fourth (descriptor on CredentialIntrospected) is the only optional response_field and had no case.'
- file: crates/mandate-testkit/src/contract.rs
  line: 182
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the claim that a null is read as an absent value wherever it appears is false, because carried reads null only at the level the mapping compares and a null nested in a $defs object is compared as a value.'
- file: crates/mandate-testkit/src/contract.rs
  line: 308
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the Errors clauses at :111 and :190 promise the outcome and the event are named, but on an undeclared command both check_single_emission and check_payload_sources emit only the command.'
- file: crates/mandate-testkit/src/contract.rs
  line: 65
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'the parse and compile failure messages interpolate the absolute CARGO_MANIFEST_DIR path while the read failure at :62 uses the repo-relative form, and the branch cannot be reached from a test without mutating generated/.'
- file: crates/mandate-testkit/src/contract.rs
  line: 352
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the ambiguity arm of declaring_outcome has no case and no seam to get one, because the IR is a compile-time const behind a OnceLock and all 59 mappings are on distinct events, so replacing the arm with the first match leaves the suite green.'
- file: crates/mandate-testkit/tests/contract.rs
  line: 555
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the only all-mappings sweep inserts every source key so it never enters the absence branch, leaving the whole absence rule resting on two hand-written fixtures, which is why the suite is green against the 154-case defect.'
- file: crates/mandate-testkit/tests/adversary_contract_1.rs
  line: 172
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the assertion that the message contains ".." is satisfied by the harness echoing the supplied name back, so it adds nothing to the expect_err above it.'
```

Held under attack: all 72 event schemas accept an instance synthesized from their own required properties; all 59 payload mappings conform and pass their sources with schema-valid values; 0 of 183 target/property mismatches across projections and `target_type.kind == optional` ⟺ outside `required` for 183/183; non-object events refused; `""` is present and `null` absent for `generated` and `literal`; six more name shapes refused without an os error or absolute path; 4 runs across 2 thread settings identical; the harness writes no file. Evidence under the unit's scratch `adversary2/`.
