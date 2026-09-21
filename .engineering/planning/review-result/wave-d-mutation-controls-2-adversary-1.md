---
format: aep.planning-md/1
id: review-result:wave-d-mutation-controls-2-adversary-1
kind: review-result
status: active
title: Adversary pass — mutation controls round 2
relations:
- reviews: story:mutation-controls
revision: 1
---
```
unit: story:mutation-controls round 2 — impl/mutation-controls-2 on fdbf214
verdict: NEEDS-CHANGE (0 blockers, 2 warnings, 4 notes)
cases: 150 → 154 executed, 1 red when written; catalogue 11 of 11 killed
origin: introduced 5 / pre-existing 1
```

```findings
- file: xtask/tests/coverage_mutants.rs
  line: 17
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the file assigns the regeneration byte-compare to the two receipt mutants only, but the receipt binds contracts/coverage.json by digest, so cargo xtask contracts refuses both relabels as well'
- file: xtask/tests/coverage_mutants.rs
  line: 174
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the demotion escapes the coverage step only because the case also repoints the entry at a live story; a status-only demotion is refused on the terminal rung'
- file: xtask/tests/coverage_mutants.rs
  line: 174
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the case asserts no precondition on story:declared-writers (active today), so the gate turns red when that story closes and the panic names neither the story nor the rung'
- file: xtask/tests/coverage_mutants.rs
  line: 243
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the entry-deleted and entry-duplicated cases restate rules xtask/tests/coverage.rs already decides'
- file: .engineering/planning/story/mutation-controls.md
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the round-2 claim that mutants::copy fails with a bare message is wrong: sync names the path'
- file: xtask/src/main.rs
  line: 154
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'contracts() has one failure message, so the two ESS mutants observe byte-identical refusals'
```

Held: the relabel dies in every accounting crate probed (graph, policy, types line/account readers; the authz demotion); the patch's `+` line equals the data case's entry; the anchor holds on `fdbf214`; every refusal names the mutated element; `alive` requires `1 passed`; `copy` names the path.

Rulings (correction round 1): F1 — the killer partition in the file and the store's round-2 line are corrected: a relabel is refused by the registry equality *and* by the regeneration byte-compare through the receipt; the receipt mutants by the byte-compare alone. F3 — the demotion case asserts its precondition (`story:declared-writers` off a terminal rung) so a future close fails by name. F2/F4 — stated in the file's doc: the escape needs the repoint; the two restated cases stay as the file's own account. F5 — the store line corrected. F6 — recorded on the tracker as a residue of `contracts()`.
