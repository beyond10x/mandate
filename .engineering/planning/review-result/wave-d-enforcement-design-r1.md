---
format: aep.planning-md/1
id: review-result:wave-d-enforcement-design-r1
kind: review-result
status: active
title: Design critic — wave D enforcement set
relations:
- reviews: story:coverage-map
- reviews: story:conformance-target
- reviews: story:authored-denial-scenarios
- reviews: story:mutation-controls
revision: 1
---
```
set: story:coverage-map, story:conformance-target, story:authored-denial-scenarios, story:mutation-controls — wave D enforcement track, from 75f41b5
verdict: needs-revision
findings: 3
```

```findings
- file: .engineering/planning/story/coverage-map.md
  line: 80
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the 110 implemented type entries are reconciled against no code, because ruling 1 names mandate_types::conformance::cases() while inventory.rs:69 excludes every derived .State enum from that account and the equality case runs only in the seven registrar crates'
- file: .engineering/planning/story/conform-gate.md
  line: 30
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its synthesize command omits --suite-format 5, which story:conformance-target freezes, so the gate would re-synthesize a format-4 suite and byte-compare it against the committed format-5 one'
- file: .engineering/planning/story/mutation-controls.md
  line: 33
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the mutant table pins deny-unknown-fields-removed to the xtask emitter while the tracker''s E4 row plans to retire that emitter, and neither body says the mutant retires with it'
```

Held: no cycle (189 edges walked); two independent pairs; no split abstraction; one owner per surface; no direction inverted. Lane notes taken as rulings: `Unsupported`, not `Unavailable`, for scenarios blocked on unrealized commands (ESS's definition), report `failed` with `blocked_on`, the release stance restated on the tracker; the `DenialReason`-only consequence named on `authored-denial-scenarios` with clause binding routed to `obligation-registry`; two ESS-side drift mutants added to round 1.

Rulings (coordinator): 1 — the type entries proven in `mandate-types` (authored types by their conformance symbols, `.State` enums by the account's pairing), the manifest-equality case in `tests/inventory.rs`, and `coverage` refusing an `implemented` crate that runs no case; 2 — `--suite-format 5` recorded on `conform-gate`; 3 — the mutant retires with the emitter, stated on both.
