---
format: aep.planning-md/1
id: review-result:wave-d-second-half-design-r1
kind: review-result
status: active
title: Design critic — wave D second half
relations:
- reviews: story:obligation-registry
- reviews: story:conform-gate
revision: 1
---
```
set: wave D second half — story:conform-gate, story:obligation-registry, story:obligations-{sts,model,federation,graph,identity,policy,authz}, with conformance-target, mutation-controls, authored-denial-scenarios in flight
verdict: needs-revision (3 blockers, 2 warnings) — every finding corrected in the store the same day
```

```findings
- file: .engineering/planning/story/obligation-registry.md
  line: 49
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the Units table and frontmatter scope still own four per-crate tests/obligations.rs files that ruling 1 hands to the binding stories, so four surfaces carry two declared owners'
- file: .engineering/planning/story/obligation-registry.md
  line: 33
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the acceptance requires every clause to carry a real-path denial test or the gate fails, an outcome the seven binding stories own, so the registry cannot be demonstrated at its own close'
- file: .engineering/planning/story/obligation-registry.md
  line: 67
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'no body says who writes the per-crate rows of contracts/obligations.json after the registry authors them, and none of the seven binding stories declares the file'
- file: .engineering/planning/story/conform-gate.md
  line: 38
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the ADR it alone owns must state vocabulary story:obligation-registry decides in the same half, and no depends_on edge records that order'
- file: .engineering/planning/story/conform-gate.md
  line: 82
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'ruling 2 names one ledger while the non-expectation-unmet rows'' blocked_on is decided in the target''s Rust and byte-compared, so the attribution has two authorities'
```

Held: no cycle over the 135 `depends_on`/`blocks` edges; three independent lanes; the seven binding stories are a decomposition by package, not padding; `xtask/src/main.rs` one owner (coordinator); the ADR one owner.

Corrections: the per-crate test files removed from the registry's scope; the registry becomes one file per crate (`contracts/obligations/<crate>.json`, authored by the registry, then owned by its binding story — each binding story's scope names its file); the registry's acceptance admits the `blocked_on <binding story>` state until that story is implemented; `story:conform-gate depends_on story:obligation-registry`; ruling 2 restated with the two authorities (`injections.json` for refused/unsupported, `expected-outcomes.json` for executed-unmet, conflicts refused).
