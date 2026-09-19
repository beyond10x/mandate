---
format: aep.planning-md/1
id: review-result:wave-e-design-r1
kind: review-result
status: active
title: Design critic, round 1 — drift-enforcement story set
relations:
- reviews: story:contract-creates
- reviews: story:contract-shapes
- reviews: story:tenancy-graph-events
- reviews: story:event-validation-harness
- reviews: story:coverage-map
- reviews: story:conform-gate
- reviews: story:conformance-target
revision: 1
---
```
set: the twelve drift-enforcement stories across waves E1–E3
verdict: needs-revision
findings: 7
```

Walked all 702 declared edges (90 depends_on, 30 blocks): no cycle; `validate` valid. The defect is uniformly the missing edge: E1's four stories declare zero depends_on among themselves while their bodies name a strict order, and E2's realizes! surface is split across three concurrent stories.

```findings
- file: .engineering/planning/story/event-validation-harness.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "Its acceptance and harness read generated/ir/system.json, produced by story:contract-shapes as a new generate kind in the same wave, with no depends_on edge and generated/ excluded."
- file: .engineering/planning/story/tenancy-graph-events.md
  line: 44
  category: boundary
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "The ResourceRegistered payload it must emit defers to whether story:contract-creates has merged ('read the yaml at dispatch'); deferring to dispatch is not an edge — state one payload."
- file: .engineering/planning/story/contract-shapes.md
  line: 27
  category: boundary
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "It emits Rust shapes from the compiled model that story:contract-creates rewrites in the same wave, and contract-creates' regeneration only covers the IR and Rust kinds if contract-shapes has already wired them; the mutual order is unrecorded in both directions."
- file: .engineering/planning/story/coverage-map.md
  line: 42
  category: design
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "It owns the realizes! macro while its only callers for federation, identity and model are two concurrent E2 stories, and federation-identity-alignment's 'from story:coverage-map's macro if merged; else a pub const' lets one wave land two registration forms."
- file: .engineering/planning/story/conform-gate.md
  line: 39
  category: design
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "Its gate byte-compares report.json, run.json, injections.json and suite.json against generated/conformance/ with no producer named: conformance-target excludes generated/ and the coordinator duty is wiring only — no item owns the first write of the corpus."
- file: .engineering/planning/story/contract-creates.md
  line: 59
  category: design
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "A specification-only story hands the coordinator a Rust behaviour change in xtask/src/main.rs:147-151 (obligations() selecting the outcome with an external cause) that no unit owns or tests."
- file: .engineering/planning/story/contract-creates.md
  line: 51
  category: design
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "It pins its acceptance on the exact creator-less residue while story:declared-writers adds creators for those same entities in the same twelve files and rewrites the same identity.yaml header line; nothing orders the two."
```
