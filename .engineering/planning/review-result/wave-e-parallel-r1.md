---
format: aep.planning-md/1
id: review-result:wave-e-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave E1 set
relations:
- reviews: story:contract-creates
- reviews: story:contract-shapes
- reviews: story:tenancy-graph-events
- reviews: story:event-validation-harness
revision: 1
---
```
set: story:contract-creates, story:contract-shapes, story:tenancy-graph-events, story:event-validation-harness — wave E1, one implementor each, in parallel from the opening commit
verdict: needs-revision
findings: 3
```

```findings
- file: .engineering/planning/story/event-validation-harness.md
  line: 23
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "Its acceptance and two of its three asserts read generated/ir/system.json, which does not exist at the wave base (cargo xtask generate emits only schema, openapi, docs, docs-ir at xtask/src/main.rs:75) and is produced solely by story:contract-shapes; this body excludes generated/ so it creates nothing, and its gate cannot be green in a worktree cut from the same base."
- file: .engineering/planning/story/contract-shapes.md
  line: 51
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "It commits generated/ir/system.json and generated/rust/** derived from the contract at the wave base while story:contract-creates rewrites all twelve domain files in the same wave; cargo xtask contracts goes red on merge, and neither body states that the coordinator regeneration reconciles it nor that contract-shapes' wiring of the IR and Rust kinds must land before contract-creates' coordinator row runs cargo xtask contracts."
- file: .engineering/planning/story/tenancy-graph-events.md
  line: 44
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "It resolves the ResourceRegistered collision with 'read the yaml at dispatch', which cannot work under same-base parallel dispatch: graph.yaml carries no resource_id at the base, contract-creates adds it, and after regeneration the event schema is additionalProperties:false with a required list, so no unit owns adding resource_id to ResourceEvent::Registered."
```

Cargo.lock: clean — `jsonschema`, `serde`, `serde_json` pre-landed for `mandate-testkit`; `mandate-model` has `serde`; `xtask` has `serde_json`. `generated/rust` at directory granularity acceptable because the other three exclude `generated/`. Noted, not scored: `contract-creates` excludes `xtask/` wholesale while handing the coordinator `xtask/src/main.rs:147-151`; `dependency-boundaries.json` lacked `jsonschema` in `external` while the pre-land was in flight.
