---
format: aep.planning-md/1
id: review-result:wave-e-tenancy-graph-events-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — tenancy-graph-events
relations:
- reviews: story:tenancy-graph-events
revision: 1
---
```
unit: story:tenancy-graph-events — crates/mandate-model + four mandate-authz test files, uncommitted on impl/tenancy-graph-events at base 9401ab9, after correction round 1
verdict: needs-change
cases: executed 77 → 81, red 4 (adversary file tests/adversary_events_2.rs, 4 cases, all red); pass-1 file 10/10 green
findings: 6 — 3 real (1 doc blocker, 2 test gaps), 2 recharacterized (event-sourcing totality, not apply defects), 1 deferred
```

```findings
- file: crates/mandate-model/src/tenancy.rs
  line: 73
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the module doc and the add_organization_membership doc promise that a closure landing between a decide call and its apply is refused rather than written into a closed tenant, and apply is total and writes it; the false promise is the defect, not the totality.'
- file: crates/mandate-model/src/tenancy.rs
  line: 487
  category: concurrency
  severity: blocker
  verdict: INFEASIBLE
  origin: introduced
  message: 'the adversary demands a total apply re-check cross-record guards decide checked; a fold that re-checks is not a rebuild (ADR 0009), so this is the runtime decide-plus-append atomicity contract and not an apply defect. Recharacterized to the doc fix above.'
- file: crates/mandate-model/src/tenancy.rs
  line: 1248
  category: concurrency
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'insert-if-absent guards the identity key; one active membership per principal is a decide-time guard the runtime enforces at append under optimistic concurrency, not a property a total apply can hold. Only reachable by two deciders against one unwritten state, which is the same runtime window.'
- file: crates/mandate-model/src/graph.rs
  line: 233
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'ResourceRegistered carries the identity twice; decide sets resource_id equal to resource.resource_id but the replay value oracle deletes resource_id before checking, so their agreement is the one emitted key with no test.'
- file: crates/mandate-model/tests/adversary_tenancy_topology.rs
  line: 344
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the case doc names the decide-then-apply sequence while its body drives the re-deciding wrapper, so it is green without covering the sequence it describes.'
- file: crates/mandate-model/src/lib.rs
  line: 1
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the event enums derive Serialize only and under serde untagged the five context-id payloads are ambiguous to deserialize, so the event-log envelope is deferred to a later story and model-agreement round-trips through the generated contract shapes, not these enums.'
```

Held: fold order-insensitivity across aggregates; `fold(log ++ log) == fold(log)` and `fold(&[]) == new()`; first-wins for all six creators; typed maps prevent cross-kind id collision; re-add after removal refused by decide; absent optionals absent at every depth; the value oracle resolves `$ref`; three mutants killed; consumers compile; six projections decide against their entity schemas. Evidence under the unit's scratch `adversary2/`.
