---
format: aep.planning-md/1
id: review-result:wave-e-tenancy-graph-events-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — tenancy-graph-events
relations:
- reviews: story:tenancy-graph-events
revision: 1
---
```
unit: story:tenancy-graph-events — crates/mandate-model/src/{tenancy,graph,lib}.rs, tests/{tenancy,graph,replay,adversary_tenancy_topology}.rs, four mandate-authz test files, uncommitted on impl/tenancy-graph-events at base 9401ab9
verdict: needs-change
cases: executed 65 → 75, red 2 (adversary file crates/mandate-model/tests/adversary_events_1.rs, 10 cases: 8 held, 2 confirmed)
findings: 7 — 1 blocker, 3 warnings, 3 notes
```

```findings
- file: crates/mandate-model/src/graph.rs
  line: 153
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'ResourceEvent::Registered serializes an absent parent as "parent": null, which the compiled mandate.graph.ResourceRegistered refuses because parent is optional and typed as mandate.core.ResourceId, a string.'
- file: crates/mandate-model/tests/replay.rs
  line: 704
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'resource_samples() only ever builds Registered with parent Some, so no case in the crate serializes the parent-less registration that carries the defect.'
- file: crates/mandate-model/tests/replay.rs
  line: 724
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the payload oracle compares serialized key sets to required and never a value against its $ref, so a null, a wrong type or a malformed uuid in any of the twelve payloads is invisible to the suite.'
- file: crates/mandate-model/tests/replay.rs
  line: 779
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'name checking is set-equality, so swapping ess_name() between two of the five payloads whose declared keys are exactly {context, id} survives every oracle in the workspace.'
- file: crates/mandate-model/src/tenancy.rs
  line: 1225
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'apply writes a creation event as an unconditional keyed insert, so a creation replayed after its record reached a terminal state returns it to the initial state, which no decide path can produce and no wired consumer reaches today.'
- file: .engineering/planning/story/tenancy-graph-events.md
  line: 27
  category: acceptance
  severity: note
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the story Scope declares fold returning Result<Tenancy, Denied> and the implementation returns Tenancy; the code is right and the story text is stale, and only the coordinator can amend it.'
- file: crates/mandate-model/src/tenancy.rs
  line: 90
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the module records the display-name admission as an unrealized denial clause but not RetireTeam''s directory-mapping clause or RemoveTeamMembership''s mapping-contribution clause, which are equally unrealized here.'
```

Held under attack: fold equals live at every prefix of a 12-command interleaved history and of a 3-deep resource tree; 32 denied paths over all 12 commands leave the whole projection equal; every base guard survives the split and `add_organization_membership` is stricter; `apply` is total (a move for an absent record writes nothing); all 12 payloads validate structurally against their schemas except the ruled `resource_id`; the four `mandate-authz` hunks are argument-only with no assertion weakened; every projection exposes every required entity field including `state`. Evidence under the unit's scratch `adversary1/`.
