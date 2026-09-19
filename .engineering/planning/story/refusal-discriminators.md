---
format: aep.planning-md/1
id: story:refusal-discriminators
kind: story
status: draft
title: Tenancy and graph refusals carry their declared outcome
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
revision: 1
---
## Why

`mandate_model::tenancy::Denied` and `mandate_model::graph::Denied` carry a `reason` and no `RefusedOutcome` discriminator, unlike `mandate_federation::Denied`, `mandate_identity::Denial` and `mandate_token::projection::Denied`. The conformance target therefore reports `denied` for every tenancy and graph refusal, and the nine synthesized `state/<Terminal>/refuses/<Cmd>` scenarios that assert `wrong-state` fail (`story:conformance-target`, 2026-09-19). Deciding the branch in the target would be manufacturing an outcome. `story:tenancy-graph-events` is `implemented`, so this is the live home.

## Outcome

Both `Denied` types carry the declared refusal outcome; the target reports it; the nine scenarios pass.

## Acceptance

`cargo xtask conform` reports the nine tenancy and graph `wrong-state` scenarios `passed`.
