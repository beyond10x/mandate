---
format: aep.planning-md/1
id: story:refusal-discriminators
kind: story
status: draft
title: Tenancy and graph refusals carry their declared outcome
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: inferred
  path: contracts/expected-outcomes.json
- confidence: cited
  path: crates/mandate-conformance/src/commands/graph.rs
- confidence: cited
  path: crates/mandate-conformance/src/commands/tenancy.rs
- confidence: cited
  path: crates/mandate-model/src/graph.rs
- confidence: inferred
  path: crates/mandate-model/src/lib.rs
- confidence: cited
  path: crates/mandate-model/src/tenancy.rs
revision: 5
---
## Why

`mandate_model::tenancy::Denied` and `mandate_model::graph::Denied` carry a `reason` and no `RefusedOutcome` discriminator, unlike `mandate_federation::Denied`, `mandate_identity::Denial` and `mandate_token::projection::Denied`. The conformance target therefore reports `denied` for every tenancy and graph refusal, and the nine synthesized `state/<Terminal>/refuses/<Cmd>` scenarios that assert `wrong-state` fail (`story:conformance-target`, 2026-09-19). Deciding the branch in the target would be manufacturing an outcome. `story:tenancy-graph-events` is `implemented`, so this is the live home.

## Outcome

Both `Denied` types carry the declared refusal outcome; the target reports it; the nine scenarios pass.

## Acceptance

`cargo xtask conform` reports the nine tenancy and graph `wrong-state` scenarios `passed`.

## Acceptance — amended 2026-09-21

`cargo xtask conform` reports the tenancy and graph `wrong-state` scenarios that the synthesizer can arrange (seven in the 146-scenario corpus today, one attributed to this story, five to `story:ess-synthesizer-prerequisites` until the ESS fix lands) as `passed`; the nine named in the original Acceptance include two the corpus does not hold.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-model` — cited
- **Files:** `crates/mandate-model/src/tenancy.rs:252` (`tenancy::Denied`), `src/graph.rs:74` (`graph::Denied`); `crates/mandate-conformance/src/commands/tenancy.rs:255-270`, `commands/graph.rs:9,85-90` — cited
- **Pattern:** `RefusedOutcome` at `crates/mandate-federation/src/lib.rs:156`, `crates/mandate-identity/src/lib.rs:282` — cited
- **Also likely:** `crates/mandate-model/src/lib.rs`, `contracts/expected-outcomes.json` — inferred
- **Confidence:** high
- **Not established:** the amended acceptance's counts — seven arrangeable, one to this story and five to ESS sum to six
