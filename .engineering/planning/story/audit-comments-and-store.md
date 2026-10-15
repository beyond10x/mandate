---
format: aep.planning-md/3
id: story:audit-comments-and-store
kind: story
status: active
title: Comments, ownership rows and planning-store records match the code
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-15T21:16:53Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-15T21:16:54Z", actor: "human:timo", revision: 3}
---
# Comments, ownership rows and planning-store records match the code

## Acceptance

Given the comments and records the audit lists, when they are corrected (the YAML comments in `delegation.yaml` and `identity.yaml`, the registry count of 43 in `crates/mandate-model/src/lib.rs`, present tense in `crates/mandate-federation`, symbol rather than line citations in the scenario summaries, the `ownership.md` rows and a composition comment in `components.yaml`, the behaviour test ids in `contracts/coverage.json`, an `#[ignore]` sweep test that reproduces the trailing-dot measurement) and the coordinator applies the store edits through `aep` (the 34 deferred clauses listed on `decision-blocker:guards`, the amended acceptances, the follow-on re-homed, stale blocker edges retargeted, `docs/architecture/unmapped.md` refreshed), then `ess specify validate --path systems/mandate`, `aep plan artifact validate` and `cargo xtask documents` pass and the ignored sweep test runs with `cargo test -- --ignored`.

## Scope

- `systems/mandate/domains/delegation.yaml`, `systems/mandate/domains/identity.yaml`, `systems/mandate/components.yaml`, `systems/mandate/scenarios/*.yaml` (comments and summaries only)
- `crates/mandate-model/src/lib.rs`, `crates/mandate-federation/src/{lib,authorize}.rs`
- `docs/architecture/ownership.md`, `docs/architecture/unmapped.md`
- `contracts/coverage.json` (test ids)
- `crates/mandate-federation/tests/` (the ignored sweep)
- `.engineering/planning/` (coordinator, through `aep` only)

## Source

Audit G-16, G-32, G-47, G-49, G-51, G-59, G-60, G-61, G-67, G-68, G-71; store edits G-28, G-30, G-31, G-33, G-35, G-70.
