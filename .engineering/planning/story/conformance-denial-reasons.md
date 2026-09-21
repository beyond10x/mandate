---
format: aep.planning-md/1
id: story:conformance-denial-reasons
kind: story
status: draft
title: The conformance run records the reason and clause of every denial
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:conform-gate
- serves: vision:mandate
revision: 1
---
## Why

`mandate-conform`'s `run.json` records, for a denied scenario, only `outcome = denied` (`review-result:wave-d-conform-gate-adversary-1` F6): no `reason`, no clause. The 54 `expectation-unmet` attributions in `contracts/expected-outcomes.json` therefore rest on a hand reading of each handler's first guard that no artifact records, and the gate cannot notice when that guard changes. `story:conformance-target` is `implemented`, so this is the live home.

## Outcome

Every denied scenario in `run.json` carries the declared `reason` and the crate-local clause name the handler refused with; `cargo xtask conform` compares them with `contracts/expected-outcomes.json` so an attribution whose guard moved is refused by name.

## Acceptance

`mandate-conform` over the committed suite writes `reason` and `clause` for all 54 denied-unmet scenarios; `contracts/expected-outcomes.json` carries both per row; `cargo xtask conform` exits non-zero when a recorded clause differs from the run's.
