---
format: aep.planning-md/3
id: story:membership-contribution-consistency
kind: story
status: draft
title: Tenancy and directory agree on manual membership contributions
relations:
- decomposes: epic:enterprise-directory
- serves: vision:mandate
revision: 1
---
# Tenancy and directory agree on manual membership contributions

## Acceptance

Given `tenancy.yaml` and `directory.yaml` revised so that the summary and denial clause of `RemoveTeamMembership` and the manual-contribution rule state one thing, when `ess specify validate --path systems/mandate` runs, then it passes, and when a team membership still carries a recorded contribution, `RemoveTeamMembership` refuses with the declared clause in `crates/mandate-model/src/tenancy.rs`. ESS scenario `remove-membership-with-contribution` passes.

## Scope

- `systems/mandate/domains/tenancy.yaml`, `systems/mandate/domains/directory.yaml`
- `crates/mandate-model/src/tenancy.rs`
- `contracts/obligations/model.json`

## Source

Audit G-13, G-36 (story S-07).
