---
format: aep.planning-md/3
id: story:consume-approval-denial-split
kind: story
status: draft
title: ConsumeApproval's denial names only what it can decide
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
revision: 1
---
# ConsumeApproval's denial names only what it can decide

## Acceptance

Given `delegation.yaml` revised so that `ConsumeApproval`'s denial cause no longer names the action/resource check that no input carries, when `ess specify validate --path systems/mandate` runs, then it passes; the `ConsumeApproval` row in `contracts/obligations/authz.json` is split, and its subject and actor halves are bound to real-path tests in `crates/mandate-authz/tests/`, with no clause left that no story can realize.

## Scope

- `systems/mandate/domains/delegation.yaml` (`ConsumeApproval`)
- `crates/mandate-authz/src/command.rs`, `crates/mandate-authz/tests/`
- `contracts/obligations/authz.json`

## Source

Audit G-17 (story S-10).
