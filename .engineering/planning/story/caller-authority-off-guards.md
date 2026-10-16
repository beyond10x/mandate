---
format: aep.planning-md/3
id: story:caller-authority-off-guards
kind: story
status: draft
title: Caller-authority clauses leave the guards blocker
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# Caller-authority clauses leave the guards blocker

## Acceptance

Given `contracts/obligations/*.json`, when `cargo xtask obligations-registry` runs, then no clause whose text is "Caller lacks … authority" is `blocked_on` `decision-blocker:guards`: each is bound to a real-path test or deferred on the story that owns its caller check, and the review result `story:caller-authority-split` promised is filed in the planning store.

## Scope

- `contracts/obligations/*.json`
- the crates whose commands carry the 24 caller-authority clauses (`crates/mandate-model`, `crates/mandate-identity`, `crates/mandate-federation`, `services/sts`, `crates/mandate-authz`) and their tests

## Source

Audit G-27 (story S-13).
