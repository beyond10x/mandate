---
format: aep.planning-md/3
id: story:resource-topology-single-source
kind: story
status: draft
title: One source of truth for registered resource state
relations:
- decomposes: epic:authorization
- serves: vision:mandate
revision: 1
---
# One source of truth for registered resource state

## Acceptance

Given a resource registered and then deregistered through the `Topology` deciders in `crates/mandate-model/src/graph.rs`, when `mandate.authorization.Check` names that resource, then it resolves from the same fold and denies; a duplicate registration is refused by the declared clause rather than the double's `AlreadyRecorded`, and `contracts/coverage.json` names the realizing symbols that are registered. ESS scenario `check-after-deregister-denies` passes.

## Scope

- `crates/mandate-model/src/graph.rs` (register, deregister)
- `crates/mandate-graph/src/double.rs`, `crates/mandate-graph/src/topology.rs`
- `crates/mandate-authz/src/context.rs` (resource resolution)
- `contracts/coverage.json` (`ResourceRegistry` rows)

## Source

Audit G-12 (story S-06).
