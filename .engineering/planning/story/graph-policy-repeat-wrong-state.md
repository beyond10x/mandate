---
format: aep.planning-md/3
id: story:graph-policy-repeat-wrong-state
kind: story
status: draft
title: Repeated graph and policy terminal moves refuse with wrong-state
relations:
- decomposes: epic:authorization
- serves: vision:mandate
revision: 1
---
# Repeated graph and policy terminal moves refuse with wrong-state

## Acceptance

Given a graph or policy record already in a terminal state, when any of the five terminal-move commands declared in `graph.yaml` and `policy.yaml` is repeated on it, then it answers `wrong-state` rather than being accepted, and `AlreadyRecorded` is gone from the graph and policy port types. Each command's state-refusal scenario passes under `cargo xtask conform`, against the record deciders and the doubles alike.

## Scope

- `crates/mandate-graph/src/record.rs`, `crates/mandate-graph/src/port.rs`, `crates/mandate-graph/src/double.rs`
- `crates/mandate-policy/src/record.rs`, `crates/mandate-policy/src/port.rs`, `crates/mandate-policy/src/double.rs`
- `systems/mandate/domains/graph.yaml`, `systems/mandate/domains/policy.yaml` (only if a lifecycle changes)

## Source

Audit G-19 (story S-11).
