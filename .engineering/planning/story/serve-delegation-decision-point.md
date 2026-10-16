---
format: aep.planning-md/3
id: story:serve-delegation-decision-point
kind: story
status: draft
title: Serve the delegation decision point and the agent commands
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
revision: 1
---
# Serve the delegation decision point and the agent commands

## Acceptance

Given `mandate-control-plane serve` configured with recorded delegations, when a delegated `GET /oauth/authorize` is made, then it is decided by a decision point over those recorded delegations and refused when none matches; the commands `systems/mandate/components.yaml` assigns to the control plane for agents are routed, or the component map is amended in the same change to say they are not. An end-to-end case in `services/control-plane/tests/` drives the delegated authorization against the spawned binary.

## Scope

- `services/control-plane/src/main.rs`, `services/control-plane/src/authority.rs`, `services/control-plane/src/adapters.rs`
- `crates/mandate-server/src/routes.rs`, `crates/mandate-server/src/decode.rs` (if routes are added)
- `systems/mandate/components.yaml`

## Source

Audit G-15 (story S-09).
