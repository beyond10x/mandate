---
format: aep.planning-md/3
id: story:traceable-recorded-contexts
kind: story
status: draft
title: Recorded credential events carry traceable contexts
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# Recorded credential events carry traceable contexts

## Acceptance

Given the control plane serving authorize, token exchange and introspection, when two exchanges are served concurrently, then each recorded event carries a correlation minted for its own request, no event carries a nil credential id or the placeholder strings `"exchange"` or `"introspect"`, and a test in `services/control-plane/tests/` asserts the two correlations are distinct.

## Scope

- `services/control-plane/src/adapters.rs` (authorize, exchange, introspect contexts)
- `services/control-plane/src/serve.rs` (per-request correlation)
- `systems/mandate/domains/credential.yaml` (only if the context shape changes)

## Source

Audit G-41 (story S-18).
