---
format: aep.planning-md/1
id: story:provisioning-replay-principal
kind: story
status: draft
title: Replaying a provisioning event through record_federation rebuilds the link without the principal
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
revision: 3
---
# Replaying a provisioning event through record_federation rebuilds the link without the principal

## Why

Adversary pass 1 on unit I1 in wave I (`review-result:wijk-i1-jit-principal-adversary-1`, finding 2, pre-existing): `services/control-plane/src/adapters.rs` `Deployment::record_federation` folds an `ExternalPrincipalProvisioned` event into the federation model only, while `authenticate` now folds it into both the federation and identity folds (`story:jit-principal-record`). A replay through `record_federation` would rebuild links without their principal records.

What reaches it: nothing found at `services/control-plane/src/main.rs:305,323` — it is fed only seeded Created/Linked events. The event-log replay `main.rs` expects (ruling D4) has not landed; it would reach it.

## Acceptance

Given a log holding an `ExternalPrincipalProvisioned` event, when it is replayed through the deployment's record path, then the identity fold holds the principal it declares.
