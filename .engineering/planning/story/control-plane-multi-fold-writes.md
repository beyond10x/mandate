---
format: aep.planning-md/1
id: story:control-plane-multi-fold-writes
kind: story
status: draft
title: A control-plane command that writes several folds keeps the earlier writes when a later one is refused
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
revision: 2
---
# A control-plane command that writes several folds keeps the earlier writes when a later one is refused

## Why

Found by **reading only** by the implementor of unit I1 in wave I, after fixing the same class in `Deployment::provisioned` (`story:jit-principal-record`). Sites in `services/control-plane/src/adapters.rs`, none run against:

- `OpeningSessionIssuer::issue`: up to three `SecurityEpochRecorded`, then `EpochSnapshotRecorded`, then `SessionOpened`, each through `try_record`; a later refusal leaves the earlier records.
- `authenticate_once`: `let _ = self.federation.apply(&authenticated.event)` discards a refusal after the identity session is open.
- token redemption (~`:2817`): `let _ = self.credentials.apply(&event)` discards a refusal after the code is consumed.

What reaches it: not established. Relates to `decision-blocker:epoch-atomicity`.

## Acceptance

Each site either decides every fold before keeping any, or its refusal is surfaced; one case per site is red before and green after, or the site is shown unreachable and documented.
