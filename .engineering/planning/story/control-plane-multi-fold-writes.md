---
format: aep.planning-md/3
id: story:control-plane-multi-fold-writes
kind: story
status: implemented
title: A control-plane command that writes several folds keeps the earlier writes when a later one is refused
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-09-23T11:18:27Z", actor: "human:timo", revision: 3, imported: true}
- {from: "proposed", to: "active", at: "2026-09-23T11:18:29Z", actor: "human:timo", revision: 4, imported: true}
- {from: "active", to: "implemented", at: "2026-09-23T12:35:49Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1,"review_outcome":2}}, imported: true}
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
