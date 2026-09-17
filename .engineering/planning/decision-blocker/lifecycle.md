---
format: aep.planning-md/1
id: decision-blocker:lifecycle
kind: decision-blocker
status: open
title: UNMAPPED-LIFECYCLE
relations:
- blocks: story:domain-runtime
revision: 1
---
Recorded entity lifecycles are immutable snapshots only. Source documents do not settle deletion, reactivation, retention, execution completion or mapping transaction lifecycle. Review concrete lifecycle and retention decisions before implementing those mutations.

Source: `docs/architecture/unmapped.md`. Clear only with reviewed concrete semantics and evidence.