---
format: aep.planning-md/1
id: decision-blocker:worker-orchestration
kind: decision-blocker
status: open
title: UNMAPPED-ORCHESTRATION
relations:
- blocks: story:directory-provenance
- blocks: story:domain-runtime
revision: 1
---
The worker currently declares the audit append port. Decide and validate job scheduling, synchronization invocation, cleanup/export scheduling, retries and delivery guarantees. Directory records and mutation commands remain control-plane-owned. Do not infer a queue protocol or lifecycle from the planned worker boundary.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.
