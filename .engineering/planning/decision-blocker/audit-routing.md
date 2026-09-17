---
format: aep.planning-md/1
id: decision-blocker:audit-routing
kind: decision-blocker
status: open
title: UNMAPPED-AUDIT-ROUTING
relations:
- blocks: story:audit-client
- blocks: story:constrained-exchange
revision: 1
---
RecordAuditEvent is the trusted worker append port. Specify admitted AuditAction/AuditOutcome values, per-domain event mappings, durable outbox transport/deduplication, retention and failure behavior. Preserve subject/actor and decision/policy correlation; unknown invalid-proof identity stays absent. No raw credentials or upstream secrets enter records. Typed events alone do not implement durable audit.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.
