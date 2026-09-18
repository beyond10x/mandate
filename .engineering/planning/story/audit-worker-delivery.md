---
format: aep.planning-md/1
id: story:audit-worker-delivery
kind: story
status: draft
title: Deliver accepted redacted audit records through the worker
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:audit-client
- depends_on: story:directory-provenance
- depends_on: story:domain-runtime
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: services/worker
revision: 4
---
# Deliver accepted redacted audit records through the worker

## Acceptance

Given a committed redacted audit record and a worker crash before acknowledgement, when the worker resumes and retries delivery, then the accepted durable append is recoverable by its stable identifier without loss or duplicate visible records under the reviewed delivery contract.

## Required observations

Exercise before/after-commit crash points, duplicate delivery, rejected emitter, redacted invalid-proof denial with unknown tenant, out-of-order delivery and unavailable sink. Producers retain their own atomic outbox ownership; this story consumes the accepted append contract and does not retrofit STS or directory mutation transactions. No credential, prompt or upstream secret is serialized. Retention, retry, ordering and deduplication choices must be approved under the existing audit/worker/lifecycle blockers before implementation. An outbox is an adapter/storage obligation, not a newly specified public entity.

## Contract and provenance

systems/mandate/domains/audit.yaml: AuditEvent and RecordAuditEvent; domains/core.yaml: AuditRecord and AuditEventId. Do not invent a new delivery-envelope entity; a required schema change must return to ESS review first.

Sources: docs/architecture/audit-routing.md:3; docs/architecture/unmapped.md:64; docs/architecture/unmapped.md:70; systems/mandate/domains/audit.yaml:1. Placement in wave 6 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper`. Every scope assertion is **cited** or **inferred**.

- **Primary write surface:** `services/worker` — inferred; retain canonical directory granularity for the worker’s delivery implementation and package-local checks.
- **Existing symbols:** `Args` and `main` — cited; the worker currently contains only a CLI scaffold, with no runtime delivery or persistence implementation.
- **Planned implementation:** accepted append-port wiring, the reviewed delivery/storage adapter, and package-local crash, retry, duplicate, emitter, tenant, ordering and sink-unavailability cases — inferred; exact modules depend on approved adapter decisions.
- **Consumed contracts:** `AuditEvent`, `RecordAuditEvent`, `AuditRecord` and `AuditEventId` — cited; this story consumes existing ESS contracts and introduces no public delivery-envelope entity.
- **Ownership boundary:** producer mutation transactions and atomic outboxes remain producer-owned; shared workspace configuration, dependency policy, test tooling, ESS and generated outputs remain coordinator-owned integration surfaces — cited.
- **Documents:** no document write surface is established for this delivery unit — inferred; unresolved contract decisions belong to prerequisite work.
- **Confidence:** medium — inferred; worker ownership is established, but runtime interfaces, storage dependencies and delivery semantics remain unresolved.
- **Would collide with:** any unit changing worker runtime modules, its package manifest or package-local tests — inferred.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Every nonterminal prerequisite and open decision blocker must be resolved before dispatch.

## Unresolved retry correlation

RecordAuditEvent accepts emitter_context and AuditRecord and returns AuditEventId; AuditRecord has no stable event identifier. The existing audit-routing decision must specify adapter/storage correlation for a committed append with a lost acknowledgement before implementation. If that requires a public input/envelope change, model and validate it through ESS first and replan consumers; this story does not invent an idempotency field. Unknown tenant is a permitted denial observation, not a reason to drop a record. Source: systems/mandate/domains/audit.yaml:113 and systems/mandate/domains/core.yaml:344.
