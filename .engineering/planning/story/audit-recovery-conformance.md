---
format: aep.planning-md/1
id: story:audit-recovery-conformance
kind: story
status: draft
title: Verify audit delivery isolation and recovery under a bounded load
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:audit-worker-delivery
- depends_on: story:credential-profiles
- depends_on: story:recovery-runbooks
- depends_on: story:protocol-adapters
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: services/worker
revision: 6
---
# Verify audit delivery isolation and recovery under a bounded load

## Acceptance

Given a deterministic two-tenant audit workload interrupted at each documented crash point, when the worker recovery conformance suite runs, then the complete required case inventory passes.

## Required observations

Run a local credential-free fixture using the selected storage adapter. Publish seed, workload size, concurrency, executed cases, fault points, elapsed time, resource use and observed delivery latency. Assert zero loss, duplicate visible records, cross-tenant reads and secret disclosure; do not invent a latency SLO. Use the actual worker/append path, not an in-memory surrogate claimed as production evidence. Any discovered worker defect is fixed within services/worker; a defect requiring another wave unit surface pauses/replans that unit. Export/analytics product APIs remain outside this bounded recovery suite.

## Contract and provenance

Existing AuditEvent/AuditRecord and tenant identities only; test fixtures are not new persisted domain entities.

Sources: docs/sources/original-design.md:2887; docs/sources/original-design.md:2893; .engineering/planning/epic/hardening.md:15; docs/architecture/unmapped.md:66. Placement in wave 9 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper` from the story, its prerequisites and the current tree — cited.

- **Primary surface:** `services/worker` — cited; the story explicitly confines the recovery suite and discovered worker fixes to this package.
- **Existing implementation:** the worker package contains only its manifest and a Clap executable scaffold; no append adapter, storage implementation or runtime tests exist — cited.
- **Planned implementation:** package-local deterministic two-tenant fixtures, authenticated-ingress replay/rejected-emitter cases, storage-backed crash/restart tests and measurement output — inferred; exact files and runtime symbols depend on completed prerequisites.
- **Consumed contracts:** `AuditEvent`, `AuditRecord`, `AuditEventId`, `RecordAuditEvent` and `VerifiedContext` — cited; fixtures introduce no persisted entity.
- **Documents:** no separate documentation write surface is required by the acceptance; fixture instructions and measurement evidence can remain package-local — inferred.
- **Confidence:** medium — inferred; package ownership is explicit, but ingress, storage, crash points and retry correlation remain unimplemented or undecided.
- **Would collide with:** any unit changing `services/worker`, including its manifest, runtime adapter, tests or fixtures — cited.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Every nonterminal prerequisite and open decision blocker must be resolved before dispatch.

## Protocol prerequisite

The replay and rejected-emitter cases must enter through the real trusted worker ingress implemented by story:protocol-adapters, so that story is a prerequisite. A direct append fixture alone cannot prove adapter authentication. Source: docs/architecture/audit-routing.md:3.

## Observation boundary

Tenant-result assertions use a package-local storage observation hook under the reviewed adapter contract, not a newly invented audit query/export API. Lost-acknowledgement retry correlation must be settled by the prerequisite audit decision; no new input identifier is guessed.
