---
format: aep.planning-md/1
id: story:recovery-runbooks
kind: story
status: draft
title: Prepare revocation and outage runbooks with explicit guarantees
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:session-epochs
- depends_on: story:audit-client
- depends_on: story:runtime-decision-dossier
- depends_on: story:credential-profiles
- depends_on: story:audit-worker-delivery
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: docs/runbooks
revision: 4
---
# Prepare revocation and outage runbooks with explicit guarantees

## Acceptance

Given the accepted runtime decisions, when a tabletop reviewer walks each emergency scenario, then the runbook identifies the authorized trigger, affected scope, fail-closed behavior, verification command contract and rollback or recovery condition without inventing an unapproved bound.

## Required observations

Cover tenant reset, federation shutdown, key compromise/rotation, PDP or STS outage, reference-resolution outage and audit-delivery outage. Separate ImmediateOnline from bounded offline validity; mark implementation-specific command spelling and unapproved TTL/SLO values UNMAPPED and assign a story to settle each. Preserve unrelated-tenant sessions. This is document/tabletop evidence only; actual failure and revocation measurements belong to story:runtime-service-qualification. Use the completed credential-profile and worker delivery contracts to name real service operations; verify each documented operation against a local fixture. Product CLI spelling remains deferred to story:product-cli; do not invent CLI commands.

## Contract and provenance

Existing PrincipalSecurityEpoch, OrganizationSecurityEpoch, FederationSecurityEpoch, SigningKey, AccessCredential and AuditEvent declarations are referenced. Numeric epochs stay UNMAPPED until decision-blocker:epoch is actually cleared.

Sources: docs/sources/architecture-addendum.md:1138; docs/sources/architecture-addendum.md:1230; docs/sources/original-design.md:2947; .engineering/planning/epic/hardening.md:15. Placement in wave 7 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper`; cited observations and inferred placement are distinguished below.

- **Primary surface:** `docs/runbooks` — inferred write location, preserving the story's existing placement.
- **Documents:** incident procedures and tabletop evidence for tenant reset, federation shutdown, key compromise/rotation, PDP or STS outage, reference-resolution outage and audit-delivery outage — cited from Required observations.
- **Files:** individual document filenames remain to be selected within the runbook surface — inferred.
- **Symbols:** existing PrincipalSecurityEpoch, OrganizationSecurityEpoch, FederationSecurityEpoch, SigningKey, AccessCredential and AuditEvent contracts are references only; no domain or runtime changes — cited from Contract and provenance.
- **Validation boundary:** verify documented service operations against prerequisite-owned local fixtures; product CLI spelling remains deferred, and actual failure/revocation measurements belong to runtime-service-qualification — cited from Required observations.
- **Confidence:** high — cited acceptance explicitly requires documents and tabletop review, and limits implementation-specific spelling and unapproved bounds to UNMAPPED.
- **Would collide with:** other writes within `docs/runbooks` — inferred; prerequisite service implementations are consumed without expanding this story's write surface.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Every nonterminal prerequisite and open decision blocker must be resolved before dispatch.
