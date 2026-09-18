---
format: aep.planning-md/1
id: story:runtime-decision-dossier
kind: story
status: draft
title: Prepare the runtime decision dossier without clearing blockers
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:foundation-contracts
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: docs/architecture
- confidence: inferred
  path: docs/architecture/runtime-decisions.md
revision: 5
---
# Prepare the runtime decision dossier without clearing blockers

## Acceptance

Given the eleven open runtime decision blockers, when an independent reviewer follows the dossier, then every blocker has a source-cited decision question, bounded alternatives, proposed owner, affected stories and exact evidence required to clear it.

## Required observations

Cover epoch representation and arithmetic, lifecycle/retention, guards and denial audit, transaction boundaries, graph/policy backend, deferred global trust, conditional subject references, uniqueness, algorithm policy, audit routing/vocabulary and worker orchestration. Global trust stays deferred. The separate Drive verifier is recorded as excluded execution tooling. Mark recommendations as proposals. Do not clear a blocker, select an unapproved algorithm/backend, claim runtime tests, or change ESS meaning. A decision can remain unanswered and this dossier can still be complete; downstream runtime cannot start until its own decisions are recorded and cleared by an authorized owner.

## Contract and provenance

Existing entities and relations in systems/mandate/domains/*.yaml are referenced only. This story creates a decision document, no domain noun or persisted envelope.

Sources: docs/architecture/unmapped.md:5; docs/sources/original-design.md:3327; docs/architecture/command-obligations.md:1. Placement in wave 1 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper` — cited from the story, its prerequisite and the repository.

- **Primary surface:** `docs/architecture` — cited existing architecture ownership boundary and canonical directory granularity.
- **Files:** `docs/architecture/runtime-decisions.md` — inferred new document placement retained from the existing scope; the file does not yet exist.
- **Symbols:** none — cited acceptance requires a decision dossier, not runtime implementation.
- **Documents:** documentation only; source-cited questions, alternatives, proposed owners, affected stories and clearance evidence for eleven runtime blockers, with Drive verification explicitly excluded — cited.
- **Also likely:** no additional write surfaces — inferred; existing specifications and architecture sources suffice as references.
- **Confidence:** high — cited acceptance explicitly requires a document and prohibits changing ESS meaning or clearing blockers.
- **Would collide with:** any work owning `docs/architecture`, including changes to its unresolved-semantics register or the proposed dossier — cited canonical directory ownership; record the directory alongside the file because AEP does not normalize ancestor/file overlaps.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Only nonterminal prerequisites and blockers applicable to this dispatched story prevent dispatch; the downstream runtime decisions are its subject, not prerequisites to writing it. Verify an eleven-row blocker matrix against `aep plan artifact blocked`; independently follow each source citation and check every row includes question, alternatives, proposed owner, affected stories and clearance evidence.
