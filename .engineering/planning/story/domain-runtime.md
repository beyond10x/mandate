---
format: aep.planning-md/1
id: story:domain-runtime
kind: story
status: draft
title: Settle remaining domain lifecycle contracts
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: docs/architecture
- confidence: cited
  path: generated
- confidence: cited
  path: systems/mandate
revision: 5
---
# Settle remaining domain lifecycle contracts

## Acceptance

Given the unresolved lifecycle register, when the source-backed lifecycle decisions are accepted and projected through ESS, then every formerly unresolved mutation has one unambiguous declared transition or an explicit prohibition.

## Required observations

Resolve UNMAPPED-LIFECYCLE with source-backed lifecycle decisions, deletion/retention rules and typed transitions before runtime mutations; update ESS plus generated contracts and conformance cases.

## Scope

- `systems/mandate` — cited planned scope; canonical directory granularity.
- `docs/architecture` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Integration obligations

ESS changes in this story also regenerate and review generated/ through ESS; the typed scope includes that projection tree. This contract unit must freeze the canonical type/port surface before the concurrent federation and graph units begin, or replan the affected units. Changing runtime behavior is not implied by projection validation.
