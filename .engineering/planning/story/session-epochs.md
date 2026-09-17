---
format: aep.planning-md/1
id: story:session-epochs
kind: story
status: draft
title: Implement exact session security generations
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:domain-runtime
scope:
- confidence: cited
  path: crates/mandate-identity
revision: 2
---
# Implement exact session security generations

## Acceptance

Given a session snapshot and an authoritative generation increment, when the session is refreshed, then it is rejected as stale without changing eligibility in unrelated organization sessions.

## Required observations

Resolve UNMAPPED-EPOCH and UNMAPPED-ATOMICITY first; exact unsigned generations never wrap, snapshot applicable principal/org/federation values and deny mismatches on refresh/exchange/high risk. Runtime epoch corpus and concurrent disable/refresh races pass.

## Scope

- `crates/mandate-identity` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
