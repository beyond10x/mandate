---
format: aep.planning-md/1
id: story:check-api
kind: story
status: draft
title: Implement stable PEP check semantics
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:tenancy-topology
- depends_on: story:graph-policy
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-authz
- confidence: cited
  path: services/authorization
revision: 3
---
# Implement stable PEP check semantics

## Acceptance

Given a protected request missing a required approval, when the PEP asks the PDP, then it receives allowed=false with a structured scoped challenge and decision identifier.

## Required observations

Validated context required; enforce tenant/space/resource/audience, ceilings and denial precedence. approval-required is allowed=false. PEP outage test denies; return decision correlation/model/policy/revision; runtime contract cases and property tests pass.

## Scope

- `crates/mandate-authz` — cited planned scope; canonical directory granularity.
- `services/authorization` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
