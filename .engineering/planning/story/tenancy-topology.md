---
format: aep.planning-md/1
id: story:tenancy-topology
kind: story
status: draft
title: Implement tenancy and resource topology
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:domain-runtime
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-model
- confidence: cited
  path: services/control-plane
revision: 3
---
# Implement tenancy and resource topology

## Acceptance

Given a resource parent in organization A, when a caller in organization B registers a child beneath it, then the registration is denied without creating accessible topology.

## Required observations

Create org memberships, teams and spaces; principals join multiple orgs without a global role. Resource registration verifies existence/ownership and fail-safe creation; cross-tenant-resource rejects mismatch and unresolved parents without partial authority.

## Scope

- `crates/mandate-model` — cited planned scope; canonical directory granularity.
- `services/control-plane` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
