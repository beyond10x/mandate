---
format: aep.planning-md/1
id: story:directory-provenance
kind: story
status: draft
title: Implement SCIM and source-aware team contributions
relations:
- decomposes: epic:enterprise-directory
- serves: vision:mandate
- depends_on: story:tenancy-topology
- depends_on: story:federation-linking
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-provisioning
- confidence: cited
  path: services/worker
revision: 3
---
# Implement SCIM and source-aware team contributions

## Acceptance

Given manual and overlapping directory contributions to one team membership, when one mapping is removed, then effective membership retains exactly the remaining valid contributions.

## Required observations

All directory corpus cases pass with concurrent SCIM and mapping removal; contributions uniquely identify source; mappings and memberships share org. Manual/overlapping sources survive; SAML and enterprise lifecycle epic retains separate exit criteria.

## Scope

- `crates/mandate-provisioning` — cited planned scope; canonical directory granularity.
- `services/worker` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
