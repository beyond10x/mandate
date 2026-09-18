---
format: aep.planning-md/1
id: story:federation-linking
kind: story
status: draft
title: Implement verified federation and explicit linking
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-federation
revision: 2
---
# Implement verified federation and explicit linking

## Acceptance

Given a verified federation proof, when its exact organization/issuer/subject key is resolved, then exactly one configured tenant and explicitly linked principal form the resulting authenticated context.

## Required observations

Runtime cases issuer-isolation, email-isolation, explicit-link, link-conflict, tenant-valid, tenant-zero, tenant-ambiguous and tenant-unverified pass; verify configured issuer/signature/client, JIT and linking authorization; no email auto-merge; OIDC discovery/JWKS caching and key rollover tested.

## Scope

- `crates/mandate-federation` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
