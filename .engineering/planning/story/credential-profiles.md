---
format: aep.planning-md/1
id: story:credential-profiles
kind: story
status: draft
title: Implement audience registry and both credential families
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- depends_on: story:audit-client
scope:
- confidence: cited
  path: crates/mandate-token
- confidence: cited
  path: services/sts
revision: 3
---
# Implement audience registry and both credential families

## Acceptance

Given a newly issued reference credential under ImmediateOnline, when it is revoked, then its next authorized introspection reports inactive even if an earlier resolution was cached.

## Required observations

Registered enabled organization-scoped targets and allowed sources required; signed/reference profiles meet declared TTL/cache guarantees; persistence contains verifier only. All credential corpus cases pass; introspection callers authorized; signing/asymmetric authentication/key rotation and expiry tested.

## Scope

- `crates/mandate-token` — cited planned scope; canonical directory granularity.
- `services/sts` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
