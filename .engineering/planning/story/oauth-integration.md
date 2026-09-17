---
format: aep.planning-md/1
id: story:oauth-integration
kind: story
status: draft
title: Integrate public-client endpoints with STS
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- depends_on: story:credential-profiles
- depends_on: story:protocol-adapters
scope:
- confidence: cited
  path: crates/mandate-server
- confidence: cited
  path: services/sts
revision: 3
---
# Integrate public-client endpoints with STS

## Acceptance

Given a fresh authorization code, when the public client redeems it through the actual OAuth endpoint, then exactly one correctly scoped credential is issued.

## Required observations

Run all PKCE corpus cases against actual federation/session/STS adapters, including two concurrent redeemers; verify form encoding, standard errors, registered redirects, state/nonce and credential profiles.

## Scope

- `services/sts` — cited planned scope.
- `crates/mandate-server` — cited planned scope.

## Contract

`systems/mandate/ess-inputs.yaml`; `docs/architecture/combined.md`; `task check` and named runtime suites.
