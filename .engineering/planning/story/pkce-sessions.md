---
format: aep.planning-md/1
id: story:pkce-sessions
kind: story
status: draft
title: Implement public-client authentication and sessions
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:session-epochs
scope:
- confidence: cited
  path: bins/mandate
- confidence: cited
  path: crates/mandate-identity
revision: 3
---
# Implement public-client authentication and sessions

## Acceptance

Given an unconsumed S256-bound authorization code, when the session core verifies the matching verifier and redirect, then exactly one concurrent caller obtains a validated redemption result for the STS boundary.

## Required observations

Implement the session/code core behind typed ports: S256 challenge verification, exact redirect binding, expiry, state/nonce and atomic one-use consumption yield a validated redemption result, not an access credential. Unit and concurrent-store tests cover missing/wrong/plain/reused code, active organization and authenticated state; CLI client primitives contain no embedded secret. Actual endpoint redemption and credential issuance are owned by story:oauth-integration.

## Scope

- `crates/mandate-identity` — cited planned scope; canonical directory granularity.
- `bins/mandate` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
