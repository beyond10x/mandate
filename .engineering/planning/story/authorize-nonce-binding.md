---
format: aep.planning-md/3
id: story:authorize-nonce-binding
kind: story
status: draft
title: The authorization request's nonce is optional or bound to the code
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
---
# The authorization request's nonce is optional or bound to the code

## Acceptance

Given a registered public client, when it calls `GET /oauth/authorize` without a `nonce`, then the request is admitted (RFC 6749 requires none), and when it sends one, the nonce is either declared as not applying without an ID token or is bound to the authorization code and compared at redemption, so a mismatch refuses with the declared nonce clause. ESS scenarios `authorize-without-nonce` and `authorize-nonce-mismatch` pass, and `AuthorizePublicClient`'s "nonce binding" clause in `contracts/obligations/federation.json` is bound to a real-path test.

## Scope

- `systems/mandate/domains/federation.yaml` (`AuthorizePublicClient.nonce`, its denial clause)
- `crates/mandate-server/src/decode.rs` (`authorize_public_client`)
- `services/control-plane/src/adapters.rs` (authorize path), `services/sts` (`AuthorizationCode` if bound)
- `contracts/obligations/federation.json`

## Source

Audit G-04 (story S-03).
