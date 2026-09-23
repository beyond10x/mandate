---
format: aep.planning-md/1
id: story:relying-party-code-flow
kind: story
status: active
title: A browser signs in through an external OIDC IdP's authorization-code flow
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-federation/src/idp_token.rs
- confidence: inferred
  path: crates/mandate-server/src/decode.rs
- confidence: inferred
  path: crates/mandate-server/src/routes.rs
- confidence: inferred
  path: generated
- confidence: inferred
  path: services/control-plane/src/main.rs
- confidence: inferred
  path: services/control-plane/src/serve.rs
- confidence: inferred
  path: systems/mandate/domains/federation.yaml
revision: 6
---
# A browser signs in through an external OIDC IdP's authorization-code flow

## Why

`/v1/federation/login` accepts only an ID token a caller already holds (`crates/mandate-server/src/decode.rs:475`); nothing in the tree redeems an authorization code at an IdP's token endpoint, and the ID token's `nonce` is never checked (`crates/mandate-federation/src/authenticate.rs:289`). An embedding application therefore has to hold the IdP client secret itself, in the browser or its SDK. An IdP whose token endpoint accepts only `client_secret_basic` needs a server-side relying party.

## Acceptance

Given a federation connection that names a redirect URI and a client-secret reference, when a browser opens `GET /v1/federation/authorize?connection_id=…`, then it is redirected to the IdP's `authorization_endpoint` with `state`, `nonce` and an S256 `code_challenge`; and when the IdP returns to `GET /v1/federation/callback`, the code is redeemed at the discovered `token_endpoint` with HTTP Basic client authentication, the returned ID token is verified by the existing verifier plus its `nonce`, and `authenticate_federation` opens a session. A wrong or replayed `state`, a wrong `nonce`, a PKCE mismatch or a refused Basic authentication opens nothing. An end-to-end case against a local RS256 IdP whose `sub` is pairwise and whose tenant claim is URL-named passes.

## Scope

- `crates/mandate-federation`: a token-endpoint port modelled on `UreqJwks` (`src/verifier_real.rs:120,228`), reusing its hardened agent and SSRF guard (`:255,330`) — inferred
- `systems/mandate/domains/federation.yaml`: connection fields for the redirect URI and the client-secret reference; `generated/` through `cargo xtask generate` — inferred
- `crates/mandate-server/src/{routes,decode}.rs`, `services/control-plane/src/{serve,main}.rs` (routes, `--client-secret-file`) — inferred

## Out of scope

Token exchange (`story:federated-token-exchange`); persistence; a secret in argv or a log.
