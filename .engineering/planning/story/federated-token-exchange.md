---
format: aep.planning-md/1
id: story:federated-token-exchange
kind: story
status: active
title: A session is exchanged for a credential another platform accepts
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-server/src/decode.rs
- confidence: inferred
  path: crates/mandate-server/src/metadata.rs
- confidence: inferred
  path: crates/mandate-server/src/routes.rs
- confidence: inferred
  path: crates/mandate-server/tests/metadata.rs
- confidence: inferred
  path: services/control-plane/src/serve.rs
- confidence: inferred
  path: services/sts/src/issue.rs
- confidence: inferred
  path: services/sts/src/lib.rs
revision: 4
---
# A session is exchanged for a credential another platform accepts

## Why

`/oauth/token` serves `authorization_code` only (`crates/mandate-server/src/decode.rs:66,575`). `mandate.credential.ExchangeCredential` is declared (`systems/mandate/domains/credential.yaml:375-418`) and realized by nothing (`services/sts/src/lib.rs:133-152`); `ResourceServer.allowed_exchange_sources` is validated at registration and read by nothing (`services/sts/src/registry.rs:108,198`). A downstream platform that validates credentials by introspection has no written-down way to obtain one from a federated login.

## Acceptance

Given a session and a resource server whose `allowed_exchange_sources` admits that session's connection, when `/oauth/token` receives `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with the session proof as `subject_token`, then `TokenExchangeAllowed` is recorded and a credential for that resource server is issued that `/oauth/introspect` answers active; a source the resource server does not admit, an expired or revoked session, or an unknown target is refused with `TokenExchangeDenied` and draws nothing. The metadata document advertises the grant. Subject-only: no actor, no delegation.

## Scope

- `services/sts`: an `ExchangeCredential` handler reusing `admitted_target`, `bounded_expiry`, `descriptor_for` (`src/issue.rs:258,293,311`) — inferred
- `crates/mandate-server/src/{routes,decode,metadata}.rs` and `tests/metadata.rs:97` — inferred
- `services/control-plane/src/serve.rs` token arm (`:613-660`) — inferred

## Out of scope

Actor and delegation exchange (`story:constrained-exchange`); durable audit delivery (`decision-blocker:audit-routing`): denials are recorded through the existing in-memory audit path.
