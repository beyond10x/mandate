---
format: aep.planning-md/3
id: story:token-guard
kind: story
status: draft
title: A service runs behind a Mandate token guard, as a sidecar or a library
relations:
- serves: vision:mandate
- informed_by: epic:openid-provider
revision: 2
---
# A service runs behind a Mandate token guard, as a sidecar or a library

Decided by `docs/adr/0013-token-guard.md`, accepted by the operator on 2026-10-15. Forks G1–G3
take the ADR's proposed options unless the implementation finds one does not hold.

## Why

A service behind an OpenID Provider verifies every bearer token itself today: a per-service sidecar
template that checks the token, admits by email or domain, limits requests per identity and bounds
the queue, plus a second JWKS verifier in the service's own code. Every deployment repeats both.
Mandate owns the JWK Set (`crates/mandate-server/src/routes.rs:22`), introspection
(`routes.rs:20`) and an empty policy-enforcement-point crate (`crates/mandate-client/src/lib.rs:1`).

## Outcome

- A library `verify(token) -> identity` in `crates/mandate-client`: signature against a cached JWK
  Set (refetch on unknown `kid`, bounded refresh rate), `iss`, `aud` in a configured list,
  `exp`/`nbf` with bounded skew, the allow rule; a typed identity or a typed refusal.
- A guard sidecar and Helm chart with values `issuer`, `audiences[]`, `allow.emails[]`,
  `allow.domains[]`, `limits.perMinute`, `limits.burst`, `limits.queue`: admits only verified,
  allowed identities, limits per identity, refuses past a bounded queue, forwards the verified
  identity in headers.

## Acceptance

- A token from another issuer, for another audience, expired, or signed by an unknown key is
  refused by both forms with the same typed refusal.
- An identity outside `allow.emails` and `allow.domains` is refused; one inside is admitted and its
  subject and email reach the service.
- One identity over `limits.perMinute` + `limits.burst` is refused while another identity is still
  admitted; requests past `limits.queue` are refused, not buffered.
- A JWK Set rotation (new `kid`) is picked up without a restart.
- The allow rule and refusals are scenarios in `systems/mandate`, observed failing first.

## Size

M–L, about 4 implementor-days: library 1.5, guard binary and limits 1.5, chart 1. Forks G1–G3 in
the ADR.

## Depends on

Nothing in this epic: not on ADR 0012's parity: the guard verifies any standard
issuer's tokens; its end-to-end proof against Mandate follows `story:oidc-signed-tokens-and-key-rotation`.
