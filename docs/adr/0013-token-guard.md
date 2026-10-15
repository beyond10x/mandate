# Mandate ships the token guard in front of a service

Status: proposed 2026-10-15. Not accepted: no implementing wave runs on it until the operator
accepts it.

## Context

A service that sits behind an OpenID Provider has to check every request's bearer token itself:
verify the signature against the provider's JWK Set, check issuer, audience and expiry, admit only
some identities, and protect itself from one caller's request volume. Downstream deployments do
this today with an Envoy sidecar template per service plus a second JWKS verifier in the service's
own code. Each deployment writes and maintains both.

Mandate already owns the pieces this check is made of: the JWK Set at `/oauth/jwks`
(`crates/mandate-server/src/routes.rs:22`), RFC 7662 introspection (`routes.rs:20`), and an empty
policy-enforcement-point crate, `crates/mandate-client` ("Rust PEP client and middleware",
`crates/mandate-client/src/lib.rs:1`). ADR 0012 makes Mandate the OpenID Provider that issues the
tokens; the check at the receiving service is the other half of the same contract.

## Proposed decision

Mandate ships a token guard, in two forms over one rule set:

1. **A library**, `verify(token) -> identity`, in `crates/mandate-client`: JWT signature against a
   cached JWK Set (refetched on an unknown `kid`, bounded refresh rate), `iss`, `aud` (one of a
   configured list), `exp`/`nbf` with a bounded clock skew, and the allow rule below. The result is
   a typed identity (subject, email, email_verified, groups, audience) or a typed refusal.
2. **A deployable guard**, a sidecar container with a Helm chart, in front of any HTTP service,
   configured by values: `issuer`, `audiences[]`, `allow.emails[]`, `allow.domains[]`,
   `limits.perMinute`, `limits.burst`, `limits.queue`. It admits a request only when `verify`
   admits its token, limits requests per verified identity, and bounds the queue of waiting
   requests (excess is refused, not buffered without limit). It forwards the verified identity to
   the service in headers the service can trust because only the guard can reach it.

The allow rule, the limits and the refusals are modelled in `systems/mandate` before they are
implemented; the JWK Set fetch and the header forms are wire forms, decided by Rust tests, as ADR
0012's fork F14 does for the provider.

## What it changes

- Mandate's scope grows from issuing and deciding to enforcing at a third party's door. That is a
  responsibility moved into this repository, which is why this ADR needs the operator's acceptance.
- A deployment drops its own sidecar template and in-code verifier for the chart and the library.
- The guard verifies tokens from any standard OpenID Provider, not only Mandate, so it can run
  before ADR 0012's parity ships.

## Open forks

- G1 per-identity limits: in-process token bucket per guard replica (simple, limits multiply with
  replicas), or a shared store (exact, a new dependency). Proposed: in-process first.
- G2 the guard's runtime: an Envoy configuration Mandate generates (JWT filter plus a small
  authorization hook), or a Mandate binary built on the library. Proposed: a Mandate binary, so
  one implementation decides both forms.
- G3 opaque reference tokens: verify only JWTs, or introspect reference credentials too.
  Proposed: JWTs first; introspection as a follow-on.

## Not decided here

Authorization beyond the allow rule (grants, approvals, ceilings) stays with the PDP; the guard
admits identities, it does not decide actions.
