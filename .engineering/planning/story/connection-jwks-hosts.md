---
format: aep.planning-md/1
id: story:connection-jwks-hosts
kind: story
status: active
title: A connection names the hosts its issuer publishes keys on
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/src/main.rs
- confidence: cited
  path: services/control-plane/tests/end_to_end.rs
revision: 6
---
# A connection names the hosts its issuer publishes keys on

## Why

The served deployment cannot be configured for most real identity providers.

`UreqJwks::admits` (`crates/mandate-federation/src/verifier_real.rs:326`) refuses
a `jwks_uri` on a host the deployment did not list — SSRF containment, and
correct. `RealVerifier::allowing_jwks_hosts` (`:880`) is the builder that lists
them. `ConnectionSeed` (`services/control-plane/src/adapters.rs:703`) is
`deny_unknown_fields`, declares no member for it, and `--connection` is the only
configuration surface the binary has.

A document naming `jwks_hosts` is refused before the listener binds:

```
mandate-control-plane: connection-0.json: unknown field `jwks_hosts`,
expected one of `connection_id`, `organization`, `issuer`, `client_id`,
`algorithm`, `tenant_resolution`, `jit_provisioning`, `link`
```

Google publishes discovery at `accounts.google.com` and its key set at
`www.googleapis.com/oauth2/v3/certs`. Okta and Entra follow the same pattern.
Each one is unconfigurable.

The loopback issuer in `services/control-plane/tests/end_to_end.rs:180` publishes
`jwks_uri` on its own origin — the one shape that happens to work — so every
end-to-end case stands on it and none of them could see this.

Measured 2026-09-21 by the adversary on the login road. It reproduces at
`b8cb155`; nothing could reach it before that commit, because the binary refused
every login.

## What this story delivers

- A `jwks_hosts` member on `ConnectionSeed`: host names, optional, absent meaning
  the issuer's own origin only.
- `main.rs` passes them to `allowing_jwks_hosts` beside the `configure_connection`
  call it already makes, after the connection id is allocated.
- An end-to-end case where the loopback issuer serves its **discovery document on
  one port and its key set on another**, the document names the second host, and
  the login completes against the spawned binary.
- A case where the same split issuer with **no** `jwks_hosts` member is refused,
  so the containment is pinned rather than inherited.

## Acceptance

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0 with both
cases, the first red before the member exists and green after. The refusal case
names what the child answered.

## Out of scope

Changing `UreqJwks::admits`, which is right as it stands. TLS — the cases stay on
loopback `http`, which `admits` allows for loopback hosts only, and a real issuer
over `https` is a road this repository has never driven.
