---
format: aep.planning-md/1
id: story:federated-jit-login
kind: story
status: active
title: A first-time user logs in and the link is made during that login
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/tests/serve.rs
revision: 5
---
# A user with no link logs in, and the link is made during that login

## Why

`decision-blocker:jit-provisioning` was cleared on 2026-09-21 in favour of
alternative 2: the adapter drives `AuthenticateFederation`; on an absent-link
denial with JIT admitted on the connection, it drives
`ProvisionExternalPrincipal`, then drives `AuthenticateFederation` again.

The command exists and nothing reaches it. Measured 2026-09-21:
`crates/mandate-federation/src/authenticate.rs:118-121` refuses
`DenialClause::LinkAbsent`, and the `jit_provisioning` field is read off the
connection and ignored. A control plane seeded with a connection carrying
`jit_provisioning: true` and no link answers `400 access_denied` to a valid
proof. A first-time user of a customer's platform therefore cannot log in at
all, which is the case the whole federated-login road exists to serve.

## What this story delivers

The three-step sequence, in the adapter that owns composition —
`Deployment::authenticate` (`services/control-plane/src/adapters.rs:842`) —
not in `mandate-federation`, whose handler decides one command and must keep
deciding one command.

- `AuthenticateFederation` refuses `LinkAbsent`.
- The adapter reads `jit_provisioning` off the selected connection. When it is
  false, the refusal stands and is returned unchanged.
- When it is true, the adapter drives `ProvisionExternalPrincipal(connection_id,
  proof)`, folds the `ExternalPrincipalProvisioned` event it emits, and drives
  `AuthenticateFederation` once more.
- A second `LinkAbsent` is returned, not retried. One retry, never a loop.

The `Principal` record is seeded by the same `ExternalPrincipalProvisioned`
event, per `identity.yaml`'s header; the identity fold materializes it
(`crates/mandate-identity/src/port.rs`).

## Acceptance

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0 with
three new cases: a connection with `jit_provisioning: true` and no link admits
a first login and returns a `session_id`; the same connection with
`jit_provisioning: false` answers the `LinkAbsent` refusal unchanged; a second
login by the same subject resolves the link the first one made and provisions
nothing. `cargo test -p mandate-federation --locked` stays exit 0 — no handler
in that crate changes.

## Out of scope

Any change to `mandate.federation.AuthenticateFederation`'s declared outcomes.
Alternative 4, SCIM push, stays `story:directory-provenance`. Provision-ahead
is unaffected and keeps working.
