---
format: aep.planning-md/3
id: story:split-issuer-tls-login
kind: story
status: draft
title: A split issuer completes a login over loopback TLS
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
---
# A split issuer completes a login over loopback TLS

## Acceptance

Given a loopback issuer whose discovery document and key set are served over TLS on two different listed hosts, when the spawned `mandate-control-plane` drives a login through it, then the login completes with `200`, replacing the `400` that `services/control-plane/tests/end_to_end.rs` asserts today for the split-issuer case, and the residue note on `story:connection-jwks-hosts` is removed.

## Scope

- `services/control-plane/tests/end_to_end.rs`
- `crates/mandate-federation/src/verifier_real.rs` (`UreqJwks` trust roots, test-only configuration)
- `docs/public/federated-login.md` ("No successful cross-host JWKS fetch")

## Source

Audit G-29 (story S-14).
