---
format: aep.planning-md/1
id: story:served-login-end-to-end
kind: story
status: implemented
title: The spawned binary completes one login against a real issuer
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federated-jit-login
scope:
- confidence: cited
  path: services/control-plane/Cargo.toml
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/src/main.rs
- confidence: cited
  path: services/control-plane/tests/end_to_end.rs
revision: 8
---
# The spawned binary completes one login against a real issuer

## Why

The federated-login road runs in-process over a real socket: login,
authorize, token, introspect, each answering the status the use case names.
Nothing has driven the **spawned binary** with a proof an issuer actually
signed. The binary wires `RealVerifier` + `UreqJwks`
(`services/control-plane/src/main.rs:99`), so it fetches a discovery document
and a JWK Set over the network and refuses a proof that is not a signed JWT
from a key that set publishes. Every in-process case substitutes a verifier
double for exactly that.

Until one login completes that way, what is proven is that the routes exist
and the handlers run — not that the composition the operator deploys can
authenticate anyone.

Two more flags are missing for the same reason `--connection` and `--key`
were: steps 2 and 3 read a registered OAuth public client and a registered
resource-server target, and no flag carries either. The in-process cases seed
them as a library caller.

## What makes this buildable now

Measured 2026-09-21:

- `UreqJwks::admits` (`crates/mandate-federation/src/verifier_real.rs:326`)
  admits `http` when the host is loopback. A local issuer on `127.0.0.1` is
  reachable without TLS.
- `mandate-token` can mint the proof and publish the matching key set:
  `CredentialSigner::sign` and `published_keys()`
  (`crates/mandate-token/src/signing_real.rs:670`), over
  `SigningKeyMaterial::from_pem` (`:485`) which carries its own `kid()` and
  `published() -> &Jwk` (`:521`).
- `dependency-boundaries.json` **already grants** `mandate-control-plane` the
  `mandate-token` library. No boundary change is needed for the signer.

## What this story delivers

- `--client <PATH>` and `--resource-server <PATH>`, repeatable, in the shape
  `--connection` and `--key` established: a JSON document carrying the
  command's inputs, the binary building the declared event and folding it
  through `record_credential`, and the seeded identity printed.
- One test that **spawns the binary as a child process**, stands a loopback
  HTTP issuer beside it publishing an OIDC discovery document and a JWK Set,
  mints a proof with `mandate-token` under the key that set publishes, and
  drives all four routes against the child over TCP.
- The child's exit status and its stdout are read and asserted, not discarded.

## Acceptance

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0 with a
case that spawns `target/debug/mandate-control-plane serve`, configured
through the four flags, and observes: `POST /v1/federation/login` with an
issuer-signed proof → 200 and a `session_id`; `GET /oauth/authorize` → 302
carrying `state` and a code; `POST /oauth/token` → 200 and a credential;
`POST /oauth/introspect` → 200 and `"active": true`. The child is killed and
reaped by the test whatever the outcome, and the test fails rather than hangs
if the child never listens.

## Out of scope

Persistence. TLS. A second issuer. Any change to what the routes decide —
this story configures and drives what is already there.
