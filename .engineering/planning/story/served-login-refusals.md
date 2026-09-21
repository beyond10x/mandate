---
format: aep.planning-md/1
id: story:served-login-refusals
kind: story
status: active
title: The spawned binary refuses at every step of the resolution order
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:served-login-end-to-end
scope:
- confidence: cited
  path: services/control-plane/tests/end_to_end.rs
revision: 4
---
# The spawned binary refuses at every step of the resolution order

## Why

`docs/architecture/federated-login.md` states the order the addendum mandates:
select the configured trust relationship; validate issuer; validate signature;
validate audience and client binding; validate nonce, state and PKCE; validate
the configured organization or tenant claim. One sentence of it is a promise on
its own — *if tenant resolution is ambiguous, Mandate denies rather than
guesses.*

`story:served-login-end-to-end` drove the **accepted** path against the spawned
binary and proved the road runs. It drove no refusal. It took two as one-off
measurements — an issuer publishing an empty key set, and a connection
document omitting `algorithm` — confirmed each turns step one into
`access_denied`, and reverted both rather than commit a case the story did not
name.

So every refusal on this road is decided by code that no test drives through
the composition an operator deploys. `DenialClause::TenantAmbiguous` exists at
`crates/mandate-federation/src/authenticate.rs:349` and nothing reaches it.

## What this story delivers

One case per step, each driving the **child process** over TCP and asserting
the status and the body it answered.

| step | construction |
|---|---|
| connection | a `connection_id` nothing seeded |
| issuer | the proof's `iss` is not the connection's |
| signature | the issuer publishes `{"keys":[]}`; and a proof signed by a key outside the published set |
| audience / client | the proof's `aud` is not the connection's `client_id` |
| nonce / state | a PKCE verifier that does not match the challenge |
| tenant claim | **ambiguous** — the promise the architecture document makes |
| configuration | a `--connection` document omitting `algorithm` |

A refusal that reaches the wire as `500`, or as a body naming an internal
clause, is a finding and not an expected value. Assert the body, not only the
status: the road already answers `400 access_denied` for causes as different as
an unconfigured algorithm and an unseeded connection, and a case that reads
only the status cannot tell those apart.

## Acceptance

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0 with one
new case per row above in `services/control-plane/tests/end_to_end.rs`, each
spawning the binary, driving it over TCP, and asserting the status **and** the
body. Every child is killed and reaped on every path. The report quotes what
the binary answered for each.

## Out of scope

Changing what any route decides. If a step cannot be made to refuse, that is a
finding to report with the observed output, not a case to weaken until it
passes.
