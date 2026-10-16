---
format: aep.planning-md/3
id: story:served-login-refusals
kind: story
status: implemented
title: The spawned binary refuses at every step of the resolution order
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:served-login-end-to-end
scope:
- confidence: cited
  path: services/control-plane/tests/end_to_end.rs
revision: 6
transitions:
- {from: "draft", to: "proposed", at: "2026-09-21T19:09:43Z", actor: "human:timo", revision: 3, imported: true}
- {from: "proposed", to: "active", at: "2026-09-21T19:09:45Z", actor: "human:timo", revision: 4, imported: true}
- {from: "active", to: "implemented", at: "2026-09-21T23:17:57Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1}}, imported: true}
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

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0 with one new case per row above in `services/control-plane/tests/end_to_end.rs`, each spawning the binary, driving it over TCP, and asserting the status **and** the body. Every child is killed and reaped on every path. The report quotes what the binary answered for each.

Amended 2026-10-16 (audit G-33). The tenant-claim row is the one exception to "driving it over TCP". An ambiguous tenant resolution is refused as a configuration before the socket: `an_ambiguous_tenant_resolution_is_refused_as_a_configuration_before_the_socket` (`services/control-plane/tests/end_to_end.rs:1747`) starts the binary with two `--connection` documents on one issuer, binds no port, and asserts exit status 2 (`:1788`) rather than a status and body over TCP. The login-time clause `TenantAmbiguous` is still reached by a deployment whose folds came from an event log, and `two_connections_on_one_issuer_from_a_log_are_still_refused_as_ambiguous` (`services/control-plane/tests/serve.rs:2936`) covers that path. Every other row keeps the acceptance as written.

## Out of scope

Changing what any route decides. If a step cannot be made to refuse, that is a
finding to report with the observed output, not a case to weaken until it
passes.
