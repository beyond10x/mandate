---
format: aep.planning-md/1
id: story:served-login-configurable
kind: story
status: active
title: serve takes a federation connection and a signing key, and one login completes
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/src/main.rs
- confidence: cited
  path: services/control-plane/tests/serve.rs
revision: 6
---
# The served deployment can be given a connection and a key

## Why

`mandate-control-plane serve` binds the login road and answers every route on
it. It cannot complete a single login, for two reasons that are configuration
and not design:

- **No connection.** `mandate.federation.RegisterFederationConnection` is in no
  route and no CLI flag. `Deployment::record_federation`
  (`services/control-plane/src/adapters.rs:760`) is the seeding path and only a
  library caller can reach it. `POST /v1/federation/login` therefore has no
  connection to select, which is step 1 of the declared resolution order.
- **No keys.** `services/control-plane/src/main.rs:88` sets `keys: Vec::new()`
  and offers no flag. Measured on 2026-09-21: `GET /oauth/jwks` answers
  `200 {"keys":[]}`.

Everything the flow needs past that is already built and was measured the same
day: `GET /.well-known/oauth-authorization-server` answers 200 with every
endpoint; `Deployment` carries `authenticate` (`:842`), `authorize` (`:914`),
`redeem` (`:1104`) and `introspect` (`:1170`); `services/control-plane`
depends on `mandate-sts` and `authorize` assembles an
`IssueAuthorizationCodeInput` and an `StsRequest`.

## What this story delivers

Two flags on `serve`, and one end-to-end test that uses them.

`--connection <PATH>`, repeatable. A JSON object:

```json
{ "connection_id": "<uuid, optional>",
  "organization": "<uuid>",
  "issuer": "https://idp.example.test",
  "client_id": "mandate-client",
  "tenant_resolution": { "configured_organization": "<uuid>" },
  "jit_provisioning": true }
```

The binary builds `FederationEvent::FederationConnectionCreated` and passes it
to `record_federation`, then prints the `connection_id` it seeded — an operator
who cannot learn the id cannot call the login route.

`--key <PATH>`, repeatable. A JWK object read into `Jwk::new`
(`crates/mandate-server/src/metadata.rs:225`), appended to
`Configuration.keys`. `Jwk::new` refuses an undeclared parameter; that refusal
is a configuration refusal and exits 2, beside the duration refusals already
there.

**Do not deserialize `FederationEvent`.** It is `Serialize`-only and
`#[serde(untagged)]`, and `crates/mandate-federation/src/record.rs:145-154`
says reading one back needs a tagged envelope that belongs to the persistence
story. The flag carries the command's inputs; the binary constructs the event.

## Acceptance

`cargo test -p mandate-control-plane --locked --no-fail-fast` exits 0, with a
test that binds a real socket and drives, in order: `POST /v1/federation/login`
with a proof the configured key signs → a `session_id`; `GET /oauth/authorize`
with that session's proof and an S256 challenge → a redirect carrying a code;
`POST /oauth/token` redeeming it → a credential; `POST /oauth/introspect` →
`active`. A configuration refusal on either flag exits 2 and names the file.

## Out of scope

Persistence. Folds still start empty and are seeded per process; seeding from
an event log stays `story:declared-writers` and the persistence work.
Registering a connection over HTTP — `RegisterFederationConnection` gains no
route here.
