---
format: aep.planning-md/3
id: story:oidc-gateway-swap-proof
kind: story
status: draft
title: An app behind an Envoy Gateway OIDC policy works unchanged on Mandate
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-discovery-and-code-flow
- depends_on: story:oidc-signed-tokens-and-key-rotation
- depends_on: story:oidc-google-upstream
- depends_on: story:oidc-refresh-and-logout
- depends_on: story:oidc-deployment-package
- depends_on: story:oidc-durable-state
revision: 1
---
# An app behind an Envoy Gateway OIDC policy works unchanged on Mandate

The epic's acceptance as a story of its own (added beside the seven parity stories, because no one
of them owns the whole road).

## Why

Each parity story proves its own step. Nothing proves the composition a gateway drives: discovery
read once at configuration, an authorization redirect, a callback to the gateway's `redirectURL`
(`/oauth2/callback` by default), a token request with client authentication, cookies holding the ID
token and access token, a refresh when `expires_in` lapses, and `logoutPath` through
`end_session_endpoint`. The use-case registry (`docs/adr/0011-use-cases.md`) is where a road with
parties outside the repository is written down, with what they do as `promise` rows.

## Acceptance

- `contracts/use-cases/oidc-relying-app.json` exists and `cargo xtask use-cases` decides it: steps by
  command, routes by `ROUTES`, configuration by the real readers, evidence by scenario and test id,
  the gateway's and Google's behaviour as `promise` rows each saying what would refute it.
- `gateway_emulation::envoy_oauth2_filter_road` (in `task check`): a Rust harness that behaves as
  Envoy's oauth2 filter does — fetch discovery, redirect with `client_id`, `redirect_uri`, `scope`,
  `state`, `nonce` and (per the measured version) PKCE; exchange the code with
  `client_secret_post`; keep tokens as cookies; refresh on expiry; log out — drives the shipped
  binary with an upstream double, and the protected app double sees the same `Authorization` /
  claim headers it sees from a recorded Dex exchange (golden file of a Dex-issued token's claim
  *names and types*, no real values).
- `gateway_emulation::cookie_budget`: with the default groups cap, the ID-token cookie stays under
  4 KB for RS256 and ES256.
- `gateway_emulation::subject_compat`: for a connection with `subject_format: dex_compatible`, the
  `sub` equals the Dex encoding for the same upstream subject and connector id (fork F1).
- A recorded run against a real Envoy Gateway in a local cluster (fork F18-C) is attached as the
  use case's evidence note: Envoy Gateway version, chart values, and the observed headers.
- `docs/public/` gains an OpenID Provider page; `docs/public/federated-login.md:58` keeps only its
  consumed-discovery half.

## Scope

- `contracts/use-cases/oidc-relying-app.json`, `contracts/conformance/use-case-report.json`.
- `services/control-plane/tests/gateway_emulation.rs`, test fixtures under
  `services/control-plane/tests/fixtures/` (no keys committed — generated at run time).
- `docs/public/openid-provider.md`, `docs/public/federated-login.md`, `b10x.docs.yaml`.

## Out of scope

Cutting over an app at the downstream platform (a deployment outside this repository).

## Depends on

`story:oidc-discovery-and-code-flow`, `story:oidc-signed-tokens-and-key-rotation`,
`story:oidc-google-upstream`, `story:oidc-refresh-and-logout`, `story:oidc-deployment-package`;
the real-gateway run also `story:oidc-durable-state`. Forks F1, F10, F18.

## Size

**M — 2 implementor-days**, plus a half-day operator-attended real-gateway run. The emulation is a
bounded HTTP client; the use-case document is authored against an existing format and checker.
