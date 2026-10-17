---
format: aep.planning-md/3
id: story:oidc-static-client-registry
kind: story
status: active
title: Apps are registered as static OIDC clients in configuration
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:35Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:35Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# Apps are registered as static OIDC clients in configuration

Parity story 4. First in dependency order: every other parity story reads the client it adds.

## Why

A `--client` document today registers a **public** client only: `ClientSeed` states `client_id`,
`organization`, `public`, `redirect_uris`, `pkce_method`
(`services/control-plane/src/adapters.rs:2047-2068`), and the authorization endpoint refuses any
client that is not public (`crates/mandate-federation/src/publicclient.rs:87`). The contract's
`mandate.federation.OAuthClient` has no client type beyond the `public` boolean, no secret, no
trusted peers and no logout redirect URIs (`systems/mandate/domains/federation.yaml:85-115`).
Dex's `staticClients` carry `id`, `secret`/`secretEnv`, `redirectURIs`, `trustedPeers`, `public`
and `name`; an app behind Envoy Gateway is a confidential client.

**Exists:** client registration through the owning command `mandate.federation.RegisterOAuthClient`
(`federation.yaml:369`, `crates/mandate-federation/src/register_client.rs`); the seeding mirror that
refuses a bad set before the socket binds (`adapters.rs:1659-1700`); byte-for-byte redirect URI
comparison (`publicclient.rs:69`); the `NAME=PATH` secret-file pattern
(`services/control-plane/src/main.rs:125`) and `ClientSecret` that never renders
(`crates/mandate-federation/src/idp_token.rs:56-85`); `deny_unknown_fields` on every document.

**New:** a confidential client type with a secret *reference* resolved to a keyed verifier (fork
F2); up to two active verifiers for rotation; `pkce_required` (fork F3); `trusted_peers`;
`post_logout_redirect_uris`; `name`; an inline default resource-server declaration (fork F11); the
contract fields that record each.

## Acceptance

Spec first — added to `systems/mandate` and observed failing before implementation:

- `OAuthClient` gains `client_type` (`Public | Confidential`), `secret_verifiers`
  (`List<mandate.core.CredentialVerifier>`, empty for public), `pkce_required`, `trusted_peers`
  (`List<mandate.core.OAuthClientId>`), `post_logout_redirect_uris`; `RegisterOAuthClient`'s inputs
  and `OAuthClientRegistered`'s payload carry them; `ess specify validate` is green and
  `cargo xtask generate` regenerates without drift.
- Scenario `oidc-client-confidential-registered`: a confidential client with one verifier is
  accepted and `OAuthClientRegistered` carries the verifier and no secret.
- Scenario `oidc-client-public-with-secret-refused`: a public client stating a verifier is denied.
- Scenario `oidc-client-public-pkce-optional-refused`: a public client with `pkce_required: false`
  is denied.
- Scenario `oidc-client-peer-unknown-refused`: a `trusted_peers` entry naming no client in the same
  organization is denied.

Runtime, decided by Rust tests:

- `control_plane::client_secret_reference_resolved`: a `--client` document with
  `"client_type": "confidential", "secret_ref": "app-a"` and `--client-secret-file app-a=PATH`
  starts; the printed client line carries no secret byte.
- `control_plane::client_secret_reference_unresolved_exits_2`: an unresolved reference, a secret
  under the entropy floor, or a redirect URI with a fragment exits 2 naming the file, before bind.
- `control_plane::client_secret_two_verifiers`: two secret references both authenticate (rotation).
- No secret byte appears in stdout, stderr, any event or any `Debug` rendering (a test greps all four).
- Adding an app is one client document and one secret file: the example in
  `docs/public/federated-login.md` `### --client` is replaced by a confidential example, and `:103`,
  `:187` stop saying "public".

## Scope

- `systems/mandate/domains/federation.yaml:85-115,369-403,532-545` (`OAuthClient`,
  `RegisterOAuthClient`, `OAuthClientRegistered`); `systems/mandate/scenarios/oidc-client-*.yaml`;
  `systems/mandate/ess-inputs.yaml`; `generated/` via `cargo xtask generate`.
- `crates/mandate-federation/src/register_client.rs`, `record.rs` (fold), `publicclient.rs` (type
  check moves to the authorization story).
- `services/control-plane/src/adapters.rs` (`ClientSeed`, `ClientSeeding`, `read_client_seed`),
  `services/control-plane/src/main.rs` (`--client-secret-file` admits client references).
- `crates/mandate-types` (a `ClientSecretVerifier` derivation helper; constant-time compare).
- `contracts/expected-outcomes.json`, `contracts/coverage.json`, `docs/public/federated-login.md`.

Collides with: `story:oidc-discovery-and-code-flow` and `story:oidc-trusted-peers` on
`federation.yaml` — the spec-first wave serializes the federation domain edits in one unit.

## Out of scope

Dynamic registration; a registration route; `private_key_jwt`; secret rotation without restart.

## Depends on

Forks F2, F3, F11 decided. No story dependency.

## Size

**M — 2 implementor-days.** One contract entity widened with four fields and four scenarios, one
seed document, one secret-resolution path that already exists for upstream secrets and is reused.
The verifier derivation and its constant-time comparison are small but must be attacked by the
adversary; generated-code churn from the contract change is the main mechanical cost.
