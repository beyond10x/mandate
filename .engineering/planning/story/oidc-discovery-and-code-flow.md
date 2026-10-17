---
format: aep.planning-md/3
id: story:oidc-discovery-and-code-flow
kind: story
status: active
title: A gateway discovers Mandate and completes the OIDC code flow as a confidential client
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-static-client-registry
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# A gateway discovers Mandate and completes the OIDC code flow as a confidential client

Parity story 1.

## Why

**Exists:**

- `GET /oauth/authorize` decoding `response_type=code`, `client_id`, `redirect_uri`, S256
  `code_challenge`, `state`, `nonce`, `target`, `scope` (`crates/mandate-server/src/decode.rs:536-548,868-898`),
  answered by `mandate.federation.AuthorizePublicClient` (`systems/mandate/domains/federation.yaml:320`,
  `services/control-plane/src/adapters.rs:3334`, `services/control-plane/src/serve.rs:569-600`) with
  a `302` carrying `code` and the exact `state`.
- `POST /oauth/token` for `authorization_code` with PKCE S256 and one-winner redemption
  (`decode.rs:909-935`, `services/sts/src/redemption.rs:265,486`, `adapters.rs:3571`).
- RFC 8414 metadata built from the route table (`crates/mandate-server/src/metadata.rs:39-125`),
  which cannot advertise an unserved path.
- The relying-party flow to an external OIDC IdP: `/v1/federation/authorize`, `/callback`,
  `/handoff` (`crates/mandate-server/src/routes.rs:149-166`), with a host-only binding cookie
  (`decode.rs:665`, `serve.rs:1178`) and a single-use pending store (`adapters.rs:1121,1294`).

**Missing for a gateway:**

1. No `/.well-known/openid-configuration` (`routes.rs:27-28` says so on purpose).
2. The authorization endpoint takes the session as `Authorization: Bearer` (`decode.rs:870`), which a
   browser redirected by a gateway cannot send; a user with no session has nowhere to go.
3. `target` is required (`decode.rs:894`) and `scope` is read as Mandate actions
   (`decode.rs:1087`); a gateway sends `scope=openid email profile` and no `target`.
4. The token endpoint refuses any presented client credential (`decode.rs:915`) and metadata says
   `token_endpoint_auth_methods_supported: ["none"]` (`metadata.rs:123`); public clients only
   (`crates/mandate-federation/src/publicclient.rs:87`).

**New:** the discovery document; a Mandate browser session (fork F4) so `/oauth/authorize` without
a session sends the browser through the existing RP flow and resumes the authorization on callback
instead of a handoff; OIDC scope handling (`openid` required; `email`, `profile`, `groups`,
`offline_access` admitted) with the target taken from the client's default resource server (fork
F11); confidential-client authentication by `client_secret_basic` and `client_secret_post` at the
token endpoint, against the verifiers `story:oidc-static-client-registry` records; PKCE per
`pkce_required` (fork F3); the authorization command generalized (fork F15).

## Acceptance

Spec first:

- `mandate.federation.AuthorizePublicClient` becomes `mandate.federation.AuthorizeClient` (fork F15)
  reading the client type from the record; `session_proof` stays its only session input; the old
  scenarios are renamed in the same change and stay green.
- Scenario `oidc-authorize-confidential-without-pkce`: a confidential client with
  `pkce_required: false` and no challenge is issued a code.
- Scenario `oidc-authorize-public-without-pkce-refused`: a public client with no challenge is denied.
- Scenario `oidc-redeem-client-auth-failed`: `RedeemAuthorizationCode` with a wrong client secret is
  denied `InvalidClient` and draws nothing.
- Scenario `oidc-redeem-public-with-secret-refused`: a public client presenting a secret is denied.

Runtime:

- `metadata::openid_configuration_members`: `GET /.well-known/openid-configuration` answers
  `issuer` byte-equal to `--issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
  `userinfo_endpoint` only if served, `end_session_endpoint` only once served,
  `response_types_supported: ["code"]`, `subject_types_supported`,
  `id_token_signing_alg_values_supported` including `RS256`, `scopes_supported`,
  `claims_supported`, `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["client_secret_basic","client_secret_post","none"]`;
  every URL comes from `ROUTES`; the RFC 8414 document carries the same values.
- `relying_party::browser_without_session_is_sent_upstream_and_returns_with_code`: a browser hitting
  `/oauth/authorize` with no session cookie is redirected to the upstream IdP; after the callback it
  is redirected to the client's `redirect_uri` with `code` and the exact `state`, and receives a
  `__Host-mandate-session` cookie (`Secure; HttpOnly; SameSite=Lax; Path=/`).
- `relying_party::session_cookie_skips_upstream`: a second authorization with the cookie answers the
  code without an upstream round-trip; `prompt=login` forces one; `prompt=none` without a session
  answers `error=login_required` to the redirect URI.
- `end_to_end::token_client_secret_basic` and `::token_client_secret_post`: both authenticate;
  both presented at once, a wrong secret, or a secret for a public client answer `401
  invalid_client` with `WWW-Authenticate: Basic`.
- `decode::authorize_oidc_scope`: `scope` without `openid` is refused `invalid_scope`; an unknown
  scope is ignored per OIDC Core 3.1.2.1 or refused (decided in the unit and written down).
- `routes.rs:27-28` and `docs/architecture/adapter-contract.md:47-49` stop listing the discovery
  path as absent; `docs/public/federated-login.md:72-81`, `docs/public/architecture.md:14`,
  `docs/public/roadmap.md:19-21` state the new route count; `crates/mandate-server/tests/routes.rs:24`
  moves.

## Scope

- `systems/mandate/domains/federation.yaml:320-368` (authorization command), `credential.yaml:208-260`
  (redemption gains client authentication inputs), `systems/mandate/scenarios/oidc-authorize-*.yaml`,
  `oidc-redeem-*.yaml`, renamed `pkce-*.yaml`; `generated/`.
- `crates/mandate-server/src/routes.rs` (`Document::OpenIdConfiguration`), `metadata.rs`
  (shared builder for both documents), `decode.rs` (authorize: cookie or bearer, OIDC scopes,
  optional target; token: `client_secret_basic`/`_post`), `crates/mandate-server/tests/{routes,metadata}.rs`.
- `crates/mandate-federation/src/publicclient.rs` → client resolution for both types;
  `crates/mandate-federation/src/authorize.rs`.
- `services/sts/src/redemption.rs` (client authentication before `decide`).
- `services/control-plane/src/serve.rs` (authorize arm `:569-600`, callback `:678` resumes a pending
  authorization), `adapters.rs` (`authorize`, pending authorization store beside `PendingLogin`).
- `contracts/use-cases/oidc-relying-app.json` (new; steps 1–4 of the road).

## Out of scope

ID/access token contents (`story:oidc-signed-tokens-and-key-rotation`), refresh and logout,
userinfo (served only if fork review asks for it; Envoy Gateway does not call it).

## Depends on

`story:oidc-static-client-registry`. Forks F3, F4, F11, F15.

## Size

**L — 4 implementor-days.** Two endpoints change shape (cookie-or-bearer authorization, client
authentication at the token endpoint), a new document, a renamed command across generated code and
scenarios, and the RP callback learns a second continuation. The session cookie is security-critical
and draws at least two adversary rounds, as the RP flow did (`review-result:wm-m1-rp-flow-adversary-1`).
Splits into two units: (a) discovery + token-endpoint client authentication; (b) browser session +
authorization resumption.

## Residue after wave 12

- The two browser cases live in `services/control-plane/tests/relying_party.rs`: only that file
  stands up an upstream identity provider that signs an ID token carrying the request's nonce.
- A public client that sends no PKCE challenge is refused in place (`ChallengeAbsent`), not
  answered `invalid_request` at its validated redirect (RFC 7636 §4.4.1).
- The STS's own client admission (`code::admitted_client`) still answers a client of another
  organization differently from an unregistered one; the authorize road never reaches it, since it
  resolves the client through the federation check first.
