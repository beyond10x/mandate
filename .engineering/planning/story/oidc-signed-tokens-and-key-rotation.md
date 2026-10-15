---
format: aep.planning-md/3
id: story:oidc-signed-tokens-and-key-rotation
kind: story
status: draft
title: The token endpoint returns signed ID and access tokens under rotating keys
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-discovery-and-code-flow
revision: 1
---
# The token endpoint returns signed ID and access tokens under rotating keys

Parity story 2.

## Why

**Exists:**

- A real JWT signer over `jsonwebtoken` with an RS256/ES256 allowlist, reserved standard claims,
  rotation with overlap ≥ TTL and emergency revocation that survives restart via
  `new_with_revocations` (`crates/mandate-token/src/signing_real.rs:80,88,548,763,789,852,955`).
- The `SigningKey` lifecycle: `RegisterSigningKey`, `RetireSigningKey` (refused unless a replacement
  is valid now), `RevokeSigningKey` (`systems/mandate/domains/credential.yaml:78,501,538,561`;
  `services/sts/src/keys.rs:177,309,362`), with `signing_admitted` and `admitted_for_verification`
  (`keys.rs:261,280`).
- `IssueSelfContainedCredential` (`credential.yaml:332`, `services/sts/src/issue.rs:411`).
- `GET /oauth/jwks` publishing `--key` public JWKs with a closed member set
  (`crates/mandate-server/src/metadata.rs:195-330`).

**Missing:** the served road signs nothing — `/oauth/token` mints a reference credential
(`services/control-plane/src/adapters.rs:3571-3630`) and `docs/public/federated-login.md:147` says
"This composition holds no signer"; the JWKS comes from `--key` documents, not from the signer, so
rotation and publication can disagree; no ID token exists anywhere in the contract; the token
response has no `expires_in` (`federated-login.md:83`), which Envoy's filter uses to set its cookie
lifetime; no `email`, `email_verified`, `name`, `groups` reach a token.

**New:** private key material from a mounted Secret (fork F17) behind the key-provider seam;
`/oauth/jwks` rendered from `CredentialSigner::published_keys` (`signing_real.rs:939`) for every key
`admitted_for_verification`; an ID token (OIDC Core 2, 3.1.3.6: `iss`, `sub`, `aud`, `exp`, `iat`,
`auth_time`, `nonce`, `at_hash`, `azp` when multi-audience, plus `email`, `email_verified`, `name`,
`groups`); a JWT access token under the client's default resource server's `SelfContained` profile
(fork F11); `expires_in`; scheduled rotation; RS256 default and ES256 per client (fork F8); the
subject per fork F1.

## Acceptance

Spec first:

- `credential.yaml` gains event `mandate.credential.IdentityTokenIssued` (jti, client, principal,
  session, signing key, issued_at, expires_at — **no claim values**, fork F13) emitted by
  `RedeemAuthorizationCode` when `openid` was granted; `RedeemAuthorizationCode`'s response declares
  `id_token` and `expires_in`.
- Scenario `oidc-id-token-issued-on-openid`: a code granted with `openid` redeems to
  `AuthorizationCodeRedeemed` and `IdentityTokenIssued`.
- Scenario `oidc-no-id-token-without-openid`: without `openid`, no `IdentityTokenIssued`.
- Scenario `oidc-sign-with-retired-key-refused`: issuance under a retired or revoked key is denied.
- Scenario `oidc-retire-without-successor-refused` (existing behaviour of `keys.rs:309`, now named).

Runtime:

- `end_to_end::id_token_verifies_against_published_jwks`: the ID token's signature verifies under a
  key fetched from `jwks_uri`; `iss` equals `--issuer`; `aud` is the client id; `nonce` equals the
  authorization request's; `exp - iat` equals the configured ID-token TTL (default `PT24H`, Dex's).
- `end_to_end::id_token_claims`: with `email profile groups` granted, the token carries `email`,
  `email_verified` (boolean), `name` and `groups` (JSON string array) from the session's recorded
  profile (a test double of the profile port until `story:oidc-google-upstream` lands); without
  `email`, no `email`.
- `end_to_end::access_token_is_jwt_for_self_contained_profile`: `access_token` is a JWT with
  `aud` = client id and `exp` bounded by the profile's `max_ttl`; `expires_in` matches.
- `keys::rotation_keeps_old_tokens_valid`: after rotation, a token signed by the previous key still
  verifies until overlap ends, the JWKS lists both, and new tokens carry the new `kid`.
- `keys::revocation_removes_key_at_once`: a revoked key leaves the JWKS on the next request.
- `signing::rs256_default_es256_per_client`: a client without `id_token_signed_response_alg`
  receives RS256; one declaring ES256 receives ES256; the discovery document lists both.
- `docs/public/federated-login.md:83` and `:147` are rewritten; `--key` documents are replaced by
  key-material references.

## Scope

- `systems/mandate/domains/credential.yaml:208-260,332-372,584-750`, scenarios `oidc-id-token-*`,
  `oidc-sign-*`, `oidc-retire-*`; `generated/`.
- `crates/mandate-token/src/signing_real.rs` (ID-token claim set; `at_hash`), `projection.rs`.
- `services/sts/src/issue.rs`, `redemption.rs` (`mint` issues the ID token), `keys.rs`
  (rehydration of revoked keys at start).
- `crates/mandate-server/src/metadata.rs` (JWKS from the signer), `decode.rs` (none),
  `crates/mandate-proto/src/oauth.rs` (token response members).
- `services/control-plane/src/main.rs` (`--signing-key NAME=PATH`, `--id-token-lifetime`),
  `adapters.rs` (`redeem`, a `ProfileClaims` port), `serve.rs` (`redeemed`).
- `docs/public/federated-login.md`.

Collides with `story:oidc-discovery-and-code-flow` on `redemption.rs` and `serve.rs` — schedule
after it or in a separate wave unit after its merge.

## Out of scope

Refresh-time reissue (`story:oidc-refresh-and-logout`), multi-audience tokens
(`story:oidc-trusted-peers`), userinfo, encrypted tokens, automatic in-process key generation.

## Depends on

`story:oidc-discovery-and-code-flow` for wiring; the key-provider and JWKS-from-signer half depends on
nothing and can start in wave 2. Forks F1, F8, F11, F13, F17.

## Size

**L — 4 implementor-days.** The signer exists and is hardened; the work is the contract event, the
claim renderer, the key-provider composition, the JWKS source switch and rotation over a served
road. Splits into (a) keys and JWKS from the signer (2 days, independent) and (b) ID/access token
issuance at the token endpoint (2 days, after story 1).
