---
format: aep.planning-md/3
id: story:oidc-refresh-and-logout
kind: story
status: active
title: Refresh tokens rotate, and a client can end the session
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-discovery-and-code-flow
- depends_on: story:oidc-signed-tokens-and-key-rotation
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# Refresh tokens rotate, and a client can end the session

Parity story 5.

## Why

**Exists:**

- `mandate.identity.RefreshCredential` with a verifier, session binding, epoch snapshot and
  `Active → Revoked` (`systems/mandate/domains/identity.yaml:82-131`); `RefreshSession`
  (`:277-294`), `RevokeRefreshCredential` (`:255`), `RevokeSession` (`:233`).
- `refresh_session` and `revoke_session` realized over the identity log
  (`crates/mandate-identity/src/session.rs:323`, `crates/mandate-identity/src/lib.rs:162-165`),
  with epoch certification.
- `RevokeAccessCredential` declared (`systems/mandate/domains/credential.yaml:186`).

**Missing:** the `RefreshCredential` entity, its event and `RevokeRefreshCredential` are realized by
no crate (`crates/mandate-identity/src/lib.rs:219-245`, `ESS_UNREALIZED`); a refresh proof resolves
to no session (`story:epoch-snapshot-generations`); the contract has no rotation, family or reuse
rule; the token endpoint admits no `refresh_token` grant (`crates/mandate-server/src/decode.rs:75`);
no end-session endpoint exists. Envoy Gateway's `refreshToken: true` needs the grant, and its
`logoutPath` uses `end_session_endpoint` from discovery.

**New:** refresh issuance on `offline_access`; rotation with a family identity, a predecessor, a
grace sibling and reuse detection (fork F6); `absolute_lifetime` and `valid_if_not_used_for`; refresh
reissuing ID and access tokens from the recorded profile; RP-initiated logout (fork F7).

## Acceptance

Spec first:

- `RefreshCredential` gains `family_id`, `client_id`, `predecessor` (optional), `issued_at`,
  `last_used_at`, states `Active | Rotated | Revoked`; events `RefreshCredentialIssued`,
  `RefreshCredentialRotated`, `RefreshFamilyRevoked`; command `mandate.identity.RotateRefreshCredential`
  (input `refresh_proof`, `client_id`).
- Scenario `oidc-refresh-rotates`: an active credential rotates; the predecessor is `Rotated`, the
  successor `Active`, one family.
- Scenario `oidc-refresh-reuse-revokes-family`: a `Rotated` credential presented outside the grace
  window is denied and `RefreshFamilyRevoked` revokes every member and the session.
- Scenario `oidc-refresh-grace-sibling-once`: a `Rotated` credential presented within the window
  yields one sibling; a second presentation revokes the family.
- Scenario `oidc-refresh-epoch-mismatch-refused`: a principal epoch advanced since issuance denies.
- Scenario `oidc-refresh-wrong-client-refused`: another client's refresh credential is denied.
- Scenario `oidc-end-session-revokes`: `RevokeSession` revokes the session's refresh families.
- `ESS_UNREALIZED` loses the four `RefreshCredential` rows; `cargo xtask coverage` moves them to
  implemented.

Runtime:

- `end_to_end::refresh_grant_returns_new_tokens`: `grant_type=refresh_token` with client
  authentication answers a new `access_token`, `id_token` (no `nonce`), `refresh_token` and
  `expires_in`; the old refresh token is refused afterwards outside the grace window.
- `end_to_end::offline_access_required`: without `offline_access`, no refresh token is returned.
- `end_to_end::end_session_redirects`: `GET /oauth/end_session?id_token_hint=…&post_logout_redirect_uri=…&state=…`
  revokes the session, clears `__Host-mandate-session`, and redirects only to a URI the client
  registered (byte for byte); an unregistered URI renders a plain signed-out response, never a
  redirect.
- `metadata::end_session_endpoint_advertised`; `grant_types_supported` includes `refresh_token`.
- Refresh tokens are opaque, ≥ 256 random bits, persisted as verifiers only (`combined.md:43`).

## Scope

- `systems/mandate/domains/identity.yaml:82-131,210-372`, scenarios `oidc-refresh-*`,
  `oidc-end-session-*`; `generated/`.
- `crates/mandate-identity/src/session.rs`, new `refresh.rs`, `lib.rs` (`realizes!`,
  `ESS_UNREALIZED`), `port.rs`.
- `crates/mandate-server/src/routes.rs` (end-session route), `decode.rs` (`refresh_token` grant,
  end-session query), `metadata.rs`.
- `services/sts/src/issue.rs` / `redemption.rs` (issue refresh at code redemption),
  `services/control-plane/src/{adapters,serve}.rs`.
- `crates/mandate-conformance/src/commands/identity.rs` (target realizes the new command).

Collides with `story:epoch-snapshot-generations` on `identity.yaml` and `mandate-identity` —
absorb its refresh-proof half or sequence after it.

## Out of scope

`/oauth/revoke` (fork F7-B follow-on), back-channel and front-channel logout, upstream session
termination at Google.

## Depends on

`story:oidc-signed-tokens-and-key-rotation` (reissue), `story:oidc-discovery-and-code-flow`
(session cookie, client authentication). Durability of families is `story:oidc-durable-state`.
Forks F4, F6, F7.

## Size

**L — 4 implementor-days.** A whole entity realized for the first time, a new command with a
concurrency-sensitive reuse rule, a new grant and a new endpoint. Reuse detection needs property
tests over interleavings and draws an adversary on the grace window.
