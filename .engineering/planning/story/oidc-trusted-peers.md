---
format: aep.planning-md/3
id: story:oidc-trusted-peers
kind: story
status: active
title: A client obtains a token for a trusted peer's audience
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-static-client-registry
- depends_on: story:oidc-signed-tokens-and-key-rotation
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:36Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# A client obtains a token for a trusted peer's audience

Parity story 6.

## Why

Dex lets client B list client A in `trustedPeers`; A then requests scope
`audience:server:client_id:B` and receives an ID token with `aud: [B, A]` and `azp: A`, which B
accepts as its own.

**Exists:** subject-only RFC 8693 exchange at `/oauth/token`
(`crates/mandate-server/src/decode.rs:71-75,464-510,566-581`; `services/sts/src/exchange.rs:245,270`),
admitted by the target resource server's `allowed_exchange_sources`
(`systems/mandate/domains/credential.yaml:11-46`, `services/sts/src/registry.rs:142,231`), recorded
as `TokenExchangeAllowed` / `TokenExchangeDenied` (`credential.yaml:663,691`) —
`story:federated-token-exchange`, implemented. `story:constrained-exchange` (draft) owns the
actor/delegation form and is not needed here.

**New:** `trusted_peers` on the client (`story:oidc-static-client-registry`) mapped onto the same
admission decision (fork F20): A's request for B's audience is admitted iff B lists A — whether it
arrives as Dex's scope at the authorization endpoint or as RFC 8693 exchange with
`audience=<B's client id>`; multi-audience ID tokens with `azp`; the exchange accepting an ID token
as `subject_token_type=urn:ietf:params:oauth:token-type:id_token`.

## Acceptance

Spec first:

- `ExchangeCredential` admits an ID-token subject; scenario `oidc-peer-exchange-allowed` (B lists A:
  `TokenExchangeAllowed`), `oidc-peer-exchange-not-trusted-refused` (B does not list A:
  `TokenExchangeDenied`, draws nothing), `oidc-peer-cross-organization-refused` (B in another
  organization: denied even if listed).
- Scenario `oidc-authorize-peer-audience-scope`: an authorization with
  `audience:server:client_id:B` from a trusted A grants B's audience; from an untrusted client the
  scope is refused `invalid_scope`.

Runtime:

- `end_to_end::peer_scope_yields_multi_audience_id_token`: the ID token's `aud` is `[B, A]` and
  `azp` is A; B's own verifier (Envoy `jwt_authn` semantics: `audiences: [B]`) accepts it.
- `end_to_end::peer_exchange_rfc8693`: the same outcome through `grant_type=…token-exchange` with
  `audience=B`, issued as an access token whose `aud` is B.
- Both forms produce one `TokenExchangeAllowed` record shape; a test asserts the decision function
  is shared (no second admission path).

## Scope

- `systems/mandate/domains/credential.yaml:373-418,663-698`, `federation.yaml` (scope parse at
  authorization), scenarios `oidc-peer-*`, `oidc-authorize-peer-*`; `generated/`.
- `services/sts/src/exchange.rs`, `registry.rs` (client-backed resource servers).
- `crates/mandate-server/src/decode.rs` (scope grammar; `subject_token_type` id_token).
- `crates/mandate-token/src/signing_real.rs` (list `aud`, `azp`).
- `services/control-plane/src/adapters.rs` (exchange composition).

## Out of scope

Actor tokens, delegation, transitive peers (`story:constrained-exchange`, `epic:advanced-delegation`).

## Depends on

`story:oidc-static-client-registry`, `story:oidc-signed-tokens-and-key-rotation`. Fork F20.

## Size

**M — 2 implementor-days.** The decision path exists and is attacked; the work is one scope grammar,
one subject token type, list audiences in the renderer and the client-to-resource-server mapping.
