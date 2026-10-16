---
format: aep.planning-md/3
id: epic:openid-provider
kind: epic
status: active
title: Mandate as an OpenID Provider
summary: Mandate becomes a standard OpenID Provider that does everything Dex does, then more
relations:
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-16T21:58:35Z", actor: "human:timo", revision: 2, decided_on: {"asserted":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-16T21:58:35Z", actor: "human:timo", revision: 3, decided_on: {"asserted":{"review_outcome":1}}}
---
# Mandate as an OpenID Provider

## Deliverables

A standard OpenID Provider with everything Dex supplies to the downstream platform, decided by
`docs/adr/0012-openid-provider.md`: OpenID Connect Discovery; the authorization-code flow with PKCE
for public and confidential clients (`client_secret_basic`, `client_secret_post`); signed JWT ID and
access tokens under rotating keys published at `/oauth/jwks`, carrying `iss`, `sub`, `aud`, `exp`,
`iat`, `email`, `email_verified`, `name`, `groups`; Google as the first upstream connector,
configured once, with hosted-domain restriction and optional Workspace groups; a static client
registry in configuration with exact redirect URIs; refresh tokens with rotation and RP-initiated
logout; Dex-style trusted-peer audiences over the existing token-exchange decision; a container
image and Helm chart with durable state, health and readiness, one replica.

After parity, coarser and not gating it: principals, organizations and links reflected in tokens;
grants, approvals and agent ceilings reflected in tokens; workload and agent authentication.

## Exit criteria

An app behind an Envoy Gateway `oidc` SecurityPolicy works unchanged when its issuer URL moves from
Dex to Mandate: the gateway discovers Mandate, a browser signs in through Google, the app receives
the same headers and claims it received from Dex (subject format per fork F1), the session refreshes
past the access-token lifetime, and logout ends it.

## Required observations

- `ess specify validate` and the conformance run are green on every scenario the parity stories add,
  each having been observed failing before its implementation.
- `contracts/use-cases/oidc-relying-app.json` is decided by `cargo xtask use-cases`, with the
  gateway's behaviour as `promise` rows naming the Envoy Gateway version measured.
- The gateway swap is proven by the in-repository emulated-gateway case in `task check` and by one
  recorded run against a real Envoy Gateway (fork F18).
- A pod restart loses no session, refresh family, link or signing key.
- No client secret, refresh token, upstream token or private key appears in an event, a log, a
  fixture or argv; upstream profile attributes are redactable.
- Every document ADR 0012 lists as stating the not-an-OP stance is corrected by the story that made
  it false.

## Contract and provenance

`systems/mandate/domains/{federation,credential,identity}.yaml` (parity), `directory.yaml`,
`tenancy.yaml`, `delegation.yaml`, `workload.yaml` (beyond Dex); `docs/adr/0012-openid-provider.md`;
`docs/architecture/combined.md:61` (OIDC among the owed product adapters);
`docs/sources/original-design.md:1855-1862`. Supersedes `docs/public/federated-login.md:58` for the
OpenID Provider scope only. Builds on `story:relying-party-code-flow`,
`story:federated-token-exchange`, `story:signing-and-verification` and `story:credential-profiles`
(all implemented); depends on `story:domain-folds-over-the-kit` and `story:listener-outbound-stall`
(draft) for durable, concurrent service.

## Out of scope

Dynamic client registration, a consent screen, SAML, device authorization, back-channel logout, the
cutover of any app at the downstream platform (a deployment outside this repository), and more than
one replica.
