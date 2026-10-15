# Mandate is an OpenID Provider

Status: accepted by the operator on 2026-10-15.

## Context

Mandate today is an OAuth authorization server and a relying party, and explicitly not an OpenID
Provider. It consumes OpenID Connect from an external OIDC IdP — discovery, JWKS, the ID token, and
since `story:relying-party-code-flow` the IdP's authorization-code flow with HTTP Basic client
authentication (`crates/mandate-federation/src/idp_token.rs:199,239`, routes
`/v1/federation/authorize|callback|handoff` at `crates/mandate-server/src/routes.rs:120-166`). It
publishes RFC 8414 metadata (`crates/mandate-server/src/metadata.rs:104`), a JWK Set
(`metadata.rs:286`), authorization-code + S256 PKCE for **public** clients only
(`crates/mandate-federation/src/publicclient.rs:87`, `metadata.rs:123` advertises
`token_endpoint_auth_methods_supported: ["none"]`), RFC 8693 subject-only exchange
(`crates/mandate-server/src/decode.rs:71-75`, `services/sts/src/exchange.rs:245`) and RFC 7662
introspection. The credential `/oauth/token` returns is a reference credential
(`services/control-plane/src/adapters.rs:3571`); a JWT signer with rotation and revocation exists as
a library (`crates/mandate-token/src/signing_real.rs:763,852,955`) and as the `SigningKey`
lifecycle (`services/sts/src/keys.rs:177,309,362`) but signs nothing on the served road, and no
ID token is issued anywhere.

`docs/public/federated-login.md:58` records the consequence: "Mandate publishes **no**
`/.well-known/openid-configuration` of its own … Mandate is not an OpenID Provider."

The downstream platform runs apps behind Envoy Gateway `oidc` SecurityPolicies whose issuer is a
Dex instance federating to Google. Every capability Dex supplies there — discovery, the
confidential-client code flow, signed ID and access tokens with rotating keys, an upstream
connector with hosted-domain restriction and Workspace groups, a static client list, refresh
tokens, cross-client audiences, a deployable chart — is either already present in Mandate in a
narrower form or is a bounded addition to what is. The combined architecture already lists OIDC
among the product adapters Mandate owes (`docs/architecture/combined.md:61`), and the original
design lists `/.well-known/openid-configuration` among the minimum STS endpoints
(`docs/sources/original-design.md:1855-1862`). The not-an-OP line was a statement of what the
served road did, not a boundary decision.

## Decision

By the operator's decision of 2026-10-15, **Mandate becomes a standard OpenID Provider that does
everything Dex does**, and then more.

1. Mandate publishes `/.well-known/openid-configuration` (OpenID Connect Discovery 1.0) under its
   configured issuer, built from the same route table as the RFC 8414 document so it cannot
   advertise a path nothing serves.
2. The authorization endpoint serves the OpenID Connect authorization-code flow to **confidential**
   clients authenticating with `client_secret_basic` or `client_secret_post`, as well as the
   existing public clients. PKCE S256 stays mandatory for public clients; for confidential
   clients it is a per-client setting, required by default (fork F3).
3. The token endpoint returns a signed JWT `id_token` and, for clients that ask for it, a signed JWT
   access token, with `expires_in`; the keys are the `SigningKey` records the STS already owns,
   published at `/oauth/jwks`, rotated on a schedule with an overlap no shorter than the longest
   token lifetime.
4. Upstream login stays federation: Mandate never holds a user password. The relying-party flow
   becomes the login step of the OP flow; Google is the first configured connector, with
   hosted-domain restriction and optional Workspace groups.
5. Clients are a static registry in configuration (id, secret *reference*, exact redirect URIs).
   Adding an app is configuration only. No dynamic client registration.
6. Refresh tokens with rotation (`offline_access`) and RP-initiated logout are served.
7. Dex's trusted-peer cross-client audience is served as a thin form over the token-exchange
   decision path that already exists, not as a second authority mechanism.
8. The deployable unit is a container image and a Helm chart with durable storage and health and
   readiness endpoints, one replica at first.

The acceptance of the whole decision is one observable: **an app behind an Envoy Gateway `oidc`
SecurityPolicy works unchanged when its issuer URL moves from Dex to Mandate.**

What Mandate does beyond Dex — principals, organizations and explicit links; grants, approvals and
agent ceilings reflected in tokens; workload and agent authentication — is sequenced after parity
and does not gate it.

Every rule already in force still holds on the new surface: the tenant is never caller-selected
(`systems/mandate/domains/federation.yaml:1`), redirect URIs compare byte for byte, raw secrets and
tokens persist only as verifiers (`docs/architecture/combined.md:43`), algorithms come from the
deployment's allowlist (RS256, ES256; `signing_real.rs:80`), every durable state is event-sourced
(`docs/adr/0009-event-sourced-persistence.md`), and every new behaviour is modelled in
`systems/mandate` before it is implemented.

## What this supersedes

- `docs/public/federated-login.md:58`, the sentence "Mandate publishes **no**
  `/.well-known/openid-configuration` of its own — no OpenID Connect command is declared, and the
  route table has no such path. Mandate is not an OpenID Provider." — **for the OpenID Provider
  scope this ADR decides, and only for it.** The row's first half (OIDC Discovery is *consumed* from
  an external OIDC IdP) stays true and stays.

## Not changed by this ADR

These documents still state the not-an-OP stance, or facts that the stance implied. This ADR does
not edit them; each is corrected by the story that makes it false, in the same change as the code:

| Location | What it says | Corrected by |
|---|---|---|
| `crates/mandate-server/src/routes.rs:27-28` | `/.well-known/openid-configuration` is deliberately absent, "no OpenID Connect command is declared" | `story:oidc-discovery-and-code-flow` |
| `docs/architecture/adapter-contract.md:47-49` | the same absence, as the adapter contract | `story:oidc-discovery-and-code-flow` |
| `docs/public/federated-login.md:72` and `:76-81` | "Six routes", and the route table that follows | `story:oidc-discovery-and-code-flow` |
| `docs/public/federated-login.md:83` | `expires_in` is absent from the token response | `story:oidc-signed-tokens-and-key-rotation` |
| `docs/public/federated-login.md:103`, `:187` | `--client` is a public client; a relying application is a public client | `story:oidc-static-client-registry` |
| `docs/public/federated-login.md:147` | "This composition holds no signer" | `story:oidc-signed-tokens-and-key-rotation` |
| `docs/public/federated-login.md:68` | no `/oauth/revoke` | a follow-on story when revocation is served (fork F7: end-session first, revocation later) |
| `docs/public/architecture.md:14`, `docs/public/roadmap.md:19-21` | six routes | `story:oidc-discovery-and-code-flow` |
| `docs/vision.md:7`, `.engineering/planning/vision/mandate.md:15` | "This milestone publishes the design and executable contract foundation, not a working identity provider" | a vision revision after parity ships (a milestone statement, not a boundary; left until it is false) |
| `docs/customer/federated-login-approval.md:66` | "We do not create or store passwords for your users." | nothing — it stays true: the OP federates and holds no password |

Observed while reading, unrelated to this decision and not changed by it: `docs/public/federated-login.md:64`
says no exchange grant is admitted, while `story:federated-token-exchange` is implemented and
`decode.rs:75` admits it.

## Consequences

- The route table grows by at least `/.well-known/openid-configuration`, an end-session endpoint and
  health/readiness paths; `crates/mandate-server/tests/routes.rs:24` (`ROUTES.len() == 9`) and the
  use-case registry (`docs/adr/0011-use-cases.md`) move with it. A new use case,
  `contracts/use-cases/oidc-relying-app.json`, records the Envoy Gateway road with the gateway's
  behaviour as `promise` rows.
- `mandate.federation.OAuthClient` stops being public-only: it gains a client type, a secret
  verifier, trusted peers and logout redirect URIs (spec first, `systems/mandate/domains/federation.yaml:85`).
- The STS signs on the served road for the first time, so `decision-blocker:algorithm-policy`'s
  allowlist and the key-provider seam stop being library-only.
- `mandate.identity.RefreshCredential` (`systems/mandate/domains/identity.yaml:82`), today realized
  by no crate (`crates/mandate-identity/src/lib.rs:219`), becomes served.
- Upstream profile attributes (email, name, groups) enter the event log for the first time. They are
  personal data and are met by redaction under ADR 0009, never by deletion.
- A served OP is a production dependency of every app behind it. The single-threaded listener
  (`services/control-plane/src/serve.rs:16-22`, `story:listener-outbound-stall`) and the in-memory
  folds (`story:domain-folds-over-the-kit`) stop being development-milestone properties and become
  blockers of the deployment story.
- The subject identifier stays the one Dex issued for a connection that replaces a Dex connector
  (fork F1); an app keyed on `sub` keeps its users only through that compatibility form.
- The cutover of any app at the downstream platform is a deployment outside this repository and is
  not authorized by this ADR (`AGENTS.md`, milestone boundary).

## Sequencing

Spec first, then parity, then beyond-Dex:

1. The forks that change the contract are decided (below).
2. Model every parity change in `systems/mandate` and get `ess specify validate` and the conformance
   run green on the new scenarios, as failing-then-passing targets.
3. Static client registry → discovery and code flow → signed tokens → refresh and logout and
   trusted peers; Google connector and packaging alongside; durable state behind the persistence
   runtime decision; the Envoy Gateway swap proof last.
4. Beyond Dex: principals, organizations and links in tokens; grants, approvals and agent ceilings
   in tokens; workload and agent authentication.

## Design forks decided (2026-10-15)

`docs/adr/0012-openid-provider-forks.md` lists every fork met while drafting this design, with its
options and costs. F1–F9 change the contract or the runtime and were decided before the spec-first
wave, each on its recommended option:

| Fork | Decision |
|---|---|
| F1 subject | Dex-compatible `sub` for a connection that replaces a Dex connector; a Mandate principal id everywhere else. |
| F2 client secrets | The configuration holds a secret-file reference; only a keyed verifier is stored; two active verifiers per client, for rotation. |
| F3 PKCE, confidential clients | A per-client setting, required by default, off only for a client whose measured gateway sends no PKCE. |
| F4 browser session | A minimal host-only session cookie bound to the `Session` record. |
| F5 consent | No consent screen for static first-party clients. |
| F6 refresh rotation | Rotation with a 2 s grace that mints at most one sibling; a reuse after the grace revokes the whole family. |
| F7 logout | RP-initiated `end_session` first; `/oauth/revoke` is a follow-on. |
| F8 signing algorithm | RS256 by default, ES256 per client. |
| F9 durable state | tokio + hyper, the organization `eventlog` kit on SQLite on a volume, one replica. |

F10–F22 are decided inside the story that meets them, on the recommendation the forks document
records, unless the story's implementation finds that recommendation does not hold.

## Not decided here

Dynamic client registration, SAML, device authorization and a consent screen for third-party
clients are not part of this decision.
