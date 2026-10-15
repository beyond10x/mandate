---
format: aep.planning-md/3
id: story:oidc-google-upstream
kind: story
status: draft
title: Google is configured once as the upstream connector, with hosted domains and Workspace groups
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
revision: 1
---
# Google is configured once as the upstream connector, with hosted domains and Workspace groups

Parity story 3.

## Why

**Exists:**

- The relying-party code flow toward any external OIDC IdP: discovery of its endpoints
  (`crates/mandate-federation/src/idp_token.rs:156`), the authorization request with `state`,
  `nonce` and S256 (`idp_token.rs:199-230`), server-side code redemption with HTTP Basic
  (`idp_token.rs:239`), nonce check (`idp_token.rs:258`), configured by a `--connection` document's
  `relying_party` member and `--client-secret-file` (`services/control-plane/src/adapters.rs:926-1012`,
  `services/control-plane/src/main.rs:125`).
- ID-token verification with an algorithm per connection, split-host JWKS (`jwks_hosts`, written for
  Google's `www.googleapis.com`), `azp` rules (`crates/mandate-federation/src/verifier_real.rs:18-20,378`).
- Tenant resolution that binds a validated claim: `verified_claim_name`/`verified_claim_value`
  (`crates/mandate-federation/src/authenticate.rs:400-415`); `hd` is a string claim Google sets and
  `issuer_verified` treats it as verified (`verifier_real.rs:1478-1485`). So **a single hosted domain
  is enforceable today** with `verified_claim_name: "hd"`.
- JIT provisioning with explicit links (`federation.yaml:274`).
- `mandate.directory.DirectoryGroup` in the contract (`systems/mandate/domains/directory.yaml:56`).

**Missing:** the upstream request asks for `scope=openid` only (`idp_token.rs:220`), so Google sends
no `email` or `name`; the verified claims are dropped after the login — nothing records email, name
or groups for later issuance (fork F13); the tenant rule takes one value where Dex's `hostedDomains`
is a list (fork F16); no Workspace groups; nothing has ever been driven against Google
(`docs/public/federated-login.md:219`).

**New:** a configurable upstream scope list (default `openid email profile`); `hd` request hint when
one domain is listed; `verified_claim_values` list on the tenant rule; a recorded profile snapshot per
login; an optional groups source over the Admin SDK Directory API with a service-account key
reference (fork F19), a mandatory allowlist and a size cap (fork F10); a connector `kind: google`
preset that fills discovery hosts and defaults so the operator writes a client id, secret reference
and domains once.

## Acceptance

Spec first:

- `mandate.core.TenantResolutionRule` admits `verified_claim_values` (a non-empty list) in place of a
  single value; scenarios `federation-hosted-domain-listed` (a token whose `hd` is any listed value
  resolves) and `federation-hosted-domain-unlisted-refused` (another `hd`, or none, is denied and
  provisions nothing).
- `federation.yaml` gains event `mandate.federation.ExternalProfileObserved` (external principal,
  email, email_verified, name, groups) emitted by `AuthenticateFederation` on acceptance; scenario
  `federation-profile-observed-on-login`; scenario `federation-profile-groups-filtered` (groups
  outside the allowlist never appear in the event).
- Scenario `federation-groups-over-cap-refused`: a login whose filtered groups exceed the cap is
  denied with a declared clause and opens no session.

Runtime:

- `relying_party::google_preset_minimal_document`: a connection document of `kind: google`,
  `client_id`, `secret_ref`, `hosted_domains: [..]` starts and serves; the printed configuration names
  the discovered endpoints.
- `relying_party::upstream_scopes_requested`: the upstream authorization URL carries
  `scope=openid email profile` and, with one domain, `hd=<domain>`.
- `relying_party::email_unverified_is_not_emitted_verified`: an upstream token with
  `email_verified: false` records `email_verified: false`.
- `groups::directory_port_double`: with a test double of the Directory API, groups are fetched for
  the logged-in user, filtered by the allowlist and recorded; a Directory API failure refuses the
  login when groups are configured `required`, and records no groups when `optional`.
- `groups::service_account_key_never_logged`: the key file's bytes appear in no event, log or
  `Debug` rendering.
- A recorded manual run against a real Google tenant is attached to the use case as a `promise` row
  (no credentials in the repository).

## Scope

- `systems/mandate/domains/core.yaml` (`TenantResolutionRule`), `federation.yaml:230-273,456-509`,
  scenarios `federation-hosted-domain-*`, `federation-profile-*`, `federation-groups-*`; `generated/`.
- `crates/mandate-federation/src/idp_token.rs` (scope list, `hd`), `authenticate.rs` (list rule,
  profile event), `verifier_real.rs` (unchanged rules; claims passed through), new
  `crates/mandate-federation/src/directory_groups.rs` (port + `ureq` implementation reusing the SSRF
  guard of `verifier_real.rs:256,331`).
- `services/control-plane/src/adapters.rs` (`ConnectionSeed` `kind`, `hosted_domains`, `groups`),
  `main.rs` (`--service-account-file NAME=PATH`).
- `contracts/use-cases/oidc-relying-app.json` (upstream party rows).

## Out of scope

Other upstream providers (later, each its own small story: GitHub, Microsoft Entra, generic OIDC is
already served); directory synchronization of groups (enterprise-directory epic); SAML.

## Depends on

None for the spec and the profile event. Its claims are consumed by
`story:oidc-signed-tokens-and-key-rotation` through a port, so the two run in parallel. Forks F10,
F13, F16, F19.

## Size

**L — 3.5 implementor-days.** Hosted-domain list and scopes are small (0.5 day); the profile event
touches the contract and the fold (1 day); the Directory API port with the service-account JWT
assertion (RFC 7523 to Google's token endpoint) and its guard is the bulk (2 days). Splits into
(a) domains, scopes, profile event; (b) Workspace groups.
