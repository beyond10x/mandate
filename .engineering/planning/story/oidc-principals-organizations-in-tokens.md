---
format: aep.planning-md/3
id: story:oidc-principals-organizations-in-tokens
kind: story
status: draft
title: Tokens carry Mandate's principal, organization and link, and links are administered
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-gateway-swap-proof
- depends_on: story:protocol-adapters
revision: 1
---
# Tokens carry Mandate's principal, organization and link, and links are administered

Beyond Dex 1. Coarse draft; decomposes further when parity has shipped.

## Why

Dex has users only as upstream claims; Mandate has principals (`systems/mandate/domains/identity.yaml:13`),
organizations (`tenancy.yaml`), explicit external links with a method and an unlink that blocks
re-provisioning (`federation.yaml:7-51,117-195`), and organization-bound sessions. None of that
reaches an app: a parity token carries no organization (fork F21), and links, connections and
clients are files an operator writes — `RegisterFederationConnection` is served by no route
(`docs/public/roadmap.md`, *What is not true yet*).

**Exists:** the commands (`LinkExternalPrincipal`, `UnlinkExternalPrincipal`,
`RegisterFederationConnection`, `DisableFederationConnection`, `RegisterOAuthClient`,
`DisableOAuthClient`), realized as deciders and seeded from flags; organization-bound sessions;
security epochs.

**New:** `org_id`, `org_name` (and `principal_kind`) claims under a `mandate` scope; one person in
several organizations choosing one at authorization (`organization` hint resolved only through the
person's own links, never as authority); administrative routes for connections, clients and links
behind credential-validated context (`story:protocol-adapters`, `decision-blocker:guards`); a
principal disabled or unlinked ending its sessions and refresh families through the epochs.

## Acceptance

- Scenarios `oidc-org-claim-from-session` and `oidc-org-hint-not-linked-refused`.
- A disabled principal's next refresh is refused (`oidc-refresh-principal-disabled-refused`).
- An administrative route registers a client and the next authorization accepts it without a
  restart.
- The organization hint never selects a tenant a link does not already bind (case
  `credential-containment` over the new routes).

## Scope

`systems/mandate/domains/{federation,identity,tenancy}.yaml`; `crates/mandate-server/src/{routes,decode}.rs`;
`services/control-plane/src/{adapters,serve}.rs`; `crates/mandate-token/src/signing_real.rs`.

## Depends on

Parity complete; `story:protocol-adapters` and `decision-blocker:guards` for the administrative
routes; `story:oidc-durable-state` (administered state must persist).

## Size

**L — 5 implementor-days** (claims 1, multi-organization selection 1.5, administrative routes 2.5),
to be split when decomposed.
