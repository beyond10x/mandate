---
format: aep.planning-md/3
id: story:oidc-authority-in-tokens
kind: story
status: draft
title: Grants, approvals and agent ceilings are reflected in issued tokens
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-principals-organizations-in-tokens
- depends_on: story:constrained-exchange
- depends_on: story:agent-security
revision: 1
---
# Grants, approvals and agent ceilings are reflected in issued tokens

Beyond Dex 2. Coarse draft.

## Why

Dex tokens carry identity and groups; authorization is the app's. Mandate decides authority:
relationships and checks (`epic:authorization`), agent capability ceilings, delegations and approvals
(`systems/mandate/domains/delegation.yaml:13-250`), with the shared intersection evaluator already
implemented (`story:agent-authority-kernel`, `crates/mandate-authz`). An OIDC token that an app or a
gateway policy reads could carry the narrowed authority instead of raw groups — but only where the
token's validity model matches the authority's revocation guarantee.

**Exists:** `AuthorityScope` on authorization codes and credentials; credential profiles with
`ImmediateOnline` vs `BoundedOffline` revocation (`credential.yaml:11-46`); the intersection
evaluator; `story:constrained-exchange` (draft) for subject/actor exchange.

**New:** an `authorization_details` (RFC 9396) or `mandate_scope` claim rendered from the evaluated
scope for clients whose resource server's profile admits self-contained authority; an `act` claim
(RFC 8693 4.1) for delegated agent tokens; approval-required outcomes surfaced as a refusal with a
pending-approval reference rather than a token; tokens bounded by the earliest applicable expiry.

## Acceptance

- Scenario `oidc-authority-claim-narrowed`: the rendered scope is exactly the intersection the
  evaluator returns and never exceeds the requested scope.
- Scenario `oidc-authority-approval-required-no-token`.
- Scenario `oidc-agent-token-act-claim`: a delegated agent token preserves subject and actor.
- A `ImmediateOnline` profile never carries authority in a self-contained token (refused at
  configuration).

## Scope

`systems/mandate/domains/{credential,delegation,core}.yaml`; `services/sts/src/{issue,exchange}.rs`;
`crates/mandate-authz`; `crates/mandate-token/src/signing_real.rs`.

## Depends on

`story:oidc-principals-organizations-in-tokens`, `story:constrained-exchange`,
`story:agent-security` (active), `epic:authorization` checks.

## Size

**L — 6 implementor-days**, dominated by the exchange it depends on; to be split when decomposed.
