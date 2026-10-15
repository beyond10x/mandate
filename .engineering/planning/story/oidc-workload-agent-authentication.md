---
format: aep.planning-md/3
id: story:oidc-workload-agent-authentication
kind: story
status: draft
title: Workloads and agents authenticate to Mandate and receive tokens
relations:
- decomposes: epic:openid-provider
- serves: vision:mandate
- depends_on: story:oidc-gateway-swap-proof
- depends_on: story:agent-security
- depends_on: story:oidc-authority-in-tokens
revision: 1
---
# Workloads and agents authenticate to Mandate and receive tokens

Beyond Dex 3. Coarse draft.

## Why

Dex authenticates people through connectors; services usually reuse a static client's secret or go
without. Mandate's contract has workload identities and `AuthenticateWorkload`
(`systems/mandate/domains/workload.yaml:5-99`, deciders at `crates/mandate-model/src/lib.rs:521-524`)
and agents with ceilings (`delegation.yaml:73-139`), but no served way for a workload to obtain a
token.

**New:** `client_credentials` for confidential clients bound to a workload identity; RFC 8693
exchange of a Kubernetes projected service-account token or a SPIFFE JWT-SVID
(`subject_token_type=urn:ietf:params:oauth:token-type:jwt`) verified against the cluster's or trust
domain's issuer through the existing federation verifier; agent tokens issued only under a ceiling;
sender constraint (DPoP or mTLS) for high-value profiles (`epic:agents-workloads`).

## Acceptance

- Scenarios `oidc-workload-client-credentials`, `oidc-workload-sa-token-exchange`,
  `oidc-workload-revoked-refused`, `oidc-agent-without-ceiling-refused`.
- A workload token's `sub` is the workload identity, distinct from any human principal and from the
  agent's execution identity.
- A DPoP-bound token is refused without a matching proof (`epic:agents-workloads` exit criterion).

## Scope

`systems/mandate/domains/{workload,delegation,credential}.yaml`; `crates/mandate-model/src/workload.rs`;
`crates/mandate-federation/src/verifier_real.rs` (workload issuers); `services/sts/src/exchange.rs`;
`crates/mandate-server/src/decode.rs`.

## Depends on

Parity complete; `story:agent-security`; `story:oidc-authority-in-tokens` for agent ceilings in tokens.

## Size

**L — 6 implementor-days**; to be split when decomposed (client credentials 1.5, workload token
exchange 2, agent issuance 1.5, sender constraint 1).
