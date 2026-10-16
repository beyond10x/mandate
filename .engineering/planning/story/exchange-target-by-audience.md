---
format: aep.planning-md/3
id: story:exchange-target-by-audience
kind: story
status: draft
title: Exchange targets by audience are declared; denials record no invented identity
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# Exchange targets by audience are declared; denials record no invented identity

## Acceptance

Given `ExchangeCredential` declaring an optional `target_audience` input and `TokenExchangeDenied` declaring `requested_target` optional with a `requested_audience`, when a token exchange names an audience that resolves to no registration, then it is refused and the recorded `TokenExchangeDenied` carries the audience as presented and no fabricated resource-server id. ESS scenario `exchange-unknown-audience-recorded` passes, and `crates/mandate-server/src/decode.rs` decodes into the declared inputs.

## Scope

- `systems/mandate/domains/credential.yaml` (`ExchangeCredential`, `TokenExchangeDenied`)
- `services/sts/src/exchange.rs`
- `crates/mandate-server/src/decode.rs`
- `crates/mandate-token/src/projection.rs`

## Source

Audit G-40 (story S-17).
