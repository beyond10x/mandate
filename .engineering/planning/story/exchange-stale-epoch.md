---
format: aep.planning-md/3
id: story:exchange-stale-epoch
kind: story
status: draft
title: Token exchange refuses a subject credential issued under a stale epoch
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# Token exchange refuses a subject credential issued under a stale epoch

## Acceptance

Given a subject credential issued under a session epoch that has since advanced, when it is presented as `subject_token` to the token-exchange grant at `POST /oauth/token`, then the exchange re-reads the session's epochs, answers `invalid_grant`, and records `TokenExchangeDenied`; the `ExchangeCredential` "stale" clause is split out in `contracts/obligations/sts.json` and bound to that real-path test, and ESS scenario `exchange-stale-epoch` passes.

## Scope

- `systems/mandate/domains/credential.yaml` (`ExchangeCredential` denial clause)
- `services/sts/src/exchange.rs` (epoch re-read)
- `services/control-plane/src/adapters.rs` (passes `epochs` instead of `None`)
- `services/sts/tests/declared_denials.rs`, `services/sts/tests/exchange.rs`
- `contracts/obligations/sts.json`

## Source

Audit G-02 (story S-02).
