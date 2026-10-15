---
format: aep.planning-md/3
id: story:relying-party-flow-spec
kind: story
status: draft
title: Specify and document the OIDC relying-party flow
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
---
# Specify and document the OIDC relying-party flow

## Acceptance

Given the three served routes `/v1/federation/authorize`, `/v1/federation/callback` and `/v1/federation/handoff`, when `ess specify validate --path systems/mandate` runs, then begin, callback and redeem-handoff are declared commands with their denials (state, binding cookie, nonce, IdP token failure, reused or expired handoff, `app_state` mismatch), the relying-party configuration is modelled or an explicit opt-out is recorded, `contracts/coverage.json` and `contracts/obligations/*.json` carry rows for them, and the relying-party cases in `services/control-plane/tests/relying_party.rs` are bound to those rows; `docs/public/federated-login.md` gains a relying-party section.

## Scope

- `systems/mandate/domains/federation.yaml`
- `crates/mandate-server/src/routes.rs`, `crates/mandate-server/src/decode.rs`
- `services/control-plane/src/adapters.rs`, `services/control-plane/src/main.rs`
- `contracts/coverage.json`, `contracts/obligations/federation.json`, `contracts/use-cases/federated-login.json`
- `docs/public/federated-login.md`

## Source

Audit G-38, G-82 (story S-15).
