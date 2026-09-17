---
format: aep.planning-md/1
id: story:audit-client
kind: story
status: draft
title: Deliver redacted audit and Rust client
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:check-api
scope:
- confidence: cited
  path: crates/mandate-audit
- confidence: cited
  path: crates/mandate-client
- confidence: cited
  path: examples/axum-service
revision: 4
---
# Deliver redacted audit and Rust client

## Acceptance

Given an Axum PEP using the Rust client, when a tenant administrator revokes its caller’s grant, then the next revision-bound protected call is denied with a correlated redacted audit record.

## Required observations

Every control-plane mutation and decision has subject/actor/correlation and revision evidence. audit-redaction passes against real serialized events/logs. Rust client and Axum PEP example enforce denied/challenge decisions and demonstrate live access changes without redeploy.

## Scope

- `crates/mandate-audit` — cited planned scope; canonical directory granularity.
- `crates/mandate-client` — cited planned scope; canonical directory granularity.
- `examples/axum-service` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
