---
format: aep.planning-md/3
id: story:conformance-subject-only-exchange
kind: story
status: draft
title: The conformance target runs subject-only exchange
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# The conformance target runs subject-only exchange

## Acceptance

Given the conformance target, when `cargo xtask conform` runs, then `ExchangeCredential` is dispatched to `services/sts` instead of being answered as unrealized, the subject-only exchange scenarios pass, only the actor and delegation scenarios stay `unsupported` with `story:constrained-exchange` as their owner in `contracts/expected-outcomes.json`, and the comment at `crates/mandate-conformance/src/commands/credential.rs:3-5` is true.

## Scope

- `crates/mandate-conformance/src/commands/credential.rs`, `crates/mandate-conformance/src/commands/mod.rs`
- `services/sts/src/lib.rs`
- `contracts/expected-outcomes.json`

## Source

Audit G-42 (story S-19).
