---
format: aep.planning-md/1
id: story:federation-admission-port
kind: story
status: draft
title: The four federation lifecycle handlers consult the admission port
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
revision: 2
---
## Why

`crates/mandate-federation/src/register_client.rs:93` decides "Caller lacks client-administration authority" through the `ClientRegistrationAdmission` port. `register_federation_connection`, `disable_federation_connection`, `disable_oauth_client` and `unlink_external_principal` take no admission argument, so their four authority clauses are unreachable and `contracts/obligations/federation.json` defers them (`review-result:wave-d-obligations-federation-adversary-1` F4). The port is not registration-specific; the four handlers were not given it.

## Outcome

The four handlers take an admission port of the same shape and refuse their authority clause when the port does not hold the caller as the named administrator, with no event appended.

## Acceptance

The four rows bind `path: real` `denial` tests in `crates/mandate-federation/tests/`, each red with the admission call removed; `cargo xtask obligations-registry` lists 0 `mandate-federation` clauses deferred to this story.

## Amended by the coordinator (2026-09-21, `review-result:wave-d-obligations-federation-adversary-2` F2)

`register_client.rs:91` calls `ConfiguredAdmission` "the `pub` double" and `crates/mandate-conformance/src/external.rs:248` registers it as the standing double for `ClientRegistrationAdmission`; no shipped implementation of the port exists, and `decision-blocker:guards` owns that adapter. So the Why's "decides … through the port" means: the handler consults the port, and the port's answer is a double's until the blocker clears.

**Outcome (amended).** The four handlers take an admission port of the same shape and refuse their authority clause when the port does not hold the caller as the named administrator, with no event appended.

**Acceptance (amended).** The four rows bind `path: double` `denial` tests (`double: mandate_federation::register_client::ConfiguredAdmission`) with `blocked_on: decision-blocker:guards`, each red with the admission call removed (the mutation control); `cargo xtask obligations-registry` lists 0 `mandate-federation` clauses deferred to this story, and `double_only` rises by four. No row of this story is `path: real` until a shipped `ClientRegistrationAdmission` exists.
