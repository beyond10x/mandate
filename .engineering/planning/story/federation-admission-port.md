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
scope:
- confidence: cited
  path: contracts/obligations/federation.json
- confidence: inferred
  path: crates/mandate-conformance/src/commands/federation.rs
- confidence: inferred
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-federation/src/disable.rs
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: cited
  path: crates/mandate-federation/src/register_client.rs
- confidence: inferred
  path: crates/mandate-federation/tests
- confidence: inferred
  path: services/control-plane/src/adapters.rs
revision: 5
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

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-federation` command handlers — cited
- **Files:** `crates/mandate-federation/src/disable.rs:101,143,197`; `src/record.rs:950` (`register_federation_connection`); `src/register_client.rs:93,189` (the `ConfiguredAdmission` pattern) — cited
- **Files:** `contracts/obligations/federation.json:246,284,528,635` (four `blocked_on` rows) — cited
- **Also likely:** `crates/mandate-conformance/src/commands/federation.rs:48-366`, `src/external.rs:250`; `services/control-plane/src/adapters.rs:923`; about 10 `crates/mandate-federation/tests/*.rs` call sites — inferred
- **Confidence:** high

**Open design call the body does not name:** `register_federation_connection` is also called by control-plane connection seeding (`adapters.rs:923`), which has no caller to admit. Client seeding skips its command for this reason (`adapters.rs:1055-1066`). How the seed path passes the new guard is undecided; left out of waves I–K for that reason.
