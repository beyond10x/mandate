---
format: aep.planning-md/1
id: story:identity-tenant-containment
kind: story
status: implemented
title: IncrementSecurityEpoch refuses a target outside the caller's organization
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/conformance/injections.json
- confidence: cited
  path: contracts/obligations/identity.json
- confidence: cited
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-conformance/tests/target.rs
- confidence: cited
  path: crates/mandate-identity/src/increment.rs
- confidence: cited
  path: crates/mandate-identity/src/port.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_obligations_identity_1.rs
revision: 8
---
## Why

`mandate.identity.IncrementSecurityEpoch` declares "tenant containment fails" among the conditions of its `denied` outcome. `crates/mandate-identity/src/increment.rs` and `<IdentityLog as SecurityEpochWrite>::increment` (`src/port.rs:917-921`) compare version and generation only; nothing compares the named `SecurityEpochTarget` with `VerifiedContext::organization`, so a caller verified in one organization advances another organization's generation (`review-result:wave-d-obligations-identity-adversary-1` F1, case `an_increment_naming_another_organizations_target_fails_tenant_containment`). The same crate already makes that comparison for `RevokeSession` at `src/session.rs:369` and for a snapshot at `src/session.rs:222`. Bounded today: `crates/mandate-server/src/obligations.rs:526` rows the command `Wire::Generated`, so no product route reaches it; the conformance target does (`crates/mandate-conformance/src/commands/identity.rs:125-143`).

## Outcome

`IncrementSecurityEpoch::execute` refuses with `TenantMismatch` when the target's organization is not the caller's — for `Organization(id)` by identity, for `Principal` and `Federation` targets by the organization the log records for them — before any append, and `contracts/obligations/identity.json` binds the clause on the real path.

## Acceptance

`crates/mandate-identity/tests/adversary_obligations_identity_1.rs` case `an_increment_naming_another_organizations_target_fails_tenant_containment` asserts the refusal and an unmoved generation and is green; `cargo xtask obligations-registry` counts "tenant containment fails" in `real_covered` with no deferral to this story.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-identity` — cited
- **Files:** `crates/mandate-identity/src/increment.rs:87` (`IncrementSecurityEpoch::execute`); `src/port.rs:911-925` (`<IdentityLog as SecurityEpochWrite>::increment`); `tests/adversary_obligations_identity_1.rs` — cited
- **Symbols:** `SecurityEpochTarget`, `VerifiedContext::organization`, `TenantMismatch` — cited
- **Pattern, read not edited:** `crates/mandate-identity/src/session.rs:222,369` — inferred
- **Documents:** `contracts/obligations/identity.json:25` — cited
- **Confidence:** high

## Scope — confirmed at close

From the implementor's confirmation table, wave I–K (`docs/plans/2026-09-23-waves-i-j-k-execution.md`). Corrections to the `## Scope` above are kept visible here, not deleted there.

identity-tenant-containment
- `increment.rs` `execute` — confirmed (the decision lives here)
- `port.rs:911-925` — wrong as the place to change: a new `TargetTenancy` impl was added at the end of `port.rs`, so line-pinned citations did not move
- `contracts/obligations/identity.json` — confirmed
- not in scope but needed: `crates/mandate-conformance/src/external.rs`, `tests/target.rs`, `contracts/conformance/injections.json`
