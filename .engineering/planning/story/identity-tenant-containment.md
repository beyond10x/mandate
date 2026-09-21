---
format: aep.planning-md/1
id: story:identity-tenant-containment
kind: story
status: draft
title: IncrementSecurityEpoch refuses a target outside the caller's organization
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
revision: 1
---
## Why

`mandate.identity.IncrementSecurityEpoch` declares "tenant containment fails" among the conditions of its `denied` outcome. `crates/mandate-identity/src/increment.rs` and `<IdentityLog as SecurityEpochWrite>::increment` (`src/port.rs:917-921`) compare version and generation only; nothing compares the named `SecurityEpochTarget` with `VerifiedContext::organization`, so a caller verified in one organization advances another organization's generation (`review-result:wave-d-obligations-identity-adversary-1` F1, case `an_increment_naming_another_organizations_target_fails_tenant_containment`). The same crate already makes that comparison for `RevokeSession` at `src/session.rs:369` and for a snapshot at `src/session.rs:222`. Bounded today: `crates/mandate-server/src/obligations.rs:526` rows the command `Wire::Generated`, so no product route reaches it; the conformance target does (`crates/mandate-conformance/src/commands/identity.rs:125-143`).

## Outcome

`IncrementSecurityEpoch::execute` refuses with `TenantMismatch` when the target's organization is not the caller's — for `Organization(id)` by identity, for `Principal` and `Federation` targets by the organization the log records for them — before any append, and `contracts/obligations/identity.json` binds the clause on the real path.

## Acceptance

`crates/mandate-identity/tests/adversary_obligations_identity_1.rs` case `an_increment_naming_another_organizations_target_fails_tenant_containment` asserts the refusal and an unmoved generation and is green; `cargo xtask obligations-registry` counts "tenant containment fails" in `real_covered` with no deferral to this story.
