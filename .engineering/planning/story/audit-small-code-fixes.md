---
format: aep.planning-md/3
id: story:audit-small-code-fixes
kind: story
status: draft
title: Small code fixes the audit found
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# Small code fixes the audit found

## Acceptance

Given each fix specified first where a scenario or outcome changes and `ess specify validate --path systems/mandate` green, when `cargo test` runs on the touched crates and `cargo xtask conform` runs, then: `IncrementSecurityEpoch` refuses a target with no recorded placement (`crates/mandate-identity/tests/adversary_tenant_containment_1.rs` inverted); revoking an already-revoked workload identity answers `wrong-state`; `revoked_binding_refuses_authentication` passes and binds its clause in `contracts/obligations/model.json`; the four PKCE and STS scenarios reach their denials with `ConfiguredAdmission` seeded; `authz-unadmitted-organization` reaches `Check` without the membership step; `pkce-code-expired` passes on the expiry clause; the subject-only exchange rows in `contracts/obligations/sts.json` are bound to `services/sts/tests/exchange.rs`; `record_delegation` takes the decided result type; unknown and foreign records refuse alike; and `WorkloadIdentity` and `WorkloadIdentityState` are registered and marked implemented.

## Scope

- `crates/mandate-model/src/{workload,lib}.rs` and tests
- `crates/mandate-identity/src/{increment,session}.rs`, `crates/mandate-identity/tests/adversary_tenant_containment_1.rs`
- `crates/mandate-authz/src/workload.rs`, `services/control-plane/src/adapters.rs` (`record_delegation`)
- `crates/mandate-graph/src/double.rs`, `crates/mandate-policy/src/double.rs`
- `crates/mandate-conformance/src/lib.rs`, `crates/mandate-conformance/src/commands/workload.rs`
- `systems/mandate/scenarios/{pkce-malformed-challenge,pkce-redirect-mismatch,pkce-wrong-org-target,sts-disabled-client-issuance,authz-unadmitted-organization,pkce-code-expired}.yaml`
- `contracts/obligations/{model,sts}.json`, `contracts/coverage.json`

## Source

Audit G-10, G-18, G-20, G-21, G-23, G-25, G-43, G-46, G-48, G-54.
