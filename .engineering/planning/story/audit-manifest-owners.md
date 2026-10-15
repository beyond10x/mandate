---
format: aep.planning-md/3
id: story:audit-manifest-owners
kind: story
status: active
title: Manifest statuses, owners and reasons match the code
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-15T21:16:52Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-15T21:16:53Z", actor: "human:timo", revision: 3}
---
# Manifest statuses, owners and reasons match the code

## Acceptance

Given the coverage manifest, the obligations ledger, the expected outcomes and the owner comments the audit lists, when each row's status, story, blocker and reason is set as the audit's tables say (the five graph and policy commands deferred on `story:graph-policy-adapter` with `decision-blocker:backend`, `RefreshSession` and `SessionRefreshed` declared on `story:declared-writers`, `AuthorizePublicClient` deferred or re-pointed, closed owners replaced by live ones, citations corrected, Workload added to the domains list of `contracts/obligations/authz.json`, the use-case registry's six routes made nine with `--client-secret-file`), then `generated/coverage/receipt.json` is regenerated, `cargo xtask coverage`, `cargo xtask obligations-registry` and `cargo xtask conform` pass, and no row names a closed story as the owner of open work.

## Scope

- `contracts/coverage.json`, `generated/coverage/receipt.json` (regenerated, never hand-edited)
- `contracts/obligations/*.json`, `contracts/expected-outcomes.json`, `contracts/use-cases/federated-login.json`, `tests/security/cases.json`
- `systems/mandate/scenarios/federation-*.yaml` (residue owner)
- owner comments in `crates/mandate-federation/src/lib.rs`, `crates/mandate-identity/src/lib.rs`, `crates/mandate-authz/src/{lib,command,event,context}.rs`, `crates/mandate-graph/src/lib.rs`, `crates/mandate-conformance/src/commands/{authz,identity,mod}.rs`, `services/control-plane/src/{adapters,authority}.rs`

## Source

Audit G-03, G-05, G-06, G-08, G-09, G-24, G-26, G-50, G-52, G-53, G-55, G-56, G-57, G-58, G-62, G-63 (domains-list part), G-64, G-65, G-66, G-69, G-87.
