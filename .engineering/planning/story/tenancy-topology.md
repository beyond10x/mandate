---
format: aep.planning-md/1
id: story:tenancy-topology
kind: story
status: active
title: Implement tenancy and resource topology
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:domain-runtime
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-model/src/graph.rs
- confidence: cited
  path: crates/mandate-model/src/lib.rs
- confidence: inferred
  path: crates/mandate-model/src/tenancy.rs
- confidence: inferred
  path: crates/mandate-model/tests/graph.rs
- confidence: inferred
  path: crates/mandate-model/tests/projections.rs
- confidence: inferred
  path: crates/mandate-model/tests/tenancy.rs
revision: 10
---
# Implement tenancy and resource topology

## Acceptance

Given a resource parent in organization A, when a caller in organization B registers a child beneath it, then the registration is denied without creating accessible topology.

## Required observations

Create org memberships, teams and spaces; principals join multiple orgs without a global role. Resource registration verifies existence/ownership and fail-safe creation; cross-tenant-resource rejects mismatch and unresolved parents without partial authority.

## Home: `crates/mandate-model` alone

`services/control-plane` is removed from scope. `mandate-control-plane` is not a `libraries` key, so `xtask/src/main.rs:117` applies the `external` allowlist `["clap","serde_json","sha2"]` to it and it cannot name `mandate-model`; `xtask/src/main.rs:259-272` requires the binary to fail on `serve`; `ownership.md:4` — "Library ownership does not add a deployment". The records this story declares are consumed by the control-plane deployment once `task:runtime-wave-integration` admits the `mandate-*` crates to service packages.

## An unmapped write, recorded

"Create org memberships, teams and spaces" has no declared command. `tenancy.yaml` declares exactly one — `RemoveOrganizationMembership` (`:125`), moving the domain's only transition (`:33-34`). `tenancy.yaml:1` parks creation on `decision-blocker:lifecycle`. This story cannot add commands: `systems/mandate` is `story:domain-runtime`'s scope. That story's `lifecycle-b` unit, which owns `tenancy.yaml`, decides under immutable-with-status which creation commands the source supports and declares them, or records that creation is administrative or SCIM-only. **Re-scope this story after wave 2 merges**; the record shapes may gain fields.

## Projections, not canonical records

All six — `Organization`, `OrganizationMembership`, `Team`, `TeamMembership`, `Space` (`tenancy.yaml:4,17,49,70,103`) and `Resource` (`graph.yaml:7`) — are plain `#[derive(Serialize, Deserialize)]` structs with their `State` enums beside them, declared without `canonical_record!` and never added to `conformance::entries()` (`crates/mandate-model/src/lib.rs:389-400`). Four assertions decide it: `macros.rs:404` hardcodes the `mandate.core.` prefix; `crates/mandate-model/tests/conformance.rs:17` panics on a missing `generated/schema/types/` path; `crates/mandate-types/tests/inventory.rs:49-65` asserts `ACCEPTED` equals the authored `mandate.core.*` set; `conformance.rs:67-79` asserts `Owner::Model == 4`. Under `docs/adr/0009-event-sourced-persistence.md` they are projections of the tenancy fold in any case. `inventory.rs:67-74` forbids *accepting* a derived state enum, not declaring one.

## Units

The coordinator interface commit lands the two `pub mod` lines in `src/lib.rs` and the two module stubs; the two units then run in parallel.

| Unit | Owns | Test file | Contents | ESS command |
|---|---|---|---|---|
| coordinator, first | `crates/mandate-model/src/lib.rs` | `crates/mandate-model/tests/projections.rs` | `pub mod tenancy; pub mod graph;`; the invariance proof that nothing entered `entries()` and `Owner::Model` is still 4 | — |
| `tenancy` | `crates/mandate-model/src/tenancy.rs` | `crates/mandate-model/tests/tenancy.rs` | the five tenancy projections and their `State` enums; principals in multiple organizations with no global role | `RemoveOrganizationMembership` (`tenancy.yaml:125`), record half |
| `graph` | `crates/mandate-model/src/graph.rs` | `crates/mandate-model/tests/graph.rs` | `Resource` with `organization_id`, `parent`, `space_id`; the cross-tenant and unresolved-parent denial the acceptance names — `graph.yaml:162` is the acceptance verbatim | `RegisterResource` (`graph.yaml:146`), record half; the port is `mandate-graph`'s (`ownership.md:11`) |

## Case ids

`cross-tenant-resource` — the single case with `story: story:tenancy-topology`.

## Decisions that apply

`decision-blocker:lifecycle` (immutable-with-status; the `State` enums are `Recorded`, `Active`/`Removed` as wave 2 declares them); `docs/adr/0009-event-sourced-persistence.md`.

## Dependency ceiling

`mandate-types`, `serde`, `serde_json` — already present in `crates/mandate-model/Cargo.toml`; nothing is added. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

`services/control-plane`. `canonical_record!` on any of the six. Any entry in `conformance::entries()`. Any edit to `crates/mandate-model/tests/conformance.rs` or `tests/adversary.rs` — if the coordinator unit does its job, neither changes. `systems/mandate`, `generated/`, `crates/mandate-graph`. `#[ignore]`.

## Sequencing note

`story:graph-policy` reaches `Resource` only through a resource-lookup port and carries no `depends_on` edge to this story; no ordering exists between the two, and `Resource`'s struct shape is not consumed by that crate. `story:check-api` depends on both and is where the port meets the struct. Disjoint from `story:federation-linking` at file level: that crate reads `mandate-model` and edits none of it.

## Gate per unit

`cargo fmt -p mandate-model -- --check`; `cargo clippy -p mandate-model --all-targets --locked -- -D warnings`; `cargo test -p mandate-model --locked`, count reported — the wave-1 conformance and adversary suites must still execute unchanged.

## Scope

- `crates/mandate-model/src/lib.rs` — cited; 408 lines, the crate's only source file; coordinator.
- `crates/mandate-model/src/tenancy.rs`, `src/graph.rs` — inferred; do not exist.
- `crates/mandate-model/tests/tenancy.rs`, `tests/graph.rs`, `tests/projections.rs` — inferred; do not exist.
- Removed: `services/control-plane`.
- Would collide with: any unit editing `crates/mandate-model/src/lib.rs`.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
