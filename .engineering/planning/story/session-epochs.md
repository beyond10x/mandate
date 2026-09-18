---
format: aep.planning-md/1
id: story:session-epochs
kind: story
status: draft
title: Implement exact session security generations
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:domain-runtime
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-identity/src/generation.rs
- confidence: inferred
  path: crates/mandate-identity/src/increment.rs
- confidence: cited
  path: crates/mandate-identity/src/lib.rs
- confidence: inferred
  path: crates/mandate-identity/src/port.rs
- confidence: inferred
  path: crates/mandate-identity/src/session.rs
- confidence: inferred
  path: crates/mandate-identity/src/snapshot.rs
- confidence: inferred
  path: crates/mandate-identity/tests/generation.rs
- confidence: inferred
  path: crates/mandate-identity/tests/increment.rs
- confidence: inferred
  path: crates/mandate-identity/tests/port.rs
- confidence: inferred
  path: crates/mandate-identity/tests/refresh.rs
- confidence: inferred
  path: crates/mandate-identity/tests/staleness.rs
- confidence: inferred
  path: crates/mandate-identity/tests/surface.rs
revision: 6
---
# Implement exact session security generations

## Acceptance

Given a session snapshot and an authoritative generation increment, when the session is refreshed, then it is rejected as stale without changing eligibility in unrelated organization sessions.

## Required observations

Resolve UNMAPPED-EPOCH and UNMAPPED-ATOMICITY first; exact unsigned generations never wrap, snapshot applicable principal/org/federation values and deny mismatches on refresh/exchange/high risk. Runtime epoch corpus and concurrent disable/refresh races pass.

## The stand-in, recorded

The generation is an ESS `Integer` — signed 64-bit; ESS 0.25.0 has no unsigned primitive — constrained non-negative and monotonic, placed in the contract on the three epoch entities by `story:domain-runtime` (wave 2). "Exact unsigned" in the Required observations is read as "exact, non-negative, never wrapping"; widening to an unsigned type when ESS gains one is a compatible change. At `i64::MAX` the increment denies and an out-of-band reset is required (`command-obligations.md:36`). This is the first numeric value in the entire contract; its projected JSON-Schema shape is unexercised and is checked at wave 2's regeneration.

## Units

A coordinator interface commit lands `src/lib.rs` and the five module files with final signatures and `todo!()` bodies; five units then own disjoint files. The dependency between rows is by signature, not by file.

| Unit | Owns | Test file | Realizes | Cases |
|---|---|---|---|---|
| coordinator, first | `crates/mandate-identity/src/lib.rs` and the five stubs | `crates/mandate-identity/tests/surface.rs` | module wiring, public re-exports, every trait signature | — |
| `generation` | `crates/mandate-identity/src/generation.rs` | `tests/generation.rs` | the `Integer`-backed generation: non-negative, monotonic, denies at maximum | `epoch-overflow` |
| `snapshot` | `src/snapshot.rs` | `tests/staleness.rs` | `SecurityEpochSnapshot` keyed by `EpochSnapshotRef`; per-dimension comparison; unrelated-organization isolation; the `Eligibility::Current | Stale(dimension)` verdict mapping to `DenialReason::StaleEpoch` | `epoch-principal`, `epoch-org`, `epoch-federation`, `epoch-isolation` |
| `session` | `src/session.rs` | `tests/refresh.rs` | the identity-local `Session` record (`identity.yaml:30-56`); `RefreshSession` eligibility; `RevokeSession` state as an input | the refresh half of the four above |
| `port` | `src/port.rs` | `tests/port.rs` | the read port — `resolve(&self, &SessionId)`, `current(&self, &SecurityEpochTarget)` — and, as a separate trait, the write port: compare-and-set on expected version | none directly; the substrate |
| `increment` | `src/increment.rs` | `tests/increment.rs` | `IncrementSecurityEpoch` (`identity.yaml:267-284`) over the write port; the concurrent disable/refresh race | `epoch-overflow` and `epoch-isolation`, increment half |

Every read method takes `&self`. The write port is a separate trait so `story:pkce-sessions`, which is explicitly non-consuming, cannot mutate a generation through a type it holds.

## Session and snapshot are identity-local, not canonical

Four reasons, each read from the tree. `canonical_record!` mints `mandate.core.<Name>` by construction (`crates/mandate-types/src/macros.rs:404`); `mandate.identity.Session` cannot go through it. `crates/mandate-model/tests/conformance.rs:71-78` asserts that crate realizes exactly the four `Owner::Model` entries. `crates/mandate-types/tests/inventory.rs:50-65` asserts `ACCEPTED` equals the `mandate.core.*` projection. `crates/mandate-model` is `story:tenancy-topology`'s scope. Under `docs/adr/0009-event-sourced-persistence.md` these records are projections of this crate's fold in any case. The vocabulary they need — `SessionId`, `PrincipalId`, `OrganizationId`, `FederationConnectionId`, `EpochSnapshotRef`, `SecurityEpochTarget`, `DenialReason::StaleEpoch` — is public at `crates/mandate-types/src/lib.rs:156-176`.

## Case ids

`epoch-principal`, `epoch-org`, `epoch-federation`, `epoch-isolation`, `epoch-overflow` (`tests/security/cases.json:265-334`). All five name `RefreshSession` and `ExchangeCredential`; the exchange half is STS's (`ownership.md:8`, `:15`) and consumes this story's read port. `RedeemAuthorizationCode` (`credential.yaml:209`) and `IntrospectCredential` (`credential.yaml:342`) deny on staleness through the same port without being realized here.

## Decisions that apply

`decision-blocker:epoch` (`Integer` stand-in; deny at maximum); `decision-blocker:epoch-atomicity` (one event-log transaction; the write port is that CAS); `docs/adr/0009-event-sourced-persistence.md` (the in-memory port implementation in tests is a fold over a `Vec` of events). `eventlog` itself is not yet wired; the port's signature is derived from "compare-and-set on expected version" and is revisited when the kit is admitted.

## Dependency ceiling

`mandate-types`, `mandate-model` — nothing else, `[dev-dependencies]` included; `xtask/src/main.rs:117-129` walks every dependency kind. `std` only. No `serde`. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

`RevokeRefreshCredential` (`identity.yaml:231-248`) — no case names it and no story owns it; recorded as unowned. `DisablePrincipal`'s authority half. Any edit to `crates/mandate-types`, `crates/mandate-model`, `systems/mandate`, `generated/`. Any numeric type in `mandate-types`. HTTP, async, a real store. `#[ignore]`.

## Gate per unit

`cargo fmt -p mandate-identity -- --check`; `cargo clippy -p mandate-identity --all-targets --locked -- -D warnings`; `cargo test -p mandate-identity --locked`, count reported.

## Scope

- `crates/mandate-identity/src/lib.rs` — cited; the crate's only file today, four `//!` lines; coordinator.
- `crates/mandate-identity/src/generation.rs`, `snapshot.rs`, `session.rs`, `port.rs`, `increment.rs` — inferred; do not exist.
- `crates/mandate-identity/tests/surface.rs`, `generation.rs`, `staleness.rs`, `refresh.rs`, `port.rs`, `increment.rs` — inferred; do not exist.
- Read, not written: `tests/security/cases.json:265-334`; `systems/mandate/domains/identity.yaml`.
- Would collide with: `story:pkce-sessions` on `src/lib.rs` only, and that file is coordinator-owned in both stories' waves; the two are sequential by `depends_on` regardless.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
