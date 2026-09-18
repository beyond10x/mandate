---
format: aep.planning-md/1
id: story:graph-policy-adapter
kind: story
status: draft
title: Attach the chosen graph and policy engines behind the ports
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:graph-policy
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: inferred
  path: crates/mandate-graph/src/adapter.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: inferred
  path: crates/mandate-graph/tests/adapter.rs
- confidence: inferred
  path: crates/mandate-policy/src/adapter.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: inferred
  path: crates/mandate-policy/tests/adapter.rs
- confidence: cited
  path: deny.toml
- confidence: cited
  path: dependency-boundaries.json
- confidence: inferred
  path: docs/adr/0010-graph-policy-backend.md
revision: 6
---
# Graph and policy adapters for the chosen backend

## Acceptance

Given the graph and policy engines named in `docs/adr/0010-graph-policy-backend.md`, when the `story:graph-policy` conformance suite runs under `cargo test -p mandate-graph -p mandate-policy` against the real adapters instead of the doubles, then it exits zero with a consistency token the engine issued.

## Required observations

Moved here from `story:graph-policy`, exactly as its moved-to sentence names them: choose graph and policy engine in ADR; concrete adapters; engine-issued consistency tokens; storage-level enforcement. Additionally, from `runtime-decisions.md` rows 5 and 7: `AuthzRevision` maps onto a real consistency token that survives Mandate's own API; storage-level exactly-one conditional reference and tenant-membership enforcement; a decision-latency target stated before load evidence means anything. "Backend types do not leak into domain" stays with `story:graph-policy`'s boundary check and is re-run, not re-owned, here. `graph-revocation` executes in `story:check-api`'s crate and is not this story's evidence.

## Why a separate story

`decision-blocker:backend` and `decision-blocker:subject-relations` are open and their clearance evidence is engine-specific. `story:graph-policy` delivers every port and pure function behind `pub` doubles; this story attaches the engines. Row 7 depends on row 2, so `decision-blocker:lifecycle` blocks this story for cascade semantics. No new crate may host an adapter (`xtask/src/main.rs:104`), so both land inside the two existing crates.

## Units

| Unit | Owns | Test file |
|---|---|---|
| coordinator, first | `crates/mandate-graph/src/lib.rs`; `crates/mandate-policy/src/lib.rs`; `Cargo.toml`; `Cargo.lock`; `dependency-boundaries.json`; `deny.toml`; `docs/adr/0010-graph-policy-backend.md` | — |
| `graph-adapter` | `crates/mandate-graph/src/adapter.rs` | `crates/mandate-graph/tests/adapter.rs` |
| `policy-adapter` | `crates/mandate-policy/src/adapter.rs` | `crates/mandate-policy/tests/adapter.rs` |

The four root config files are declared so the scheduler sees this story collide with every other claimant of `Cargo.lock`; it is ordered against `story:pkce-sessions` through `story:check-api`, which `depends_on` both.

## Scope

- `crates/mandate-graph/src/adapter.rs`, `tests/adapter.rs`; `crates/mandate-policy/src/adapter.rs`, `tests/adapter.rs` — inferred; do not exist.
- `docs/adr/0010-graph-policy-backend.md` — inferred; authored only on the operator's decision.
- `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml` — coordinator.

## Validation and contract

`cargo test -p mandate-graph -p mandate-policy --locked`, counts reported.
