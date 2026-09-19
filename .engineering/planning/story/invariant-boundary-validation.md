---
format: aep.planning-md/1
id: story:invariant-boundary-validation
kind: story
status: draft
title: Enforce entity invariants the schema projection drops
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:protocol-adapters
- depends_on: story:login-adapters
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: crates/mandate-server/src/context.rs
- confidence: inferred
  path: crates/mandate-server/src/invariants.rs
- confidence: cited
  path: crates/mandate-server/src/lib.rs
- confidence: inferred
  path: crates/mandate-server/tests/context.rs
- confidence: inferred
  path: crates/mandate-server/tests/invariants.rs
revision: 5
---
# Enforce entity invariants at the boundary the schema projection drops them at

## Acceptance

Given a record whose entity invariant bounds a field, when a value outside the bound arrives at a product adapter, then it is refused before any command runs, although `generated/schema/entities/**` admits it.

## Required observations

ESS 0.25.0 projects an entity `invariants:` entry into prose only; the JSON Schema for the entity carries no `minimum`, `const` or equivalent. Found by the wave-2 adversary against `story:domain-runtime`: `Delegation.transitive` declares `transitive == false` and projects as `{"type":"boolean"}`; the three epoch `generation >= 0` invariants project as `{"type":"integer"}`. The projection is ESS's; the mitigation here is boundary validation in the trusted adapter (`story:protocol-adapters`, `context` unit) against the compiled IR's invariants, and a test that every declared invariant has a boundary check. The ESS-side fix is out of this repository.

## Scope

Derived 2026-09-18 by `story-scoper` on `integration/wave-20260918-004`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-server` — cited; `docs/architecture/ownership.md:20` gives the crate "shared transport/authentication adapters". The crate is a 4-line doc stub (`crates/mandate-server/src/lib.rs:1-4`), has no `tests/` and no `context.rs`.

### Where the invariants are declared, and what each projection keeps

Four `invariants:` blocks exist in `systems/mandate/domains/*.yaml` — cited:

| Entity | Declared | Field | Invariant |
|---|---|---|---|
| `mandate.delegation.Delegation` (`delegation.yaml:10`) | `delegation.yaml:68-69` | `transitive` `:31` | `transitive == false` (header `:7`) |
| `mandate.identity.PrincipalSecurityEpoch` (`identity.yaml:161`) | `identity.yaml:174-175` | `generation: Integer` `:166-167` | `generation >= 0` |
| `mandate.identity.OrganizationSecurityEpoch` (`:176`) | `identity.yaml:189-190` | `:181-182` | `generation >= 0` |
| `mandate.identity.FederationSecurityEpoch` (`:191`) | `identity.yaml:204-205` | `:196-197` | `generation >= 0` |

- **JSON Schema drops all four** — cited: `generated/schema/entities/mandate.delegation.Delegation.schema.json:69-71` `"transitive": {"type": "boolean"}`; the three epoch schemas `:11-13` `"generation": {"type": "integer"}`. Across all 36 entity schemas the only constraint keywords are `enum` and `const`; `minimum`/`exclusiveMinimum` occur zero times. Pinned by the tripwire `crates/mandate-types/tests/contract_adversary.rs:319-369`, which asserts the gap persists.
- **The compiled IR retains all four, structured** — cited: `ess specify compile --path systems/mandate --format json` yields `.entities["…"].invariants == ["transitive == false"]` / `["generation >= 0"]`; the other 32 entities carry `[]`.
- **No IR is committed** — cited: `generated/` holds `docs`, `docs-ir`, `openapi`, `schema` only; `xtask/src/main.rs:187-197` obtains the IR at check time and never writes it.
- **No wire body carries either field today** — cited: no hit for `"transitive"` or `"generation"` under `generated/schema/{commands,events,responses,types}`; the four entities reach the wire only as records.

### Who enforces at the boundary today

- `crates/mandate-server/src/lib.rs:1-4` — four lines of doc; `Cargo.toml:13-15`: `mandate-types`, `mandate-proto`, no dev-dependencies.
- `crates/mandate-types` — no constructor or validating function on `record.rs` (`ResourceRef :16`, `AuthorityScope :31`, `VerifiedContext :63`); `value.rs` validation is lexical only; `src/inventory.rs:464-485` lists the three epoch entities under `EXCLUDED_ENTITIES`.
- `crates/mandate-proto/src/lib.rs:98-118` — `WireContract::from_wire` decodes the declared form and nothing more.
- The one runtime guard in the tree is `crates/mandate-identity/src/generation.rs:26-42` (`Generation::new` returns `None` below zero) — outside `mandate-server`'s ceiling.

### Files, units, ceiling

- **Files:** `crates/mandate-server/src/context.rs` — cited from the story's Scope (marked inferred there); does not exist; created by `story:protocol-adapters` (`depends_on`).
- **Also likely:** `crates/mandate-server/src/invariants.rs`, `crates/mandate-server/tests/invariants.rs`, `crates/mandate-server/tests/context.rs` — inferred.

| Unit | Owns | Test file | Produces |
|---|---|---|---|
| A `invariants` | `crates/mandate-server/src/invariants.rs` — inferred | `crates/mandate-server/tests/invariants.rs` — inferred | the declared-invariant table as checks over decoded values with a refusal type; the completeness test that scans `systems/mandate/domains/*.yaml` `invariants:` blocks with `std::fs` (precedent `contract_adversary.rs:51-67,121-123`) and asserts every `entity.field` pair has a registered check |
| B `context` | `crates/mandate-server/src/context.rs` — cited | `crates/mandate-server/tests/context.rs` — inferred | the check wired into the adapter's decode path ahead of dispatch; the acceptance test: a record body with `generation = -1` or `transitive = true` is refused and no command is invoked |
| coordinator | `crates/mandate-server/src/lib.rs` — cited | — | the `mod invariants;` line and one crate-doc sentence |

- **Dependency ceiling:** `dependency-boundaries.json` `mandate-server: [mandate-types, mandate-proto]` — cited. Dev- and build-dependencies count (`xtask/src/main.rs:117-126`). So: no `build.rs`, no `include_str!` of `generated/`, no `serde_json` in tests. The IR is read at test time by `std::fs` over the yaml or by `std::process::Command` running `ess specify compile` with string scanning — inferred choice, cited constraint.
- **Wave-2 precedent:** every reader of `generated/` is test-time `concat!(env!("CARGO_MANIFEST_DIR"), "/../../generated/schema")` — `crates/mandate-types/tests/inventory.rs:10`, `crates/mandate-proto/tests/adversary.rs:14`, `crates/mandate-model/tests/adversary_tenancy_topology.rs:26`.

### Excluded

`generated/**`, `xtask/`, `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `systems/mandate/domains/*.yaml` (read, never written), `crates/mandate-types/tests/contract_adversary.rs:319-369` (the tripwire stays green; the projection is untouched), `crates/mandate-identity/src/generation.rs` (outside the ceiling). The ESS-side fix is out of this repository.

- **Confidence:** medium — all four invariants and all four dropped projections are cited, but `context.rs` does not exist yet and no wire body carries a bounded field today, so the decode hook is unplaced.
- **Would collide with:** `story:protocol-adapters` — shares `context.rs`, `tests/context.rs` and `lib.rs` outright; this story `depends_on` it, so the two never share a wave. None by file with `declared-writers`, `event-payloads-for-folds`, `check-api`, `oauth-integration`, `pkce-sessions`, `product-listener`. Semantic: `SecurityEpochRecorded { target, generation }` from `story:event-payloads-for-folds` would be the first wire body carrying a bounded field, so this story sequences after it.

### Gate

Per unit: `cargo fmt -p mandate-server -- --check && cargo clippy -p mandate-server --all-targets --locked -- -D warnings && cargo test -p mandate-server --locked`. Sanity for unit A: `ess specify compile --path systems/mandate --format json | grep -c 'generation >= 0'` (expect 3). Coordinator: `task check` plus `cargo test -p mandate-types --locked --test contract_adversary`.

### Not established

- The decode hook: no compiled command, event or response body carries `generation` or `transitive`, so where an out-of-bound value can arrive at a product adapter today is unplaced.
- How unit A reads the IR without `serde_json`: the std-only yaml scan is inferred from `contract_adversary.rs:121-123`.
- The `invariants.rs` / `context.rs` split is the scoper's, not the story's; the story names one file.

- At the wave D opening (2026-09-19): the `context` unit this story names as its mitigation surface moved to `story:login-adapters` as `decode` (the decoding boundary for the road commands; `VerifiedContext` construction stays with `story:protocol-adapters`); `depends_on story:login-adapters` recorded.
