---
format: aep.planning-md/1
id: story:contract-shapes
kind: story
status: implemented
title: Generated Rust contract shapes for every event, command and entity
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-contract/Cargo.toml
- confidence: cited
  path: crates/mandate-contract/src/lib.rs
- confidence: inferred
  path: crates/mandate-contract/tests
- confidence: cited
  path: generated/rust
- confidence: inferred
  path: xtask/src/emit.rs
- confidence: inferred
  path: xtask/src/main.rs
- confidence: inferred
  path: xtask/tests/emit.rs
revision: 14
---
## Acceptance

Given the compiled model at `generated/ir/system.json`, when `cargo xtask generate` runs, then `generated/rust/mandate-contract/src/{types,entities,commands,events}.rs` are emitted deterministically from it and `cargo xtask contracts` byte-compares them with a fresh emission; and when a field is removed from an ESS event that a Rust representation still carries, a round-trip of that representation into the generated shape fails on the unknown field.

## Why

At `874a74f` no check binds a Rust event, command input or entity record to its ESS declaration; five event-shape drifts are live and undetected. ESS 0.26.0's `ess generate types --target rust` admits only type roots, so Mandate emits the three unguarded kinds itself until ESS does (an ESS story replaces the emitter byte-for-byte).

## Scope

- `xtask/src/emit.rs` — inferred; the emitter: IR → Rust. Mapping: `declared → Name`; `optional → Presence<T>` (Absent | Present, `#[serde(default, skip_serializing_if)]`, `null` refused); `list → Vec<T>`; string/timestamp/duration/bytes/uuid → `String`; integer → `i64`; enum → enum with the declared variant names and `#[serde(rename)]`; union → `#[serde(tag = "kind", content = "value", deny_unknown_fields)]`; newtype → `#[serde(transparent)]`; struct/entity/event/input/response/error → `#[serde(deny_unknown_fields)]` record; entity = `id` + fields + `state: <Entity>State`. Names follow ESS's `declaration_name` (`MandateFederationFederationAuthenticated`, `…AuthenticateFederationInput`, `…Response`). Refuses to emit an event or entity that references `mandate.core.CredentialSecret` or `CredentialProof`.
- `xtask/tests/emit.rs` — inferred; emitter tests: determinism, every IR element emitted, transient refusal, a golden sample per kind.
- `generated/ir/system.json` — cited (new generated kind: `ess specify compile --path systems/mandate --format json`, deterministic key order).
- `generated/rust/mandate-contract/src/{types,entities,commands,events}.rs` — cited (emitted; never hand-edited).
- `crates/mandate-contract/{Cargo.toml,src/lib.rs}` — cited; thin crate with `#[path = "../../../generated/rust/mandate-contract/src/<kind>.rs"] pub mod <kind>;` under `#![allow(clippy::all)]`-scoped modules; deps `serde`, `serde_json` only; header comment carries `source_digest` and the ESS version.

### Units

| Unit | Owns | Test | Produces |
|---|---|---|---|
| `emitter` | `xtask/src/emit.rs` | `xtask/tests/emit.rs` | the emitter and its golden tests |
| `contract-crate` | `crates/mandate-contract/src/lib.rs`, `crates/mandate-contract/Cargo.toml`, `generated/ir/system.json`, `generated/rust/**` | `cargo build -p mandate-contract` | the crate compiling over the emitted files |
| coordinator | `xtask/src/main.rs` (`generate` gains the IR and Rust kinds; `contracts` compares them), workspace `Cargo.toml` member, `dependency-boundaries.json` | `cargo xtask contracts` | wiring at integration |

### Excluded

`xtask/src/main.rs` (coordinator wires `mod emit;` and the two kinds), `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml`, `systems/`, every other crate.

### Gate

`cargo xtask generate && cargo xtask contracts && cargo test -p xtask --locked && cargo build -p mandate-contract --locked`.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).

## Coordinator rulings at dispatch, 2026-09-19

- `xtask/src/main.rs` joins this story's scope for E1 only: the unit adds `mod emit;` and the Rust kind to `generate()` and `contracts()`, because no other E1 unit touches that file and the story's gate (`cargo xtask generate && cargo xtask contracts`) is not runnable without the wiring. The general rule (coordinator wires `main.rs`) resumes in E2.
- In a fresh checkout `cargo xtask generate` refuses with `unowned output destination …; adopt exact generated reference bytes explicitly` (ESS 0.26.0 output ownership; the ledger `generated/.ess-output/` is ignored by git). Recipe, once per tree: `cargo xtask contracts`, then `ess generate output adopt --ownership-root generated --from target/xtask-contract-regeneration --owner projection:<kind>` for `schema`, `openapi`, `docs`, `docs-ir`. Verified on the coordinator tree 2026-09-19: four adopts exit 0, in-place `ess generate --kind schema` then writes 311 artifacts with no diff.

## Coordinator rulings after adversary pass 1, 2026-09-19

- Integers (A1-3, blocker): the schema projects `integer` unbounded and ESS's own Rust realization maps it to `serde_json::Number`; the emitter does the same, so the two projections and the future realizer agree. The plan's "integer → `i64`" decision is superseded by measurement. Domain crates keep their `u64`/`i64` fields; the agreement tests convert through JSON.
- Absence (A1-2): `Presence` exists in field position only. `Presence::Absent` refuses to serialize with an error naming the rule; `null` refuses to deserialize; `list<optional<T>>` is refused at emission (A1-8). The adversary case `presence_absent_does_not_survive_its_own_serialization` was amended by the coordinator to assert that property (renamed `presence_absent_refuses_to_serialize_and_null_refuses_to_deserialize`).
- Names Rust cannot take (A1-1): the emitter refuses strict and reserved keywords of edition 2024 and the path keywords (`self`, `Self`, `super`, `crate`) alike, naming the declaration; no `r#` escaping, because a refusal at `cargo xtask generate` reports against the model, where the fix belongs.
- Missing refusals (A1-5, A1-6, A1-7, A1-9): a declared name the model does not carry, two declarations sharing a Rust name, an entity field named `state`, and an entity with no lifecycle state are each refused by name, in the emitter's existing refusal style, so the emitter never depends on ESS's earlier step to have refused them.
- Lists (A1-4): one golden carries a `Vec<…>` field and one round trip in `crates/mandate-contract/tests` exercises a list.
- Module doc (A1-10): the emitter's doc states what ESS 0.26.0's realizer does differently (`serde_json::Number`, `Box<T>`, untagged unions, `EssPresence`) and that retirement means the realizer's output, once it admits these roots, is byte-compared against the emitter's before the emitter goes; no byte-for-byte promise today.
- The story's Scope line about `#![allow(clippy::all)]` is withdrawn (A1-11): the generated modules pass the workspace lints without it.

## Coordinator rulings after adversary pass 2, 2026-09-19

- Optionals live in record fields only (A2-1): the emitter refuses an `optional` in every position `positions()` reports that is not a record field — union variant, newtype `of`, nested optional, list element — naming the declaration, because the ESS schema projection spells absence there as `null` or a dropped key and `Presence` cannot carry either.
- Every refusal names its declaration (A2-2), including the unmapped-primitive and unmapped-type-expression refusals.
- Integer exactness (A2-3): `serde_json::Number` carries every integer in the i64 and u64 ranges exactly; no contract integer leaves that range; `2^64 + 1` and `-0` are documented as the bound, not asserted. The adversary's case was amended to assert the representable range.
- The module doc states the union content key is the emitter's literal (A2-5) and where validation runs (A2-7); the pass-1 adversary doc comment on absence was corrected by the coordinator (A2-4).
- The story Scope's `integer → i64`, `#![allow(clippy::all)]` and `source_digest` header lines are superseded by the shipped emitter and these rulings (A2-6).
