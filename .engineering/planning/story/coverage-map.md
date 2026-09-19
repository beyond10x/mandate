---
format: aep.planning-md/1
id: story:coverage-map
kind: story
status: draft
title: Every contract element maps to its implementation and checks, machine-checked
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-shapes
scope:
- confidence: inferred
  path: contracts/coverage.json
- confidence: cited
  path: crates/mandate-authz/src/lib.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: cited
  path: crates/mandate-types/src/macros.rs
- confidence: cited
  path: generated/coverage/receipt.json
- confidence: inferred
  path: xtask/src/coverage.rs
- confidence: inferred
  path: xtask/src/receipt.rs
- confidence: inferred
  path: xtask/tests/coverage.rs
revision: 4
---
## Acceptance

Given `contracts/coverage.json` and `generated/ir/system.json`, when `cargo xtask coverage` runs, then it fails if any compiled command, event, entity, type or error has no entry or any entry names a non-compiled element; every `implemented` entry's symbols are proven by the compiler and its tests by `cargo test -- --list`; `declared` entries name a story and carry no implementation; `deferred` entries name an open `decision-blocker`; the receipt `generated/coverage/receipt.json` is byte-identical to what `cargo xtask generate` wrote; and the per-kind table is printed. A new event added to ESS with no entry fails the gate.

## Scope

- `contracts/coverage.json` — inferred; format `mandate-coverage/1`; one entry per element `{element, kind, status, crate, impl, tests, story, blocker?, reason?}`; seeded from the audit (implemented: the 21 commands with deciding handlers, the 11+ events with Rust forms, the 18 entities with records, all 110 types; declared: the rest, each with its story; deferred: entries whose blocker is open).
- `xtask/src/coverage.rs` — inferred; the step (manifest ↔ IR both directions; `ESS_REALIZATIONS` per crate read from the test binaries' `--list`? no — from each crate's lib test asserting equality; test-id existence via `cargo test --workspace --no-run --locked --message-format=json` and `--list --format terse`; receipt byte-compare; table).
- `xtask/src/receipt.rs` — inferred; writes `generated/coverage/receipt.json` `{format, ess_version, source_digest, ir_digest, contract_crate_digest, manifest_digest, counts, tests, agreement_suites, mutants}` during `generate`.
- `xtask/tests/coverage.rs` — inferred; red/green over a scratch copy: orphan entry, missing element, `deferred` with no blocker, `implemented` with no test, stale receipt.
- `crates/mandate-types/src/macros.rs` — cited; `realizes!` macro: `const _` referencing the symbol + `pub const ESS_REALIZATIONS: &[(&str, &str)]`.
- `crates/mandate-authz/src/lib.rs`, `crates/mandate-graph/src/lib.rs`, `crates/mandate-policy/src/lib.rs` — cited; `realizes!` registrations (federation/identity/model register in their own stories).
- `generated/coverage/receipt.json` — cited (generated).

### Units

| Unit | Owns | Test | Produces |
|---|---|---|---|
| `manifest` | `contracts/coverage.json` | `xtask/tests/coverage.rs` | the seeded map |
| `step` | `xtask/src/coverage.rs`, `xtask/src/receipt.rs` | same | the step and the receipt writer |
| `registry` | `crates/mandate-types/src/macros.rs`, the three `lib.rs` | lib tests | `realizes!` and registrations |

One agent, serially. The coordinator wires `mod coverage; mod receipt;`, the `Action` and the `Check` line.

### Excluded

`xtask/src/main.rs`, `Cargo.*`, `generated/**` other than `coverage/`, other crates' `lib.rs`.

### Gate

`cargo test -p xtask -p mandate-types -p mandate-authz -p mandate-graph -p mandate-policy --locked`; `cargo xtask coverage` on the tree.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).
