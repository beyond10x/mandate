---
format: aep.planning-md/1
id: story:coverage-map
kind: story
status: active
title: Every contract element maps to its implementation and checks, machine-checked
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-shapes
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: contracts/coverage.json
- confidence: cited
  path: crates/mandate-authz/src/lib.rs
- confidence: inferred
  path: crates/mandate-authz/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-federation/tests/contract_agreement.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: inferred
  path: crates/mandate-graph/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-identity/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-model/tests/contract_agreement.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: inferred
  path: crates/mandate-policy/tests/contract_agreement.rs
- confidence: cited
  path: crates/mandate-types/src/macros.rs
- confidence: inferred
  path: crates/mandate-types/tests/inventory.rs
- confidence: cited
  path: generated/coverage/receipt.json
- confidence: inferred
  path: services/sts/tests/contract_agreement.rs
- confidence: cited
  path: xtask/src/coverage.rs
- confidence: cited
  path: xtask/src/receipt.rs
- confidence: cited
  path: xtask/tests/coverage.rs
revision: 13
---
## Acceptance

Given `contracts/coverage.json` and `generated/ir/system.json`, when `cargo xtask coverage` runs, then it fails if any compiled command, event, entity, type or error has no entry or any entry names a non-compiled element; every `implemented` entry's symbols are proven by the compiler and its tests by `cargo test -- --list`; `declared` entries name a story and carry no implementation; `deferred` entries name an open `decision-blocker`; the receipt `generated/coverage/receipt.json` is byte-identical to what `cargo xtask generate` wrote; and the per-kind table is printed. A new event added to ESS with no entry fails the gate.

## Scope

Derived 2026-09-19 by `story-scoper` on `integration/wave-20260919-005` at `75f41b5`. **cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `xtask` — cited; the step (`xtask/src/coverage.rs`), the receipt writer (`xtask/src/receipt.rs`), the step's test (`xtask/tests/coverage.rs`), all following the step-module pattern (`#[path = "../src/<step>.rs"] mod <step>;`, `xtask/tests/emit.rs:7-9`).
- **Files (new):** `contracts/coverage.json`, `xtask/src/coverage.rs`, `xtask/src/receipt.rs`, `xtask/tests/coverage.rs`; `crates/mandate-authz/tests/contract_agreement.rs`, `crates/mandate-graph/tests/contract_agreement.rs`, `crates/mandate-policy/tests/contract_agreement.rs` — the three crates with no registry test today.
- **Files (existing):** `crates/mandate-types/src/macros.rs:472-489` (`realizes!`, `ESS_REALIZATIONS`); `crates/mandate-{authz,graph,policy}/src/lib.rs` (the three `realizes!` registrations this story owns); the per-crate manifest-equality case added beside the registry↔IR pair in `crates/mandate-federation/tests/contract_agreement.rs:447,492`, `crates/mandate-identity/tests/contract_agreement.rs:471,525`, `services/sts/tests/contract_agreement.rs:308,359`, `crates/mandate-model/tests/contract_agreement.rs:736-770`.
- **Generated:** `generated/coverage/receipt.json`, written only by `generate()` (`xtask/src/main.rs:77-99`) and byte-compared for free: `files()` (`:58-76`) walks the whole tree and `contracts()` (`:130-142`) diffs it against the regeneration.
- **Coordinator-owned:** `xtask/src/main.rs` (`mod coverage; mod receipt;`, `Action::Coverage { root }`, the `Check` line after `documents()`, the `generate()` call after `emit::emit`), `Cargo.*`, `dependency-boundaries.json`, other `generated/**`.
- **Measured:** the registries cover 95 of 292 IR elements (federation 24, identity 18, model 22, sts 31; 0 duplicated, 0 naming a non-IR element) plus 14 `ESS_UNREALIZED` = 109 accounted; 183 in no registry (core 70/74, delegation 23, directory 31, audit 12, policy 9, workload 5, authorization 3, tenancy 16/31, graph 14/17). The 110 types are implemented and pinned (`crates/mandate-types/tests/inventory.rs:37,42,48`) but 13 sit in a registry.
- **`deferred`:** `xtask/src/documents.rs:136 store_blocked()` already returns `Blocker{id, status, blocks}` from `aep plan artifact blocked --format json` — reuse it. `declared` seeds: the 14 `ESS_UNREALIZED` reasons name their story verbatim.
- **Tests proven:** `cargo test --workspace --locked --no-run --message-format=json` after the gate's own test run reuses the warm target dir; ~127 `--list --format terse` spawns cached in one pass. The gate's `run()` discards stdout, so the ids are not reusable from `check`'s run (coordinator-owned line; do not touch).
- **Gate:** `cargo test -p xtask --locked`; `cargo run -p xtask --locked -- coverage`; the seven per-crate cases under their crates' `cargo test`.
- **Would collide with:** any unit touching `xtask/src/main.rs` (coordinator; `story:product-listener` cites it — the coordinator sequences the two wirings); the three crate roots (`check-api`, `graph-policy`, `graph-policy-adapter`, `testkit-doubles` — later-wave drafts); any unit adding under `generated/**` (one byte-compare covers the tree; `conformance-target` adds `generated/conformance/` — the coordinator regenerates once after both merge).

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).

## Rulings — wave D enforcement track, 2026-09-19

Coordinator, wave D enforcement track, 2026-09-19.

1. **The manifest is authored, not generated**: the registries prove one third of the contract and a generated map would read as complete. `contracts/coverage.json` carries every IR element (292 at `75f41b5`): `implemented` for the 95 registered plus the 110 types proven by `mandate_types::conformance::cases()` and the inventory pins (no 110-entry `realizes!`), `declared` with its story for the rest, `deferred` where `aep plan artifact blocked` names an open blocker on that story.
2. **The `crate` column is the registrar**: the crate whose `ESS_REALIZATIONS` names the element (the STS registers the credential events realized by `mandate-token` types; `ownership.md:13` describes authority, not registration). The per-crate case asserts `ESS_REALIZATIONS == manifest entries where crate == CARGO_PKG_NAME`.
3. **One realizer per element** is asserted by `cargo xtask coverage` over the manifest; the cross-crate probe in `crates/mandate-federation/tests/adversary_writers_2.rs` stays as the one Rust-level pair. No `mandate-realizations` binary, no write-to-`target/` protocol.
4. **The receipt binds digests and counts only** (`format`, `ess_version`, `source_digest`, `ir_digest`, `contract_crate_digest`, `manifest_digest`, counts by kind × status, the mutant set once `story:mutation-controls` lands); test ids and agreement suites are the step's live check, not the receipt's, so `generate()` nests no cargo test build.
5. **`Action::Coverage { root }`** so `story:mutation-controls`' data mutants can run the step over a scratch root; wired by the coordinator at integration.
6. **Order in the wave:** `coverage-map` merges before `mutation-controls`' round 2 and before the coordinator's single regeneration that also picks up `generated/conformance/`.

- Corrections at the enforcement opening, after `review-result:wave-d-enforcement-parallel-r1`: the unit's gate is `cargo test -p xtask --locked` — `xtask/tests/coverage.rs` includes the step by `#[path = "../src/coverage.rs"]` (the `emit`/`documents` pattern) and drives `coverage(root)` over the real tree — not the `cargo run -- coverage` invocation, which needs `Action::Coverage { root }` and is verified by the coordinator after wiring at integration. Between this story's merge and the coordinator's regeneration, `cargo xtask contracts` is red in every unit tree on `generated/coverage/receipt.json` (the E1 rule), and the coordinator states the window on the wave page.

- Corrections after `review-result:wave-d-enforcement-design-r1`: the 110 `type` entries carry `crate: mandate-types` and are proven there — the 74 authored types by the symbol each `mandate_types::conformance::cases()` entry constructs (`crates/mandate-types/src/conformance.rs`), the 36 derived `.State` enums by `DERIVED_STATE_ENUMS` paired with the generated `mandate_contract::entities::<Entity>State` shape in `crates/mandate-types/tests/conformance.rs` — and `mandate-types` runs the manifest-equality case in `crates/mandate-types/tests/inventory.rs` (added to scope), so every `implemented` entry is reconciled in a crate that runs the case. An entry naming a symbol that does not exist fails that crate's case; an entry naming a crate that runs no case fails `cargo xtask coverage`'s check that every `implemented` crate is a registrar or `mandate-types`.
