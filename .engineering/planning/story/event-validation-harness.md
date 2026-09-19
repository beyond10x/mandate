---
format: aep.planning-md/1
id: story:event-validation-harness
kind: story
status: implemented
title: A test harness that validates emitted events against the closed contract
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-testkit/Cargo.toml
- confidence: inferred
  path: crates/mandate-testkit/src/contract.rs
- confidence: cited
  path: crates/mandate-testkit/src/lib.rs
- confidence: inferred
  path: crates/mandate-testkit/tests/contract.rs
revision: 8
---
## Acceptance

Given `generated/schema/events/*.schema.json` and `generated/ir/system.json`, when a test calls `mandate_testkit::contract::{assert_event_conforms, assert_single_emission, assert_payload_sources}`, then a payload carrying an obsolete field fails, a payload missing a required field fails, a `null` for an absent optional fails, a wrong number of emitted events for an outcome fails, and a payload whose `input_field`/`response_field`/`literal` source disagrees with the command's input, response or declared literal fails.

## Why

Nothing at `874a74f` validates any of the 72 events against a closed schema. Structural round-trips (generated shapes) prove shape; only a JSON Schema validator proves `pattern`, `enum`, `const`, `type: integer` and `oneOf` exclusivity.

## Scope

- `crates/mandate-testkit/src/contract.rs` — inferred; the harness. `assert_event_conforms(ess_name, &serde_json::Value)` loads the event schema and validates with `jsonschema` (formats on); `assert_single_emission(&[(&str, Value)], outcome)` reads the IR: every accepted outcome `emits` exactly one, every denied outcome none; `assert_payload_sources(command, input: &Value, response: Option<&Value>, event: &Value)` reads the IR `payload` list: `input_field`/`response_field`/`literal` compared by value, `generated` by presence.
- `crates/mandate-testkit/src/lib.rs` — cited; `pub mod contract;`.
- `crates/mandate-testkit/tests/contract.rs` — inferred; the harness's own red/green cases (obsolete field, missing required, null optional, two emissions, wrong source).
- `crates/mandate-testkit/Cargo.toml` — cited; `jsonschema = { version = "=0.52.1", default-features = false }`, `serde`, `serde_json` — pre-landed by the coordinator with `dependency-boundaries.json`.

### Units

One unit, one agent.

### Excluded

`dependency-boundaries.json`, `deny.toml`, `Cargo.lock` (coordinator), every other crate, `generated/`.

### Gate

`cargo fmt -p mandate-testkit -- --check && cargo clippy -p mandate-testkit --all-targets --locked -- -D warnings && cargo test -p mandate-testkit --locked`.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).

## Coordinator rulings at integration, 2026-09-19

- Shipped signatures, accepted as the story's surface: `check_event_conforms(ess_name, payload)`, `check_single_emission(command, outcome, emitted: &[(&str, &Value)])`, `check_payload_sources(command, input, response: Option<&Value>, event_name, event)` and their `assert_*` wrappers. `event_name` is needed because a command's payload mapping is per event; the outcome is resolved from (command, event) and an ambiguous resolution (one event declared on two outcomes) is refused by name rather than taking the first — unreachable in today's IR (59 commands, one emitting outcome each) and closed for the wrong-state outcomes `contract-creates` adds.
- Absence is symmetric: an optional source absent from the input agrees with an absent target and disagrees with a carried one; `null` is absence on both sides for every source kind, because the contract declares no nullable type. A supplied `response: None` where the mapping reads the response stays a failure.
- Every event key must be a declared payload target for its outcome (key-set comparison), and an event name is decided against the IR's event map before any file is read.
- Adversary pass 1 (`review-result:wave-e-event-validation-harness-adversary-1`) recorded `fixed`: 8 findings, all addressed in correction round 1; the adversary's 13 cases stay in the tree and pass.
