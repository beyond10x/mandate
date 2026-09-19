---
format: aep.planning-md/1
id: story:conformance-target
kind: story
status: draft
title: An in-process ESS conformance target over the real Mandate handlers
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:federation-identity-alignment
- depends_on: story:tenancy-graph-events
- depends_on: story:contract-creates
- depends_on: story:authored-denial-scenarios
scope:
- confidence: inferred
  path: crates/mandate-conformance/src/commands
- confidence: inferred
  path: crates/mandate-conformance/src/establish.rs
- confidence: inferred
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-conformance/src/lib.rs
- confidence: cited
  path: crates/mandate-conformance/src/main.rs
- confidence: inferred
  path: crates/mandate-conformance/src/node.rs
- confidence: inferred
  path: crates/mandate-conformance/tests/target.rs
- confidence: cited
  path: generated/conformance/injections.json
- confidence: cited
  path: generated/conformance/report.json
- confidence: cited
  path: generated/conformance/run.json
- confidence: cited
  path: generated/conformance/suite.json
revision: 6
---
## Acceptance

Given the synthesized and authored suite, when `mandate-conform --suite <suite> --impl-digest <d> --out <dir>` runs, then every scenario executes against the real handlers through `ess_conformance::ConformanceTarget`, the target reports what it observed (emitted events serialized through the crates' own types, resulting state, denials with the declared reason) and never a manufactured expectation, every standing double and injected fault is written to `injections.json`, and the run yields `report.json` (report/2) and `run.json` deterministically.

## Scope

- `crates/mandate-conformance/src/lib.rs` — cited; `MandateTarget` with a per-scenario `Live` (fresh folds: `Vec<FederationEvent>` + `Projection::fold`, `IdentityLog`, `Tenancy`, `Topology`, the graph/policy doubles, `SequentialAllocator`, a real `SessionIssuer` adapter appending `SessionOpened`/`EpochSnapshotRecorded`), the armed external outcome, the injection log; `identity()` = (`mandate-conformance`, `0.1.0+src.<12hex>`).
- `src/node.rs` — inferred; `Node ↔ serde_json::Value`.
- `src/commands/{federation,identity,authz,tenancy,graph}.rs` — inferred; one function per implemented command: decode → real handler against the scenario's fold → `took(accepted).emitting(..)` + response, or `took(denied).with_error(reason)` with the fold asserted unchanged.
- `src/external.rs` — inferred; `configure_external_outcome` arms the next invocation's fault at the port the handler consults; refuses before dispatch where no port can deny; logs every injection and standing double to `injections.json` `{scenario, command, port, kind, blocked_on}`.
- `src/establish.rs` — inferred; `establish_entity` for entities whose spec names an adapter writer; `Unsupported` otherwise.
- `src/main.rs` — cited; the frozen CLI `--suite --impl-digest --out`.
- `tests/target.rs` — inferred; the target's own contract: a scenario over a known suite slice, determinism across two runs, injections recorded.

Reference: `examples/billing-realization/tests/conformance.rs:135-300` in the ESS repository at tag `0.26.0`; in-process path `AdmittedSuite::from_json → Runner::for_suite(..).run_admitted(..)` → `CountReport::from_run`.

Unsupported today, therefore red until remediated (named with their story in `story:conform-gate`'s expected outcomes): `AuthorizePublicClient/accepted` (`story:oauth-integration`), graph relationship/revocation and policy supersession (`story:graph-policy-adapter`), the 30 declared-only commands.

### Units

One agent, ~1.9k lines; units `bridge`, `commands`, `external+establish`, `tests`, serially.

### Excluded

Every other crate, `generated/`, `systems/`, `xtask/`, `Cargo.*`.

### Gate

`cargo fmt -p mandate-conformance -- --check && cargo clippy -p mandate-conformance --all-targets --locked -- -D warnings && cargo test -p mandate-conformance --locked`; `cargo run -p mandate-conformance --locked -- --suite <scratch>/suite.json --impl-digest 000000000000 --out <scratch>/out` twice, byte-identical outputs.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).
