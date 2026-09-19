---
format: aep.planning-md/1
id: story:conform-gate
kind: story
status: draft
title: task check runs the conformance suite and binds its evidence to the revision
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:conformance-target
- depends_on: story:coverage-map
scope:
- confidence: inferred
  path: docs/adr/0010-drift-enforcement.md
- confidence: inferred
  path: generated/conformance/expected-outcomes.json
- confidence: inferred
  path: xtask/src/conform.rs
- confidence: inferred
  path: xtask/tests/conform.rs
revision: 5
---
## Acceptance

Given the coordinator-frozen CLI `mandate-conform --suite --impl-digest --out`, when `cargo xtask conform` runs in `task check`, then the suite is re-synthesized and byte-compared with `generated/conformance/suite.json`, the target runs and `report.json`, `run.json`, `injections.json` are byte-compared with `generated/conformance/`, `report.outcomes` equals `generated/conformance/expected-outcomes.json` both ways with `skipped` zero and every non-passed scenario naming a live story, and `suite.provenance.spec_digest == x-ess-provenance.source_digest`; a scenario that disappears, a count that changes, or a source change without a regenerated report fails the gate.

## Scope

- `xtask/src/conform.rs` — inferred; the step: synthesize (`ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir --compact --out target/conformance/suite.json`), run the binary with `<d>` = sha256 over `crates/**/src`, `systems/**`, the suite (first 12 hex), byte-compare the four files, compare outcomes, check digests; `--release` mode fails on stale AEP evidence (`spec_digest` or `implementation` ≠ current).
- `xtask/tests/conform.rs` — inferred; red/green over a scratch copy: vanished scenario, changed count, stale report, identity mismatch.
- `generated/conformance/{suite,report,run,injections}.json` — cited (generated).
- `generated/conformance/expected-outcomes.json` — inferred; `{passed: [ids], failed: [{id, blocked_on}], unsupported: [{id, blocked_on}], error: [{id, blocked_on}]}`, hand-maintained, every non-passed entry with a story.
- `docs/adr/0010-drift-enforcement.md` — inferred; the standard: generated shapes, coverage map, closed event validation, conformance target, obligations registry, replay proofs, mutation controls, evidence binding, independent review; what `deferred` and `double_only` mean; what a release may claim.
- AEP (coordinator, store writes): `executable-system-specification:mandate` created, `set --model-digest <spec_digest>`, `move --to validated`; `evidence --from generated/conformance/report.json --suite generated/conformance/suite.json --ref git:<sha>`; `move --to conforming` only when `conformance_status: passed`.

### Units

One agent: `step`, `expected-outcomes`, `adr` serially. The coordinator wires the `mod`, `Action`, `Check` line and writes the store.

### Excluded

`xtask/src/main.rs`, `crates/mandate-conformance/**`, `systems/`, `Cargo.*`, `.engineering/`.

### Gate

`cargo test -p xtask --locked`; `cargo xtask conform` on the tree.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).
