---
format: aep.planning-md/1
id: story:conform-gate
kind: story
status: implemented
title: task check runs the conformance suite and binds its evidence to the revision
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:conformance-target
- depends_on: story:coverage-map
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
scope:
- confidence: cited
  path: contracts/conformance/injections.json
- confidence: cited
  path: contracts/expected-outcomes.json
- confidence: cited
  path: docs/adr/0010-drift-enforcement.md
- confidence: inferred
  path: generated/conformance/suite.json
- confidence: cited
  path: xtask/src/conform.rs
- confidence: cited
  path: xtask/tests/conform.rs
revision: 22
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

- Correction at the wave D enforcement opening, after `review-result:wave-d-enforcement-design-r1`: the synthesize invocation this gate byte-compares is `ess verify conform synthesize --path systems/mandate --scenarios systems/mandate --target ir --compact --suite-format 5 --out target/conformance/suite.json` — format 5 frozen by `story:conformance-target` (format 4 emits no `coverage` key, and `qualification` needs it). The committed location of the target's four outputs and their byte-compare are this story's `conform()` step.

- From `review-result:wave-d-authored-denials-adversary-2` F8 (2026-09-19): `ess verify conform author` exits 0 while `synthesize --suite-format 5` exits 1 on the 52 pre-existing refusals; "the counts are the verdict" is a convention until this story's `cargo xtask conform` step compares the suite byte-for-byte and the counts against `expected-outcomes.json`. Also: the 54 `expectation-unmet` synthesized scenarios in the target run carry `blocked_on: story:conform-gate` pending per-scenario attribution here.

## Scope — re-derived 2026-09-19 (wave D second half)

By `story-scoper` on `6d812e0`, reading the unmerged target in its tree. Cited unless marked inferred.

- **Primary surface:** `xtask` — `xtask/src/conform.rs` (new), `xtask/tests/conform.rs` (new, `#[path]`-included, toy fixtures for a vanished scenario, a changed count, a stale report, an identity mismatch), `docs/adr/0010-drift-enforcement.md`.
- **Coordinator-owned wiring (excluded):** `xtask/src/main.rs` `mod`/`Action::Conform { root, release }`/`Check` line after `coverage_map`; `generate()` gains the suite synthesis.
- **Invocation:** the built binary `target/debug/mandate-conform` (already spawned by `Check`; `boundaries()` refuses an `xtask → mandate-conformance` edge), after `cargo build --locked -p mandate-conformance` for a cold tree. `mandate-conform` exits 0 on any written report by design, so the verdict is read from `report.json`, never the status.
- **ESS invocation:** `ess verify conform synthesize --suite-format 5` has no flag tolerating refusals and exits 1 on the 52 pre-existing ones; the step spawns tolerantly and decides on the artifact (`suite.coverage.counts`, `suite.provenance.spec_digest == x-ess-provenance.source_digest`, both `2f11d2da…` today).
- **Collisions:** none by file with `mutation-controls`, `coverage-map`, `obligation-registry`; the suite bytes change when `authored-denial-scenarios` merges (146 → 166) — this story's corpus is regenerated after that merge. `xtask/src/main.rs` wiring is coordinator-serialised.
- **Size:** one large unit — `conform.rs` 450–650 lines, tests 350–500, `expected-outcomes.json` ~146 rows, the ADR 150–300 lines.
- **Not found:** the plan's B5 section is not in `docs/plans/` (the design lives in this story's body); `--release` mode was unspecified — ruled below.

## Rulings — wave D second half, 2026-09-19

1. **Where the corpus lives.** `generated/` holds ESS output only: `generated/conformance/suite.json` is written by `generate()` through `ess verify conform synthesize --suite-format 5` (an ESS projection; `contracts()` byte-compares it like the other kinds). The target's outputs are not committed as whole files: `report.json` and `run.json` are computed fresh by the step and compared on their *outcomes* and *counts* against the authored `contracts/expected-outcomes.json` (exact set equality both ways, `skipped == 0`); `contracts/conformance/injections.json` is committed and byte-compared by `conform()`, since it is the honesty ledger of doubles and armings and is deterministic. This keeps `generate()` free of any workspace compilation (`xtask/src/receipt.rs` principle) and avoids recommitting ~2.9 MB on every source change; the source binding the acceptance asks for is the coverage receipt's (`generated/coverage/receipt.json`) plus `report.implementation`'s digest recorded as AEP evidence at wave close. The same ruling holds for `story:obligation-registry`'s report: `contracts/conformance/obligations-report.json`, compared by its own step.
2. **The attribution ledger** is `contracts/expected-outcomes.json`: per scenario `{id, outcome: passed|failed|unsupported|error, blocked_on?}`; `conform()` takes the story from `expected-outcomes.json` where `injections.json` says `expectation-unmet` (the target's "not attributed here" marker, `story:conform-gate`), from `injections.json` otherwise, and refuses when both name a different story or when a named story is on a terminal rung (the frontmatter reader `xtask/src/coverage.rs` already has). A row moves by editing that one file.
3. **`--release`.** `Action::Conform { root, release }`: in release mode the step additionally reads the latest `evidence` on `executable-system-specification:mandate` and fails when its `spec_digest` differs from the suite's provenance or its recorded implementation digest differs from the current one. The AEP artifact is created by the coordinator at this story's merge (`aep plan artifact new executable-system-specification mandate`, `set --model-digest`, `evidence --from report.json --suite suite.json`).
4. **Order.** This unit is cut after `story:conformance-target` merges (its CLI is frozen: `--suite --impl-digest --out`), and its corpus regenerated after `story:authored-denial-scenarios` merges.

## Corrections after `review-result:wave-d-second-half-design-r1` (2026-09-19)

- `depends_on story:obligation-registry` recorded: the ADR this story owns states the coverage, conformance and obligations vocabulary (`implemented`/`declared`/`deferred`; `passed`/`failed`/`unsupported`; `real_covered`/`double_only`/`deferred`), so the registry's format lands first.
- Ruling 2 restated with its two authorities named: `injections.json` (the target's own output, byte-compared) is the authority for every scenario the target refuses before dispatch or does not support — its `blocked_on` is compiled into `crates/mandate-conformance` and moves by a change there; `contracts/expected-outcomes.json` is the authority for executed scenarios whose expectation is unmet (the target marks them `story:conform-gate`). `conform()` refuses a row present in both with different stories, and refuses a story on a terminal rung in either. A row moves in the file that holds it.

- After `review-result:wave-d-second-half-parallel-r1` (2026-09-19): `generate()`'s suite synthesis spawns `ess verify conform synthesize --suite-format 5` tolerantly (its exit 1 on the 52 pre-existing refusals is not a failure) and decides on the artifact's counts and `spec_digest`; the two ESS mutants of `story:mutation-controls` keep their `contracts` kill (a contract mutation moves the suite bytes too). Merge order for the second half, stated once: conformance-target → mutation-controls → conform-gate → obligation-registry; `authored-denial-scenarios` whenever its commit is admitted, followed by a coordinator regeneration of `generated/conformance/suite.json`.

## Acceptance — amended 2026-09-19 (replaces the Acceptance above where they differ)

`cargo xtask conform` exits 0 on a tree where: `generated/conformance/suite.json` is byte-identical to a fresh `ess verify conform synthesize --suite-format 5` (the same counts and `spec_digest`); a fresh `mandate-conform` run's per-scenario outcomes equal `contracts/expected-outcomes.json` exactly both ways with `skipped == 0`; its `injections.json` is byte-identical to `contracts/conformance/injections.json`; every `blocked_on` in either ledger names a story off a terminal rung, and no scenario is attributed to two different stories. It exits non-zero, naming the scenario, when a scenario vanishes, an outcome changes, a count changes, a digest differs or an attribution is dead. `cargo xtask conform --release` additionally exits non-zero when the latest evidence on `executable-system-specification:mandate` carries a `spec_digest` or implementation digest other than the tree's. `report.json` and `run.json` are computed, not committed.

- Implementor result (2026-09-21): green in its tree — `xtask/src/conform.rs` (957 lines), `xtask/tests/conform.rs` (15 cases, red first), `contracts/expected-outcomes.json` (146 rows), `contracts/conformance/injections.json`, `docs/adr/0010-drift-enforcement.md` (189 lines); 128 xtask cases; `cargo xtask contracts` red only on `generated/conformance/suite.json` until `generate()` is wired (patch in scratch). Counts 146 / 29 passed / 54 failed / 0 error / 63 unsupported / 0 skipped. Attribution across 11 live stories: `testkit-doubles` 38, `declared-writers` 16, `authored-denial-scenarios` 16, `directory-provenance` 13, `agent-authority-kernel` 10, `graph-policy-adapter` 9, `audit-worker-delivery` 6, `constrained-exchange` 5, `oauth-integration` 2, `refusal-discriminators` 1, `agent-security` 1; the rule (state no declared command writes → `testkit-doubles`; a record a realized command could arrange → `authored-denial-scenarios`; a value the declaration admits → `declared-writers`) is in the ADR. Two brief claims measured wrong and corrected in the design: the receipt's `source_digest` is a tree digest, not the suite's `spec_digest` (the step checks `spec_digest` against all 318 schemas' provenance and the receipt's currency separately); `synthesize --scenarios systems/mandate` exits 1 writing nothing while no authored scenario is merged, so `generate()` uses the short form. The ADR argues `error == 0` and the step now enforces it (the 15th case). Residue: a second private `terminal_rung` copy (coordinator's deduplication); `generated/conformance/suite.json` is 2 MB. Adversary 1 dispatched.

- Correction (2026-09-21, after `review-result:wave-d-conform-gate-adversary-1`): the "long form" synthesize invocation in the earlier correction is withdrawn — `--scenarios systems/mandate` is passed exactly when `ess-inputs.yaml`'s `scenarios:` list is non-empty (ESS refuses an empty explicit list); `generate()` and `conform()` share that rule. `--release` binds through AEP's own records (frontmatter `model_digest`; the latest evidence journal line's `ref: git:<sha>` compared with HEAD over the source directories). Two draft stories created as attribution homes: `story:conformance-denial-reasons` (the run records the denial reason and clause) and `story:ess-synthesizer-prerequisites`. Correction 1 dispatched.

- Correction 1 result (2026-09-21): 140 xtask cases in its tree, 136 green, 1 ignored, 1 red only because the tree's store lacks the two stories created today (green at the integration head). `--release` reads what AEP writes (frontmatter `model_digest`; the last evidence journal line's `ref: git:<sha>` compared with HEAD over the source directories; the prose scan deleted; six cases); `--scenarios` passed iff the list is non-empty (a listed unparseable file is noticed); the receipt's `ess_version` held against the tool and the pin; a sourceless root refused; a report seam (`Seams.doctor`) so `error`/`skipped` are refused by scenario name; re-attribution: 53 rows → `story:ess-synthesizer-prerequisites`, 1 → `story:refusal-discriminators`, `story:testkit-doubles` keeps its 13 recorded rows; `coverage::terminal_rung` `pub` and stripping quotes and comments, a differential case over both readers (the copy stays while the pass-1 adversary file declares no `mod coverage`). The coordinator amended the pass-1 fixture to resolve `HEAD` at runtime instead of a literal ref. Adversary 2 dispatched.

- Corrections after `review-result:wave-d-conform-gate-adversary-2` (2026-09-21): ruling 3's evidence command is `aep plan artifact evidence executable-system-specification:mandate --from <report.json> --suite <suite.json> --ref git:<sha> --at <instant>` — `--ref` names the commit the run was taken at and is what `--release` binds; the `--scenarios` decision is ESS's (the flag first, the bare form on the "selected no authored files" refusal); the not-committed report and run measure 0.92 MB, not 2.9.

- Correction 2 result (2026-09-21): 28 cases in `xtask/tests/conform.rs`; the synthesize decision is ESS's (both invocations recorded in the ADR and mirrored by `generate()`); `--release` requires a clean source tree (`git status --porcelain` over the digest's own pathspec, each component ending in `/*` — a bare `crates/*/src` matches nothing in git), compares over that pathspec, and reads the latest `ess_conformance` record by `at`; the recorder's route `--from report --suite suite` is unavailable at AEP 0.55.0 (suite version 9 unsupported), so the evidence is recorded with `--kind ess_conformance --ref git:<sha>`. Unit committed `5778579`, merged `b3bee7c` (one conflict on `coverage.rs`, the gate's version taken); wiring and the suite as a generated kind in `eb22b1c`; on the integration head: `cargo xtask conform` exit 0 (146 / 29 / 54 / 0 / 63 / 0, eleven live stories), `contracts` byte-identical, 225 xtask cases. Coordinator amendments to the adversary files: the runtime-ref fixture (the earlier edit was a literal), the pass-2 helper matching the F3/F4 rule, and both stale-evidence fixtures taking the parent of the last source-touching commit.
