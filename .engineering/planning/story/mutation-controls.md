---
format: aep.planning-md/1
id: story:mutation-controls
kind: story
status: active
title: Named red/green mutation controls prove the protections detect faults
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:coverage-map
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: tests/mutants
- confidence: cited
  path: xtask/src/mutants.rs
- confidence: cited
  path: xtask/tests/coverage_mutants.rs
- confidence: inferred
  path: xtask/tests/mutants.rs
revision: 10
---
## Acceptance

Given `tests/mutants/<name>.{patch,json}`, when `cargo xtask mutants` runs, then every named mutant applies cleanly to a scratch copy of the tree, the named target test fails (or compilation fails where declared), and a mutant whose patch no longer applies fails the step loudly; and given `xtask/tests/coverage_mutants.rs`, data mutations of the coverage manifest and the generated artifacts are each refused by the step they target.

## Scope

Derived 2026-09-19 by `story-scoper` at `75f41b5`. **cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `xtask` — `xtask/src/mutants.rs`, `xtask/tests/mutants.rs`, `tests/mutants/<name>.{patch,json}`; round 2 `xtask/tests/coverage_mutants.rs` after `story:coverage-map` merges.
- **Mechanism (B):** copy the tree (via `git ls-files`, never `files()` — it skips only `.ess-output`, not `target/` 2.5 GB) to one reused `target/mutants/tree/`, `git apply` the patch, run the named test under a shared `CARGO_TARGET_DIR` (a path package's id contains its manifest dir, so the copy gets its own fingerprint set while external deps are reused), revert, next mutant; a patch that does not apply fails loudly. The implementor measures first: one mutant cold and warm; whether the reused directory reuses fingerprints across apply/revert; `git apply` in a `.git`-less copy; CI is cold (`.github/workflows/ci.yml` has no cargo cache, `timeout-minutes: 20`).
- **Named mutants, round 1 (six, each with its killer):** `event-dropped` (`crates/mandate-identity/src/port.rs:632`; `-p mandate-identity --test emitted_events`), `event-field-obsolete` (`services/sts/src/issue.rs:379` `epochs: None`; `-p mandate-sts --test emitted_events`), `tenant-mapping-corrupt` (`crates/mandate-model/src/tenancy.rs:965`; `-p mandate-model --test adversary_tenancy_topology`), `revocation-bypass` (`services/sts/src/binding.rs:267`; `-p mandate-sts --test binding`), `lifecycle-transition-wrong` (`crates/mandate-token/src/projection.rs:978`; `-p mandate-token --test adversary_profiles_1`), `deny-unknown-fields-removed` (`xtask/src/emit.rs:732`; `-p xtask --test emit`). Plus `cas-ahead` (`services/sts/src/store.rs:546` `!=` → `<`; killed by `services/sts/tests/adversary_transaction_1.rs` `the_command_path_presents_the_version_it_read_and_the_append_compares_it_both_ways`, which asserts an `expected` ahead of the stream is refused) and `redelivery-refused` (`services/sts/src/store.rs:321`; `services/sts/tests/store.rs:207,235`). `manifest-relabel` waits for `coverage-map`.
- **Gate:** `cargo test -p xtask --locked`; `cargo run -p xtask --locked -- mutants`, wall clock reported; if over five minutes, a second CI job (coordinator, `.github/workflows/ci.yml`).
- **Coordinator-owned:** `xtask/src/main.rs` (`mod mutants;`, `Action::Mutants`, `mutants()?` last in `Check`), `.github/workflows/ci.yml`.
- **Would collide with:** `xtask/src/main.rs` writers (coordinator sequences the wirings); no file collision with `coverage-map`. Hazard: once `mutants()` is in `check`, a story renaming a target test turns the gate red — the mutant table names its targets so the coordinator re-pins.

## Rulings — wave D enforcement track, 2026-09-19

Coordinator, wave D enforcement track, 2026-09-19.

1. Round 1 is mechanism (B) with eight named mutants (the six of the plan plus `cas-ahead` and `redelivery-refused` from wave C, each with a killing test already in the tree); `manifest-relabel` and the data mutants (A) are round 2 after `story:coverage-map` merges, same implementor.
2. The tree copy is `git ls-files`-driven into one reused directory under `target/`; the wall clock of one mutant cold and warm is measured and reported before the mechanism is fixed; over five minutes for the set means a second CI job, wired by the coordinator.
3. `mutants()` is the last `Check` step; a mutant whose target test no longer exists fails the gate by name.

- Corrections at the enforcement opening, after `review-result:wave-d-enforcement-parallel-r1`: the unit's gate and the cold/warm measurement run through `xtask/tests/mutants.rs`, which includes the step by `#[path = "../src/mutants.rs"]` and drives `mutants(root)` — not the `cargo run -- mutants` invocation, wired by the coordinator at integration. The eight patch anchors (`crates/mandate-identity/src/port.rs:632`, `services/sts/src/issue.rs:379`, `crates/mandate-model/src/tenancy.rs:965`, `services/sts/src/binding.rs:267`, `crates/mandate-token/src/projection.rs:978`, `xtask/src/emit.rs:732`, `services/sts/src/store.rs:546`, `:321`) are read anchors the store's `scope:` cannot express; none is written by a running unit; `port.rs` sits in `story:declared-writers`' scope with no unit in flight.

- Corrections after `review-result:wave-d-enforcement-design-r1`: (a) `deny-unknown-fields-removed` is anchored on the xtask emitter and retires with it at the E4 close (the tracker's row says so); (b) two ESS-side drift mutants join round 1 — `ess-field-removed` (a patch deleting a field from an event in `systems/mandate/domains/*.yaml`; kill: `cargo xtask contracts` fails on projection drift, kill kind `check-fails`) and `ess-field-added` (a field added to an event; same kill) — so the class E1 was built for has a named mutant; ten in round 1.
