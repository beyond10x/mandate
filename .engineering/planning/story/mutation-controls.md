---
format: aep.planning-md/1
id: story:mutation-controls
kind: story
status: implemented
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
revision: 19
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

- From the implementor, round 1 (2026-09-19): ten mutants, each killed by the test it names; measured — copy 844 files / 18 MB / 1.3 s; one mutant cold 17.5 s, warm 0.1 s; the ten warm 25–30 s, cold ~100 s (sccache buys 2 %); `contracts` in the copy 5.7 s warm. Two mechanism traps closed: `git apply` with the copy as cwd finds the enclosing repository, prints "Skipped patch" and exits 0 having done nothing — the working invocation is `git -C <repo> apply --unsafe-paths --directory=<copy>/`, with a byte-compare of every named file after applying; a `cp -p` revert keeps the source mtime and cargo's fingerprint, so the reverted run re-ran the mutated binary — every write is a fresh-mtime write of differing bytes only. Corrections to the Scope: `redelivery-refused`'s killer is `store::a_redemption_after_the_terminal_state_writes_nothing` (`tests/store.rs:235`), its anchor `store.rs:328`; the step refuses a record whose anchor lies outside its patch's hunks. The three `cited` scope rows naming files absent at the base are destinations. The `xtask/src/main.rs` wiring patch is in the coordinator's scratch; `cargo xtask mutants` exists once wired; round 2 waits for `coverage-map`.

- Adversary pass 1 (2026-09-19): 0 blockers, 4 warnings, 3 notes, rulings in `review-result:wave-d-mutation-controls-adversary-1`; the catalogue runs warm in 23.47 s (one run, under the five-minute ceiling), and the whole-catalogue test case is removed so the gate pays once; correction 1 dispatched. Scope prose correction: `redelivery-refused` anchors `services/sts/src/store.rs:328`, not `:321`.

- Correction 1 result (2026-09-19): 94 xtask cases green (`mutants` lane 6 → 11, the whole-catalogue case removed; the five adversary cases green); the catalogue of ten runs green in 26 s warm through a scratch driver (`Action::Mutants` unwired until the alignment commit); `check-fails` records carry `refusal` and `killed` asserts it; the anchor is compared with the lines the patch rewrote (LCS after prefix/suffix trim) in a pre-pass before any build; the reused copy is pruned except its top-level `target/`; `anchored` decides against removed lines and the line a pure insertion follows (all ten records already satisfy it); `sync` carries the mode; `revert` runs before `apply`'s result is inspected. Named remainder: unknown record keys are accepted silently. Adversary 2 dispatched.

## Acceptance — amended 2026-09-19 (replaces the Acceptance above where they differ)

`cargo xtask mutants` exits 0 printing `| Mutant | Target test | Observed failure |` with one row per record in `tests/mutants/`: a `test-fails` record's named test fails on the mutated copy and passes on the unmutated one; a `compile-fails` record's target fails to build; a `check-fails` record's named xtask step exits non-zero and its stderr carries the record's `refusal` substring. A record whose patch no longer applies, whose anchor is outside the rewritten lines, whose kill is not observed, or whose killing run does not terminate within the bound fails the step by name.

- Correction 2 result (2026-09-19): 104 xtask cases green (all ten adversary cases); the anchor is `stated ∪ rewritten` with slides named and drift still refused (a new `placed()` decides whether the hunk landed where its header says); an insertion before line 1 anchors on line 1; the `check-fails` refusal is read only from what follows cargo's last `Running` line; records refuse every key no run reads (collected as the lookups happen — the derive route needs `serde` in `xtask/Cargo.toml`, coordinator's; the collected set is the stronger form); every killing run bounded by wall clock (600 s default, `try_wait` polling, child killed). Catalogue: ten of ten killed in 24 s warm. Unit committed `a311951`, merged `d05fffc`; coordinator wiring (`mod mutants`, `Action::Mutants`, `mutation_controls()` last in `check`) in the alignment commit that follows, verified by a run on the integration head. Residue: a patch whose header lies but whose anchor names the true landing line still passes (`placed()` computes the fact; a two-line refusal if wanted). Round 2 (`xtask/tests/coverage_mutants.rs`, `manifest-relabel`) is a follow-on unit cut from the wired head.

- Round 2 result (2026-09-21, `impl/mutation-controls-2` on `fdbf214`): `xtask/tests/coverage_mutants.rs` (11 cases, red first) and `tests/mutants/manifest-relabel.{patch,json}`; 150 xtask cases, 1593 workspace tests; eleven mutants killed in 28.6 s warm. Measured, against the brief: a well-formed relabel (`deferred` → `implemented` with a real symbol and same-crate test, or `implemented` → `declared` onto a live story) passes `cargo xtask coverage` — the step reads the manifest and the compiled test list, not the registries — so `manifest-relabel` is a `test-fails` record killed by `mandate-authz::contract_agreement::the_coverage_manifest_names_exactly_what_this_crate_realizes` (the registry equality, the real detector); the receipt mutants (digest altered, receipt deleted) are killed by regeneration + byte-compare (`cargo xtask contracts`), not by the coverage step. A record carries no `reason` key (the step refuses unread keys); the rationale is in the test file's doc comments. Observation for the coordinator: `mutants::copy` fails with a bare "No such file or directory" when `git ls-files` lists an intent-to-add path absent from disk. Adversary dispatched.

- Correction to the round-2 line above (2026-09-21, `review-result:wave-d-mutation-controls-2-adversary-1`): `mutants::copy` names the path it cannot read (the "bare message" claim was wrong); a relabel is refused both by the registry equality and by the regeneration byte-compare through the receipt's `manifest_digest`. Residue for `contracts()`: one failure message for every generated input, so the two ESS mutants observe byte-identical refusals.

- Round 2 correction (2026-09-21): the killer partition corrected in the file and backed by a case (a relabel moves the receipt, so the byte-compare kills it too); the demotion case asserts its precondition by story and rung; the coordinator applied the adversary's own finding to the adversary file (its red case asserted the receipt unchanged; the truth is that it moves — `assert_ne!`, deviation 10). 155 xtask cases. Committed and merged as the bot.
