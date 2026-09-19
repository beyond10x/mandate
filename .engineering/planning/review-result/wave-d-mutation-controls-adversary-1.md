---
format: aep.planning-md/1
id: review-result:wave-d-mutation-controls-adversary-1
kind: review-result
status: active
title: Adversary pass — mutation controls
relations:
- reviews: story:mutation-controls
revision: 1
---
```
unit: story:mutation-controls — impl/mutation-controls on fe03999
verdict: NEEDS-CHANGE (0 blockers, 4 warnings, 3 notes)
cases: 84 → 89 executed, 5 red when written; the ten-mutant catalogue runs warm in 23.47 s and 26.52 s
origin: introduced 7 / pre-existing 0
```

```findings
- file: xtask/src/mutants.rs
  line: 559
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'a check-fails mutant is recorded as killed by any non-zero exit of the named step, so a patch that breaks credential.yaml as YAML is accepted as a kill for a control declaring projection drift, against the step doc''s claim that each kill is asserted in its own terms'
- file: xtask/src/mutants.rs
  line: 417
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'git apply lands a hunk wherever its context matches and exits 0, and nothing compares that against the hunk header, so the committed deny-unknown-fields-removed patch with its header moved to line 129 still rewrites line 732 while the record anchors line 132 and the step accepts it'
- file: xtask/src/mutants.rs
  line: 374
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'copy only writes into the reused tree and never prunes, so a file the repository has stopped tracking stays in the copy; the live copy holds 449 untracked files, and one file deleted from generated/ would red both ESS mutants at alive with a projection-drift message that blames the tree'
- file: xtask/src/mutants.rs
  line: 358
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'anchored admits any line inside a hunk pre-image range, three context lines wide each side, so a record may anchor the next function''s doc comment; the shipped ess-field-added record anchors credential.yaml:593, a context line, against the doc''s claim that the anchor names a line the patch rewrites'
- file: xtask/src/mutants.rs
  line: 404
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'sync writes through fs::write so a tracked 100755 file arrives in the copy as 644; nothing found that reaches it, docs/customer/build.sh is the only such tracked file and nothing invokes it'
- file: xtask/src/main.rs
  line: 450
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'cargo test --workspace inside Action::Check already executes the whole ten-mutant catalogue through xtask/tests/mutants.rs, measured at 23.47 s warm, so wiring mutants() as the last Check step makes the gate pay for the set twice'
- file: xtask/src/mutants.rs
  line: 189
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'an apply failure propagates before revert runs, unlike the killed failure which is deferred past it, so a partly applied patch leaves the reused copy mutated, which compounds with the copy never pruning'
```

Held under attack: both ESS mutants are killed by projection drift and their patches validate clean; nine of ten anchors name a rewritten line; each mutant is the fault its name claims; `Kill::Test` selects one test with `--exact` and requires `0 passed; 1 failed`; `alive` proves the target green unmutated; a patch cannot touch an unnamed file; deletions refused; unknown kinds, empty catalogue, stray files refused; the fresh-mtime revert defeats fingerprint reuse across two mutants on one file. Stale prose: the story's Scope names `redelivery-refused` at `:321`; the record's `:328` is right.

Rulings (correction round 1): F1 — a `check-fails` record carries a `refusal` string and `killed` asserts the step's stderr contains it. F2 — after `apply`, the file is diffed against the source and the changed line set must contain the anchor. F3 — `copy` removes every path in the copy that is not in the tracked set, except the copy's own `target/`. F4 — the anchor must be a removed line or the line immediately preceding a pure insertion; the doc says so. F5 — `sync` carries the source mode. J1 — the whole-catalogue case leaves `xtask/tests/mutants.rs` (mechanism cases on toy repositories stay); `cargo xtask mutants`, last in `Check`, is the one run of the catalogue. J2 — `apply`'s result is held until `revert` has run.
