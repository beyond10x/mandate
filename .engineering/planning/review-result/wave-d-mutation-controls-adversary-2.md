---
format: aep.planning-md/1
id: review-result:wave-d-mutation-controls-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — mutation controls
relations:
- reviews: story:mutation-controls
revision: 1
---
```
unit: story:mutation-controls — impl/mutation-controls on fe03999, after correction 1
verdict: NEEDS-CHANGE (0 blockers, 3 warnings, 3 notes)
cases: 94 → 99 executed, 4 red when written; catalogue 24.78 s, ten distinct kills
origin: introduced 6 / pre-existing 0
```

```findings
- file: xtask/src/mutants.rs
  line: 512
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the header reading in stated and the written-file reading in rewritten disagree by one line for a slidable insertion, and the anchor must satisfy both, so a git-generated patch that duplicates the line beside it can be anchored on no line and is refused with a message claiming it drifted'
- file: xtask/src/mutants.rs
  line: 478
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'a pure insertion before line 1 follows no line, so both readings return the empty set and a mutation at the first line of a file cannot be entered under any anchor'
- file: xtask/src/mutants.rs
  line: 855
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the declared refusal is matched against every line of the run''s stderr including cargo''s own, so a step that exited non-zero printing nothing was recorded as killed on cargo''s Running line'
- file: xtask/src/mutants.rs
  line: 337
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the module refuses an unread refusal field and silently accepts every other unknown key, including refusals, one letter from the field it reads'
- file: xtask/src/mutants.rs
  line: 749
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the killing run has no wall-clock bound, so a mutant whose run does not terminate hangs the gate undiagnosed; no committed mutant loops'
- file: xtask/tests/adversary_mutants_1.rs
  line: 187
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the five pass-1 case names state the defect while their bodies assert the corrected property, and two near-duplicate correctly named cases in xtask/tests/mutants.rs'
```

Held: a hunk landing at an offset is still refused; no state carried between mutants (867 files byte-identical after the run, zero untracked outside the copy's `target/`); two mutants on one file yield distinct kills; a module becoming a directory is survived and the stale file pruned; nested `target/` pruned; no tracked symlinks; `Kill::parse` refuses every named malformation.

Rulings (correction round 2, the last): F1 — the anchor is accepted when either reading names it (`stated ∪ rewritten`); where the two readings differ by a slide the table cell says so and nothing claims drift. F2 — an insertion before line 1 is anchored on line 1, the line it precedes. F3 — the refusal is matched only against what the step itself wrote: the step's binary is run directly from the copy's build directory (no `cargo run` lines), or the stderr after cargo's last `Running` line; a step that prints nothing is not killed. F4 — records are parsed with `deny_unknown_fields`. F5 — a wall-clock bound on every killing run (`try_wait` polling, 600 s default), refusing the mutant with "the killing run did not terminate". F6 — the coordinator renames the five pass-1 cases to the property each asserts and removes the two near-duplicates from the adversary file (the unit's own cases keep them). Round 2 of this story (`xtask/tests/coverage_mutants.rs`, `manifest-relabel`) is a follow-on unit cut from the head that carries the coverage step.
