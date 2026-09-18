---
format: aep.planning-md/1
id: review-result:wave3-gate-reads-document-deliverables-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:gate-reads-document-deliverables
tags:
- model-deviation-opus
relations:
- reviews: story:gate-reads-document-deliverables
revision: 1
---
```
unit: story:gate-reads-document-deliverables, correction round 1 — working tree at <worktree>, branch impl/gate-reads-document-deliverables, uncommitted over base 0d1947d
verdict: CONFIRMED
cases: executed 22→28, red 6
origin: introduced 10 / pre-existing 0 / undecided 0
wrote-outside-worktree: 4 paths (<scratch>/adv-NZ6hWc/ 4.5M; <scratch>/mut-B92L9Y/ 1.3M; <scratch>/mut-path.txt; <build-dir>/xtask-adversary-2-cases/ 148K)
needs-coordinator: whether D-3/D-4/D-5 hold the unit — three surfaces written this round survive mutation with the whole suite green
```

Round 1 answered every pass-1 finding: `adversary_documents.rs` 10/10 green, md5 unchanged. Live step: exactly the 8 known drift lines, exit 1. Adversary file this pass: `xtask/tests/adversary_documents_2.rs` (6 cases, all red). Mutation battery in a scratch crate: 11 mutants, 8 caught, 3 survived (M2 never record a silent table; M6 store column always last; M8 `blocker_id` refuses the bare slug).

## Findings

```yaml
findings:
  - id: D-1
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:318"
    message: "Reading.silent_tables records a Blocker table only when its parsed-row count reaches zero (:318-323, :373-375), so one row whose blocker cell stops parsing is dropped with no report while the other rows keep the count above zero. Measured: an eleven-row index whose row 2 lost its backticks returned success with 1 store-derived row set matching. Fix: record the line of every row of an opened Blocker table whose blocker cell did not parse."
  - id: D-2
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:358"
    message: "The silent-drop guard has no analogue for the field shape: section_blocker (:218-222) admits a heading's blocker only through backticks, so a (store). field under a heading naming the blocker without backticks yields no claim, no comparison and no report. Measured: success with 0 store-derived row sets. Fix: report a (store). field that resolved to no section."
  - id: D-3
    severity: high
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "xtask/src/documents.rs:53"
    message: "The silent_tables machinery added this round to answer A-5 has no test: discarding every push leaves the entire suite green (mutant M2) and changes nothing on the live tree. Fix: one case asserting the 'this table names a Blocker column and states no blocker' message."
  - id: D-4
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "xtask/src/documents.rs:230"
    message: "Bare-name support in blocker_id — the reason federated-login.md:124 is eight claims — has no test: refusing the bare slug leaves the suite green (mutant M8) while the live document errs 'this table names a Blocker column and states no blocker'. Fix: a fixture with a Blocker column of bare names and no store column."
  - id: D-5
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "xtask/src/documents.rs:205"
    message: "columns() returning an optional store column found by label is unpinned: replacing the search with the last index leaves the suite green (mutant M6) and makes the live federated-login.md:124 compare its 'What it forecloses' column against the store. Fix: a fixture whose store column is not last, and one with a Blocker column and no store column."
  - id: D-6
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:226"
    message: "blocker_id is find_map over the cell's quoted tokens and returns the first match, so a Blocker cell naming two blockers claims one and never looks the other up; the row still counts. Constructed. Fix: claim every blocker the cell names."
  - id: D-7
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:230"
    message: "Any backtick-quoted lowercase-slug token in a Blocker cell becomes decision-blocker:<slug>, the exact hazard the module's comment at :215-217 refuses in a heading; a cell reading '`none` yet — tracked under `decision-blocker:epoch`' failed the gate claiming decision-blocker:none. Fix: accept a bare slug only when the cell's single quoted token is one, else require the full id."
  - id: D-8
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:326"
    message: "Widening the exclusion heading test to the prefix exclu overshot onto Exclusive: '## Exclusive access and lock ordering' marks its claims excluded and every other claim of those blockers is then reported as excluded-and-a-row. Introduced by this correction (mutant M1 localises it). Fix: match the whole word, excluded or exclusion(s)."
  - id: D-9
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:260"
    message: "field_paragraph breaks at a blank line and leading_ids reads only the opening run of ids, so a row set written as a markdown list reads as the empty set and is reported as drift that does not exist. Fix: treat a following list block as the field's continuation, or report that the row set could not be read."
  - id: D-10
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:336"
    message: "A Blocker-column table with no delimiter row never opens, so it is invisible and invisible to silent_tables. Not a GFM table; the guard's coverage stops where a malformed table starts. Fix: record a header row carrying a Blocker column that is not followed by a delimiter."
```

## Attacked and could not break

Live behaviour unchanged (8 lines, exit 1); no `silent_tables` false positive on the two claims tables; `Decision-Blocker:` prefix reported; an Excluded table with a disagreeing store column is compared and reported; bare name and full id for one blocker in two tables — one status check, one match; symlinked document followed, dangling one reported with its path; deterministic over 10 reads; `--store` path with a space is one argv element; M3, M4, M5, M7, M9, M10, M11 all caught.
