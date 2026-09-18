---
format: aep.planning-md/1
id: review-result:wave3-gate-reads-document-deliverables-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:gate-reads-document-deliverables
tags:
- model-deviation-opus
relations:
- reviews: story:gate-reads-document-deliverables
revision: 1
---
```
unit: story:gate-reads-document-deliverables — working tree at <worktree>, branch impl/gate-reads-document-deliverables, uncommitted over base 0d1947d
verdict: CONFIRMED (blocker)
cases: executed 11→21, red 9
origin: introduced 9 / pre-existing 0 / undecided 0
wrote-outside-worktree: 3 paths (<scratch>/adv-NZ6hWc/ 9.1M; <build-dir>/xtask-adversary-cases/ 244K; <build-dir>/adv-copy-inside/ removed again)
needs-coordinator: whether the "every mention must still be in the blocked report" assertion is wanted at all — not in the story's boundary; A-1's fix changes the step's contract
```

## Diff under attack

`xtask/src/main.rs` +18; untracked `xtask/src/documents.rs`, `xtask/tests/documents.rs`. Adversary file: `xtask/tests/adversary_documents.rs` (10 cases; 9 red, 1 green). Suite after: `adversary_documents` FAILED 1 passed 9 failed; `documents` 11 passed.

## Findings

```yaml
findings:
  - id: A-1
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:271"
    message: "documents() asserts that every textual occurrence of decision-blocker: in every declared document is still in the blocked report, not every row set. A cleared blocker leaves the report entirely, so clearing one blocker turns task check red in every declared document whose prose merely names it. Reached, not constructed: docs/architecture/unmapped.md:9-74 names twelve blockers in prose and states no row set; federated-login.md:7,:84,:103,:118 names four more in running sentences; the base commit already records approval evidence on decision-blocker:algorithm-policy, which both name. Not one of the story's three assertions; SC6 (runtime-decisions.md:362) and FL4 (federated-login.md:162) scope the open check to rows and named blockers. Fix: run the open/reported check over the blockers of recognised claims, not over named(text); do not simply delete the branch, since the status branch at :276 is unreachable (A-8)."
  - id: A-2
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:176"
    message: "named() scans the raw bytes, so a blocker id inside a fenced code block is read as a claim about the store, against the module's own doc (documents.rs:8-9) that it does not read prose. Constructed today; same root cause and fix as A-1."
  - id: A-3
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:182"
    message: "The id scanner admits a trailing colon, yielding the phantom id decision-blocker:epoch: for an unbackticked mention followed by a colon. Constructed; every live mention is backticked or followed by a space. Fix: stop the token at the first colon after the prefix, or require backtick quoting as blocker_id() at :127 already does."
  - id: A-4
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:123"
    message: "store_field() reads a (store). field from one line and leading_ids() stops at its end, so a field whose id list wraps is read as its first line only; a drifted row body was accepted with 2 store-derived row sets match. Constructed today (every paragraph in docs/architecture is one line), but the integration patch rewrites eight of those lines. Fix: join a (store). field with its continuation lines before parsing ids."
  - id: A-5
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:112"
    message: "store_columns() matches a header cell only as the bare word Blocker and only as Blocks or a cell ending (store); a bolded or reworded header silently drops the whole table with no error and no floor on the row count (0 store-derived row sets match on a drifted table). Fix: strip emphasis from header cells and fail when a document with a Blocker-column table yields zero claims, or pin the expected count."
  - id: A-6
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:108"
    message: "cells() splits on every pipe without honouring the GFM escape, so one escaped pipe shifts every column to its right and the store column reads the wrong cell; federated-login.md:160 already writes an escaped pipe inside a table cell. Fix: split on a pipe not preceded by a backslash, and unescape."
  - id: A-7
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:204"
    message: "SC7 is enforced by recognising the excluded section as a heading starting with excluded; Exclusions does not match, so renaming that one heading turns the whole SC7 assertion off silently. Constructed; the live heading matches. Fix: match by shape or by a broader prefix, or assert the excluded section exists in a document that has one."
  - id: A-8
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:276"
    message: "The status != open branch is unreachable against the live store: a cleared blocker leaves the report rather than appearing with a different status, and all 14 live groups report open; xtask/tests/documents.rs:174 asserts a state parse_blocked can never build. Not a defect on its own; the reason A-1's fix must narrow rather than delete."
  - id: A-9
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "xtask/src/documents.rs:263"
    message: "str::trim does not remove U+FEFF, so a document whose entire content is a byte order mark counts as present and non-empty. Constructed. Fix: trim the BOM too, or require at least one heading."
  - id: A-10
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/documents.rs:256"
    message: "declared() propagates the bare read_dir error before any document problem is collected, so a bad --root is answered with No such file or directory (os error 2) and no path, while every other failure names its file. Fix: wrap the error with the joined path."
  - id: A-11
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/main.rs:25"
    message: "The --root doc comment promises reproduction on a copy, but store_blocked() resolves the planning store from --root via current_dir(root), so cargo xtask documents --root <copy> on a copy without .engineering exits 1 with no --store was given and no .engineering/project.yaml was found, never reporting the emptied document. Measured. store_blocked() has no test coverage because the suite is store-independent. Fix: resolve the store from the workspace root or pass --store; say so in the comment."
  - id: A-12
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "xtask/src/main.rs:328"
    message: "documents() is wired into Check before contracts(), cargo deny, aep plan artifact validate and the five-binary serve refusal, and every step short-circuits; while the step is red by design on this tree those four steps never execute. Fix: place documents() after aep plan artifact validate."
```

## Attacked and could not break

All failures reported not the first (green case); `Blocker` not first column; trailing pipes and padded cells; empty store answer; extra JSON keys; non-UTF-8 and dangling symlinks (reported naming the path); same blocker in two documents; deterministic file order; suite independent of the live store (verified with `aep` off `PATH`: 11 passed); the acceptance through `task check` (relative root is the workspace after `set_current_dir`).
