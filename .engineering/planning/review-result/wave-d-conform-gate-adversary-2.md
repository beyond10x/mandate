---
format: aep.planning-md/1
id: review-result:wave-d-conform-gate-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — conform gate
relations:
- reviews: story:conform-gate
revision: 1
---
```
unit: story:conform-gate — impl/conform-gate on 7ed17be, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 3 warnings, 4 judgement rows)
cases: 142 → 147 executed, 5 red when written
origin: introduced 9 / pre-existing 0
```

```findings
- file: xtask/src/conform.rs
  line: 259
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'authored() reads the scenarios list with str and calls it non-empty unless the text after the key is exactly [], so a comment beside scenarios: [] passes --scenarios to a synthesizer that refuses an empty list'
- file: xtask/src/conform.rs
  line: 268
  category: boundary
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the same scan ends the block at any column-0 non-item, so a comment line or an indented flow list makes a non-empty list read as empty, --scenarios is dropped and the gate exits 0 on a specification listing an unparseable scenario file'
- file: xtask/src/conform.rs
  line: 1092
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '--release decides on git diff --quiet <sha> HEAD, a two-commit comparison, while the digest, the build and the report read the working tree, so an uncommitted source edit moves the implementation under test and not the answer'
- file: xtask/src/conform.rs
  line: 1095
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the release rule holds crates services systems whole while the implementation digest covers crates/*/src, services/*/src and systems, so a test-only commit refuses an unchanged release'
- file: xtask/src/conform.rs
  line: 1150
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'latest_evidence matches entity, id and event type and not the record''s kind, and takes the last line rather than the latest at, so a later approval carrying --ref supplies the commit a release is decided on'
- file: contracts/expected-outcomes.json
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'story:refusal-discriminators holds one row while its acceptance names nine wrong-state scenarios and the corpus holds seven, six failing, five attributed to the synthesizer'
- file: docs/adr/0010-drift-enforcement.md
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the release check requires ref: git:<sha> and no document instructs the recorder to pass --ref; aep plan artifact evidence --from defaults it to the report''s path'
- file: docs/adr/0010-drift-enforcement.md
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the ADR and ruling 1 say ~2.9 MB for report.json and run.json; measured 0.92 MB'
- file: xtask/src/conform.rs
  line: 1093
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'evidence() reads the artifact and journal from root and runs git in the workspace, against its module doc'
```

Held: the 53-row re-attribution (8 sampled, none a visible handler defect); ledger integrity; the two `terminal_rung` copies token-identical; the suite byte-compare path-independent; the 318-schema digest agreement; `skipped`/`error` by scenario name; a doctored `counts.passed` refused by column.

Rulings (correction round 2, the last): F1/F2 — no text scan of YAML: the step passes `--scenarios systems/mandate` and, when ESS refuses with its "selected no authored files" refusal (exit 1, no suite written), re-runs without the flag — the decision is ESS's own reading of the list; the ADR states it and `generate()` mirrors it. F3 — `--release` additionally requires `git status --porcelain -- crates/*/src services/*/src systems` empty. F4 — the diff pathspec is `crates/*/src services/*/src systems`, the digest's own set. F5 — `latest_evidence` filters on the conformance kind and takes the latest by `at`. J1 — `story:refusal-discriminators`' acceptance amended by the coordinator to the wrong-state scenarios the synthesizer can arrange, seven in the corpus. J2 — ruling 3's command line gains `--ref git:<sha>`, in the story and the ADR. J3 — the number corrected to the measured 0.92 MB. J4 — the module doc corrected.
