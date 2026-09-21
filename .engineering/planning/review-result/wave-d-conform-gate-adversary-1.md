---
format: aep.planning-md/1
id: review-result:wave-d-conform-gate-adversary-1
kind: review-result
status: active
title: Adversary pass — conform gate
relations:
- reviews: story:conform-gate
revision: 1
---
```
unit: story:conform-gate — impl/conform-gate on 7ed17be
verdict: NEEDS-CHANGE (3 blockers, 2 warnings, 4 judgement rows)
cases: 128 → 133 executed, 5 red when written
origin: introduced 8 / pre-existing 1
```

```findings
- file: xtask/src/conform.rs
  line: 849
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '--release reads spec_digest and +src.<12hex> out of the artifact markdown, while AEP records evidence as an aep.evidence.record/v1 line in journal.jsonl and the document carries only frontmatter model_digest, so the release check refuses every tree whose evidence the coordinator recorded'
- file: xtask/src/conform.rs
  line: 200
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the synthesize invocation omits --scenarios, so ess-inputs.yaml''s scenario list is never read and no authored scenario can reach the corpus the gate compares'
- file: xtask/src/conform.rs
  line: 894
  category: boundary
  severity: blocker
  verdict: INFEASIBLE
  origin: introduced
  message: 'last_hex scans the whole document twice, so prose below a stale evidence record supplies both digests; unreachable only because the store never writes that section'
- file: xtask/src/conform.rs
  line: 298
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the receipt''s ess_version is never read and conform() spawns ess without the version pin generate() makes, so a receipt claiming ess 0.1.0 is accepted'
- file: xtask/src/conform.rs
  line: 339
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'implementation_digest silently skips absent crates/, services/ and systems/ and answers the digest of nothing; the fixture roots hold no crates/ or services/, so the only release case binds evidence to a digest over systems/ alone'
- file: contracts/expected-outcomes.json
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'all 54 expectation-unmet rows have the identical first unmet check and the run records no denial reason, so the attribution rests on a hand reading no artifact records and no comparison can falsify'
- file: contracts/expected-outcomes.json
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'story:testkit-doubles carries 38 of 117 non-passed scenarios on a draft story about relocating doubles, whose scope does not cover the cause its 16 tenancy rows share'
- file: xtask/src/conform.rs
  line: 648
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the dedicated skipped != 0 refusal is unreachable behind the column loop, and report.json/run.json have no fixture seam'
- file: xtask/src/conform.rs
  line: 817
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the third terminal_rung copy compares the raw value, so a quoted status or a trailing comment reads as live'
```

Held: every ledger refusal by name; `blocked_on` on a passed row refused; `spec_digest` against all 318 schemas; two ledgers naming one scenario refused; absolute and relative synthesize paths agree; determinism.

Rulings (correction round 1): F1/F3 — `--release` reads what AEP writes and nothing else: the artifact's frontmatter `model_digest` must equal the suite's `spec_digest`, and the latest `aep.evidence.record/v1` line for `executable-system-specification:mandate` in `.engineering/planning/journal.jsonl` must carry a `ref: git:<sha>` from which `git diff --quiet <sha> HEAD -- crates services systems` reports no change (the implementation has not moved since the evidence); the prose scanner goes. F2 — the step passes `--scenarios systems/mandate` exactly when `ess-inputs.yaml`'s `scenarios:` list is non-empty (the long form refuses an empty list today); the ADR states it; the story's "long form" correction is amended to this rule; `generate()` mirrors it. F4 — `sources()` reads the receipt's `ess_version` and `conform()` checks `ess --version` against it and the pin. F5 — a root holding none of the three source directories is refused; fixture cases pass a `sources` seam naming the workspace so the release case binds a real digest. F6 — routed to `story:conformance-denial-reasons` (new): the run records `reason` and clause per denial and the gate compares them. F7 — the sixteen tenancy rows and every other row whose cause is "the synthesizer arranged no prerequisite" move to `story:ess-synthesizer-prerequisites` (new); `story:testkit-doubles` keeps only rows whose cause is a double living in a library crate. F8 — the report is read through a seam so a doctored `error`/`skipped` is refused by the scenario's name; the unreachable block goes. F9 — the shared `coverage::terminal_rung` (now `pub`) is used, and it strips quotes and a trailing comment.
