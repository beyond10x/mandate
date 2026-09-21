---
format: aep.planning-md/1
id: review-result:wave-d-second-half-acceptance-r1
kind: review-result
status: active
title: Acceptance critic — wave D second half
relations:
- reviews: story:conform-gate
- reviews: story:obligation-registry
revision: 1
---
```
set: wave D second half
verdict: needs-revision (3 blockers, 2 warnings) — each story now carries an amended Acceptance section naming the command and the expected output
```

```findings
- file: .engineering/planning/story/conform-gate.md
  line: 31
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the acceptance byte-compares report.json and run.json under generated/conformance/, which ruling 1 never commits'
- file: .engineering/planning/story/obligation-registry.md
  line: 25
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the acceptance names contracts/obligations.json and generated/conformance/obligations-report.json, both replaced by the rulings'
- file: .engineering/planning/story/conformance-target.md
  line: 34
  category: acceptance
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: 'the acceptance requires every scenario to execute against the real handlers while 63 of 146 answer Unsupported, and no sentence names the counts'
- file: .engineering/planning/story/authored-denial-scenarios.md
  line: 21
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: 'the second clause is not decided by the synthesize run it names'
- file: .engineering/planning/story/mutation-controls.md
  line: 25
  category: acceptance
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: 'the acceptance names no expected outcome for a check-fails mutant'
```

Held: the seven binding stories are checkable as written. Corrections: an `## Acceptance — amended` section on each of the five stories with the command and the expected output.
