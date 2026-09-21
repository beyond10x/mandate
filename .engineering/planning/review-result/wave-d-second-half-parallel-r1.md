---
format: aep.planning-md/1
id: review-result:wave-d-second-half-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic — wave D second half
relations:
- reviews: story:obligation-registry
- reviews: story:conform-gate
revision: 1
---
```
set: wave D second half (conform-gate, obligation-registry + 7 binding stories, conformance-target, mutation-controls, authored-denial-scenarios)
verdict: needs-revision (4 blockers, 4 warnings) — corrected in the store the same day
```

```findings
- file: .engineering/planning/story/obligation-registry.md
  line: 67
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'all seven binding stories change contracts/obligations.json and the report, which the registry''s scope claims alone, so "one file each, parallel-safe" is false for two files'
- file: .engineering/planning/story/obligations-sts.md
  line: 22
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'seven concurrently placed items write two undeclared shared files'
- file: .engineering/planning/story/obligation-registry.md
  line: 17
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the registry''s scope still claims four per-crate tests/obligations.rs files the binding stories own'
- file: .engineering/planning/story/obligation-registry.md
  line: 33
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the Acceptance names generated/conformance/obligations-report.json, a file generate() does not write, in the directory contracts() byte-compares whole'
- file: .engineering/planning/story/conform-gate.md
  line: 75
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the coordinator-wired generate() suite synthesis changes what contracts() returns, which is what mutation-controls'' two ESS mutants kill through, and the spawn mode for an exit-1 synthesize is unstated'
- file: .engineering/planning/story/authored-denial-scenarios.md
  line: 35
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'under conform-gate ruling 1 this story''s merge moves generated/conformance/suite.json, a byte-compared generated file'
- file: .engineering/planning/story/conformance-target.md
  line: 76
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'ruling 6 says authored merges first while the authored story says last; the order conform-gate''s corpus depends on is written two ways'
- file: .engineering/planning/story/conformance-target.md
  line: 17
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: pre-existing
  message: 'its scope claims Cargo.lock, dependency-boundaries.json and its Cargo.toml, which the wave assigns to the coordinator'
```

Corrections: the registry is one file per crate under `contracts/obligations/`, each binding story's scope names its file, the report lives under `contracts/conformance/` (see `review-result:wave-d-second-half-design-r1`); the per-crate test files left the registry's scope; `generate()` spawns `ess verify conform synthesize --suite-format 5` tolerantly and decides on the artifact (stated on `story:conform-gate`); the two ESS mutants still kill through `contracts` — a contract mutation moves the suite bytes as well as the projections; the authored merge triggers a coordinator regeneration of `generated/conformance/suite.json` once conform-gate has landed (stated on both stories); the merge order is one statement: conformance-target → mutation-controls → conform-gate → obligation-registry; authored-denial-scenarios whenever its commit is admitted, followed by a suite regeneration; conformance-target's scope drops the three coordinator files.
