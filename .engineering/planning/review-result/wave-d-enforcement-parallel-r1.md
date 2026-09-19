---
format: aep.planning-md/1
id: review-result:wave-d-enforcement-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic — wave D enforcement set
relations:
- reviews: story:coverage-map
- reviews: story:conformance-target
- reviews: story:authored-denial-scenarios
- reviews: story:mutation-controls
revision: 1
---
```
set: story:coverage-map, story:conformance-target, story:authored-denial-scenarios, story:mutation-controls — wave D enforcement track, from 75f41b5
verdict: needs-revision
findings: 7
```

```findings
- file: .engineering/planning/story/conformance-target.md
  line: 86
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'generated/conformance/{suite,report,run,injections}.json land inside the tree contracts() byte-compares whole while generate() writes six kinds and none is conformance/, so the single coordinator regeneration cannot clear it and cargo xtask check stays red for every later unit'
- file: .engineering/planning/story/conformance-target.md
  line: 63
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the four committed artifacts are a function of systems/mandate/scenarios/, which story:authored-denial-scenarios creates in a worktree cut from the same commit, so authored merges first does not put those files in this story''s tree and no body names who re-runs mandate-conform after that merge'
- file: .engineering/planning/story/conformance-target.md
  line: 79
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'ruling 1 requires mandate-testkit admitted as a dev dependency before the unit tree is cut, but the manifest has no [dev-dependencies] and the boundary line omits it'
- file: .engineering/planning/story/coverage-map.md
  line: 63
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the declared gate cargo run -p xtask -- coverage cannot run in this story''s worktree, because Action::Coverage is wired by the coordinator at integration on xtask/src/main.rs'
- file: .engineering/planning/story/coverage-map.md
  line: 86
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the body never says cargo xtask contracts is red in the unit tree and between the merges, the way the E1 rulings said it'
- file: .engineering/planning/story/mutation-controls.md
  line: 34
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the declared gate cargo run -p xtask -- mutants and the required cold/warm measurement both need Action::Mutants, which the body hands the coordinator'
- file: .engineering/planning/story/mutation-controls.md
  line: 36
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the scope and the collision line name none of the eight source files the patches are line-anchored to; the anchors are verified in the tree, the collision class is not expressible in scope'
```

Answers: the four file sets intersect nowhere except through the coordinator's `xtask/src/main.rs` wirings and `generated/**`; the merge order (authored → coverage-map → conformance-target → mutation-controls round 2) is consistent; the read-anchor class is inexpressible in `scope:`; `story:declared-writers` has no unit in flight (its B/C2 rows say later wave).

Rulings (coordinator): 1, 2 — nothing under `generated/conformance/` this wave; the target's outputs go to `target/conformance/`, `story:conform-gate` decides the committed location; the coordinator re-runs `mandate-conform` on the merged head after both merges and records the counts. 3 — `mandate-testkit` admitted in the pre-land. 4, 6 — both xtask units gate through their `#[path]`-included step tests (`cargo test -p xtask`); the CLI actions are verified after the coordinator wires them. 5 — the red window stated. 7 — the anchors recorded in prose.
