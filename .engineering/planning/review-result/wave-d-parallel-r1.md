---
format: aep.planning-md/1
id: review-result:wave-d-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave D set
relations:
- reviews: story:login-adapters
- reviews: story:product-listener
revision: 1
---
```
set: story:login-adapters, story:product-listener — wave D, from a954be8
verdict: needs-revision
findings: 5
```

```findings
- file: .engineering/planning/story/product-listener.md
  line: 66
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the body''s Units table still assigns crates/mandate-federation/src/lib.rs, crates/mandate-federation/src/adapters.rs, services/sts/src/serve.rs and services/sts/src/lib.rs to this story''s units, files ruling D1 struck, and crates/mandate-federation/src/lib.rs is in the scope of story:declared-writers (active)'
- file: .engineering/planning/story/product-listener.md
  line: 106
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the listener serves the RFC 8414 and JWKS documents but the body does not say whether their two paths become entries of crates/mandate-server/src/routes.rs or are hardcoded in services/control-plane/src/serve.rs outside the disjointness proof'
- file: .engineering/planning/story/login-adapters.md
  line: 80
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the collision statement denies sharing a file with story:product-listener on the grounds of a file set ruling D1 struck and replaced with services/control-plane/** in the same opening'
- file: .engineering/planning/story/login-adapters.md
  line: 60
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the scope asserts LIBRARIES = 17 and the boundary keys hold, but the wave''s opening commit moves LIBRARIES to 18 and adds a mandate-control-plane key before round 1''s tree is cut, and the body does not record the coordinator as the writer of those files'
- file: .engineering/planning/story/login-adapters.md
  line: 80
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the collision list does not name story:declared-writers (active, holding systems/** and generated/**), whose surface regenerates the 61 operationIds this story''s obligations equality and disjointness proof are pinned to'
```

Answers: no literal intersection between the two rounds' file sets including the pre-lands; the `obligations` equality and disjointness proof read `generated/openapi/*.yaml`, which round 2 does not change; `crates/mandate-server/**` is also held by `story:protocol-adapters` and `story:invariant-boundary-validation` (drafts, not selected); `services/control-plane/**` by nobody live. Not established: whether `story:declared-writers` moves during the wave; the route-table home of the two document paths.

Rulings (coordinator): 1 — the listener's Units section superseded (done after the design critic); 2 — the two document paths are route-table entries of `login-adapters`; 3, 4, 5 — corrections appended to `login-adapters` (the listener's files, the coordinator as the writer of the two policy files in the opening commit, `declared-writers` quiescent this wave).
