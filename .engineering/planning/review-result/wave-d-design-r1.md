---
format: aep.planning-md/1
id: review-result:wave-d-design-r1
kind: review-result
status: active
title: Design critic, round 1 — wave D set
relations:
- reviews: story:login-adapters
- reviews: story:product-listener
revision: 1
---
```
set: story:login-adapters, story:product-listener — wave D, from a954be8; four opening decisions judged
verdict: needs-revision
findings: 8
```

```findings
- file: .engineering/planning/story/protocol-adapters.md
  line: 63
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its body still owns the five units story:login-adapters now delivers and still closes itself to implemented on exactly that evidence, so after the split two stories claim one outcome'
- file: crates/mandate-federation/src/lib.rs
  line: 360
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the context unit delivers a VerifiedContext and the acceptance demands credential-containment on the road commands, but no road command declares a context input and the tree records that VerifiedContext''s credential had no source on them, so the unit''s only consumers sit behind the product routes the residue story keeps'
- file: .engineering/planning/story/product-listener.md
  line: 67
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the body carries two unit tables that give the same two units two different homes'
- file: .engineering/planning/story/product-listener.md
  line: 50
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the acceptance names a running mandate-sts and the route table story:protocol-adapters declares, but ruling D3 keeps mandate-sts among the five binaries that must refuse serve and the route table is now story:login-adapters'' routes unit'
- file: .engineering/planning/story/invariant-boundary-validation.md
  line: 32
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'it names story:protocol-adapters'' context unit as its mitigation surface and holds only depends_on story:protocol-adapters, while the split moved that unit'
- file: .engineering/planning/story/login-adapters.md
  line: 67
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'it records the product route paths as already reviewed inside a unit row, while story:protocol-adapters:50 still reserves that choice for the critic panel or the operator'
- file: .engineering/planning/story/login-adapters.md
  line: 75
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the same body both leaves the metadata unit with story:protocol-adapters and gives it to itself in the addendum'
- file: .engineering/planning/story/product-listener.md
  line: 125
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'ruling D1 justifies one process holding both authorities by citing ownership.md:15, the credential row reading STS alone issues, resolves, exchanges and revokes credentials, and no artifact owns a change to it'
```

Judged sound: the edge set acyclic (97 `depends_on` edges walked); D1's crate direction (nothing depends on the composition; the `[lib]` in a binary package has the wave B precedent); D2's supply (`httparse` in the lock, MIT OR Apache-2.0). Out of lane, named: what the hand-rolled writer must pin (the adversary's); D3's checkability; D4's consequence stated where a reader looks; the wave page closing `oauth-integration` on the listener's test (corrected: the page now says the story's own close follows).

Rulings (coordinator): 1 — `protocol-adapters`' Units superseded; 2 — `context` becomes `decode` (the decoding boundary: exactly the declared inputs, undeclared fields refused; `VerifiedContext` and `credential-containment` stay with the product routes); 3, 4 — the listener's Units and Acceptance rewritten (`mandate-control-plane`, `login-adapters`' route table); 5 — the edge recorded on `invariant-boundary-validation`; 6 — the route paths are proposed by the unit and fixed by the coordinator's review at the adversary pass, reported to the operator; 7 — `metadata` is `login-adapters`'; 8 — the composition hosts both deployment roles, the authority rows do not move, `ownership.md` gains that sentence in the opening commit.
