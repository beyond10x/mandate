---
format: aep.planning-md/1
id: review-result:wave-d-obligation-registry-adversary-1
kind: review-result
status: active
title: Adversary pass — obligation registry
relations:
- reviews: story:obligation-registry
revision: 1
---
```
unit: story:obligation-registry — impl/obligation-registry on 6d812e0
verdict: NEEDS-CHANGE (2 blockers, 2 warnings, 1 note)
cases: 131 → 135 executed, 4 red when written
origin: introduced 5 / pre-existing 0
```

```findings
- file: contracts/obligations/graph.json
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the clause "parent is unresolved or belongs to another organization" holds a real row deciding only the tenant half and a GraphDouble row for the unresolved-parent half, so the step counts it real_covered and drops its blocked_on, while the real path for an unresolved resource answers Unavailable, not a denial'
- file: xtask/src/obligations_registry.rs
  line: 830
  category: mutant
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'obligation() has no reader for the README rule that a double row never covers: a double row added to a clause a real row already covers leaves every report column unmoved and the step exits 0'
- file: xtask/src/obligations_registry.rs
  line: 237
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the amended Acceptance says every named test belongs to the entry''s crate while the step exempts cases and addendum rows; 4 of 45 case rows use it and the addendum half is unexercised'
- file: contracts/obligations/sts.json
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'two IssueAuthorizationCode/RedeemAuthorizationCode clauses enumerate two conditions each and are counted real_covered on a single ExpiryUnbounded discriminator; "authority narrowing" and "atomic issuance" are driven by nothing'
- file: xtask/src/obligations_registry.rs
  line: 375
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'terminal_rung is byte-identical to coverage.rs:536-558; drift risk only'
```

Held: all 41 clause lists tile their causes with nothing dropped; STS bindings decide their clauses both ways; 32 distinct no-state-change tests; the six policy double-only clauses are honest (no real refusal exists); the case ids are bounded both ways; the report is byte-stable and moves; no new dependency.

Rulings (correction round 1): F1/F4 — a clause whose conditions have different deciders is split into its conditions (the split stays a verbatim tiling of the cause); a condition whose real path cannot produce the declared denial (`parent is unresolved` answers `Unavailable`) is `double_only` with `blocked_on` the story that owns the real path (`story:graph-policy-adapter` for the graph resolution; `story:obligations-sts` for the two undriven STS conditions until a real test exists). F2 — `obligation()` refuses a `double` row on a clause a `real` row covers ("a double row belongs where the real path does not cover"), and a clause with both `real` and `double` rows is impossible by that rule. F3 — the Acceptance is amended: the same-crate rule holds for clause and no-state-change rows and for `addendum` rows (the exemption is removed there); a `cases` row may name a test of `mandate-proto` or `mandate-server` in addition to the entry's crate, because a security case filed at the wire is decided there — bounded to those two packages in the step and in the README. F5 — `coverage::terminal_rung` becomes `pub` (scope extended by that one-word change to `xtask/src/coverage.rs`) and the duplicate is deleted.
