---
format: aep.planning-md/1
id: review-result:wave-d-coverage-map-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — coverage map
relations:
- reviews: story:coverage-map
revision: 1
---
```
unit: story:coverage-map — impl/coverage-map on fe03999, after correction 1
verdict: NEEDS-CHANGE (3 blockers, 1 warning)
cases: 107 → 111 executed, 4 red when written; nine-crate lane 1119 green
origin: introduced 4 / pre-existing 0
```

```findings
- file: contracts/coverage.json
  line: 53
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the unit''s rule at xtask/src/coverage.rs:53-55 says a .State element that is not implemented carries its record''s status, story and blocker, and the four identity epoch .State entries carry declared/story:federation-identity-alignment against records that are implemented/story:session-epochs; nothing compares the two'
- file: xtask/src/coverage.rs
  line: 433
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'decide() accepts a declared entry whose story file merely exists, so 16 of the 40 declared entries route at a story the store reports implemented (11 tenancy commands, mandate.tenancy.Denied on story:tenancy-topology; the four epoch .State on story:federation-identity-alignment; DecisionRecorded on story:check-api)'
- file: xtask/src/receipt.rs
  line: 46
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'receipt::receipt takes a repository root while generate() is given the generated-output root, so no single-argument wiring lets contracts()'' byte-compare cover the receipt'
- file: xtask/src/coverage.rs
  line: 551
  category: mutant
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'a crate holding ESS_UNREALIZED whose agreement suite never runs the contradiction clause passes every gate step; no member is one today'
```

Held: the four open blockers hold their stories; the R2 exemption branch cannot name a non-existent realizer; `members()` leaks nothing; `--list --ignored` on a binary with no ignored cases is empty and exit 0; R5's bar is the ruled one. Residue: `named_realizer` stops at a backtick.

Rulings (correction round 2, the last): F1 — the rule is refined and checked: a `.State` whose record is not `implemented` carries the record's status, story and blocker; a `.State` whose record is `implemented` but whose enum no crate registers is `declared` on the live story that will register it — the four identity epoch/snapshot `.State` on `story:epoch-snapshot-generations`; `decide()` checks both branches (the adversary case is amended by the coordinator to the refined rule). F2 — `decide()` reads the story's frontmatter and refuses a `declared` entry on a terminal rung; the eleven tenancy commands and `mandate.tenancy.Denied` become `implemented` by `mandate-model` with their deciding symbols registered (`realizes!` extended to a `Type::method` path where the realization is a method) and same-crate tests named; `mandate.authorization.DecisionRecorded` → `declared` on `story:declared-writers`. F3 — `receipt::receipt(source, out)` writes `out/coverage/receipt.json`; the coordinator wires `receipt::receipt(Path::new("."), root)` in `generate()`. F4 — a step check: every member whose `src/lib.rs` names `ESS_UNREALIZED` has a `tests/contract_agreement.rs` naming the contradiction clause. Residue — `named_realizer` tolerates a backtick.
