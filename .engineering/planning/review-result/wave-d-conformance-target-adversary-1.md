---
format: aep.planning-md/1
id: review-result:wave-d-conformance-target-adversary-1
kind: review-result
status: active
title: Adversary pass — conformance target
relations:
- reviews: story:conformance-target
revision: 1
---
```
unit: story:conformance-target — impl/conformance-target on fe03999, after rounds 1–2
verdict: NEEDS-CHANGE (2 blockers, 2 warnings, 3 notes)
cases: 28 → 32 executed, 4 red when written
origin: introduced 5 / pre-existing 1 / undecided 1
```

```findings
- file: crates/mandate-conformance/src/commands/identity.rs
  line: 79
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'two scenarios are attributed to story:session-epochs, whose status is implemented and whose lifecycle admits no move back to active, so the gap is owned by nobody and the initiative''s release stance is not met'
- file: crates/mandate-conformance/src/lib.rs
  line: 628
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '21 of 23 rows recorded kind armed at a named port are inert, the scenario reaching the same terminal category with every configure_external_outcome step removed, so injections.json attributes 17 of the 29 passes to a fault that was not placed'
- file: crates/mandate-conformance/src/commands/authz.rs
  line: 57
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'check() takes the arming and discards it, substituting no reader, while the ledger records the scenario as armed at mandate_graph::port::GraphRead'
- file: crates/mandate-conformance/src/external.rs
  line: 324
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'mandate.identity.RevokeSession is refused before dispatch with "consults no port" while revoke_session reads IdentityRead::resolve through the concrete log; the module doc enumerates twelve portless commands and the table carries thirteen'
- file: crates/mandate-conformance/src/commands/authz.rs
  line: 10
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the module doc promises injections.json records the five CheckRequest bounds the target states rather than evaluates, and the document names none of them'
- file: crates/mandate-conformance/src/lib.rs
  line: 413
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'identity_unchanged() is an unconditional pass whose doc claims it compares the log length; Live::open is private and no scenario reaches an identity refusal that appends'
- file: systems/mandate
  category: property
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'every synthesized expect_error step carries an error name and no fields, so the 19 passing denied scenarios prove only the declared error type; the authored unit closes this'
```

Held: no manufactured outcome (flipping two expectations moved both scenarios to failed); real handlers on the accepted transitions; 17 standing doubles, 17 rows; `diff -r` byte-identical, `--impl-digest` moves `report.implementation` only, `spec_digest` equal; no `HashMap` on a serialized path, no clock; all partitions close; fold isolation; every `Unsupported` a permanent property. With all arming removed the run reads 39 / 57 / 50.

Rulings (correction round 1): F1 — every `blocked_on` names a story off a terminal rung, checked by a unit case against the store frontmatter; the two rows move to `story:epoch-snapshot-generations`. F2/F3 — armed readers count consultations and the row carries `consulted: n`; `Check` substitutes a `GraphRead` double when armed. F4 — the reason text becomes true, routing unchanged, doc count 13. F5 — the five bounds join `STANDING`. F6 — compare the length. F7 — routed. Plus the integral-float decoder note from the authored unit.
