---
format: aep.planning-md/1
id: review-result:wave-d-obligations-identity-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-identity
relations:
- reviews: story:obligations-identity
revision: 1
---
```
unit: story:obligations-identity — impl/obligations-identity on 181e6c0, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 2 warnings)
cases: 126 → 130 executed, 4 red when written (crates/mandate-identity/tests/adversary_obligations_identity_2.rs, 510 lines)
origin: introduced 4 / pre-existing 0
suite: cargo test -p mandate-identity --locked --no-fail-fast → 130 executed / 26 targets, 4 failed, exit 101; clippy all-targets 0; obligations-registry `mandate-identity 12 5 1 6` / `all 176 69 9 98` exit 0; xtask obligations_registry 24 passed
attacked and unbroken: the three RefreshSession real clauses; RevokeSession tenancy + no_state_change; both pass-1 pins; report arithmetic; clause tiling; test ids
```

```findings
- file: contracts/obligations/identity.json
  line: 30
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the overflow clause is rowed path real while the atomicity clause refused three lines away in the same function is rowed path double against the same declared double, and the IR''s own accepted-outcome summary assigns unsigned-overflow denial to the adapter, so the published real_covered 5 / double_only 1 rests on two incompatible readings of one decider'
- file: contracts/obligations/README.md
  line: 116
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the README states as fact that there are eight double-backed clauses and that they all defer to story:graph-policy-adapter, which was true at 181e6c0 and is falsified by this unit''s ninth clause deferring to decision-blocker:epoch-atomicity'
- file: contracts/obligations/identity.json
  line: 147
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'RefreshSession''s command-level obligation was moved off the binding story onto story:declared-writers with the doc claiming that story folds the declared event, while coverage.json rows mandate.identity.SessionRefreshed implemented under story:session-epochs and declared-writers.md never names the event or the command, and the registry step only refuses this for the crate''s own binding story'
- file: crates/mandate-identity/tests/obligations.rs
  line: 21
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the span src/port.rs:917-921 is cited for the claim that IdentityLog is the only implementor of SecurityEpochWrite and holds neither name, the statement being at :911, which is the same defect pass-1 F3 raised and the correction said it had re-read every citation for'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Accepted.** Both refusals live in `<IdentityLog as SecurityEpochWrite>::increment`: the compare-and-set at `crates/mandate-identity/src/port.rs:919-921`, already rowed `double` by pass-1 F4, and the generation overflow at `:922-924`. One function is not two paths. Under the cross-unit rule recorded on `review-result:wave-d-obligations-graph-adversary-1` — a clause decided by store/adapter code whose only implementor is a standing double is `double` — both rows of "the exact unsigned generation is at its maximum" become `path: double`, `double: mandate_identity::IdentityLog`, `blocked_on: decision-blocker:epoch-atomicity`. The table becomes `mandate-identity 12 / 4 / 2 / 6`. | correction 2 |
| F1b | **Coordinator's extension, same rule.** With the authority and tenant-containment clauses deferred and the other two now `double`, every refusal `IncrementSecurityEpoch` can reach on the shipped path is the write port's, so `a_refused_increment_emits_nothing_and_leaves_the_log_unchanged` measures the double's own behaviour: the `no_state_change` row becomes `path: double`, `double: mandate_identity::IdentityLog`, and the command carries `blocked_on: decision-blocker:epoch-atomicity` (`README.md`: "A command-level `blocked_on` carries the `no_state_change` obligation under the same rule"). This is the shape `mandate-graph` already publishes for four of its five `no_state_change` rows. Clause counts are unaffected. | correction 2 |
| F2 | **Confirmed, and it is the coordinator's file, not the unit's.** The defect is not the count being wrong but a count being stated at all: `contracts/obligations/README.md` named a number and a closed list of deferral targets, and both move on every merge that adds a document — the sentence was true at `181e6c0` and false two units later. Rewritten by the coordinator to state the rule and no instance: a double-backed clause defers to the story owning the port's real implementation **or** to the open `decision-blocker` holding the question, with `story:graph-policy-adapter` and `decision-blocker:epoch-atomicity` named as the two live examples and the report named as the thing that counts. The adversary case is amended by the coordinator to the invariant a README can hold — no count that the directory falsifies, and every double-backed deferral resolving to a live story or an open blocker. The unit does not touch either file; the case is red in the unit tree until the coordinator amends it. | coordinator |
| F3 | **Accepted in part; the routing stands and the record was missing.** `contracts/coverage.json` rows `mandate.identity.SessionRefreshed` `implemented` under `story:session-epochs`, whose status is `implemented` — a terminal rung the step refuses, so that story cannot hold the deferral whatever the manifest says. `story:declared-writers` is `active` and is where the coordinator routed this gap when pass-1 F2 withdrew the `no_state_change` row; what the adversary read is the unit tree's base copy of the store, which predates that append. The coordinator's `.engineering/planning/story/declared-writers.md:164` now names both `mandate.identity.RefreshSession` and `mandate.identity.SessionRefreshed`, cites `crates/mandate-identity/src/port.rs:305-361` for `IdentityEvent` having no arm for the event, and states that the command's `no_state_change` obligation is deferred there until it is folded. The deferral to `story:declared-writers` is therefore correct and the third of the case's three accepted answers is now true; the coordinator copies that store file into the unit tree so the case reads it, and the closing store commit lands it. The manifest row itself — an event rowed `implemented` under an implemented story while nothing appends it — is a coverage-map defect and is appended to the same story. | correction 2 (no change) + coordinator |
| F4 | **Confirmed.** Cite `crates/mandate-identity/src/port.rs:911`. Pass-1 F3 raised the same class and correction 1 said it had re-read every citation; re-reading is what failed. Correction 2 checks every citation in `crates/mandate-identity/tests/obligations.rs` **mechanically** — for each cited span, read those lines and assert the phrase the citation claims for them occurs inside — and reports the check, not the reading. | correction 2 |
