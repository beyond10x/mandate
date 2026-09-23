---
format: aep.planning-md/1
id: review-result:wijk-k1-cross-crate-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on K1 (cross-crate-clauses)
relations:
- reviews: story:cross-crate-clauses
revision: 1
---
unit: story:cross-crate-clauses. Findings cover commit f4b4d6f plus one untracked test file
verdict: red (strongest verdict returned: NEEDS-CHANGE)
cases: executed 239→244, red 5
origin: introduced 5, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k1/scratch/{adv1-alone.log, adv1-suite.log, adv1-suite-nff.log}
needs-coordinator: yes. Findings 1 and 2 need a ruling on the two federation rows before the 86 real is published.

Cases in xtask/tests/adversary_cross_crate_1.rs, all red: an_empty_clause_is_refused_and_counts_nothing; a_joiner_stated_as_a_clause_is_refused (only the report fixed point notices); a_double_through_a_private_module_is_refused (mandate_identity::port::IdentityLog accepted; port is private at lib.rs:134); decided_in_on_a_command_entry_is_refused; decided_in_on_a_no_state_change_row_is_refused (the doctored registry was accepted: all 190 86 21 83).

Suite: cargo test -p xtask --locked --no-fail-fast EXIT=101, 239 passed, adversary_cross_crate_1 0 passed 5 failed. clippy clean.

F1 federation.json:303 NEEDS-CHANGE introduced blocker: the DisableOAuthClient clause is counted real on a test that never runs DisableOAuthClient; disable_oauth_client (disable.rs:197-226) has no such refusal; in the composition a disabled client is refused by registered_public_client (adapters.rs:2670) before the STS. Reaches: every obligations-registry run counts it in the 86.
F2 federation.json:221 NEEDS-CHANGE introduced blocker: nothing in mandate-sts narrows (services/sts/src/code.rs:39-42: authority narrowing is mandate-authz's); the named test uses an empty scope() (code.rs:154); the composition admits with scope: None (adapters.rs:2770); 6 of the test's 10 cases are refused earlier by the composition (adapters.rs:2670-2700). Fix: split into 'STS code issuance' and 'narrowing is refused', blocked_on on the narrowing half.
F3 obligations_registry.rs:863 INFEASIBLE introduced warning: removing the sibling-containment check lets an empty clause or a bare joiner tile the cause and add one to clauses and real_covered; only the report fixed point, which --write clears, notices.
F4 obligations_registry.rs:513 INFEASIBLE introduced note: unresolved_double never checks that the module path is public.
F5 obligations_registry.rs:464 INFEASIBLE introduced note: decided_in on a command entry or a no_state_change row is ignored without a refusal, against the README.

Not broken: renamed/#[ignore]d/feature-gated tests in a decided_in row are refused; two changed contract rows move no count; only federation changed in the report (+2 real, -2 deferred); replaced literals read the value before mutating, none tautological; a decided_in naming a third crate is refused.

```findings
- file: contracts/obligations/federation.json
  line: 303
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the DisableOAuthClient clause is counted real on an STS issuance test that never runs DisableOAuthClient, whose handler has no such refusal, and whose disabled-client refusal the composition makes in mandate-federation before the STS is reached'
- file: contracts/obligations/federation.json
  line: 221
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the narrowing half of "STS code issuance/narrowing is refused" has no decider in mandate-sts (services/sts/src/code.rs:39-42), the named test uses an empty scope, and the clause should be split with the narrowing half deferred'
- file: xtask/src/obligations_registry.rs
  line: 863
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'removing the containment check lets an empty clause or a bare joiner tile the cause and add one to clauses and real_covered, refused only by the report fixed point that --write clears'
- file: xtask/src/obligations_registry.rs
  line: 513
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'unresolved_double never checks that the module path is public, so mandate_identity::port::IdentityLog is admitted although it cannot be named outside the library'
- file: xtask/src/obligations_registry.rs
  line: 464
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'decided_in on a command entry or a no_state_change row is ignored without a refusal, although the README says the field sits on a clause and nothing else'
```
