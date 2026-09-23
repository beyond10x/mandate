---
format: aep.planning-md/1
id: review-result:wijk-j3-disjoint-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on J3 (federation-rule-disjointness)
relations:
- reviews: story:federation-rule-disjointness
revision: 1
---
unit: story:federation-rule-disjointness, commit afcd3a2 on base ab1ee6d plus the one untracked test file added
verdict: red (NEEDS-CHANGE, blocker)
cases: executed 316→318, red 2
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/j3/scratch/{adv1-suite.log,adv1-suite-nff.log,adv1-conformance.log,adv1-xtask-conform.log}
needs-coordinator: yes. The fix belongs in systems/mandate/scenarios/, then cargo xtask generate and a change to contracts/expected-outcomes.json; none is on the unit's assignment.

Cases in crates/mandate-federation/tests/adversary_rule_disjointness_1.rs (both red): each replays the RegisterFederationConnection steps of generated/conformance/suite.json through the shipped writer and compares with the stated outcome.
- the_authored_ambiguous_tenant_scenario_registers_both_connections
- every_replayable_scenarios_registrations_answer_as_the_suite_states (6 decided, 1 disagrees)
Red output:
the contract document states each registration's outcome and the writer answers differently: [(4, "accepted", "denied TenantResolutionUnadmitted")]
1 of 6 replayable scenarios disagree with the writer: [("mandate.federation/authored/federation-ambiguous-tenant", [(4, "accepted", "denied TenantResolutionUnadmitted")])]

Suite: cargo test -p mandate-federation --locked --no-fail-fast 316 passed, 2 failed, EXIT=101.
What reaches it: cargo xtask conform EXIT=1 — mandate.federation/authored/federation-ambiguous-tenant: ./contracts/expected-outcomes.json expects passed and the run answers failed. cargo test -p mandate-conformance --test target passes 11/11 and does not catch it.

F1 systems/mandate/scenarios/federation-ambiguous-tenant.yaml:50 NEEDS-CHANGE introduced blocker: the scenario registers {tid: acme} for a1 then {dept: acme} for a2 and states both accepted; the new collides (record.rs:942) refuses the second. Base record.rs:940 admitted it. Suggested fix: the second registration expects denied; the ambiguity clause comes from elsewhere; cargo xtask generate; update contracts/expected-outcomes.json and contracts/use-cases/federated-login.json:690.
F2 crates/mandate-federation/tests/obligations.rs:737 CONFIRMED introduced note: the doc says the race is the only way to reach the multiple-match pair; replaying a history the old guard admitted also reaches it (Deployment::record_federation is a raw fold, services/control-plane/tests/serve.rs:2924-2936). Assertions unchanged (TenantAmbiguous).

Could not break: no claim folding on either side (record.rs shape, authenticate.rs:382); one claim one value (verifier_real.rs:1269); one org two rules agree (record.rs:977, authenticate.rs:333-337); disabled connections (disable.rs:117); configured-org vs claim rule; issuer exact compare (record.rs:819, verifier_real.rs:1200). Mutants reasoned, not run.

```findings
- file: systems/mandate/scenarios/federation-ambiguous-tenant.yaml
  line: 50
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the authored scenario states the second-organization {dept: acme} registration accepted, the new collides refuses it, and cargo xtask conform fails on it'
- file: crates/mandate-federation/tests/obligations.rs
  line: 737
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the multiple-match case's doc says the race is the only way to reach the pair, but replaying a history admitted before this story also reaches it
```
