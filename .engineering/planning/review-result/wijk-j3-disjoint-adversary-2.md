---
format: aep.planning-md/1
id: review-result:wijk-j3-disjoint-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on J3 (federation-rule-disjointness)
relations:
- reviews: story:federation-rule-disjointness
revision: 1
---
unit: story:federation-rule-disjointness, commits afcd3a2..cfea365 on base ab1ee6d, plus one untracked test file
verdict: red (NEEDS-CHANGE, warning)
cases: executed 318→320, red 2
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: 4 paths in ~/.cache/claude-tmp/wijk/j3/scratch (adv2-generate.log, adv2-conform.log, adv2-oblreg.log, adv2-suite.log)
needs-coordinator: yes. The fix is in systems/mandate/scenarios/federation-ambiguous-tenant.yaml and contracts/use-cases/federated-login.json:690.

Cases in crates/mandate-federation/tests/adversary_rule_disjointness_2.rs (both red); each replays generated/conformance/suite.json through the shipped writer and authenticator:
- the_ambiguous_tenant_scenario_is_refused_as_ambiguous: left Err(LinkAbsent), right Err(TenantAmbiguous) — with 1 connection standing its login is refused for another reason
- some_scenario_cited_for_more_than_one_organization_stands_two_organizations: step 6 cites 8 authored scenarios for 'more than one organization is denied'; replayed, none stands two connections

Runs: cargo test -p mandate-federation --locked --no-fail-fast 101, 318 passed, 2 failed; cargo xtask generate 0, no diff under generated/; cargo xtask conform 0; cargo xtask obligations-registry 0 (83 real).

F1 federation-ambiguous-tenant.yaml:4 NEEDS-CHANGE introduced: the scenario named and summarised for the multiple-match clause stands one connection; its login ends LinkAbsent, asserted only as reason Denied (authenticate.rs:122,130,250,253 all satisfy it). At base both connections registered and the check was TenantMismatch.
F2 federated-login.json:690 NEEDS-CHANGE introduced: step 6 cites the scenario as passed evidence that more than one organization is denied; none of the 8 cited authored scenarios can reach that state any more. The statement is still true through :718 (authenticate::tenant_ambiguous) and obligations.rs (the race). Fix: move the :690 citation to the registration-refusal claim (:255) and rename or re-summarise the scenario.

```findings
- file: systems/mandate/scenarios/federation-ambiguous-tenant.yaml
  line: 4
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the scenario named and summarised for the multiple-match clause stands one connection and its login is refused LinkAbsent, asserted only as reason Denied, so it no longer reaches TenantAmbiguous'
- file: contracts/use-cases/federated-login.json
  line: 690
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: step 6 cites the ambiguous-tenant scenario as passed evidence that more than one organization is denied, and none of its 8 cited authored scenarios can reach that state any more
```
