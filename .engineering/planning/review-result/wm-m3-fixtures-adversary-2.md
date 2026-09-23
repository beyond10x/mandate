---
format: aep.planning-md/1
id: review-result:wm-m3-fixtures-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on M3 (federation-fixtures-rs256)
relations:
- reviews: story:federation-fixtures-rs256
revision: 1
---
unit: story:federation-fixtures-rs256, HEAD c90e990 (base 871c11b0) plus one untracked test file
verdict: red
cases: executed 357→360, red 1
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m3/scratch/adv2-suite.log
needs-coordinator: no

Cases in crates/mandate-federation/tests/adversary_fixtures_rs256_2.rs: a_numeric_tenant_claim_beside_an_unverified_fallback_logs_no_tenant_type (green; catches a mutant moving the call above the fallback return — read, not run); provisioning_refuses_a_numeric_tenant_claim_before_the_admission_check_and_names_its_type (green, jit on and off); a_rule_without_a_value_does_not_blame_the_tenant_claims_type (red at :338: left [TenantClaimNotText(Number)], right []).

Suite: cargo test -p mandate-federation --locked --no-fail-fast EXIT=101, 359 passed, 1 failed. clippy and fmt clean.

F1 authenticate.rs:337 CONFIRMED introduced note: a rule with a claim name and no value matches nothing, yet a numeric claim logs TenantClaimNotText(Number); the denial is TenantZero either way, as base. Reaches: register_federation_connection accepts such a rule (record.rs:941); the control-plane seed's tenant_resolution defaults a missing value (mandate-model/src/lib.rs:100) — read, not run. Fix: report the type only when the rule has both a name and a value.

Not broken: denials match base by construction; subject checks still first; provisioning path order unchanged, no double log; the defaulted method's only wrapper is the known RecordingVerifier; ClaimType carries no value; duplicate keys and exact-key lookup as base.

```findings
- file: crates/mandate-federation/src/authenticate.rs
  line: 337
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'a tenant rule with a claim name and no value matches nothing, yet a numeric claim logs TenantClaimNotText(Number) while a string claim logs nothing, so the refusal log names a type that decided nothing'
```
