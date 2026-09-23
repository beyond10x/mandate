---
format: aep.planning-md/1
id: review-result:wm-m3-fixtures-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on M3 (federation-fixtures-rs256)
relations:
- reviews: story:federation-fixtures-rs256
revision: 1
---
unit: story:federation-fixtures-rs256 — commit 18efbc51 (HEAD over base 871c11b0) plus one untracked test file
verdict: red
cases: executed 353→356, red 2
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wm/m3/scratch/{adv1-helpers.rs, adv1-suite.log}
needs-coordinator: yes (decide whether the type refusal belongs in step 6 rather than step 3)

Cases in crates/mandate-federation/tests/adversary_fixtures_rs256_1.rs (RS256, RSA-2048, RealVerifier): control_a_mismatched_string_tenant_claim_is_refused_as_unverified_fallback (green); a_numeric_tenant_claim_does_not_mask_the_unverified_fallback_clause (red: left TenantZero, right UnverifiedFallback, :253); a_numeric_tenant_claim_does_not_pre_empt_the_empty_subject_refusal (red: left TenantMismatch, right InvalidCredential, :271).

Suite: cargo test -p mandate-federation --locked --no-fail-fast EXIT=101, 354 passed, 2 failed. clippy and fmt clean.

F1 verifier_real.rs:1377 NEEDS-CHANGE introduced warning: the step-3 type refusal pre-empts the step-6 fallback analysis; the comment at :1436 says the refusal answers what authenticate_federation would have answered had the claim been skipped, which case :253 shows false. Reaches: two same-organization connections on one issuer with rules on different claims (record.rs:996 guards only other organizations), read not run, plus an IdP sending a numeric tenant claim and an unverified email.
F2 verifier_real.rs:1377 INFEASIBLE introduced note: a blank sub is now reported as a tenant mismatch; the refusal fires before the subject checks at authenticate.rs:276. Reaches: nothing found.
Fix: record the claim's type in the verifier and refuse inside resolve_tenant after the fallback check, or correct the comment.

Not broken: other-organization rules on a different claim are refused at registration; non-string email/phone refused before the hint path; duplicate claims keep the last value; exact-key lookup; only the type name is carried (main.rs:414 eprintln too); no pinned refusal order broke; RS256 via RealVerifier confirmed; TenantZero declared (lib.rs:256); a mutant refusing every non-string claim is caught by the iat/exp assertion.

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 1377
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the step-3 type refusal pre-empts the step-6 fallback analysis, so a numeric tenant claim beside an unverified-email rule match answers TenantZero instead of UnverifiedFallback, contradicting the comment at :1436'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 1377
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a whitespace-only sub beside a numeric tenant claim is now reported as TenantMismatch/TenantZero instead of InvalidCredential/EmptySubject, a state no observed IdP reaches
```
