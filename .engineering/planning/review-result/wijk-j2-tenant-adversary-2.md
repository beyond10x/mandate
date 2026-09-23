---
format: aep.planning-md/1
id: review-result:wijk-j2-tenant-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on J2 (identity-tenant-containment)
relations:
- reviews: story:identity-tenant-containment
revision: 1
---
unit: story:identity-tenant-containment, commit 74f14b1 (base c2eab4e) plus one untracked test file
verdict: red
cases: executed 140→141, red 1
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/j2/scratch/adv2-suite.log
needs-coordinator: yes (should a placement that no longer binds a live session still refuse the increment? A tenancy-semantics rule, not a test fix)

Case: crates/mandate-identity/tests/adversary_tenant_containment_2.rs, a_principal_whose_only_other_organization_session_is_revoked_can_be_advanced_by_its_own_organization — red. P opens a session in B, B revokes it; P opens a live session in A; asserts a caller in A can advance P and A's session then gets StaleEpoch.
panicked at crates/mandate-identity/tests/adversary_tenant_containment_2.rs:117:5: organization A was refused the increment of a principal whose generation gates no live session outside A: a revoked session in B still places the principal there (TargetTenancy::organizations_of never forgets a placement)
  left: Err(TenantMismatch)
  right: Ok(())

Suite: cargo test -p mandate-identity --locked --no-fail-fast exit 101, 140 passed, 1 failed. clippy Finished; fmt clean.

F1 increment.rs:145 INFEASIBLE introduced warning: contained refuses when any record places P in another org; organizations_of (port.rs:948) counts every placement ever recorded, revoked sessions included. increment.rs:135-137's reason does not hold when B has no live session. mandate-model tenancy.rs:1310: a principal joins as many organizations as it is admitted to. Reaches: nothing found — control-plane never calls IncrementSecurityEpoch; mandate-server marks it Wire::Generated (obligations.rs:526); the conformance scenario uses an unplaced federation target. Fix is a design call: count only live placements, or accept and document.

Could not break: the pass-1 pinned case pins the atomicity gap only (its read precedes the landing), but removing the check turns 3 named rows plus 5 other cases red; identity.json path real is honest under contracts/obligations/README.md; mutants .all→.any, org arm true, arms None are caught; no existing caller gets TenantMismatch; injections consulted 2 right for the generated federation target.

```findings
- file: crates/mandate-identity/src/increment.rs
  line: 145
  category: judgement
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'a placement is never forgotten, so a principal whose only other-organization session was revoked can no longer be advanced by its own organization, and that organization''s live session keeps refreshing (red case adversary_tenant_containment_2.rs:117; no production caller of execute)'
```
