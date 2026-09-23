---
format: aep.planning-md/1
id: review-result:wijk-j2-tenant-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on J2 (identity-tenant-containment)
relations:
- reviews: story:identity-tenant-containment
revision: 1
---
unit: story:identity-tenant-containment, commit 3b33fdf on base c2eab4e, plus one untracked test file
verdict: red
cases: executed 139→140, red 1
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/j2/scratch/adv1-suite.log
needs-coordinator: yes (whether the tenancy read has to be atomic with the compare-and-set is a design call for the port, not a test fix)

Case: crates/mandate-identity/tests/adversary_tenant_containment_1.rs, a_placement_committing_between_the_tenancy_read_and_the_compare_and_set_is_not_advanced_past — red. A test port wraps IdentityLog and, inside increment, records another organization's snapshot and SessionOpened before the real compare-and-set.
Red output:
panicked at crates/mandate-identity/tests/adversary_tenant_containment_1.rs:144:5: a caller verified in OrganizationId(...10...) advanced a generation the other organization's fresh session is bound to (execute returned Ok(SecurityEpochIncremented { ... target: Principal(...) })); the tenancy read is not covered by the compare-and-set token
  left: Generation(1)
  right: Generation(0)

Suite: cargo test -p mandate-identity --locked --no-fail-fast exit 101, 139 passed, 1 failed. clippy Finished.

F1 increment.rs:118 INFEASIBLE introduced warning: execute checks tenancy with one read (organizations_of) then calls increment; the CAS token is only the target's stream version, and recording a snapshot or opening a session places the target without moving it. Reaches: nothing today — IdentityLog is always held under one &mut (services/control-plane/src/adapters.rs:3003, crates/mandate-conformance/src/commands/identity.rs:141); reachable with a concurrent adapter (the SQLite backend the ADR names); identity.yaml:309 asks the adapter to atomically increment and preserve isolation. Suggested fix: containment check inside SecurityEpochWrite::increment under the same lock or token, or placements advance a token the CAS checks.
F2 port.rs:943 INFEASIBLE introduced note: organizations_of reads only the identity log, so a connection the federation log owns but no login has placed is accepted for increment by any organization. Nothing depends on the generation (every epoch check goes through a snapshot, which is itself a placement). Only route: the conformance target (mandate-server/src/obligations.rs:526 Wire::Generated). No case: the identity crate has no connection-registration event.

Could not break: every placing event is read (snapshot, SessionOpened, FederationAuthenticated, provisioning); each placement arm is exercised in tests/increment.rs; no in-process order where an unplaced target has a dependent generation; refusing a target in two organizations cannot lock out a real principal (link.rs:71-79; PrincipalAcrossOrganizations); the adversary_obligations_identity_1 flip is stronger; conformance change honest by reading (consulted 2 right for principal/federation targets).

```findings
- file: crates/mandate-identity/src/increment.rs
  line: 118
  category: concurrency
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'the tenancy read and the compare-and-set are two port calls with no shared token; a placement committing between them lets another organization advance a generation a fresh session is bound to (reachable only by a concurrent adapter)'
- file: crates/mandate-identity/src/port.rs
  line: 943
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: organizations_of consults only the identity log, so a connection the federation log owns but no login has placed is accepted for increment by any organization, with no dependent session affected
```
