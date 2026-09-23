---
format: aep.planning-md/1
id: review-result:wl-l3-enabled-for-issuer-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on L3 (enabled-for-issuer-filters-in-the-implementor)
relations:
- reviews: story:enabled-for-issuer-filters-in-the-implementor
revision: 1
---
unit: story:enabled-for-issuer-filters-in-the-implementor, commit 10e9036 (base bde627b) plus one untracked test file
verdict: red
cases: executed 330→334, red 3
origin: introduced 1, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l3/scratch/adv1-suite.log
needs-coordinator: yes. Decide where the fix goes: the fold arm (pre-existing) or enabled_on_issuer (this unit), or both.

Cases in crates/mandate-federation/tests/adversary_enabled_for_issuer_1.rs: a_redelivered_connection_creation_after_a_disable_is_not_enabled_on_the_issuer (red); a_redelivered_disabled_sibling_changes_no_authentication (red: left Err(TenantAmbiguous), right Ok(org 10)); a_redelivered_disabled_sibling_changes_no_registration (red: left Err(TenantResolutionUnadmitted)); a_store_answering_the_selected_connection_twice_is_not_ambiguous (green).

Suite: cargo test -p mandate-federation --locked --no-fail-fast EXIT=101, 331 passed, 3 failed.

F1 record.rs:494 NEEDS-CHANGE pre-existing warning: the FederationConnectionCreated fold arm always pushes a new record and does not skip a held identity (the OAuthClientRegistered arm at :627 and record_link do); disable changes only the first record (:507-513). Reaches: the kit's at-least-once delivery (the crate's own comment at :627); then a disabled connection in org B makes org A's logins TenantAmbiguous and blocks registrations. Denials only. Pre-existing by reading, not run at base.
F2 lib.rs:638 CONFIRMED introduced warning: enabled_on_issuer takes state from the record the store lists, not from connection(id); the doc claim at lib.rs:493 fails for a stale copy.

Held: issuer equality exact on both sides (mandate-types/src/macros.rs:97); TenantZero/TenantAmbiguous/OrganizationMismatch cases unmodified; duplicates collapse into a BTreeSet; mutants removing either check are caught; Disabled is terminal; remaining callers do not decide on the filter.

```findings
- file: crates/mandate-federation/src/record.rs
  line: 494
  category: concurrency
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'the FederationConnectionCreated fold arm pushes unconditionally, so a redelivered creation after a disable leaves an Enabled copy that makes other organizations logins TenantAmbiguous and refuses their registrations'
- file: crates/mandate-federation/src/lib.rs
  line: 638
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: enabled_on_issuer reads lifecycle state from the store enumeration rather than from connection(id), so the doc claim at lib.rs:493 that a store answering a disabled connection changes no decision fails for a stale Enabled copy
```
