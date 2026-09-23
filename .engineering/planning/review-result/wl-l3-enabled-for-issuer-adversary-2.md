---
format: aep.planning-md/1
id: review-result:wl-l3-enabled-for-issuer-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on L3 (enabled-for-issuer-filters-in-the-implementor)
relations:
- reviews: story:enabled-for-issuer-filters-in-the-implementor
revision: 1
---
unit: story:enabled-for-issuer-filters-in-the-implementor, HEAD a4d55e8 (base bde627b) plus one untracked test file
verdict: red
cases: executed 334→339, red 2
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l3/scratch/adv2-case.log, adv2-suite.log
needs-coordinator: yes. Decide whether a listed id that connection(id) answers None should fail closed.

Cases in crates/mandate-federation/tests/adversary_enabled_for_issuer_2.rs: a_listed_collider_the_store_cannot_answer_by_identity_still_refuses_registration (red: left Ok(connection), right Err(TenantResolutionUnadmitted)); a_listed_sibling_the_store_cannot_answer_by_identity_still_makes_the_login_ambiguous (red: left Ok(org 10), right Err(TenantAmbiguous)); a_stale_enabled_copy_in_the_enumeration_decides_nothing (green); an_enumeration_misreporting_the_issuer_decides_nothing (green); a_second_creation_with_other_fields_keeps_the_first_record (green).

Suite: cargo test -p mandate-federation --locked --no-fail-fast 337 passed, 2 failed, EXIT=101. clippy clean.

F1 lib.rs:657 INFEASIBLE introduced note: filter_map(connection) drops a listed id with no by-id answer, so a colliding foreign connection is accepted and an ambiguous login admitted, contradicting 'narrows, never widens' at lib.rs:643; base (authenticate.rs:315, record.rs:975) used the listed record and failed closed. Reaches: nothing — Projection, RecordedPrincipals and conformance Substituted agree between listing and lookup.
F2 record.rs:468 CONFIRMED introduced note: the doc says no event is silently discarded; the new arm at :498 (and OAuthClientRegistered) skips silently.

Held: skipping a repeated creation loses nothing read (ids from the allocator, record.rs:1001; control-plane refuses repeated ids, adapters.rs:966-973); conformance seed_connection (establish.rs:311) unchanged; issuer mismatch and stale copies handled; dedup harmless.

```findings
- file: crates/mandate-federation/src/lib.rs
  line: 657
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'enabled_on_issuer drops a listed id whose connection(id) answers None, so a colliding foreign connection is accepted at registration and an ambiguous login is admitted, contradicting the narrows-never-widens doc at lib.rs:643; no shipped store reaches it'
- file: crates/mandate-federation/src/record.rs
  line: 468
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the apply doc still says no event is silently discarded while the FederationConnectionCreated arm now silently skips a held identity
```
