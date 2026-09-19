---
format: aep.planning-md/1
id: review-result:wave-c-design-r1
kind: review-result
status: active
title: Design critic, round 1 — wave C set
relations:
- reviews: story:oauth-transaction
- reviews: story:declared-writers
revision: 1
---
```
set: story:oauth-transaction, story:declared-writers (contract round 2) — wave C, from 0589bce
verdict: needs-revision
findings: 6
```

```findings
- file: .engineering/planning/story/oauth-integration.md
  line: 16
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its scope list and Units table still claim src/{store,code,binding,redemption}.rs, their tests and units U1-U4, which the split moved to story:oauth-transaction, so two stories own one surface'
- file: .engineering/planning/story/oauth-transaction.md
  line: 81
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the AccessCredential its acceptance counts is seeded by AuthorizationCodeRedeemed under gap 1, but no item in the set owns the fold arm that materializes it'
- file: .engineering/planning/story/declared-writers.md
  line: 154
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the gap-1 field set (credential_id, reference_verifier) is not the whole AccessCredential record, so the seeding event it declares cannot build one - issued_at is non-optional and target is what the fold resolves issuing_profile from'
- file: .engineering/planning/story/oauth-transaction.md
  line: 77
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'moving the AuthorizationCode.State realizer into the STS registry leaves crates/mandate-federation/src/lib.rs:96 naming the same element, and that file is in no item''s scope and outside the -p mandate-sts gate'
- file: docs/plans/2026-09-19-wave-c-execution.md
  line: 18
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'story:oauth-transaction declares no depends_on story:declared-writers although its emitted-event tests construct the AuthorizationCodeRedeemed shape that story''s contract round changes first'
- file: tests/security/cases.json
  line: 421
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the coordinator row reassigns pkce-state-nonce to story:pkce-sessions, whose body records that it owns no corpus case and cannot re-own one'
```

Judged sound: the edge set is acyclic where it orders work (the only cycle is an `informed_by` back-edge); the `pub` in-memory CAS fake is a test double (ADR 0009 governs durable state); the narrowed `IdentityRead` mirror at the STS is the right direction. Not established: `issued_at`'s source for a redemption-issued credential (no timestamp input or response field); no gate compares the sts and federation registries.

Rulings (coordinator): 1 — the endpoint story's scope rows removed and Units superseded (done after the parallel critic); 2 — the fold arm is `oauth-transaction`'s (`crates/mandate-token/src/projection.rs` in scope); 3 — the event mirrors `CredentialReferenceIssued`'s record fields, `credential_id` and `target` from a widened response, `reference_verifier` and `issued_at` generated; 4 — the federation registry line is `oauth-transaction`'s and its gate covers `mandate-federation`; 5 — `depends_on story:declared-writers` recorded; 6 — `pkce-state-nonce` back on `story:oauth-integration`.
