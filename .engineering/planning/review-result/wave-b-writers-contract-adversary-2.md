---
format: aep.planning-md/1
id: review-result:wave-b-writers-contract-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — declared-writers contract round
relations:
- reviews: story:declared-writers
revision: 1
---
```
unit: story:declared-writers contract round after correction 1 — impl/writers-contract on 162f22c
verdict: NEEDS-CHANGE (4 blockers, 2 warnings, 2 notes)
cases: 6 new probe cases, all red at the time of the pass; pass 1's ten re-run: 7 green, 3 red by ruling
origin: introduced 7 / pre-existing 1
```

```findings
- file: systems/mandate/domains/credential.yaml
  line: 112
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the synthesized scenario RegisterSigningKey/outcome/accepted registers a key with not_before equal to expires_at and asserts accepted, creating a record the entity invariant declared in the same commit forbids; publishing a view does not fix it but yields an invariant scenario no implementation can pass, because the synthesizer never consults an invariant when building command input'
- file: docs/architecture/command-obligations.md
  line: 18
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'correction 1 deleted the window-ordering clause from the denial and this row and replaced it with an invariant that reads fields no view publishes, so ESS refuses every scenario for it (ESS-SYNTH-011, base 2 to head 5) and drops it from the schema projection: the condition is published in no obligation and checked by nothing'
- file: systems/mandate/domains/credential.yaml
  line: 424
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'IntrospectCredential''s new accepted summary declares a well-formed proof that resolves to no record an accepted active: false answer, while its denied outcome and command-obligations.md:12 name the presented proof being unresolvable as required denial behaviour — one input with two contradictory declared answers'
- file: systems/mandate/domains/credential.yaml
  line: 515
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the RegisterSigningKey summary concludes that revoked material never returns under a second identity, but the only uniqueness declared is over key_reference, a handle to the material, and none over the thumbprint just added, so the contract admits the readmission signing_real.rs:736-739 refuses by comparing thumbprints'
- file: systems/mandate/domains/federation.yaml
  line: 397
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'RegisterOAuthClient creates an organization-scoped record and names no organization, tenant or binding condition in its denial, while DisableOAuthClient on the same entity names outside the verified organization and 13 of the 15 creating commands name one'
- file: systems/mandate/domains/credential.yaml
  line: 517
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the three commands over SigningKey disagree about who administers a key: registration requires platform signing-key administration authority and retirement and revocation require it unqualified'
- file: systems/mandate/domains/federation.yaml
  line: 305
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the summary sources display_name from the validated proof''s claims but names no claim, the response types it as a bare String, and federated-login.md says nothing about a display name'
- file: systems/mandate/domains/credential.yaml
  line: 111
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'ESS 0.26.0 does not type the invariant''s comparison — it accepts algorithm < expires_at, a string newtype against a Timestamp — and carries the predicate to the runner as an uninterpreted string, so whether not_before < expires_at is chronological or lexicographic is fixed nowhere'
```

Held: `thumbprint` cannot be smuggled by a caller (no input, response-sourced); `String` loses nothing the signer compares; 61 obligations rows verbatim and alphabetical, one externally caused outcome each; components owners correct; the `RegisterOAuthClient` summary's three claims hold and the empty-set contradiction is resolved; the identity header's claims hold; no unlisted pin moves. An outcome split for active/inactive is not expressible (`when:` may read only declared input, `ESS-COMMAND-003`).

Rulings (coordinator, correction round 2): F1+F2 — the invariant stays (domain validation is not an external denial); the synthesizer's equal-timestamp input is an ESS gap routed to the ESS wave (`synthesizer consults entity invariants when building creating-command input`); the summary names the expected failure; the `keys` unit's tests pin the refusal. F3 — the denial says "malformed" only; a well-formed proof resolving to no record is `active: false`. F4 — the denial refuses key reference or key material already recorded. F5 — "or organization binding is invalid". F6 — all three signing-key commands require platform authority. F7 — the summary says the subject is the display name until a connection admits a display-name claim (`story:federation-linking`). F8 — routed to the ESS wave beside `story:invariant-boundary-validation`; note only.
