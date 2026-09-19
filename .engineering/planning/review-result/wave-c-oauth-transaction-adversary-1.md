---
format: aep.planning-md/1
id: review-result:wave-c-oauth-transaction-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — oauth-transaction
relations:
- reviews: story:oauth-transaction
revision: 1
---
```
unit: story:oauth-transaction — impl/oauth-transaction on f951f9d (18 unit files + 4 coordinator patches)
verdict: NEEDS-CHANGE (0 blockers, 3 warnings, 2 notes)
cases: 24 (19 sts, 5 token), all green; suite 556 → 582 executed
origin: introduced 5
```

```findings
- file: services/sts/src/code.rs
  line: 34
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the module doc states the client rule enforced is a registered, enabled public client, but OAuthClientReads asks only for the organization and whether the client is enabled and nothing asks whether the client is public'
- file: services/sts/src/code.rs
  line: 411
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'IssueAuthorizationCode''s declared denial names exact redirect URI and its summary binds the code to a validated exact redirect, but the handler records input.redirect_uri unvalidated and the client port cannot answer the registered redirect set'
- file: services/sts/src/code.rs
  line: 45
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'bounded expiry is bounded below only — a caller may name an expires_at in year 9999 and get a redeemable code — and no ceiling is declared in credential.yaml, the entity invariants, CredentialProfile or any mandate.core type'
- file: crates/mandate-token/src/projection.rs
  line: 596
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'DenialClause gains 17 variants naming sessions, OAuth clients, redirect URIs and PKCE verifiers in a crate that models none of them, and four of the session variants are not phrases of either command''s declared denial'
- file: services/sts/tests/store.rs
  line: 263
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'three mutants on the one-winner guarantee stay green against the unit''s suite — a compare-and-set written expected < actual, a skip_serializing_if dropped from one payload declaration, and StreamVersion narrowed to u64 — each now covered by a case in services/sts/tests/adversary_transaction_1.rs'
```

Held: S256 agrees with an independent digest and encoder for every declared verifier length, the pad-bit rule exact, constant-time comparison; the one-winner race (version read once before deciding, CAS equality both ways, the loser writes nothing); the redirect byte-exact under twelve normalizations; the session re-read fails closed for unknown, revoked, expired, undatable and unresolvable; domain separation between a code and a credential of identical bytes; the credential's subject/organization/epochs from the session, audience and profile from the registration, scope and target from the code, expiry the minimum of profile and code pinned both ways, the context per the summary; introspects active then inactive through the real `resolve`; the registries exhaustive in both crates; both folds rebuild from `&[]`; redelivery insert-if-absent; payload sources and schemas carried and bare.

Rulings (coordinator, correction round 1): F1 — `OAuthClientReads` answers `is_public` and the handler refuses a non-public client; F2 — the port answers `redirect_registered` and the handler refuses an unregistered exact redirect at issuance; F3 — the handler takes the deployment's code-lifetime bound as a constructor argument (the contract declares no ceiling; residue restated); F4 — every `DenialClause` variant is a phrase of a declared denial, the four session variants merged into the two the redemption's denial carries, with a test mapping every constructed clause to its command's denial text; F5 — the adversary's cases stand.
