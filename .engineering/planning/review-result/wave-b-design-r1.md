---
format: aep.planning-md/1
id: review-result:wave-b-design-r1
kind: review-result
status: active
title: Design critic, round 1 — wave B set
relations:
- reviews: story:credential-profiles
- reviews: story:declared-writers
revision: 1
---
```
set: story:credential-profiles, story:declared-writers — wave B, from a76267b; five coordinator decisions judged
verdict: needs-revision
findings: 8
```

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 11
  category: design
  severity: blocker
  verdict: needs-revision
  origin: pre-existing
  message: 'it declares depends_on story:credential-profiles while wave A landed its signer first and the credential-profiles issue unit now consumes CredentialSigner from signing_real.rs, so the only edge between the two names the opposite of the real order and the true one cannot be added without a cycle'
- file: .engineering/planning/story/credential-profiles.md
  line: 143
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its resolve acceptance rests on the corrected IntrospectCredential denial and its projection unit folds the SigningKeyRegistered shape, both produced by the declared-writers contract round this wave, and no depends_on edge records that order while the wave page schedules the two as disjoint and parallel'
- file: .engineering/planning/story/credential-profiles.md
  line: 125
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its registry unit is required to satisfy mandate_federation::authorize::TargetRegistry, which cannot be implemented without a mandate-sts to mandate-federation edge the pre-landed boundary entry does not admit'
- file: .engineering/planning/story/credential-profiles.md
  line: 123
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'no unit row names RegisterSigningKey, RetireSigningKey or RevokeSigningKey, so the SigningKey record its projection unit lands has a declared writer and no caller and RealSigner::new_with_revocations stays unreachable'
- file: .engineering/planning/story/declared-writers.md
  line: 82
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'OAuthClientRegistered carries organization_id beside context, two carriers of one fact in one event, and neither the A2 row nor a denied clause says the accepted outcome refuses an organization_id other than context.organization, which the existing fold takes as the binding'
- file: systems/mandate/domains/credential.yaml
  line: 608
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'C0 corrects the denial text but leaves CredentialIntrospected carrying context and an optional descriptor only, so under the ruling an accepted-inactive answer emits an event naming neither the credential introspected nor the answer given'
- file: .engineering/planning/story/declared-writers.md
  line: 85
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'A3 adds a Principal record to the identity fold without saying whether the Session arm refuses an opening naming a principal no event created, which is the rule that file already applies to the epochs handle'
- file: .engineering/planning/story/declared-writers.md
  line: 109
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'its Exclusions say the story is contract-only and crate realizations belong to the owning stories, while its A4 row lands the RegisterOAuthClient handler in crates/mandate-federation/src/register_client.rs and a realizes! registration, so the same body claims and disclaims that realization'
```

Judged sound: accepted + `active: false` is a correction (the response's `active: Boolean` is otherwise unreachable; the corpus says "inactive"); one signing surface with a stated direction (`ownership.md:15`, `signing_real.rs:770-774`); a declaration is a sound Principal writer (`identity.yaml:8-10` form, `port.rs:304-321` precedent); the `[lib]` target in `services/sts` (boundaries key on the package, `serve` refusal execs the binary). `resolve` can be honest over an in-memory fold if the test owns a caching resolver double and shows it is not consulted; `issue` signs through `CredentialSigner` alone this wave. Recommendation, not a finding: a public client registration should refuse a PKCE method other than S256 (`publicclient.rs:86,106-108` already refuses it at authorization). No cycle among the store's 90 `depends_on` edges.
