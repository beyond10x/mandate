---
format: aep.planning-md/1
id: review-result:wave-b-writers-realization-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — declared-writers realization round
relations:
- reviews: story:declared-writers
revision: 1
---
```
unit: story:declared-writers realization round (A3 principal-fold, A4 oauth-client-fold) — impl/writers-realization on a2624e0
verdict: NEEDS-CHANGE (1 blocker, 3 warnings, 1 note)
cases: 7 (2 identity, 5 federation); 4 red, 3 held; suite 385 → 392 executed
origin: introduced 5
```

```findings
- file: crates/mandate-federation/src/record.rs
  line: 641
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the new OAuthClientRegistered arm answers a redelivered creation with FoldError::OAuthClientExists, making the whole domain log unfoldable, against the insert-if-absent rule mandate-model/src/tenancy.rs:1283 states as universal and record_link keeps 32 lines below it; its stated reason — that two accepted commands could share one client identity — is false, because next_o_auth_client_id mints the identity per record'
- file: crates/mandate-federation/src/publicclient.rs
  line: 11
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the module AuthorizePublicClient reads its client through still states that no declared event creates an OAuthClient, that the port answers None until story:declared-writers lands, and that neither read model has a creating event — three claims this unit''s own creating command and creation arm falsified, in the file the Scope named as a site to rewrite'
- file: crates/mandate-identity/src/port.rs
  line: 478
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'principal_of enforces one of the two literals federation.yaml pins in ExternalPrincipalProvisioned under a doc heading that cites mandate_federation''s fold, which enforces both, so a payload whose link_method is not ConfiguredFederation is unreadable to one fold and seeds a Principal in the other'
- file: crates/mandate-federation/tests/replay.rs
  line: 544
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'a_second_registration_under_one_client_identity_is_unreadable folds one event twice and calls it two registrations, pinning the blocker above as intended behaviour'
- file: crates/mandate-identity/src/lib.rs
  line: 177
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'mandate.identity.Principal.State is now named by two crates'' ESS_REALIZATIONS where the base kept them disjoint on purpose, and no test compares registries across crates'
```

Held: the organization binding (no organization input; cross-tenant resolve refused; two organizations with one redirect set fold cleanly); the three declared denials provoked through the real handler with nothing emitted and the fold unchanged, the id allocated after every guard; distinct ids; `UnknownOAuthClient` for an id no event created; disable wrong-state; register → disable → rebuild equals the live projection; `AuthorizePublicClient` reads `public`, `redirect_uris`, `pkce_method` and state from the real fold (exact redirect match; non-public, disabled and never-registered refused); A3's `display_name` and `kind` from the event; a second provisioning of one `principal_id` refused; ruling 5 pinned both ways; `Principal` round-trips the generated entity; the registries exhaustive; `PrincipalState::Disabled` unreachable and stated.

Rulings (coordinator, correction round 1): F1+F4 — insert-if-absent, `OAuthClientExists` deleted, the unit's case rewritten to the property; F2 — the unit applies its own doc patch to `publicclient.rs`; F3 — both pinned literals enforced by `principal_of`; F5 — one realizer per element: identity realizes `Principal.State`, federation's enum is the port's view.
