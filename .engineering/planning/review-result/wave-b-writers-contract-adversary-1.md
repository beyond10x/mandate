---
format: aep.planning-md/1
id: review-result:wave-b-writers-contract-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — declared-writers contract round
relations:
- reviews: story:declared-writers
revision: 1
---
```
unit: story:declared-writers contract round (A1, A2, C0, C1) — impl/writers-contract on 162f22c
verdict: NEEDS-CHANGE (2 blockers, 7 warnings, 4 notes)
cases: 10 probe cases over the compiled IR and synthesize; 9 red at the time of the pass
origin: introduced 9 / pre-existing 4
```

```findings
- file: systems/mandate/domains/federation.yaml
  line: 395
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the synthesized conformance scenario RegisterOAuthClient/outcome/accepted registers a client with redirect_uris: [] and asserts accepted, which is exactly the input the same unit''s denial clause and command-obligations.md:43 publish as required denial behaviour'
- file: systems/mandate/domains/credential.yaml
  line: 510
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the synthesized conformance scenario RegisterSigningKey/outcome/accepted registers a key with not_before equal to expires_at and asserts accepted, which is exactly the input the same unit''s denial clause and command-obligations.md:18 publish as required denial behaviour'
- file: systems/mandate/domains/credential.yaml
  line: 481
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'RegisterSigningKey names no collision on key_reference and the entity declares no invariant, so the contract admits a second Recorded SigningKey over material an earlier record already moved to Revoked'
- file: systems/mandate/domains/credential.yaml
  line: 421
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'replacing ''presented verifier is invalid/revoked/expired'' with ''malformed or unresolvable'' leaves IntrospectCredential the only command taking a CredentialProof whose declared denial names no invalid, revoked, expired or stale proof, so nothing requires refusing a caller whose own credential was revoked'
- file: docs/architecture/command-obligations.md
  line: 43
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the row publishes ''a public client names a PKCE method other than S256'' as required denial behaviour while mandate.core.PkceMethod declares exactly one variant, so no caller can provoke the refusal'
- file: systems/mandate/domains/identity.yaml
  line: 9
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the A1 declaration closes mandate.identity.Principal''s writer in prose only: synthesize still answers ''no outcome creates one'' for that entity three times, unchanged from base, while OAuthClient and SigningKey cleared ten between them'
- file: systems/mandate/domains/credential.yaml
  line: 690
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'SigningKeyRegistered and the SigningKey record carry no kid and no thumbprint, so RealSigner::new_with_revocations cannot rebuild RevokedKey from the record without re-resolving the material of a key revoked as compromised'
- file: systems/mandate/domains/credential.yaml
  line: 656
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'credential_id on CredentialIntrospected makes it the only event carrying a bare CredentialId whose emitting outcome declares no subject, and a fold that refuses an instance no event created has no rule for an introspection of a credential this log never issued'
- file: systems/mandate/domains/credential.yaml
  line: 77
  category: property
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'not_before < expires_at validates and compiles as an ESS entity invariant (proved on a scratch copy), so the unit stated as an unchecked denial sentence a condition the contract can carry as a checked predicate'
- file: systems/mandate/domains/federation.yaml
  line: 293
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the only payload writing Principal.kind binds the literal User, so Agent, Service and ServiceAccount have no writer at all, and A1''s ''the whole Principal record'' does not say that three of the four declared kinds can never be seeded'
- file: systems/mandate/domains/federation.yaml
  line: 294
  category: property
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'Principal.display_name is bound generated: true on the event A1 declares as the Principal''s seeding event, and the command''s response does not carry it, so the record''s display name is invented by the implementation'
- file: systems/mandate/domains/credential.yaml
  line: 424
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'no summary and no authored prose anywhere constrains active against credential_id and descriptor, so an answer with active: true, credential_id: None and descriptor: None conforms and an audit reader cannot tell it from a denial'
- file: systems/mandate/domains/credential.yaml
  line: 483
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'RegisterSigningKey takes a tenant-scoped VerifiedContext and creates a record with no organization field while naming neither tenancy nor platform authority in its denial'
```

Held: obligations wiring verbatim and alphabetical; `components.yaml` owners correct; both creating events carry every record field plus the minted id; `organization_id` from the response could not be broken; corpus 50 traced; no new synthesize refusal code; `Recorded` as the initial state (liveness is the signer's clock). Refusals base 59 → head 49: seven `SigningKey`, three `OAuthClient` cleared; the three `mandate.identity.Principal` refusals remain.

Rulings (coordinator, correction round 1): F1+F5 — the denial drops the empty-set and PKCE clauses (neither expressible: no list-length predicate; one `PkceMethod` variant), the summary states an empty set is inert; F2+F9 — `not_before < expires_at` becomes a `SigningKey` invariant; F3+F13 — "platform signing-key administration authority … key reference unresolvable or already recorded"; F7 — record, event and response gain `thumbprint: String`, `SigningKeyId` is the kid; F4 — the caller's own proof validity returns to the denial; F8+F12 — the accepted outcome's summary fixes active/credential_id/descriptor and states the event folds into nothing; F11 — `ProvisionExternalPrincipal` responds `display_name`, the payload sources it; F6+F10 — P1 kept, the header names the User-only seeding and the three remaining refusals as residue until `RegisterPrincipal` (later wave).
