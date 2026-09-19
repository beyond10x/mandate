---
format: aep.planning-md/1
id: review-result:wave-d-authored-denials-adversary-1
kind: review-result
status: active
title: Adversary pass — authored denial scenarios
relations:
- reviews: story:authored-denial-scenarios
revision: 1
---
```
unit: story:authored-denial-scenarios — 23 files + ess-inputs.yaml on fe03999
verdict: NEEDS-CHANGE (9 blockers, 5 warnings, 2 notes)
cases: 6 read-only probes over the compiled suite and the handlers; 4 red; suite 146 → 169
origin: introduced 13 / pre-existing 1
```

```findings
- file: systems/mandate/scenarios/pkce-reuse.yaml
  line: 26
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the arranged verifier is a literal, not a digest, so presents_in refuses InvalidCredential before the Consumed branch; the file asserts wrong-state and is permanently red'
- file: systems/mandate/scenarios/pkce-stale-session-epoch.yaml
  line: 142
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the presented code is a fixed literal while the real code is returned only in the response, so presents_in refuses InvalidCredential and StaleEpoch is never reached'
- file: systems/mandate/scenarios/introspect-audience-mismatch.yaml
  line: 42
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'no credential is issued in the timeline, so the caller proof resolves to nothing and CallerProofInvalid fires before AudienceMismatch'
- file: systems/mandate/scenarios/federation-configured-method-on-explicit-link.yaml
  line: 52
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'principal_id names a Principal nothing creates, so PrincipalMismatch fires before LinkingAuthority'
- file: systems/mandate/scenarios/authz-cross-tenant-resource.yaml
  line: 5
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'arrange is empty and no CreateOrganization runs, so Tenancy::admits is false and InvalidCredential fires before any placement is read'
- file: systems/mandate/scenarios/authz-missing-approval.yaml
  line: 5
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'same empty tenancy: InvalidCredential fires before ApprovalRequired can be decided'
- file: systems/mandate/scenarios/identity-stale-epoch-refresh.yaml
  line: 37
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'RefreshSession declares only refresh_proof and no port resolves a proof to a session, so StaleEpoch is unreachable from a file'
- file: systems/mandate/scenarios/federation-audience-mismatch.yaml
  line: 42
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the proof carries literal signature bytes, an unpublished kid and an exp equal to the step instant, so the real verifier refuses ProofInvalid and AudienceMismatch is unreachable'
- file: systems/mandate/scenarios/federation-ambiguous-tenant.yaml
  line: 72
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'same unsigned and expired proof, so TenantAmbiguous is never reached'
- file: systems/mandate/scenarios/federation-issuer-mismatch.yaml
  line: 42
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'green only by coincidence: ProofInvalid and IssuerMismatch share InvalidCredential, so deleting the issuer guard leaves this and the two subject scenarios passing'
- file: systems/mandate/scenarios/pkce-wrong.yaml
  line: 125
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'CodeProofMismatch fires before the verifier comparison and both are InvalidCredential, so the pkce_verifier this file exists to test is never compared; pkce-code-expired likewise'
- file: systems/mandate/scenarios/pkce-stale-session-epoch.yaml
  line: 4
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'three summaries cite a source range that does not produce the asserted reason'
- file: systems/mandate/scenarios/federation-audience-mismatch.yaml
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: '14 of 23 summaries cite a corpus row the scenario does not drive, four cite rows whose expected is an acceptance, four rows are claimed twice'
- file: .engineering/planning/story/authored-denial-scenarios.md
  line: 46
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the two gate commands disagree on the same tree: --suite-format 5 exits 1 on the 52 pre-existing refusals while --target ir --compact exits 0'
- file: systems/mandate/scenarios/sts-disabled-registration-caller.yaml
  line: 56
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'step-for-step identical to the synthesized state/Disabled/refuses scenario plus the reason field; credential-revoked-twice and pkce-reuse likewise'
- file: systems/mandate/scenarios/pkce-reuse.yaml
  line: 8
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'an arrange instance no step references is silently dropped by the compiler; three further files carry one'
```

Held: `no_events` semantics; `at` monotonic; `ess-inputs.yaml` complete; input totality; every `capture` field exists; the `Bytes` padding and PKCE forms; both negative controls refuse; the dead guard measured — changing all 23 expected reasons compiles with 0 refusals, so neither gate sees a wrong reason.

Rulings (coordinator, correction round 1): the STS possession-first files seed the `AuthorizationCode` (and `AccessCredential` for introspection) through `setup:` with the real domain-separated digest of the presented material, computed offline from `verifier.rs`'s tag; the authz files seed tenancy through real accepted commands; the link file seeds the `ExternalPrincipal`; the claim-driven federation files keep the decode-only `ConstructedVerifier` as a recorded standing double (not an injected fault) with live `exp`; `identity-stale-epoch-refresh` dropped (no port resolves a proof to a session; routed to `story:session-epochs`); citations and corpus tags corrected; dangling instances removed; the authoritative gate is format 5 compared on counts.
