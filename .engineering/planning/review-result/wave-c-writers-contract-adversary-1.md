---
format: aep.planning-md/1
id: review-result:wave-c-writers-contract-adversary-1
kind: review-result
status: active
title: Adversary pass — declared-writers contract round 2
relations:
- reviews: story:declared-writers
revision: 1
---
```
unit: story:declared-writers contract round 2 — impl/writers-contract-2 on 975788e (credential.yaml +26/−1)
verdict: NEEDS-CHANGE (2 blockers, 3 warnings, 3 notes)
cases: 19 probe cases over the compiled IR, the synthesized suite and the consumer documents; 11 red; origin introduced 5 / pre-existing 3
```

```findings
- file: systems/mandate/domains/credential.yaml
  line: 235
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the redemption is the only one of the four creators of AccessCredential that sources epochs as generated rather than from a response field, so the epoch binding the denial''s staleness rule turns on is the one record field the synthesized suite compares against nothing and the testkit checks for presence alone'
- file: systems/mandate/domains/credential.yaml
  line: 245
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the accepted summary states that the generated context is read from the code record and the session it names, but two of VerifiedContext''s five required fields — credential and correlation — are carried by none of those records'
- file: docs/architecture/federated-login.md
  line: 52
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the login road''s design still states the redemption''s answer as credential, descriptor after this diff widened the response to also carry credential_id and target'
- file: systems/mandate/domains/credential.yaml
  line: 233
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'an Optional payload target sourced generated is admitted absent by the ESS suite''s expect_event shape and required present by mandate-testkit''s generated arm; this round takes the class from three instances to five'
- file: systems/mandate/domains/credential.yaml
  line: 8
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the header says a fold materializes the credential from that event alone, but the fold it names reads the ResourceServer record for the issuing profile and refuses UnknownIssuingTarget when the target is not already registered'
- file: systems/mandate/domains/credential.yaml
  line: 8
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the declaration is invisible to the compiled IR, which knows three creators of AccessCredential and not this fourth, so nothing obliges the credential_id on the event to be fresh; the id comes from the allocator, reached by nobody'
- file: systems/mandate/domains/credential.yaml
  line: 250
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the denial names a stale source/session epoch, two epochs, while the new summary accounts for one, and a redemption has no source credential for the other half to name'
- file: systems/mandate/domains/credential.yaml
  line: 241
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'nothing ties the response''s target to the target on the code the outcome consumes while the summary asserts the binding, and ESS 0.26.0 has no payload source that reads the subject record'
```

Held: the event carries every declared `AccessCredential` field; `requested_scope` is on `descriptor.scope`; no event carries a `CredentialSecret`; `reference_verifier` sourced identically on all four creators; one outcome declares the event; every field has a source; no counted pin moves (74/36/61/26); the obligations row verbatim; a target disabled between issuance and redemption is already a declared denial; synthesize 146/52 unchanged with identical ids.

Rulings (coordinator, correction round 1): F1 — the response carries `epochs` and the event sources it from the response; F2 — the summary names a source for every required context field (`credential` = the issued credential's id, `correlation` minted, the rest from the code record and its session) and says the stale epoch is the session's (F7); F5 — the header says the fold reads the event and the issuing registration the log already holds; F3 — the coordinator aligns `federated-login.md:52` at regeneration; F4 — pre-existing, already routed; F6, F8 — recorded.
