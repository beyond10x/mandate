---
format: aep.planning-md/1
id: review-result:wave-c-oauth-transaction-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — oauth-transaction
relations:
- reviews: story:oauth-transaction
revision: 1
---
```
unit: story:oauth-transaction after correction 1 — impl/oauth-transaction on f951f9d
verdict: NEEDS-CHANGE (0 blockers, 3 warnings, 3 notes)
cases: 2 new (sts), both red; pass 1's 24 re-run green; suite 591 → 593 executed
origin: introduced 5 / pre-existing-in-kind 1
```

```findings
- file: services/sts/tests/declared_denials.rs
  line: 186
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the ROWS table claims to carry every (command, clause) pair this crate constructs and carries no row for (IntrospectCredential, OrganizationMismatch), which resolve.rs:498 constructs on an ordinary two-organization deployment'
- file: services/sts/src/redemption.rs
  line: 321
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the PKCE verifier is decided after the session, client and target re-reads, so a caller holding an intercepted code but not the verifier reads session liveness, epoch staleness, client enablement and tenant agreement off the one declared wire field DenialReason'
- file: services/sts/tests/declared_denials.rs
  line: 426
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'SessionUnusable is rowed to narrowing/atomic issuance validation fails while binding.rs:253 says these conditions go under the nearest phrase the denial carries, source/session epoch is stale — the substring check passes and the two documents disagree'
- file: services/sts/src/code.rs
  line: 425
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'admitted_client maps an is_enabled reader that cannot answer to Denied/ClientDisabled while is_public and redirect_registered map the same state to Unavailable; no OAuthClientReads implementation in this tree reaches it'
- file: services/sts/src/code.rs
  line: 670
  category: acceptance
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'AuthorizationCodeIssued.scope is declared generated and the accepted summary says narrowed scope, the handler emits input.requested_scope verbatim, and narrowing needs mandate-authz which is outside this crate''s dependency ceiling'
- file: services/sts/src/redemption.rs
  line: 274
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'CodeUnknown carries DenialReason::Denied and CodeProofMismatch carries InvalidCredential, so the single declared wire field tells a caller whether a code_id exists, which the module doc says it cannot'
```

Held: the ceiling inclusive at the bound and refused past it, at the floor, for `PT0S`, a calendar designator and unparseable text; the ceiling independent of the profile's `max_ttl`; issuance-time only; the new port answers (`None` → `Unavailable`, minting nothing; public-but-disabled, confidential, another client's redirect); the both-direction claim for the two code commands; every row's phrase a real substring; the merged session clauses distinguishable on the wire and pinned; redemption after a client is disabled refused, after made confidential admitted (the denial names the disabled client only); the exact redirect compared to the code's per `pkce-redirect`; the instant and base64url readers; the record field for field; the CAS both ways with the loser writing nothing.

Rulings (coordinator, correction round 2): F1 — the row added with its contract observation and the both-direction check extended to every drivable command; F2 — `None` from `is_enabled` is `Unavailable`; F3 — possession (code proof and PKCE verifier) decided before the session, client and target re-reads; F4 — `SessionUnusable` rows to the epoch phrase with the observation that the denial declares no session phrase (routed to the contract); F6 — `CodeUnknown` carries `InvalidCredential`; F5 — residue: scope narrowing is `mandate-authz`'s, outside the STS ceiling.
