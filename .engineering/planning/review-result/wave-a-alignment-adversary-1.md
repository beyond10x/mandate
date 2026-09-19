---
format: aep.planning-md/1
id: review-result:wave-a-alignment-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — federation-identity-alignment
relations:
- reviews: story:federation-identity-alignment
revision: 1
---
```
unit: story:federation-identity-alignment — crates/mandate-federation and crates/mandate-identity, uncommitted on impl/alignment at base b1d6297
verdict: needs-change
cases: executed 268 → 274, red 6 (adversary files: federation tests/adversary_alignment_1.rs 2 cases, identity tests/adversary_alignment_1.rs 4 cases, all confirmed)
findings: 6 — 1 blocker, 3 warnings, 1 warning (mutant), 1 note
```

```findings
- file: crates/mandate-federation/src/authorize.rs
  line: 293
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the consumed-code refusal returns RefusedOutcome::WrongState whose ir_name() is wrong-state, and mandate.federation.AuthorizePublicClient, the element the crate registry pairs with this handler, declares only accepted and denied; the wrong-state outcome is RedeemAuthorizationCode (credential domain), a different command.'
- file: crates/mandate-federation/src/record.rs
  line: 466
  category: concurrency
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'an ExternalPrincipalUnlinked naming a link the fold displaced into conflicts aborts Projection::fold with UnknownExternalPrincipal, so a log every handler accepted against the state it read leaves no federation read model at all.'
- file: crates/mandate-identity/src/port.rs
  line: 422
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'try_record decides the lexical form of every identifier on a FederationAuthenticated payload but not of expires_at, so the log appends a payload the closed schema refuses and materializes a Session the entity schema refuses.'
- file: crates/mandate-identity/src/port.rs
  line: 517
  category: property
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the snapshot generations are derived from the log position of EpochSnapshotRecorded rather than carried by it, so a recording landing after an increment binds the post-increment generation and refresh_session certifies a session that increment should have staled; reachable by log only, no adapter writes these events yet.'
- file: crates/mandate-identity/src/port.rs
  line: 260
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'IdentityEvent::ess_name has no oracle in this crate because emitted_events.rs passes a literal element name and contract_agreement.rs matches on the variant, and the three declared context-id identity payloads are indistinguishable by schema.'
- file: crates/mandate-identity/src/lib.rs
  line: 152
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the registry documentation names four declared elements as the ones this crate does not realize while the contract declares 15, including DisablePrincipal, RevokeRefreshCredential and the three SecurityEpoch entities the replay case claims to rebuild.'
```

Held: `FederationEvent::ess_name` pinned twice; the three `disable.rs` handlers and `revoke_session` return wrong-state only from the terminal state on commands that declare it; every other refusal site returns `Denied` on commands without wrong-state; no denial mutates; second open refused in both orders; `IdentityLog` replay is a fixed point; the compare-and-set and the maximum-generation denial hold; no `null` at any depth; malformed identifiers on a login payload refused; federation's coverage claim exact. Evidence under the unit's scratch `adversary1/`.
