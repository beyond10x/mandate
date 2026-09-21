---
format: aep.planning-md/1
id: review-result:wave-d-conformance-target-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — conformance target
relations:
- reviews: story:conformance-target
revision: 1
---
```
unit: story:conformance-target — impl/conformance-target on fe03999, after correction 1
verdict: NEEDS-CHANGE (1 blocker, 4 warnings, 1 note)
cases: 35 → 39 executed, 4 red when written
origin: introduced 6 / pre-existing 0
```

```findings
- file: crates/mandate-conformance/src/external.rs
  line: 545
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'four of Substituted''s port methods (ConnectionStore::enabled_for_issuer, IdentityRead::resolve, SigningKeyReads::signing_keys, KeyMaterialResolver::thumbprint) answer without calling self.read(), so a command consulting only them is written armed-unreached with consulted 0'
- file: crates/mandate-conformance/src/external.rs
  line: 780
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'Substituted''s thumbprint answers None where the standing ScenarioKeys answers Some for every reference, so the rule that a substituted absence is what the standing fold answers when empty does not hold at RegisterSigningKey''s port'
- file: crates/mandate-conformance/src/external.rs
  line: 590
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'Substituted does not override IdentityRead::as_of and answers None where the standing log answers Some(FIXED_INSTANT), so refresh_session fails closed with a clause the standing reader never reaches'
- file: crates/mandate-conformance/src/external.rs
  line: 750
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the doc says Substituted::check''s CouldNotAnswer is what an empty GraphDouble answers; an empty GraphDouble refuses at admits with Denied(Denied)'
- file: crates/mandate-conformance/src/external.rs
  line: 171
  category: property
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'Ledger::consulted derives armed-standing from refused == 0 alone, so "the arming could not change the scenario" is an inference, not a measurement'
- file: crates/mandate-conformance/src/lib.rs
  line: 98
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the 22 standing_doubles omit AllowedAlgorithms(["ES256"]) and CodeLifetime("PT10M"), both stated as a deployment''s, while CredentialDigest is listed under the same criterion'
```

Held: `node::to_json` at 2^63, 1e20, -0.0 and 1.0 into an integer; the frontmatter parser against a body `status:`; `identity_unchanged` (two fields, derived `PartialEq`); `Check` armed refuses on the empty tenancy fold before any port (consulted 0 is the measurement); the twelve `armed-standing` rows each match their standing counterpart today; `diff -r` byte-identical; report/2 29 / 54 / 0 / 63 / 0.

Rulings (correction round 2, the last): F1 — every port method of `Substituted` counts through `self.read()`. F2 — the substituted resolver keeps answering absence (that is the arming: `KeyReferenceUnresolvable`), the doc sentence at `:46` says "what an *empty* real store answers" and names `ScenarioKeys` as a standing double that is not empty. F3 — `as_of` is overridden with the run's fixed instant (a property of the run, not a record). F4 — the doc sentence is corrected: an empty `GraphDouble` refuses with `Denied`; the substituted reader answers `Unavailable` as an absence, and the difference is stated. F5 — the label is renamed to what is measured: `armed-unrefused` ("consulted n times, refused nothing"); no claim that the arming could not change the scenario. F6 — the two rows join `STANDING`.
