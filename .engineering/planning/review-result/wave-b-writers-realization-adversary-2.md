---
format: aep.planning-md/1
id: review-result:wave-b-writers-realization-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — declared-writers realization round
relations:
- reviews: story:declared-writers
revision: 1
---
```
unit: story:declared-writers realization round after correction 1 — impl/writers-realization on a2624e0
verdict: NEEDS-CHANGE (2 warnings, 2 notes)
cases: 9 (4 identity, 5 federation); 3 red, 6 held; suite 391 → 400 executed
origin: introduced 3 / pre-existing 1
```

```findings
- file: crates/mandate-identity/src/port.rs
  line: 482
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'principal_of calls itself the same seam as session_of and says it decides the lexical form of every declared identifier, but parses principal_id alone of the payload''s ten fields, so try_record appends a provisioning whose organization_id, connection_id, external_principal_id or linked_at the generated closed schema refuses'
- file: crates/mandate-identity/src/port.rs
  line: 674
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'an ExternalPrincipalProvisioned carrying an empty or untrimmed subject makes the whole mandate.federation log unreadable (FoldError::EmptySubject) and is appended by the identity log, which materializes a mandate.identity.Principal from it — pass 1''s F3 class at the field correction 1 did not reach'
- file: crates/mandate-federation/tests/emitted_events.rs
  line: 618
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'no case in either crate registers a client with public: false, so a handler writing the literal true into OAuthClientRegistered instead of input.public is green against everything the unit shipped'
- file: crates/mandate-federation/src/lib.rs
  line: 52
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'mandate-federation carries no ESS_UNREALIZED and no exhaustiveness case, so correction 1''s move of mandate.identity.Principal.State out of its registry rests on a one-realizer-per-element claim that no case in the crate makes'
```

Held: insert-if-absent with a differing payload (first wins field for field); no path registers a client into an organization the context does not carry; the allocator untouched by every refusal; `public: false`, duplicate and empty redirect sets, an unconstructible non-S256 method, a trailing slash at authorization all as documented; the doc rewrite complete; both records out of the residue pins; identity's registry exhaustive with every realized symbol a `use`; `PrincipalDisabled` unappendable and stated; ruling 5 in both orders.

Rulings (coordinator, correction round 2): F1+F2 — `principal_of` decides every declared field as `session_of` does and fails closed; F3 — the `public: false` case joins `emitted_events.rs`; F4 — federation gains `ESS_UNREALIZED` and the exhaustiveness case.
