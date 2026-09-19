---
format: aep.planning-md/1
id: review-result:wave-b-credential-profiles-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — credential-profiles
relations:
- reviews: story:credential-profiles
revision: 1
---
```
unit: story:credential-profiles — impl/credential-profiles on a2624e0 (six units, 19 files)
verdict: CONFIRMED (2 blockers, 2 warnings, 2 notes)
cases: 6 (3 token, 3 sts); 4 red, 2 held; suite 187 → 193 executed
origin: introduced 6
```

```findings
- file: services/sts/src/resolve.rs
  line: 269
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'a revoked ImmediateOnline credential answers active from a cached resolution once its audience is disabled and re-registered under BoundedOffline, because introspect_credential reads the revocation guarantee from the caller''s current registration and never from the registration the presented credential was issued under'
- file: crates/mandate-token/src/projection.rs
  line: 739
  category: mutant
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'move_key writes the state it is handed without reading the record''s own, so a SigningKeyRetired redelivered or ordered after a SigningKeyRevoked rebuilds a key the log revoked as Retired, which the contract still admits for verification and which the composition''s RealSigner::new_with_revocations rehydration then drops from the revocation list'
- file: services/sts/src/resolve.rs
  line: 206
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'resolve.rs:26 says a BoundedOffline cached answer is bounded by the profile''s positive_cache_ttl, but the field is read only by registry::admits_profile and by nothing that decides anything, so a registration publishing PT0S still has an arbitrarily old cached positive answer authorize a revoked credential'
- file: services/sts/src/issue.rs
  line: 107
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'no test in the workspace instantiates IssuanceSigner for RealSigner, and services/sts dev-dependencies carry no key-generation crate so none under services/sts/tests can, leaving every issue case on StaticSigner, which writes none of iss sub aud exp nbf iat jti'
- file: services/sts/src/registry.rs
  line: 221
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the doc sentence claims an outstanding credential for a disabled target is refused at introspection where the registration is read again, but the registration read again is the caller''s and the presented credential''s issuing registration is never re-read'
- file: services/sts/src/issue.rs
  line: 69
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'Sha256Digest is a bare SHA-256 with no domain separation, so reference secrets, self-contained tokens and the authorization-code verifiers story:oauth-integration will add share one value space; no reachable confusion because the record sets are disjoint'
```

Held: the acceptance as written (the caching double correctly wired, the read-cache-first mutant would flip it, the positive control keeps the counter live); tenant and audience isolation on introspection; the raw secret reaches no event or record (compiler-enforced `PersistedValue`, redaction on `Debug` and `Serialize`); constant-time comparison; window ordering as instants; reference and thumbprint duplicate refusal in every state; registry 25 ∪ 9 = 34 elements both directions; emitted events against `generated/schema` and `generated/ir`; round trips populated and bare with no `null`; redelivery on the other two records; `fold(&[])` rebuilds field for field.

Rulings (coordinator, correction round 1): F1+F6 — the projection keeps the issuing target and profile; the guarantee is the issuing registration's; a disabled issuing target answers inactive. F2 — `move_key` honours the declared `from:` sets. F3 — the resolution port carries the entry's instant; the bound is enforced; `PT0S` never answers from the cache. F4 — `aws-lc-rs` and `rand` admitted as `mandate-sts` dev-dependencies by the coordinator in the unit tree (deviation 1 on the wave page); one end-to-end case with a run-time generated `RealSigner`. F5 — domain-separated digests.
