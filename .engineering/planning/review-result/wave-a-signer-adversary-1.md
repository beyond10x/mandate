---
format: aep.planning-md/1
id: review-result:wave-a-signer-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — token-signer
relations:
- reviews: story:signing-and-verification
revision: 1
---
```
unit: token-signer (story:signing-and-verification) — crates/mandate-token/src/signing_real.rs, tests/signing_real.rs, uncommitted on impl/signer at base b1d6297
verdict: needs-change
cases: executed 29 → 44, red 6 (adversary file tests/adversary_signing_1.rs, 15 cases: 9 held, 6 confirmed)
findings: 9 — 3 blockers, 2 warnings, 4 notes
```

```findings
- file: crates/mandate-token/src/signing_real.rs
  line: 443
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'serde flatten writes the caller claims after the signer claims into one JSON object, so a caller claim named exp, nbf, iat, iss, sub, aud or jti is a duplicate key that wins under every last-wins reader and sets its own expiry, audience and subject.'
- file: crates/mandate-token/src/signing_real.rs
  line: 631
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the duplicate claim keys make the emitted token undecodable by jsonwebtoken itself (duplicate field exp), so sign produces credentials the verifier unit own library refuses.'
- file: crates/mandate-token/src/signing_real.rs
  line: 573
  category: boundary
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'no revocation tombstone exists, so rotate accepts the exact key material revoke dropped and the signer signs under the revoked kid again.'
- file: crates/mandate-token/src/signing_real.rs
  line: 525
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'RealSigner::new accepts overlap_seconds shorter than ttl_seconds unchecked, so a rotated-out key leaves the published set while the credentials it signed are still unexpired.'
- file: crates/mandate-token/src/signing_real.rs
  line: 432
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the envelope doc states a value that does not serialize as a map is refused, but a unit value and None are signed.'
- file: crates/mandate-token/src/signing_real.rs
  line: 262
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'DER carrying bytes after the key structure is accepted for both families because the remainder der_take returns is discarded.'
- file: crates/mandate-token/tests/signing_real.rs
  line: 131
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'ProfileClaims is the only claims type the 17 cases sign and it collides with no standard claim, so no existing case can observe the claims-envelope defect.'
- file: crates/mandate-token/tests/signing_real.rs
  line: 202
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the suite asserts only a published JWK kid, never its use, alg, kty or crv nor the absence of private parameters.'
- file: crates/mandate-token/src/signing_real.rs
  line: 285
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'der_inside_pem ignores the PEM label and stops at the first END line, so a wrongly labelled key loads silently and a concatenated two-key file loads only the first.'
```

Held: header integrity (`kid`, `alg`, `typ` from the active key only); allowlist closed under 31 look-alike names at every entry; published JWKs carry public parameters only with `use`/`alg`/`crv` correct; eleven Debug renderings leak nothing against sixteen probes; malformed key material refused without a panic; `exp` exact with zero leeway; an HS256 forgery over the published modulus refused. Suite: the three named mutants are killed; the blind spots are the two weak-oracle rows. Evidence under the unit's scratch `adversary1/`.
