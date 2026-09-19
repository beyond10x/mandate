---
format: aep.planning-md/1
id: review-result:wave-a-verifier-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — federation-verifier
relations:
- reviews: story:signing-and-verification
revision: 1
---
```
unit: federation-verifier (story:signing-and-verification) — crates/mandate-federation/src/verifier_real.rs, tests/verifier_real.rs, uncommitted on impl/verifier at base b1d6297
verdict: needs-change
cases: executed 181 → 207, red 10 (adversary file tests/adversary_verifier_1.rs, 26 cases: 16 held, 10 confirmed)
findings: 11 — 3 blockers, 4 warnings, 4 notes
```

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 196
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'UreqJwks panics with "uri scheme is https, provider is Rustls but feature is not enabled" on any https issuer, so the shipped JWKS source cannot fetch from a real IdP at all.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 856
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'a claim with no <claim>_verified companion counts as verified, so an email the issuer never asserted verified resolves a tenant and issues a session, which is the tenant-unverified contract case inverted.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 267
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the jwks_uri guard bounds no destination: any absolute https URI is admitted, and userinfo before the @ satisfies the issuer-prefix arm, so a discovery document makes the verifier fetch from a host of its choosing.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 655
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'an unknown kid costs one upstream key-set read per unauthenticated presentation, the refresh storm the cited design forbids and the opposite of the doc comment at :630.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 633
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the key-cache mutex is held across the JwksSource call, so one slow issuer stalls verification for every issuer (1.445 s measured).'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 734
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'a token whose aud also names an untrusted relying party is admitted with no azp, against OIDC Core 3.1.3.7 step 3.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 894
  category: correctness
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the crit header parameter is never read, so a JWS naming a critical extension nothing understands is admitted, against RFC 7515 4.1.11.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 756
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'sub has no upper bound, so a one-megabyte subject verifies and becomes a composite-key component and a generated display name on a persisted event.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 559
  category: judgement
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'no key-cache invalidation exists, so emergency revocation can only be waited out for up to key_max_age; the API lacks a forget(issuer) or a cache generation the operator can bump.'
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 1552
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'both ureq cases build their own agent through UreqJwks::over, so the shipped UreqJwks::new configuration is never exercised and deleting max_redirects(0) leaves the suite green.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 700
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'typ at+jwt is refused, so an RFC 9068 access token presented as the proof fails every login closed; no documented flow presents one, recorded rather than raised.'
```

Held: algorithm confusion in every form refused (HS256 over the public key under RS256/ES256/HS256/none headers, lowercase alg, absent alg); `jku`/`x5u`/`x5c`/embedded `jwk` refused and never fetched; a JWK carrying `alg: HS256` refused; cross-issuer `kid` isolation; duplicate `kid` deterministic and fail-closed; claims boundaries (`exp == now` refused, `nbf == now` admitted, leeway 0; malformed `exp`/`aud`/`iss`/`sub` forms refused); the shipped source follows no redirect; malformed bodies refuse the proof; 13 malformed inputs no panic. Evidence under the unit's scratch `adversary1/`.
