---
format: aep.planning-md/1
id: review-result:wave-a-verifier-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — federation-verifier
relations:
- reviews: story:signing-and-verification
revision: 1
---
```
unit: federation-verifier (story:signing-and-verification) — crates/mandate-federation/src/verifier_real.rs + tests, uncommitted on impl/verifier at base b1d6297, after correction round 1
verdict: needs-change
cases: executed 215 → 228, red 6 (adversary file tests/adversary_verifier_2.rs, 13 cases: 7 held, 6 confirmed); pass-1 file 26/26 green
findings: 8 — 1 warning, 7 notes; pass-1 findings held (A1-3, A1-4, A1-6 held for their instance with edge gaps)
```

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 908
  category: concurrency
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the negative cache checks missed_at and stores it either side of the port call, so N simultaneous presentations of one unknown kid are N upstream reads, against the doc and the round-1 ruling of at most once per issuer per refetch interval.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 310
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'admits compares whole authorities with no scheme-based default-port normalization, so a discovery document spelling the default port leaves the connection with no key set.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 316
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the listed-host arm pins the host and not the port, so the discovery document chooses any TCP port on a host the deployment listed.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 315
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the loopback guard on a listed host is a string inequality against localhost, which localhost.localdomain and localhost. both defeat.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 1027
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'a non-string azp is not read at all, so the doc claim that an azp naming another party is refused does not hold for it.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 1037
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the untrusted-audience test counts audiences instead of testing membership, so aud naming only this client twice is refused.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 256
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'hardened_config inherits ureq default proxy from ALL_PROXY/HTTPS_PROXY/HTTP_PROXY, so the shipped source destination is environment-dependent in a way allowing_jwks_hosts never named.'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 1042
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'no nonce or jti is read anywhere, so a captured ID token verifies repeatedly until exp; the verify seam cannot carry the relying party nonce, so this is the login flow design, not this unit.'
```

Held: the https panic closed as a class (shipped config driven to a successful read); the companion rule decides only the claim it names; the URI parse survives uppercase, `?`/`#`, `%40`, backslash, IPv6 literals and label confusion; `forget` inside the negative interval refetches; stalled and non-TLS listeners refused inside the timeout; no parser differential with `ureq`; key/algorithm confusion refused before any signature; a 10 MiB body cap from `ureq`. Evidence under the unit's scratch `adversary2/`.
