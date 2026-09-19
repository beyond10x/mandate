---
format: aep.planning-md/1
id: review-result:wave-b-credential-profiles-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — credential-profiles
relations:
- reviews: story:credential-profiles
revision: 1
---
```
unit: story:credential-profiles after correction 1 — impl/credential-profiles on a2624e0
verdict: CONFIRMED (1 blocker, 3 warnings, 2 notes)
cases: 5 (2 token, 3 sts); 3 red, 2 held; suite 203 → 208 executed
origin: introduced 6
```

```findings
- file: services/sts/src/resolve.rs
  line: 392
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'a credential whose issuing registration was disabled is refused nothing as the caller proof — introspect_credential decides the caller by live() and by whichever registration holds the audience now — so after an ordinary disable-and-re-register it reads the successor registration''s full descriptor and credential_id while the same handler answers active:false for it'
- file: services/sts/src/issue.rs
  line: 258
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'admitted_target never asks whether the target holds its audience and resolve::usable does, so an issuance against an enabled registration that audience_conflicts names is accepted and mints a secret whose credential introspects inactive at the same instant'
- file: crates/mandate-token/src/projection.rs
  line: 751
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'Projection::fold is all-or-nothing, so one SigningKeyRegistered duplicating a key_reference or thumbprint — the same racing pair the audience index is tolerant of — makes every ResourceServer and AccessCredential in the log unreadable'
- file: services/sts/src/registry.rs
  line: 149
  category: judgement
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'admits_profile couples revocation and requires_online_authorization in one direction only, and nothing downstream reads the field, so a registration publishing requires_online_authorization:true under BoundedOffline has a revoked credential authorized from a cached positive answer'
- file: services/sts/src/resolve.rs
  line: 285
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'no fixture dates a cached answer at exactly positive_cache_ttl or at the request instant, so both comparisons in inside_cache_bound survive mutation'
- file: services/sts/src/keys.rs
  line: 226
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'publishing is documented as whether a key is published for continued verification but excludes Retired, which credential.yaml says remains admitted for verifying credentials already issued under it'
```

Held: the acceptance and correction 1's guarantee gates in every cell; `cached_at` default refusal, `PT0S`, future-dated answers; the `#[serde(skip)]` residue cannot be dropped by a wire round trip (`Serialize` only, no `Default`) and `fold(&[])` rebuilds it; domain tags closed, zero-free, prefix-free, the code-verifier tag never a credential domain; the run-time `RealSigner` case covers `aud exp nbf iat jti kid` and the profile bound; retire/revoke ordering through handlers and fold; emitted events decided response-to-event against the IR.

Rulings (coordinator, correction round 2): F-1 — the caller's proof gets `usable()`; F-2 — `admitted_target` requires the target to hold its audience; F-3 — key uniqueness becomes a projection view, first holder wins, conflicting keys never published; F-4 — `requires_online_authorization: true` never asks the cache; F-5 — boundary fixtures; F-6 — `publishing` renamed to what it answers and `admitted_for_verification` added.
