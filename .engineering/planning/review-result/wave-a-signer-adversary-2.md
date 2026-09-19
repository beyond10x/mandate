---
format: aep.planning-md/1
id: review-result:wave-a-signer-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — token-signer
relations:
- reviews: story:signing-and-verification
revision: 1
---
```
unit: token-signer (story:signing-and-verification) — crates/mandate-token/src/signing_real.rs + tests, uncommitted on impl/signer at base b1d6297, after correction round 1
verdict: needs-change
cases: executed 53 → 66, red 4 (adversary file tests/adversary_signing_2.rs, 13 cases: 9 held, 4 confirmed); pass-1 file 15/15 green
findings: 7 — 1 blocker, 2 warnings, 4 notes; pass-1 findings all held except the revocation class (not closed against a second holding)
```

```findings
- file: crates/mandate-token/src/signing_real.rs
  line: 881
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'at overlap == ttl the published window ends exactly on a credential exp, so the signing key leaves the published set at an instant a zero-leeway relying party still accepts the credential, against the invariant the module states.'
- file: crates/mandate-token/src/signing_real.rs
  line: 803
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'rotate frees a windowed kid at now == drops_at, so fresh material takes the kid while a credential signed under it is still accepted and the published set resolves that kid to a key that never signed it.'
- file: crates/mandate-token/src/signing_real.rs
  line: 799
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'rotate never compares the thumbprint it computes against the keys already held, so one key file installs under a second kid and the published set carries one public key twice.'
- file: crates/mandate-token/src/signing_real.rs
  line: 888
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'revoke tombstones the thumbprint but drops only the entry whose kid matched, so a second holding of the compromised material keeps signing and stays published after the emergency path ran.'
- file: crates/mandate-token/src/signing_real.rs
  line: 897
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'a repeated revoke of an already-revoked kid answers UnknownKid rather than RevokedKey.'
- file: .engineering/planning/story/signing-and-verification.md
  line: 72
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the wave-opening dependency ruling records jsonwebtoken feature rust_crypto with a pure-Rust rationale while the tree ships aws_lc_rs since the opening commit; corrected by the coordinator.'
- file: crates/mandate-token/src/signing_real.rs
  line: 558
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'claims_object bounds the caller map neither in key count nor in size and documents no bound.'
```

Held: 28 reserved-name spellings refused; 9 homoglyph/invisible keys, nesting and a repeated serializer key never displace a standard claim; every emitted token decodes incl. a 10 000-claim one; the RFC 7638 thumbprint recomputed independently matches for both families; a serializer failure yields no partial token; `u64::MAX` clock/ttl/overlap saturate; revoking the only key fails closed; rehydrated foreign tombstones inert; the three named mutants killed. Evidence under the unit's scratch `adversary2/`.
