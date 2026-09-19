---
format: aep.planning-md/1
id: review-result:wave-a-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave A set
relations:
- reviews: story:signing-and-verification
- reviews: story:federation-identity-alignment
- reviews: story:model-agreement
revision: 1
---
```
set: story:signing-and-verification (2 units), story:federation-identity-alignment, story:model-agreement — wave A, from c04dba5
verdict: needs-revision
findings: 2
```

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 40
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the acceptance eight federation cases are tests/link.rs and tests/authenticate.rs, and removing the ConstructedVerifier double from them writes the same two files story:federation-identity-alignment claims for its concurrent FederationEvent payload call sites, and neither story ruling names the other on them'
- file: .engineering/planning/story/signing-and-verification.md
  line: 58
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'token-signer lands the signing port implementation but no signing port exists in crates/mandate-token, so the unit surface beyond signing_real.rs is unestablished while the ruling declares the crate root untouchable after the opening commit'
```

Also named: the seam-change landing path for `FederationVerifier::verify`; `ureq` TLS and `jsonwebtoken` features decided in the opening commit; `model-agreement`'s `types` unit needs `crates/mandate-types/src/inventory.rs:496` and `tests/inventory.rs:160`; `federation-identity-alignment` excludes `authorize.rs` while its inherited item needs it. `crates/mandate-types/tests/conformance.rs` collides with nothing.
