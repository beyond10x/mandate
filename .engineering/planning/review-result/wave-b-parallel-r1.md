---
format: aep.planning-md/1
id: review-result:wave-b-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave B set
relations:
- reviews: story:credential-profiles
- reviews: story:declared-writers
revision: 1
---
```
set: story:credential-profiles, story:declared-writers — wave B, from a76267b
verdict: needs-revision
findings: 3
```

```findings
- file: .engineering/planning/story/credential-profiles.md
  line: 128
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the crate-roots row builds an exhaustive ESS_REALIZATIONS/ESS_UNREALIZED registry over mandate.credential whose only remedy for the two elements story:declared-writers adds to that domain is its correction round, and the wave gives this story one round, so the registry is written in a tree cut before the coordinator regenerates the IR and fails whichever way it is written'
- file: .engineering/planning/story/declared-writers.md
  line: 104
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the Collisions bullet rules out a collision with story:credential-profiles on file evidence alone and does not say that its contract round adds mandate.credential.RegisterSigningKey and SigningKeyRegistered to the domain that story registry and tests/contract_agreement.rs account for exhaustively against the regenerated generated/ir/system.json'
- file: .engineering/planning/story/credential-profiles.md
  line: 78
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the body names two owners for crates/mandate-token/src/lib.rs and services/sts/src/lib.rs in two live sections, coordinator-owned with two coordinator interface commits and this story implementor shared with no other unit this wave, and nothing marks the first superseded'
```

Answers: no file intersection between the two scope sets (21 and 12 paths); the collision is through `generated/ir/system.json`, which the contract round changes and the credential registry asserts exhaustively; the `IntrospectCredential` text change breaks nothing in `credential-profiles`' gate; the crate roots are held by no other live story. Unassessed surfaces named: `services/sts/tests/contract_agreement.rs` (no file for the `mandate-sts` half of the registry); stale frontmatter scope rows on `credential-profiles`; `components.yaml` and the obligations row without a line on `declared-writers` C1; `crates/mandate-identity/src/lib.rs:208-216` (Principal in `ESS_UNREALIZED`) missing from A3.
