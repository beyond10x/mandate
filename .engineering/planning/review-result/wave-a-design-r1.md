---
format: aep.planning-md/1
id: review-result:wave-a-design-r1
kind: review-result
status: active
title: Design critic, round 1 — wave A set
relations:
- reviews: story:signing-and-verification
- reviews: story:federation-identity-alignment
- reviews: story:model-agreement
- reviews: story:credential-profiles
revision: 1
---
```
set: story:signing-and-verification, story:federation-identity-alignment, story:model-agreement — wave A
verdict: needs-revision
findings: 5
```

```findings
- file: .engineering/planning/story/signing-and-verification.md
  line: 58
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'its token-signer unit implements a signing port that nothing in this wave declares; the only artifact that declares one is story:credential-profiles signing unit, which this wave pulls the story ahead of'
- file: .engineering/planning/story/credential-profiles.md
  line: 85
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'its signing unit row still lands the signing and verification port, kid and the rotation window in crates/mandate-token/src/signing.rs, the same surface token-signer now lands first in signing_real.rs, so the two rows are two owners of one surface'
- file: .engineering/planning/story/federation-identity-alignment.md
  line: 66
  category: design
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the wave stated deliverable open a Session from FederationAuthenticated appears in no scope line and no unit row, and it is the seam between federation-shapes (src/record.rs) and identity-shapes (src/port.rs) across a boundary that admits mandate-identity only mandate-types and mandate-model'
- file: .engineering/planning/story/federation-identity-alignment.md
  line: 73
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'crates/mandate-federation/src/authorize.rs is named Excluded and simultaneously put in scope by the wave-opening ruling, and no unit row and no scope entry owns it'
- file: .engineering/planning/story/signing-and-verification.md
  line: 73
  category: design
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'its ruling says the blocker clears at this wave close on cases that include refusal at issuance, which decision-blocker:algorithm-policy assigns to story:credential-profiles, an item this wave does not carry'
```

Answers: pulling ahead is sound for the verifier (seam landed) and needs the port declared for the signer; no ownership conflict with `session-epochs`/`pkce-sessions` but the fold work crosses the recorded direction `mandate-federation → mandate-identity`; `model-agreement` independent; no cycle among 91 `depends_on` edges over 43 nodes.
