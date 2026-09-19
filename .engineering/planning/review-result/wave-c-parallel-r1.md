---
format: aep.planning-md/1
id: review-result:wave-c-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave C set
relations:
- reviews: story:oauth-transaction
- reviews: story:declared-writers
revision: 1
---
```
set: story:oauth-transaction, story:declared-writers (contract round 2) — wave C, from 0589bce
verdict: needs-revision
findings: 3
```

```findings
- file: .engineering/planning/story/declared-writers.md
  line: 154
  category: parallel-safety
  severity: blocker
  verdict: needs-revision
  origin: introduced
  message: 'the third of the three contract gaps routed here lands its only deliverable on a tests/security/cases.json corpus row, a file this body disclaims and that story:oauth-transaction holds as cited scope, so the gap has no named landing file and the two rounds meet in one nobody owns'
- file: .engineering/planning/story/oauth-integration.md
  line: 26
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the scope block and the Units table still claim the nine services/sts files story:oauth-transaction now claims, while only the prose Scope paragraph was re-recorded'
- file: .engineering/planning/story/oauth-transaction.md
  line: 95
  category: parallel-safety
  severity: warning
  verdict: needs-revision
  origin: introduced
  message: 'the Would collide with list omits story:product-listener, which holds services/sts/src/lib.rs as cited scope and declares a coordinator mod serve; edit to it'
```

Answers: no intersection on the two rounds' edited files; the contract round adds no element (fields and a header declaration only; `mandate.core.CredentialVerifier` exists at `core.yaml:123`), so the STS realization registry does not move; the `services/sts/src/lib.rs` ruling is safe within the wave (no other story naming the file is selected); one unowned surface — the `AccessCredential` fold arm in `crates/mandate-token/src/projection.rs` that gap 1 implies (routed to the design critic's verdict). Not established: whether the contract round adds `credential_id` to `RedeemAuthorizationCode`'s response (the declared response carries `credential` and `descriptor` only, `credential.yaml:241-245`); the six `pkce-*` rows still naming `story:oauth-integration`.

Rulings (coordinator): finding 1 — gap 3 withdrawn from the contract round (no contract change); the coordinator reassigned the seven `pkce-*` corpus rows (`pkce-valid/wrong/redirect/reuse` → `oauth-transaction`, `pkce-missing/plain` → `protocol-adapters`, `pkce-state-nonce` → `pkce-sessions`) in the opening commit; finding 2 — the endpoint story's stale scope rows removed and its Units section superseded; finding 3 — the collision addendum recorded on `oauth-transaction`. The response must carry `credential_id` for the event to source it: added to the contract round's gap 1.
