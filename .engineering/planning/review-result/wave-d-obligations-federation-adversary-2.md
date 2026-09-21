---
format: aep.planning-md/1
id: review-result:wave-d-obligations-federation-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-federation
relations:
- reviews: story:obligations-federation
revision: 1
---
```
unit: story:obligations-federation — impl/obligations-federation on 0ecccae, after correction 1
verdict: NEEDS-CHANGE (1 blocker, 1 warning)
cases: 301 → 304 executed, 2 red when written (crates/mandate-federation/tests/adversary_obligations_federation_2.rs)
origin: introduced 2 / pre-existing 0
```

```findings
- file: contracts/obligations/federation.json
  line: 579
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'All three mandate.federation.RegisterOAuthClient clauses are published path: real while every one of the three refusals is decided by an implementation of ClientRegistrationAdmission and not by mandate-federation — a second implementation of the same port, with the crate unchanged, turns all three refusals into acceptances — and crates/mandate-conformance/src/external.rs:248 registers ConfiguredAdmission as that port''s standing double beside GraphDouble and PolicyDouble, whose clauses carry path: double, so contracts/conformance/obligations-report.json:5 counts three double-backed clauses in real_covered (31 where 28 is decided) and the registry step compares path against nothing.'
- file: .engineering/planning/story/federation-admission-port.md
  line: 23
  category: judgement
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'The draft story''s acceptance requires the four remaining authority rows to bind path: real tests that are "red with the admission call removed", which does not discriminate real from double for a port-decided clause, so landing it as written adds four more real_covered rows decided by the same fixture; its stated reason — that register_client.rs:93 decides the clause — is contradicted at register_client.rs:91 ("the pub double") and :96 ("No crate in this crate''s dependency ceiling decides one"), and the unit repeats it verbatim at crates/mandate-federation/tests/obligations.rs:30.'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | accepted under the cross-unit rule (`review-result:wave-d-obligations-graph-adversary-1`): a clause decided by a port whose only implementation is a standing double is `double`. The three `RegisterOAuthClient` rows become `path: double`, `double: mandate_federation::register_client::ConfiguredAdmission`, `blocked_on: decision-blocker:guards` — the blocker whose text is the trusted-context adapter that would decide them for real. Report `mandate-federation 40 / 28 / 3 / 9`, `all 176 / 76 / 11 / 89`. The prose at `tests/obligations.rs:30` follows. | correction 2 |
| F2 | accepted. `story:federation-admission-port` is amended: the four handlers take the port (its work); the four rows then bind `path: double` deferring to `decision-blocker:guards`, exactly as the three `RegisterOAuthClient` rows do after F1; "red with the admission call removed" remains the mutation control, not the real/double discriminator. | coordinator |

Not broken: F2's re-arrangement (M5 kills it; both halves reached through the writer), six of seven guard deletions killed by `tests/obligations.rs` alone (the seventh is bound elsewhere, correctly), all nine re-pointing targets live, the `pkce-state-nonce` rows, the arithmetic for the classification as written.

Correction 2 is the last correction this unit gets; the coordinator verifies it by running the unit gate and the two adversary targets in the tree.
