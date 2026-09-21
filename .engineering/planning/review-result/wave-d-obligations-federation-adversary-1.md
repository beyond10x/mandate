---
format: aep.planning-md/1
id: review-result:wave-d-obligations-federation-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — obligations-federation
relations:
- reviews: story:obligations-federation
revision: 1
---
```
unit: story:obligations-federation — impl/obligations-federation on 0ecccae, the unit's three files uncommitted
verdict: NEEDS-CHANGE (4 warnings, 1 note)
cases: 299 → 301 executed, 2 red when written (crates/mandate-federation/tests/adversary_obligations_federation_1.rs)
origin: introduced 4 / pre-existing 1
```

```findings
- file: crates/mandate-federation/src/record.rs
  line: 917
  category: property
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'collides is documented as deciding whether two rules on one issuer could both match one proof and instead tests exact rule equality, so register_federation_connection admits {org: acme} beside {dept: eng} and one proof carrying both claims makes every login on that issuer TenantAmbiguous, with no command to un-register the second connection'
- file: crates/mandate-federation/tests/obligations.rs
  line: 668
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the multiple-match half of ''tenant resolution has zero or multiple matches'' is published real_covered on a projection hand-folded from two equal claim rules, which register_federation_connection refuses to create — proved by the green tests/adversary_pass2.rs:231 — so the evidence is a state no history reaches; a different-claim pair is reachable and would fix the case'
- file: contracts/obligations/federation.json
  line: 221
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: '''STS code issuance/narrowing is refused'' and ''disablement cannot stop the issuance of new authorization codes to it'' defer to story:oauth-integration, which scopes services/sts alone, does not own the composition at services/control-plane/src/adapters.rs:1046, and cannot discharge either clause under the registry''s same-crate rule because mandate-federation makes no STS call; the story that does own the path, story:oauth-transaction, is implemented and would have been refused as terminal'
- file: crates/mandate-federation/src/disable.rs
  line: 37
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the four decision-blocker:guards re-pointings rest on ''no crate in this crate''s dependency ceiling decides an authorization decision'', which register_client.rs:93 contradicts by deciding the identically-shaped client-administration clause through a ClientRegistrationAdmission port that is in no way registration-specific; the three lifecycle handlers simply were not given that port, and the deferral should name the story that adds it'
- file: crates/mandate-federation/tests/obligations.rs
  line: 603
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the issuer and audience proof cases stay green with the verifier''s issuer binding, audience binding and untrusted-party check removed entirely — authenticate.rs:249 and :256 re-check and yield the same clause — so only two of the four ''proof clauses through RealVerifier'' are actually decided by RealVerifier; the rows stay correct as path: real and tests/verifier_real.rs covers the verifier half separately'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | confirmed, pre-existing, out of the unit's scope. Home: `story:federation-rule-disjointness` (draft). The two adversary cases are pinned by the coordinator to the shipped behaviour (the pair is admitted; the incumbent's login then answers `TenantAmbiguous`) and name the story. | story |
| F2 | accepted: the multiple-match case arranges a different-claim pair through `register_federation_connection`, the state the shipped writer produces today. When `story:federation-rule-disjointness` lands, the binding is re-examined by that story. | correction 1 |
| F3 | accepted as a registry gap. Home: `story:cross-crate-clauses` (draft): a clause row names `decided_in: <crate>` and the same-crate rule holds it to that crate. The two rows defer to that story. | correction 1 (rows) + story |
| F4 | accepted. Home: `story:federation-admission-port` (draft): the four handlers take the admission port `register_o_auth_client` already takes. The four authority rows defer to that story instead of `decision-blocker:guards`. | correction 1 (rows) + story |
| F5 | noted; rows unchanged. The story body's "four proof clauses through `RealVerifier`" is amended to two (signature, expiry) by the coordinator. | coordinator |

Not broken: the other nine bound cases, the three guard inversions, the `pkce-state-nonce` binding, the other five re-pointings, the four `blocked_on` targets, the report arithmetic, `register_o_auth_client` boundaries.
