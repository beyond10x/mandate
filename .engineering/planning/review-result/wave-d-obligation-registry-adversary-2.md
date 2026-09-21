---
format: aep.planning-md/1
id: review-result:wave-d-obligation-registry-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligation registry
relations:
- reviews: story:obligation-registry
revision: 1
---
```
unit: story:obligation-registry — impl/obligation-registry on 6d812e0, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 2 warnings)
cases: 138 → 142 executed, 4 red when written
origin: introduced 4 / pre-existing 0
```

```findings
- file: contracts/obligations/sts.json
  line: 381
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'RedeemAuthorizationCode''s split put real_covered on "atomic issuance validation fails" while the one discriminator the precedent attributes there is ExpiryUnbounded, an expiry-bound check that fires before anything is minted; round 1''s F4 was relabelled, not fixed'
- file: xtask/src/obligations_registry.rs
  line: 656
  category: mutant
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'the step decides each clause is a substring of its cause and never that the clause set accounts for it, so a binding story can delete an unbindable clause and exit 0; "the set still tiling the cause" has no reader'
- file: xtask/src/obligations_registry.rs
  line: 662
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the duplicate check is exact equality only, so a clause inside another clause of the same command is admitted and inflates clauses and real_covered with nothing new decided'
- file: contracts/obligations/policy.json
  line: 15
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: '7 of the 8 double_only clauses defer to story:obligations-<crate> although the only non-test implementor of PolicyAdministration and ResourceRegistry is each crate''s own double, so no test those stories write can bind them'
```

Held: the seven split halves tile their causes; the one-path rule, the ignored-id subtraction, the liveness transition, the 41/20 partition against the coverage manifest, the report's stability, the `owners` bound in the data.

Rulings (correction round 2, the last): F1 — `ExpiryUnbounded` decides `IssueAuthorizationCode`'s "bounded expiry validation fails" only; both halves of `RedeemAuthorizationCode`'s "narrowing/atomic issuance validation fails" are `blocked_on: story:obligations-sts` (real-covered falls to 68). F2/F3 — the step reads the tiling: the clauses of a command, in order, separated only by `,`, `;`, `or`, `/` and whitespace, account for every other character of the cause exactly once; a dropped clause, a nested clause and an overlap are refused by name. F4 — a `double` row's `blocked_on` names the story that owns the port's real implementation and never the crate's binding story; the seven rows move to `story:graph-policy-adapter` (the `PolicyAdministration` and `ResourceRegistry` ports); the step refuses a `double` row deferring to `story:obligations-<crate>`.
