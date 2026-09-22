---
format: aep.planning-md/1
id: story:caller-authority-split
kind: story
status: implemented
title: Measure which caller-authority clauses the tenancy fold can decide
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: contracts/obligations/authz.json
- confidence: cited
  path: contracts/obligations/federation.json
- confidence: cited
  path: contracts/obligations/graph.json
- confidence: cited
  path: contracts/obligations/identity.json
- confidence: cited
  path: contracts/obligations/model.json
- confidence: cited
  path: contracts/obligations/policy.json
- confidence: cited
  path: contracts/obligations/sts.json
revision: 11
---
# Which caller-authority clauses a fold can decide

## Why

Wave D bound every implemented command's denial clauses to tests and measured
that 86 of 190 are deferred. `decision-blocker:guards` holds 45 of the 136
`blocked_on` references, and 31 of those 45 are one sentence repeated across
seven crates: *Caller lacks <some> authority*. No handler in
`mandate-model`, `mandate-graph`, `mandate-federation`, `mandate-identity` or
the STS consults any authority at all.

`mandate-authz::check` (`crates/mandate-authz/src/lib.rs:204`) is the decider
that exists, and it cannot be called from any of them: `mandate-authz` depends
on `mandate-model`, `mandate-graph` and `mandate-policy`, so the edge would be
a cycle. Its `evaluate()` (`src/evaluate.rs:238`) also consults the graph and
policy ports, whose only implementors are `GraphDouble` and `PolicyDouble`.

So a port added carelessly moves a clause from `deferred` to `double` and
raises `real_covered` by nothing. Wave D's standing rule: a clause is `real`
only when handler code over the fold decides it.

## What this story delivers

A measurement, not an implementation. For each of the 31 clauses, one row:

| column | meaning |
|---|---|
| command | the IR command the clause belongs to |
| clause | the verbatim substring |
| decider | the fold, the graph engine, the policy engine, or none |
| verdict | `fold` — decidable today from `Tenancy` + `VerifiedContext`; `engine` — needs `story:graph-policy-adapter`; `unreachable` — no shipped path |

The evidence for `fold` is a named function that answers the question today.
`Tenancy::may_add_organization_membership`
(`crates/mandate-model/src/tenancy.rs:744`) is one; `AuthorityScope` on
`VerifiedContext` (`crates/mandate-types/src/record.rs:63`) is the other input.
A row marked `fold` with no such function named is not a `fold` row.

Each clause's `blocked_on` is then re-pointed off `decision-blocker:guards` to
the story that owns it.

## Acceptance

`cargo xtask obligations-registry` exits 0 with no clause left on
`decision-blocker:guards` for the caller-authority class, and the
`review-result` this story files carries all 31 rows with their verdict and,
for every `fold` row, the `file:line` of the function that decides it.

## Out of scope

Writing any handler, port or trait. This story measures and re-points; the
work follows in `story:tenancy-authority` and `story:graph-policy-adapter`.
