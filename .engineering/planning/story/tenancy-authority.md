---
format: aep.planning-md/1
id: story:tenancy-authority
kind: story
status: draft
title: The tenancy handlers refuse a caller the fold says lacks authority
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- informed_by: initiative:drift-enforcement
- depends_on: story:caller-authority-split
scope:
- confidence: cited
  path: contracts/obligations/model.json
- confidence: cited
  path: crates/mandate-model/src/authority.rs
- confidence: cited
  path: crates/mandate-model/src/tenancy.rs
- confidence: cited
  path: crates/mandate-model/tests/obligations.rs
revision: 5
---
# The tenancy handlers refuse a caller without authority

## Why

Every tenancy command declares a refusal for a caller who lacks the authority
the command needs — organization administration, team administration, space
administration, membership administration. `crates/mandate-model/src/tenancy.rs`
makes none of them. `contracts/obligations/model.json` rows 14 of those clauses
on `decision-blocker:guards`, which is the honest record of a refusal nothing
reaches.

`story:caller-authority-split` says which of them a fold can answer. This story
implements that subset and no more.

## Shape

The pattern is the one the repository already uses twice —
`ClientRegistrationAdmission` (`crates/mandate-federation/src/register_client.rs:93`)
and `SubjectAdmission` (`crates/mandate-graph/src/relationship.rs:49`): the
trait is declared beside the handler that refuses on it, and implemented above.
Do not invent a third shape, and do not route through `mandate_authz::check` —
`mandate-authz` depends on `mandate-model`, so the edge is a cycle, and its
`evaluate()` consults ports whose only implementors are doubles.

The real implementor reads `Tenancy` and lives in this crate, because the
question is a membership question and the fold holds the memberships.
`Tenancy::may_add_organization_membership` (`src/tenancy.rs:744`) is the
existing example.

The refusal is the handler's: it consults the port and returns the declared
`Denied` itself. That is what makes the registry row `real` rather than
`double`.

## Acceptance

`cargo test -p mandate-model --locked --no-fail-fast` exits 0 with one new
denial case per bound clause, each red before the handler change and green
after. `cargo xtask obligations-registry` exits 0 and `mandate-model`'s
`real_covered` rises by the number of clauses `story:caller-authority-split`
marked `fold`. A mutation control per new refusal: delete the guard, and
exactly its case falls.

## Out of scope

Clauses the split marked `engine` — those wait for
`story:graph-policy-adapter`. The value-admission clauses (display name,
redirect URI) belong to `story:invariant-boundary-validation`.
