---
format: aep.planning-md/1
id: story:tenancy-authority
kind: story
status: implemented
title: An authority decision is composed above the domain crates
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- informed_by: initiative:drift-enforcement
- depends_on: story:caller-authority-split
scope:
- confidence: cited
  path: dependency-boundaries.json
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/control-plane/src/authority.rs
- confidence: cited
  path: services/control-plane/tests/authority.rs
revision: 18
---
# An authority decision is composed above the domain crates

## Why this story replaces the one that was here

This story was specified on 2026-09-21 as *"the tenancy handlers refuse a
caller the fold says lacks authority"*, on two premises measured false the next
day by `story:caller-authority-split`:

- `VerifiedContext` (`crates/mandate-types/src/record.rs:63`) carries `subject`,
  `actor`, `organization`, `audience`, `credential`, `delegation`, `execution`,
  `correlation`. It carries **no authority scope**. `AuthorityScope` is a
  separate record at `:31` and is never embedded.
- `Tenancy::may_add_organization_membership` (`crates/mandate-model/src/tenancy.rs:744`)
  is not an authority decider. Its only refusal arm is a containment check, and
  that refusal is already bound by name to the sibling clause
  `organization_id differs from the verified organization`.

The crate settles it: `tenancy.rs:93-95` — *"Whether a caller holds the authority
a command names … is `mandate-authz`'s and is decided nowhere here"* — and
`:317-318` — *"membership carries no authority by itself, which stays with grants
and relationships."*

**0 of 31 caller-authority clauses are decidable from a fold.** A trait added to
`mandate-model` would take a double, produce `double_only` rows, and raise
`real_covered` by nothing.

## What is actually missing

21 clauses name an authority decision no shipped adapter makes, across
`mandate-tenancy` (11), `mandate-credential` (6), `mandate-identity` (2),
`mandate-federation` (1) and `mandate.authorization.Check` (1).

`mandate_authz::check` (`crates/mandate-authz/src/lib.rs:204`) is the decider
that exists. No composition can call it:

- `dependency-boundaries.json` permits `mandate-authz` exactly two dependents —
  `mandate-testkit` and `mandate-conformance`, both test infrastructure.
- `mandate-control-plane`, the composition binary, lists `mandate-sts`,
  `mandate-federation`, `mandate-identity`, `mandate-server`, `mandate-proto`,
  and not `mandate-authz`.
- `mandate-server` is bounded to `mandate-types` and `mandate-proto`, so
  `story:protocol-adapters` cannot reach it either.

So the work is a boundary change plus a call site, above the domain crates,
where the cycle does not exist.

## What this story delivers

- `dependency-boundaries.json` admits `mandate-control-plane → mandate-authz`,
  with the reason recorded where the file records reasons.
- The composition decides authority **before** handler dispatch, for the
  commands whose clauses name it, and returns the declared refusal.
- Per bound clause, a real-path denial case, red before and green after, and a
  mutation control: delete the guard and exactly its case falls.

`mandate_authz::check` consults the graph and policy ports, whose only
implementors are doubles, so **some of these will land `double` and not `real`.**
Measure the split before building, as `story:caller-authority-split` did, and
say which clauses each verdict covers. A unit that reports 21 `real` without
that measurement has not understood the rule.

## Acceptance

`cargo xtask obligations-registry` exits 0 and `real_covered` rises by the
number of clauses the measurement said the composition decides over the fold.
`cargo run -p xtask -- boundaries` exits 0. `decision-blocker:guards` holds
fewer caller-authority clauses, and every one it still holds is named with the
reason.

## Out of scope

The graph and policy engines. The 7 clauses re-pointed to
`story:graph-policy-adapter` and the 3 on `story:agent-authority-kernel` stay
theirs.
