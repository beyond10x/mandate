---
format: aep.planning-md/1
id: story:credential-context-guards
kind: story
status: draft
title: Check refuses each credential-derived context condition on its own evidence
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- informed_by: initiative:drift-enforcement
- depends_on: story:caller-authority-split
scope:
- confidence: cited
  path: contracts/obligations/authz.json
- confidence: cited
  path: contracts/obligations/sts.json
- confidence: cited
  path: crates/mandate-authz/src/context.rs
- confidence: cited
  path: crates/mandate-authz/tests/obligations.rs
revision: 5
---
# A credential-derived context that is invalid, revoked, expired or stale is refused

## Why

`mandate.authorization.Check` declares four conditions on one clause —
*Credential-derived context is invalid/revoked/expired/stale* — and wave D's
authz unit found that the three tests named for it all drove the `direct`
guard and decided none of the four. The clause now publishes one condition per
row (`contracts/obligations/authz.json`) and eight of them are on
`decision-blocker:guards`.

Two more sit beside them: `sts/IssueAuthorizationCode`'s trusted
control-plane caller/session context, and
`sts/IntrospectCredential`'s principal/connection/epoch validation.

## Shape

`mandate-authz::context` already holds the reader: `Binding`, `Bound` and
`bind()` at `crates/mandate-authz/src/context.rs:38-94`, and `direct()` at
`:176`. The four conditions are questions about the credential the context was
validated from, and `VerifiedContext.credential`
(`crates/mandate-types/src/record.rs:63`) names it.

Each condition gets its own refusal and its own case. A row that names a test
which does not drive the condition it is rowed against is the defect wave D
measured; do not reproduce it.

## Acceptance

`cargo test -p mandate-authz --locked --no-fail-fast` exits 0 with one case per
condition, red before and green after. `cargo xtask obligations-registry`
exits 0 with no caller-context clause of `Check` left on
`decision-blocker:guards`, and each bound row names a test that drives its own
condition and no sibling's.

## Out of scope

The caller-authority clauses — `story:tenancy-authority` and
`story:graph-policy-adapter` own those. Any change to the graph or policy
ports.
