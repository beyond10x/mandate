---
format: aep.planning-md/3
id: story:real-handler-decides-first
kind: story
status: draft
title: The real handler decides before any armed fault in every domain
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
---
# The real handler decides before any armed fault in every domain

## Acceptance

Given the conformance target with the admission stand-in seeded (from `audit-small-code-fixes`), when the authored scenarios `pkce-malformed-challenge` and `pkce-wrong-org-target` run, then `IssueAuthorizationCode` and `Check` go through `standing_first` so the real handler decides before an armed fault, both scenarios pass with their authored denial reasons rather than `Denied`, and the pin in `crates/mandate-conformance/tests/adversary_ess_repin_1.rs` is narrowed to what still holds.

## Scope

- `crates/mandate-conformance/src/commands/credential.rs`, `crates/mandate-conformance/src/commands/authz.rs`
- `crates/mandate-conformance/src/external.rs`
- `crates/mandate-conformance/tests/adversary_ess_repin_1.rs`
- `contracts/expected-outcomes.json`

## Source

Audit G-22 (story S-12).
