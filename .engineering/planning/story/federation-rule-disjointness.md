---
format: aep.planning-md/1
id: story:federation-rule-disjointness
kind: story
status: draft
title: Registration refuses two tenant rules one proof could satisfy
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/federation.json
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_obligations_federation_1.rs
- confidence: inferred
  path: crates/mandate-federation/tests/obligations.rs
revision: 4
---
## Why

`crates/mandate-federation/src/record.rs:917` `collides` is documented as deciding whether two tenant rules on one issuer could both match one proof, and instead tests exact rule equality. `register_federation_connection` therefore admits `{org: acme}` for one organization beside `{dept: eng}` for another on the same issuer; one proof carrying both claims satisfies both rules and every login on that issuer answers `TenantAmbiguous`, and no command un-registers the second connection (`review-result:wave-d-obligations-federation-adversary-1` F1). `tests/adversary_pass2.rs:231` closed the equal-rule half only.

## Outcome

`collides` answers `true` for two `Shape::Claim` rules on different claim names on one issuer; two rules on the same claim name with different values remain admitted side by side. The `tenant resolution has multiple matches` binding in `contracts/obligations/federation.json` is re-examined, since the state it arranges is then refused at registration.

## Acceptance

`crates/mandate-federation/tests/adversary_obligations_federation_1.rs` cases `a_second_organizations_rule_one_proof_also_satisfies_is_refused_at_registration` and `the_admitted_pair_ends_the_incumbents_logins_on_that_issuer` assert refusal at registration and an incumbent login that keeps resolving, and are green; `cargo xtask obligations-registry` still counts the multiple-match clause on the real path or defers it to the story that owns the path.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-federation` registration guard — cited
- **Files:** `crates/mandate-federation/src/record.rs:935` (`collides`; the body's `:917` has drifted) — cited
- **Files:** `crates/mandate-federation/tests/adversary_obligations_federation_1.rs:197,226` (pin today's behaviour as `..._is_admitted_at_registration`; inverted and renamed) — cited
- **Also likely:** `contracts/obligations/federation.json:453` (multiple-match row) — cited; `crates/mandate-federation/tests/obligations.rs` — inferred
- **Confidence:** high
- **Not established:** whether a seeded `--connection` document in control-plane tests puts two different-claim rules from different organizations on one issuer; if so it starts being refused
