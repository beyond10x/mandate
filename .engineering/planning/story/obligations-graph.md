---
format: aep.planning-md/1
id: story:obligations-graph
kind: story
status: implemented
title: Bind mandate-graph's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/graph.json
- confidence: cited
  path: crates/mandate-graph/tests/obligations.rs
revision: 7
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-graph` is one file this story owns: 5 commands, ~19 clauses; denials as GraphError (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-graph` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-graph/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-graph` command as `deferred` on this story, and `cargo test -p mandate-graph --locked --test obligations` is green.

- Result (2026-09-21, at merge): **`mandate-graph` decides none of its 19 published denial clauses on a shipped path.** The Outcome above said every clause would move from `deferred` to `real_covered`; the shipped document moves `real_covered` from 6 to **0**. That is the honest number and it is what this registry was built to publish. Final table `mandate-graph 19 / 0 / 8 / 11` (`cargo run -p xtask -- obligations-registry`, coordinator verification 2026-09-21). 8 clauses are `double` on `mandate_graph::double::GraphDouble`; 11 are re-pointed with cited source lines — to `decision-blocker:guards`, `decision-blocker:epoch-atomicity`, `story:graph-policy-adapter` and `story:cross-crate-clauses`. The Acceptance — "no clause of a `mandate-graph` command is `deferred` on this story" — is met entirely by re-pointing and re-classification, not by binding.
- Why: `crates/mandate-graph/src/relationship.rs`'s `admit` decides almost nothing of its own. It checks `declared_name(write.relation)`, then propagates `lookup.placement(organization, write.resource)?` at `:117` and `admission.admits(organization, write.subject)?`; it compares no organization. Every decider the crate's five commands reach is behind `ResourceRegistry`, `ResourceLookup`, `SubjectAdmission`, `RelationshipWriter` or `RevocationWriter`, and `GraphDouble` is the only implementor of each. `story:graph-policy-adapter` is what moves this number.
- Adversary pass 2 ruled (`review-result:wave-d-obligations-graph-adversary-2`): 3 blockers, 2 warnings, 2 notes. F1 and F2 were **pre-existing** — "resource tenancy mismatches" was counted `real_covered` on a `TenantMismatch` produced by a `Tree` stub in a test binary, and "the relationship is not admitted by the authorization model" on two `declared_name` cases, while `crates/mandate-graph/src/relationship.rs:10` says that refusal is `mandate-policy`'s. The second is now re-pointed to `story:cross-crate-clauses`. F3 moved the `WriteRelationship` `no_state_change` row to its four `double` siblings.
- One rule generalised out of F4 and recorded for the whole registry: **a `double` value is a `::`-separated Rust path into a library target.** `graph.json` had shipped `"mandate-graph::relationship::Members"` — not a Rust path at all, and naming a stub inside a test binary. The step checks only that the field is non-empty; that gap is on `story:cross-crate-clauses`.
- Two coordinator-owned registry adversary cases in `xtask/tests/` were red as a consequence of this reclassification and were corrected, not suppressed: each read a precondition out of the committed registry rather than constructing it, so any correct ruling about which clauses are `real` turned them red. The unit distinguished the red it caused from the one it inherited by measurement — reinstalling the correction-1 document, running both targets, restoring byte-identically — and enumerated the class over all eight cases in the two files.
