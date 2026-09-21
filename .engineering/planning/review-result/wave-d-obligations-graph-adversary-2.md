---
format: aep.planning-md/1
id: review-result:wave-d-obligations-graph-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-graph
relations:
- reviews: story:obligations-graph
revision: 1
---
```
unit: story:obligations-graph — impl/obligations-graph on 181e6c0, after correction 1
verdict: NEEDS-CHANGE (3 blockers, 2 warnings, 2 notes)
cases: 94 → 99 executed, 5 red when written (crates/mandate-graph/tests/adversary_obligations_graph_2.rs, 461 lines)
origin: introduced 5 / pre-existing 2
suite: cargo test -p mandate-graph --locked --no-fail-fast → 99 executed, 5 failed, exit 101 (94 pass with the new file skipped); clippy 0; obligations-registry `mandate-graph 19 2 7 10` / `all 176 64 13 99` exit 0; xtask obligations_registry 24 passed
probes on a scratch copy: (a) register_resource skips parent-tenancy → F6's case red; (b) admit skips declared_name → 4 red; (c) write_relationship records before admit refuses → 2 red including the WriteRelationship no-state-change case
attacked and unbroken: report arithmetic; the four pass-1 pins; six double clause rows; the graph-revocation cases row; WriteRelationship tiling; the four double no_state_change cases
```

```findings
- file: contracts/obligations/graph.json
  line: 232
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'the clause "resource tenancy mismatches" is counted in real_covered, but admit compares no organization — it propagates lookup.placement(..)? at src/relationship.rs:117, and the TenantMismatch its named case asserts is produced by the Tree stub at crates/mandate-graph/tests/relationship.rs:72-74, the same defect pass-1 F5 corrected in the clause above it'
- file: contracts/obligations/graph.json
  line: 242
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'the clause "the relationship is not admitted by the authorization model" is counted in real_covered on two declared_name cases, but admit accepts every well-formed relation name and consults no model, and crates/mandate-graph/src/relationship.rs:10 says that refusal is mandate-policy''s'
- file: contracts/obligations/graph.json
  line: 256
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the WriteRelationship no_state_change row is path real while the four sibling rows built the same way are double, and a probe that makes GraphDouble::write_relationship record before admit refuses turns the named case red — the ordering it measures is the double''s, and the real row also drops the command''s blocked_on'
- file: contracts/obligations/graph.json
  line: 221
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the double value "mandate-graph::relationship::Members" is not a Rust path and names nothing — the stub lives in the test binary crates/mandate-graph/tests/relationship.rs:85 — and xtask checks only that the field is non-empty'
- file: contracts/obligations/README.md
  line: 116
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the README states eight double-backed clauses defer to story:graph-policy-adapter and the report this diff rewrote counts 13, and the sentence''s port list is stale the same way — RevocationWriter and SubjectAdmission now back double rows, not only ResourceRegistry'
- file: .engineering/planning/story/obligations-graph.md
  line: 25
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the Outcome says every clause is decided on the real path and the crate''s rows move from deferred to real_covered, and the shipped document moves real_covered from 6 to 2 — to 0 if the two blockers above are upheld — while the literal Acceptance line still passes'
- file: crates/mandate-graph/tests/obligations.rs
  line: 166
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the two withdrawn require_revision cases carry clean doc comments but their expect_err strings at :166 and :193 still say the revision "the removal" and "the revocation" must be visible at, the tie to the two commands F1 and F2 established no path makes'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Upheld.** `crates/mandate-graph/src/relationship.rs:116-117` reads `lookup.placement(organization, write.resource)?` and `admit` compares no organization of its own; the `TenantMismatch` is the `ResourceLookup` implementor's. `GraphDouble` implements `ResourceLookup` (`crates/mandate-graph/src/double.rs:208`) and is the crate's only one. The clause becomes `path: double`, `double: mandate_graph::double::GraphDouble`, `blocked_on: story:graph-policy-adapter`, and its case drives that double rather than the `Tree` stub. | correction 2 |
| F2 | **Upheld; the clause is another crate's.** `crates/mandate-graph/src/relationship.rs:10` states in the crate's own module doc that admission by the authorization model is `mandate-policy`'s, and `declared_name` answers a different condition — whether the relation name names anything. The clause defers to `story:cross-crate-clauses` with that source line, `tests: []`; this is the shape `review-result:wave-d-obligations-federation-adversary-1` F3 established for an STS-decided federation clause. The two `declared_name` cases stay in `tests/obligations.rs` as what they are: evidence of a refusal `mandate.graph.WriteRelationship`'s declared cause publishes no clause for. That observation is appended to `story:unpublished-refusals`, which was created on the model pass for exactly it. | correction 2 + story |
| F3 | **Upheld.** Every refusal `admit` reaches is the lookup's, the admission's or the name check's, and probe (c) shows the ordering the case measures is `GraphDouble::write_relationship`'s. The `no_state_change` row becomes `path: double`, `double: mandate_graph::double::GraphDouble`, and `mandate.graph.WriteRelationship` gains the command-level `blocked_on: story:graph-policy-adapter` its four siblings carry. | correction 2 |
| F4 | **Upheld, and the rule is general.** A `double` names a stand-in a reader can resolve: a `::`-separated Rust path into a **library** target. A stub defined inside a test binary is not one — nothing outside that binary can follow it, and the step checks only that the field is non-empty. `GraphDouble` implements `SubjectAdmission` (`crates/mandate-graph/src/double.rs:345`), so "outside tenant membership" takes `double: mandate_graph::double::GraphDouble` and its case drives that double. The step's missing check is appended to `story:cross-crate-clauses`, the registry follow-up that already carries pass-1 F6; `story:obligation-registry` is `implemented` and cannot hold it. | correction 2 + story |
| F5 | **Upheld, and it is the coordinator's file.** The defect is a count and a closed list of deferral targets being stated in `contracts/obligations/README.md` at all — both move on every merge that adds a document. Rewritten by the coordinator to state the rule and no instance, naming the report as the thing that counts. The adversary case is amended by the coordinator to the invariant a README can hold; it is red in the unit tree until then and the unit does not touch either file. | coordinator |
| F6 | **Confirmed.** The story body carries the measured result at merge, as `obligations-sts` and `obligations-federation` do. After F1, F2 and F4 `mandate-graph`'s `real_covered` is 0: nothing in the crate decides a published denial clause on a shipped path today, because every decider is behind `ResourceRegistry`, `ResourceLookup`, `SubjectAdmission`, `RelationshipWriter` or `RevocationWriter`, and `GraphDouble` is the only implementor of each. That is the number this registry exists to publish, and `story:graph-policy-adapter` is what moves it. | coordinator |
| F7 | **Confirmed.** Correct both `expect_err` strings at `crates/mandate-graph/tests/obligations.rs:166` and `:193` to say what the withdrawn cases now assert; a message that names a tie no path makes is the same defect one rung down. | correction 2 |
