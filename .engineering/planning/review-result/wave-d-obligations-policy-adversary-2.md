---
format: aep.planning-md/1
id: review-result:wave-d-obligations-policy-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-policy
relations:
- reviews: story:obligations-policy
revision: 1
---
```
unit: story:obligations-policy — mandate-wd-obl-policy, branch impl/obligations-policy, base a2a55c3, after correction 1
verdict: NEEDS-CHANGE (0 blockers, 2 warnings, 3 notes)
cases: 76 → 79 executed, 3 red when written (crates/mandate-policy/tests/adversary_obligations_policy_2.rs, 370 lines)
origin: introduced 5 / pre-existing 0 / undecided 0
suite: cargo test -p mandate-policy --locked --no-fail-fast → 79 executed / 13 targets + doc-tests, 3 failed, exit 101, every failure the adversary's own; fmt 0; clippy all-targets 0; obligations-registry exit 0 `mandate-policy 8 0 4 4`; xtask obligations_registry 24 passed; the story's Acceptance command exit 0
mutation probe (scratch copy, worktree never touched, copy's target/ deleted): M1 drop policy.organization_id == organization at src/double.rs:264 → 2 red, exactly correction 1's case and pass 1's; M2 the same at :301 → 2 red, likewise; M3 drop policy.current() → 0 red, 76 green; M4 drop model.current() → 0 red, 76 green
citation check (mechanical, 20 citations): 16 exact, 4 where the statement continues one or two lines past the cited line, 0 not found. No stale citation — this is not the class that bit three units this week.
attacked and unbroken: real_covered 0 (two implementors of PolicyAdministration in the workspace, and crates/mandate-conformance/src/commands/mod.rs:200-209 independently rows both commands unrealized); the four coordinator pins each fail when the thing they guard moves; both re-pointings admissible and their cited lines true; supersede boundaries (empty fold, unresolved id, another organization's record, record last in the fold, repeated call, already-superseded subject); report arithmetic; no mandate-policy clause wording is pinned in xtask/tests/obligations_registry.rs
```

```findings
- file: crates/mandate-policy/tests/obligations.rs
  line: 53
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the paragraph claims dropping either half of the later-version predicate fells its two new cases, and dropping the current() half from src/double.rs:264 and :301 leaves all 76 cases green'
- file: crates/mandate-policy/tests/obligations.rs
  line: 70
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the deferral is justified by "the eleven authority clauses of contracts/obligations/sts.json" and that document has 13 clauses on decision-blocker:guards, 10 naming authority and 9 doing both; eleven is its implemented command count'
- file: contracts/obligations/README.md
  line: 119
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the registry''s normative README says mandate_identity::IdentityLog is the only implementor of SecurityEpochWrite, and crates/mandate-conformance/src/external.rs:672 implements it in a library target too'
- file: crates/mandate-policy/tests/obligations.rs
  line: 36
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the no-state-change cases are said to show no rule, role or trusted attribute moved, and published() folds none of the three, so those dimensions are compared empty to empty and the fields are private so no test binary can assert on them'
- file: crates/mandate-policy/tests/obligations.rs
  line: 46
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the claim that every record_policy and record_model in this crate''s and mandate-authz''s tests folds a same-organization record is falsified at :271 and :308 of the same file'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Upheld, and take the fix that closes both halves.** The adversary offered two: correct the sentence, or fold an already-superseded later record into one of the two cases. Only the second also decides the conjunct, and the conjunct is decidable — the case's own first three assertions show a fold whose only later same-organization record is superseded is refused and the same fold with it current is accepted. Correction 2 folds a superseded later record into each of the two cases, so `current()` and `organization_id == organization` are both load-bearing, and shows M3 and M4 each felling a case. Then the sentence is true as written and nothing has to be softened. A claim that a mutation fells a case is worth exactly what the mutation says, and this one had never been run. | correction 2 |
| F2 | **Confirmed.** Eleven is `sts.json`'s implemented **command** count, not a clause count. Restate as "the authority clauses of `contracts/obligations/sts.json`" with no number, for the reason this half has now met four times: a count written beside a document that another story is still editing is false on a schedule nobody controls. | correction 2 |
| F3 | **Upheld, and it is my sentence.** I wrote it into `contracts/obligations/README.md` in alignment commit `237d93e`, in the same paragraph where I had just removed a stale count — and I replaced a rotting number with a rotting enumeration. `crates/mandate-conformance/src/external.rs:672` implements `mandate_identity::SecurityEpochWrite` for `Substituted`, outside that file's `#[cfg(test)]` at `:1039`, so it is a library target and the sentence was false when I committed it. Two library implementors, verified by `grep 'impl .*SecurityEpochWrite for'` over `crates/` and `services/` excluding `tests/`. Corrected by the coordinator: the paragraph now states that the file carries no count, no closed deferral list **and no claim about how many implementors a port has**, because all three move on a merge and the question has a command that answers it at the moment it is asked. The unit does not touch the README. | coordinator |
| F4 | **Confirmed, note, no action.** `rules`, `trusted` and `roles` are compared empty to empty because `published()` folds none of them, and the fields are private with no accessor, so a test binary cannot assert on them without modelling the fold. The adversary stated it rather than constructing it, which is the right call. Recorded on `story:graph-policy-adapter`, which owns the real adapter and will have to decide what a no-state-change comparison covers once there is a store behind it. | story |
| F5 | **Confirmed.** The sentence is falsified 225 lines below itself, by cases the same correction added. Restate it as a statement about the corpus it was written about, or delete it — a sentence that its own file disproves is worse than no sentence. | correction 2 |
| (a) | **Split.** The adversary asked whether the two "no later X version is recorded for that organization" clauses should go to one condition per clause, as `story:obligations-authz` did when it went 9 → 15. Yes: `contracts/obligations/README.md` states the rule — "one clause per condition the cause enumerates" — and two documents applying the same named rule at different granularities make the registry's own counts incomparable. The adversary has already measured that the split tiles (the gap is whitespace). Expect `mandate-policy 10 clauses / 0 real / 6 double / 4 deferred`. | correction 2 |
