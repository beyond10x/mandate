---
format: aep.planning-md/1
id: review-result:wave-d-obligations-model-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — obligations-model
relations:
- reviews: story:obligations-model
revision: 1
---
```
unit: story:obligations-model — mandate-wd-obl-model, branch mandate-wd-obl-model, base eb22b1c, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 3 warnings, 2 notes)
cases: 112 → 115 executed, 3 red when written (crates/mandate-model/tests/adversary_obligations_model_2.rs)
origin: introduced 7 / pre-existing 0 / undecided 0
suite: cargo test -p mandate-model --locked --no-fail-fast → 115 executed / 17 targets, 3 failed, exit 101; fmt 0; clippy all-targets 0; obligations-registry `mandate-model 41 12 0 29` / `all 177 78 8 91` exit 0; xtask obligations_registry 24 passed
load-bearing probe: the rule of case 226 re-implemented outside the tree with a uniform offset — +0 fails 10/10 rows, +73 fails 0/10, so the case is exactly sensitive to the defect
attacked and unbroken: clause tiling and verbatim substrings re-derived from generated/ir/system.json for all 10 commands and 41 clauses; all seven re-pointing targets present and non-terminal; the fold section's arithmetic (13/9/1/3/3 = 29, matching the 29 blocked_on clauses); pass-1's rewritten bidirectional fold-section case re-parsed independently, 29 triples agreeing both ways; the other nine real rows' attribution; the three non-tenancy.rs citations; no_state_change (the refuses! macro compares the whole cloned Tenancy); report byte-reproduction
```

```findings
- file: crates/mandate-model/tests/obligations.rs
  line: 35
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: 'all ten rows of the ''What is bound here'' guard table cite src/tenancy.rs spans that are 73 lines stale after the unit''s own doc edit and correction 1''s rewrite, so every row names unrelated code — :917, cited for holds_team_membership, is self.apply(&event) inside create_team'
- file: crates/mandate-model/tests/obligations.rs
  line: 55
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the quotation attributed to src/tenancy.rs:113-118 that justifies deferring the three display-name clauses to decision-blocker:guards appears nowhere in the fold, because correction 1 reworded the sentence to ''no admission rule for a display name exists to implement'' and moved it to :121-125'
- file: contracts/obligations/model.json
  line: 101
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the clause ''organization_id differs from the verified organization and the caller lacks platform organization-administration authority'' is counted in real_covered while the same command entry defers ''Caller lacks membership-administration authority'' to decision-blocker:guards on the ground that the fold decides authority nowhere — both rest on the unvalidated MembershipAuthority input, and README requires a clause whose conditions have different deciders to be split, which correction 1 did for AddTeamMembership and not here'
- file: crates/mandate-model/tests/adversary_obligations_model_1.rs
  line: 213
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the five src/tenancy.rs citations the coordinator pinned into pass 1''s ''Shipped record:'' messages (:213, :265, :280, :323, :338) carry the same 73-line drift, so story:unpublished-refusals will be picked up against line numbers that name other code'
- file: crates/mandate-model/tests/obligations.rs
  line: 70
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the three mandate.directory deferrals are justified by the claim that the cited spans ''each name the record (MembershipContribution, DirectoryGroupTeamMappingCreated)'', and correction 1''s rewrite removed DirectoryGroupTeamMappingCreated from src/tenancy.rs entirely'
- file: contracts/obligations/model.json
  line: 164
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the clause text ''team or'' satisfies every rule the step enforces but names no condition the cause enumerates, so the published denial contract carries a refusal condition reading ''team or'' — it is half a condition plus an admitted list joiner taken into the clause'
- file: .engineering/planning/story/obligations-model.md
  line: 25
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the Outcome states that tests/obligations.rs decides every clause of the crate''s implemented commands on the real path with one denial case per clause; 12 of 41 moved to real_covered, 29 stay deferred, and no case exists for any of the ten authority clauses — the Acceptance is nonetheless met, so this is a result line and not a correction'
```

## Rulings (coordinator, 2026-09-21)

| # | ruling | route |
|---|---|---|
| F1 | **Confirmed, blocker.** Thirteen citations are 73 lines stale because correction 1's own rewrite of `src/tenancy.rs:107-206` moved the `impl Tenancy` block down and nobody moved the citations with it. Correct all thirteen to the spans the adversary measured. **And the fix is not the corrected numbers — it is that nothing checked them.** Correction 2 adds to `crates/mandate-model/tests/obligations.rs` the check `story:obligations-identity` landed for the same defect: scrape every `file:line` span out of this file's own doc comments, read the cited lines, and refuse both a span that does not hold the phrase it is cited for and a citation the table does not carry. This is the third time in one wave that a unit said it had re-read its citations and had not; re-reading is the thing that fails, and a stale citation is exactly as wrong as a stale count in a README. | correction 2 |
| F2 | **Confirmed.** Re-quote from `src/tenancy.rs:121-125`. The mechanical check of F1 must cover quotations, not only spans, so this class cannot recur either. | correction 2 |
| F3 | **Upheld as a blocker; the clause is split.** The adversary's defence for the unit is stated and rejected on its own evidence: `MembershipAuthority` is the caller's statement and not a grant (`crates/mandate-model/src/tenancy.rs:93-96`, the unit's own citation), so the conjunct the fold evaluates is whether the caller *claims* platform authority, not whether it has it — the case establishes a refusal for a caller that says it lacks authority, which is not the declared condition. Counting that in `real_covered` while the sibling clause defers to `decision-blocker:guards` for the reason that the fold decides authority nowhere publishes one decision as both shipped and unshipped. `contracts/obligations/README.md` is explicit: "where two conditions of one clause have different deciders, the clause is split into those conditions". Correction 1 performed that split on `AddTeamMembership` under this same rule; taking the conjunction reading here would require withdrawing that one. So: split into `"organization_id differs from the verified organization"` (keeps the real row, the tenancy comparison the fold does make) and `"the caller lacks platform organization-administration authority"` (`tests: []`, `blocked_on: decision-blocker:guards`). The adversary has already verified both halves are verbatim substrings, that `and` is an admitted joiner, that they tile, and that neither lies inside a sibling. Expect 42 clauses and one more deferral. | correction 2 |
| F4 | **Confirmed; the coordinator's file, the coordinator's fix.** The five `Shipped record:` citations in `crates/mandate-model/tests/adversary_obligations_model_1.rs` carry the same +73 drift, and they are what `story:unpublished-refusals` will be picked up against. Corrected by the coordinator to `:701-707`, `:706`, `:932-935`, `:934`, `:661`/`:894`/`:1083`. The unit does not touch that file. | coordinator |
| F5 | **Confirmed.** `DirectoryGroupTeamMappingCreated` is no longer in `src/tenancy.rs` and the claim that the cited spans "each name the record" is false; the directory group is at `:180-189`. Restate the justification against what the file now holds. Covered by F1's check going forward. | correction 2 |
| F6 | **Confirmed as a note; the text stands and the conflict is recorded.** `"team or"` is the smallest text the step admits — `team` alone lies inside three siblings and is refused (`xtask/src/obligations_registry.rs:674-680`, measured by correction 1 at three refusals). So the README's granularity rule, "one clause per condition the cause enumerates", and the step's substring rule pull against each other, and where they do, the step wins and the published contract carries a condition name that is half a condition. That is a defect in the pair of rules, not in this document, and churning the text cannot fix it. Appended to `story:cross-crate-clauses` with the two step gaps already recorded there. | story |
| F7 | **Confirmed.** Result line on the story at merge, as for every binding unit this half. | coordinator |
