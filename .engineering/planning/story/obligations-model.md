---
format: aep.planning-md/1
id: story:obligations-model
kind: story
status: implemented
title: Bind mandate-model's denial clauses to real-path tests
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- depends_on: story:obligation-registry
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/model.json
- confidence: inferred
  path: crates/mandate-model/src/tenancy.rs
- confidence: cited
  path: crates/mandate-model/tests/obligations.rs
revision: 8
---
## Why

`story:obligation-registry` (wave D second half) authors `contracts/obligations.json`, the clause-level map from every implemented command's external denial clauses to the real-path tests that decide them. The binding for `mandate-model` is one file this story owns: 10 commands, ~49 clauses; no clause vocabulary today (scoper's estimate on `6d812e0`, split of each IR `condition.cause` on comma/`or`; granularity checked against `services/sts/tests/declared_denials.rs:108`). Until it lands, the registry carries `blocked_on: story:obligations-model` for every unbound clause of this crate and the step stays green.

## Outcome

`crates/mandate-model/tests/obligations.rs` decides every clause of the crate's implemented commands on the real path — one denial case per clause naming the clause verbatim, one no-state-change case per command — and `contracts/obligations.json` names each; the crate's rows in `contracts/conformance/obligations-report.json` move from `deferred` to `real_covered`.

## Acceptance

`cargo xtask obligations-registry` reports no clause of a `mandate-model` command as `deferred` on this story, and `cargo test -p mandate-model --locked --test obligations` is green.

- Result (2026-09-21, at merge): the Outcome above said `crates/mandate-model/tests/obligations.rs` would decide **every** clause of the crate's implemented commands on the real path, one denial case per clause, and that the crate's rows would move from `deferred` to `real_covered`. Of 42 clauses the unit leaves **12 real, 0 double and 30 re-pointed** — `decision-blocker:guards` 14, `decision-blocker:epoch-atomicity` 9, `story:directory-provenance` 3, `story:declared-writers` 3, `decision-blocker:lifecycle` 1 — plus 7 `cases` rows re-pointed per their own `story` field. No case exists for any of the ten `Caller lacks …` clauses, because authority is `mandate-authz`'s and `crates/mandate-model/src/tenancy.rs:93-96` says so: `MembershipAuthority` is the caller's statement, not a grant. Final table `mandate-model 42 / 12 / 0 / 30` (`cargo run -p xtask -- obligations-registry`, coordinator verification 2026-09-21). The Acceptance — "no clause of a `mandate-model` command is `deferred` on this story" — is met by re-pointing as well as by binding.
- Two adversary passes, and the second one is why the clause count is 42 rather than 41. `AddOrganizationMembership` published "organization_id differs from the verified organization **and** the caller lacks platform organization-administration authority" as one clause decided on the real path, while the same command deferred its sibling authority clause to `decision-blocker:guards` for the reason that the fold decides authority nowhere. Both rest on the same unvalidated input: the adversary wrote a membership into another organization by naming `MembershipAuthority::PlatformOrganizationAdministration`, so the row established that the fold refuses a caller which *says* it lacks platform authority, not one that lacks it. Split per `contracts/obligations/README.md`, as correction 1 had already done for `AddTeamMembership`.
- **The citation defect, and the check that ends it.** Adversary 2 found that all thirteen `src/tenancy.rs` citations in `tests/obligations.rs` were 73 lines stale — correction 1's own rewrite of the fold's doc section moved the `impl Tenancy` block down and left every citation behind, so `:917`, cited for `holds_team_membership`, was `self.apply(&event);` inside `create_team`. It proved the case was exactly sensitive to the defect by re-implementing the rule outside the tree and applying a uniform offset: +0 fails 10 of 10 rows, +73 fails 0. This was the third unit in one wave to report that it had re-read its citations and not have. Correction 2 therefore landed the check rather than the numbers: `every_citation_this_file_makes_states_what_it_is_cited_for` scrapes the file's own doc comments and closes three sets in both directions — 21 `file:line` spans, every attributed quotation, and 5 files named without a line — so a citation cannot be added without being checked, and a span that stops holding its phrase fails the suite. It caught the correction's own regression immediately: adding one bullet to the fold's doc shifted 18 spans by +2.
- One part of the class remains unmachine-checked and is recorded rather than claimed: a quotation attributed to prose ("the declared cause reads …") names no file, so nothing resolves it. The check covers citations that name a file or a span.
