---
format: aep.planning-md/1
id: review-result:wave2-graph-policy-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:graph-policy
tags:
- model-deviation-opus
relations:
- reviews: story:graph-policy
revision: 1
---
```
unit: story:graph-policy — working tree at <worktree>, branch impl/graph-policy, uncommitted over base 11ce4818
verdict: CONFIRMED (blocker)
cases: executed 97→103, red 4
origin: introduced 7 / pre-existing 0 / undecided 0
wrote-outside-worktree: 1 directory, 114M (listed in part 6)
needs-coordinator: none
```

## 1. `git --no-pager diff --stat`

```
 crates/mandate-graph/src/lib.rs  | 77 ++++++++++++++++++++++++++++++++++++++--
 crates/mandate-policy/src/lib.rs | 62 ++++++++++++++++++++++++++++++--
 2 files changed, 135 insertions(+), 4 deletions(-)
```

Both of those are the **implementor's** uncommitted work, not mine — I changed no tracked file. My own additions are untracked, and `git status --porcelain -uall | grep adversary` is the whole of what I wrote in the worktree:

```
?? crates/mandate-graph/tests/adversary_double.rs
?? crates/mandate-policy/tests/adversary_precedence.rs
```

Two paths, both test files. No implementation file was edited, briefly or otherwise; the two guard mutations were made on copies in scratch and compiled with `rustc` against the existing dep rlibs.

## 2. The cases I added, and their red output when written

`crates/mandate-graph/tests/adversary_double.rs` — 4 cases (2 red, 2 green-on-tree/red-on-mutant)
`crates/mandate-policy/tests/adversary_precedence.rs` — 2 cases (2 red)

**A. `adversary_precedence.rs:96 a_deny_rule_is_not_overridden_by_an_allow_recorded_before_it`** — red.

```
running 1 test
test a_deny_rule_is_not_overridden_by_an_allow_recorded_before_it ... FAILED
thread '...' panicked at crates/mandate-policy/tests/adversary_precedence.rs:107:5:
assertion `left == right` failed: combined.md:53 (cited by double.rs:12) says denies override grants, and the double holds a deny for exactly this request
  left: Allow
 right: Deny
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
```

**B. `adversary_double.rs:76 a_grant_for_a_subject_the_double_was_never_told_about_is_not_an_allow`** — red.

```
running 1 test
test a_grant_for_a_subject_the_double_was_never_told_about_is_not_an_allow ... FAILED
thread '...' panicked at crates/mandate-graph/tests/adversary_double.rs:102:5:
double.rs:7-9 promises a subject the double was never told about is refused, and port.rs:86-87 declares SubjectUnresolved as a reason check cannot answer; the read path consults no membership at all and answered Ok(Observed { revision: AuthzRevision("3"), through: ResourceRef { resource_type: ResourceType("document"), resource_id: ResourceId(Uuid([10, ...])) } })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
```

**C. `adversary_double.rs:123 a_resource_is_identified_the_same_way_by_the_write_path_and_the_deregister_path`** — red.

```
running 1 test
test a_resource_is_identified_the_same_way_by_the_write_path_and_the_deregister_path ... FAILED
thread '...' panicked at crates/mandate-graph/tests/adversary_double.rs:150:5:
the write path recorded two records for one declared identity (Recorded) and the deregister path then moved both of them in one reported move (Recorded); graph.yaml:8-11 identifies a Resource by its ResourceId alone
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
```

**D. `adversary_precedence.rs:129 combining_in_groups_agrees_with_combining_all_at_once_when_a_group_is_empty`** — red.

```
running 1 test
test combining_in_groups_agrees_with_combining_all_at_once_when_a_group_is_empty ... FAILED
thread '...' panicked at crates/mandate-policy/tests/adversary_precedence.rs:136:5:
assertion `left == right` failed: precedence.rs:95-96 claims combining is associative; an empty group injects Denied(Denied) into a combination that is otherwise Allowed
  left: Denied(Denied)
 right: Allowed
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
```

**E/F — the two mutant-catching cases. Green on the tree, red on a mutated copy.** `adversary_double.rs:167 a_space_confined_grant_contributes_no_authority` and `:225 a_grant_owned_by_another_organization_answers_nothing_in_this_one` both pass against the tree. The probe: I copied `crates/mandate-graph/src/` into scratch twice and deleted one guard in each copy (mutant 1 drops `&& grant.scope.space.is_none()` at `double.rs:165`; mutant 2 drops the two `organization` comparisons at `double.rs:153` and `:163`), built each copy as an rlib with `rustc`, and ran **the implementor's seven test files** against them:

```
                 mutant 1                                mutant 2
boundary       2 passed 0 failed                       2 passed 0 failed
double        11 passed 0 failed                      11 passed 0 failed
port           7 passed 0 failed                       7 passed 0 failed
record         6 passed 0 failed                       6 passed 0 failed
relationship   6 passed 0 failed                       6 passed 0 failed
revocation    11 passed 0 failed                      11 passed 0 failed
topology       9 passed 0 failed                       9 passed 0 failed
```

All 52 existing cases stay green under both mutants. My two cases do not:

```
---- a_space_confined_grant_contributes_no_authority stdout ----   [mutant 1]
a grant confined to a space carries no authority outside it; double.rs:165 is the only thing
refusing it and nothing else asserts it: Ok(Observed { revision: AuthzRevision("3"), through: ... })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out

---- a_grant_owned_by_another_organization_answers_nothing_in_this_one stdout ----   [mutant 2]
another organization's grant must not answer this organization's check: Ok(Observed { revision:
AuthzRevision("3"), through: ... })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out
```

## 3. The suite, after the cases existed

`cargo test -p mandate-graph -p mandate-policy --locked --no-fail-fast` → **exit 101**. Summary lines, verbatim:

```
     Running tests/adversary_double.rs
running 4 tests
test a_grant_for_a_subject_the_double_was_never_told_about_is_not_an_allow ... FAILED
test a_resource_is_identified_the_same_way_by_the_write_path_and_the_deregister_path ... FAILED
test result: FAILED. 2 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/boundary.rs        test result: ok. 2 passed; …
     Running tests/double.rs          test result: ok. 11 passed; …
     Running tests/port.rs            test result: ok. 7 passed; …
     Running tests/record.rs          test result: ok. 6 passed; …
     Running tests/relationship.rs    test result: ok. 6 passed; …
     Running tests/revocation.rs      test result: ok. 11 passed; …
     Running tests/topology.rs        test result: ok. 9 passed; …
     Running tests/adversary_precedence.rs
running 2 tests
test combining_in_groups_agrees_with_combining_all_at_once_when_a_group_is_empty ... FAILED
test a_deny_rule_is_not_overridden_by_an_allow_recorded_before_it ... FAILED
test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/boundary.rs        test result: ok. 2 passed; …
     Running tests/double.rs          test result: ok. 14 passed; …
     Running tests/port.rs            test result: ok. 7 passed; …
     Running tests/precedence.rs      test result: ok. 12 passed; …
     Running tests/record.rs          test result: ok. 6 passed; …
   Doc-tests mandate_graph            ok. 1 passed;   ok. 1 passed;
   Doc-tests mandate_policy           ok. 1 passed;   ok. 1 passed;
```

97 implementor cases (52 graph + 41 policy + 4 doctests — matching the number the implementing state declared) plus my 6 = 103 executed, 4 red. `cargo fmt -p mandate-graph -p mandate-policy -- --check` exits 0 and `cargo clippy -p mandate-graph -p mandate-policy --all-targets --locked -- -D warnings` is clean with my files present, so the red is assertions and nothing else. Full log: `…/adversary/suite-final.log`.

## 4. Findings

Every finding is against the working tree above. `git show 11ce4818:crates/mandate-graph/src/double.rs` → *"exists on disk, but not in 11ce4818"*; at the base both crate roots are the 4-line scaffold. So **every origin is `introduced`** — there is no base behaviour to reproduce against.

| # | file:line | What is wrong | Verdict / severity / origin | What was measured | What reaches it |
|---|---|---|---|---|---|
| 1 | `crates/mandate-policy/src/double.rs:182` | `evaluate` resolves its own rules with `.find()`, so the rule recorded **first** answers. A `deny` recorded after an `allow` for the identical `(organization, subject, action, resource)` is never seen: the double answers `Allow` while holding a `Deny` for that exact request, and the answer flips with recording order. `docs/architecture/combined.md:53` — cited by `double.rs:12` and `precedence.rs:3` — says denies override grants; `lib.rs:5` names `precedence` the single home of that rule and the double bypasses it. | CONFIRMED / blocker / introduced | `adversary_precedence.rs:107`, `left: Allow, right: Deny`, exit 101 | `PolicyDouble::allow` and `::deny` are both public and neither rejects an overlapping tuple; the story's *"What `story:check-api` needs"* section names the deny-precedence combinator and publicly constructible doubles, so a grant-then-deny scenario is the canonical setup for that consumer. **Fix (named, not applied):** collect every matching rule and fold it through `crate::precedence::combine`, or at minimum let `PolicyEffect::Deny` win over the rest. |
| 2 | `crates/mandate-graph/src/double.rs:420` | `GraphRead::check` never consults membership. `double.rs:7-9` says of this double "What it does *not* know, it refuses … a subject the double has not been told about is `Unanswered::SubjectUnresolved`, not an admission", and `port.rs:86-87` declares `SubjectUnresolved` as one of the four reasons `check` can fail to answer for. The read path can never produce it; it answers `Ok(Observed)` — an allow — for a subject the double was never told about. | CONFIRMED / warning / introduced | `adversary_double.rs:102`, answered `Ok(Observed { revision: AuthzRevision("3"), through: … })` | `record_grant` (`double.rs:93`) is documented as the only way a grant enters the fold and validates nothing, so any scenario that seeds a grant without calling `admit_subject` gets an allow. **Fix:** `check` calls `SubjectAdmission::admits` before `holds`, or `record_grant` refuses a subject it was not told about. |
| 3 | `crates/mandate-graph/src/double.rs:126` | The write path keys a resource by the whole `ResourceRef` (`entry`, `:126`) and the deregister path by the `ResourceId` alone (`:289-293`). `graph.yaml:8-11` declares `mandate.graph.Resource`'s identity as `id: ResourceId` with `resource_type` a field, and `DeregisterResource` takes `instance: id`. Consequence: a second registration of one identity under another type is reported `Recorded` — a second record for one identity — and one `DeregisterResource` then moves both while reporting one move, against `topology.rs:72-73` and `graph.yaml:205` ("no child resource, relation or grant is destroyed as a side effect of this one"). The two halves cannot both be right. | NEEDS-CHANGE / warning / introduced | `adversary_double.rs:150`, second register `Recorded`, both refs then unresolvable from one reported move | `register_resource` takes a `ResourceRef` and nothing rejects a recorded id under a second type — but **nothing found** that does it: I constructed the state. The drift against `graph.yaml`'s declared identity stands regardless. **Fix:** key `entry` by `resource_id`. |
| 4 | `crates/mandate-policy/src/precedence.rs:95` | The doc says "combining is commutative and associative" and `Combined::component` (`:57-58`) exists "so results can be combined further". It is not associative over an empty group: `combine(&[])` is `Denied` (`:122`), and that denial survives into the combination, where flattening the same components allows. The existing `combining_is_associative` (`tests/precedence.rs:77`) uses only non-empty groups. | CONFIRMED / note / introduced | `adversary_precedence.rs:136`, `left: Denied(Denied), right: Allowed` | `Combined::component` is public and documented for exactly this composition; no caller exists in this wave — `story:check-api` consumes it later. Fail-closed, so the risk is a lost allow, not a leaked one. **Fix:** a doc line saying combination in groups is only associative over non-empty groups, or `combine` returning `Option`. |
| 5 | `crates/mandate-graph/src/double.rs:165` | The space-confinement guard is dead weight as far as the suite is concerned: no case in `crates/mandate-graph/tests/**` constructs `AuthorityScope.space` as anything but `None` (`grep -rn space` finds two hits, both `space: None`). Deleting the guard leaves all 52 cases green; the implementor reports this behaviour as a deliverable. | CONFIRMED / warning / introduced | mutant 1 probe, 52/52 green with the guard removed; `adversary_double.rs:204` red against the mutant, green against the tree | The guard is correct today — the finding is that nothing was holding it. The case is supplied. |
| 6 | `crates/mandate-graph/src/double.rs:163` | Same for both tenancy comparisons in `holds` (`:153` relations, `:163` grants). Every tenancy case in the suite is refused earlier by `placement` or `admits`, so none reaches `holds`; deleting both comparisons leaves all 52 green, and a check then answers with another organization's grant. | CONFIRMED / warning / introduced | mutant 2 probe, 52/52 green with both comparisons removed; `adversary_double.rs:254` red against the mutant, green against the tree | The grant branch is pinned by the case I added. The relation branch at `:153` cannot be reached from outside the crate — `write_relationship` enforces tenancy, so no public API can insert a cross-organization `Relation` — and it is therefore untestable from an integration test. Named as residue, not fixed. |
| 7 | `crates/mandate-graph/src/relationship.rs:92` | `admit` trims the relation name to test emptiness but stores it untrimmed, and `holds` compares exactly. `" viewer "` is accepted as a relation distinct from `"viewer"`, indistinguishable in a log line and never matching a check for `"viewer"`. Judgement only — fail-closed, and I wrote no case for it. | CONFIRMED / note / introduced | read of `relationship.rs:92` against `double.rs:151-157`; no case | `RelationshipWrite.relation` is a caller-supplied `&str` with no normalization anywhere on the path. **Fix:** store `relation.trim()`, or reject a name that differs from its trim. |

## 5. Attacked and could not break

- **The seal on both port traits.** A scratch crate implementing `mandate_graph::port::Revision` for a local `BackendToken`, and `mandate_policy::port::AttributeInput` for a local `BackendRow`, both fail with `E0277: the trait bound … : port::sealed::Sealed is not satisfied` — so the two `compile_fail` doctests fail for the reason they claim, not incidentally.
- **`topology::ancestry` termination.** The cycle guard plus `chain.len() == MAX_ANCESTRY_DEPTH` both hold; a `ResourceLookup` that returns a `Placement.resource` different from the ref asked for defeats the `contains` check, but the depth bound still terminates it as `HierarchyUnbounded`.
- **The revision-bound read.** `caught_up_to` is exact membership in the issued list — no text ordering of an opaque token anywhere — and `require_revision` runs before any authority is looked at, so a stale reader answers neither allowed nor denied.
- **The acceptance itself.** A revoked grant is denied at R, at any earlier floor, and through the inherited path; the same for a removed relation. I could not construct an allow after revocation.
- **Idempotency.** `WriteRelationship`, `RemoveRelation`, `RevokeGrant`, `RegisterResource`, `DeregisterResource`, `SupersedePolicy`, `SupersedeAuthorizationModel` all return `AlreadyRecorded` and issue no second revision on a repeat.
- **Space-confined grants and `Evaluation`.** A `scope.space = Some(_)` grant only ever denies (see finding 5 for the coverage gap, not a behaviour gap); `Evaluation` carries a `PolicyEffect` and no `Decision`. No engine name in either crate (`grep -riE 'spicedb|openfga|zanzibar|authzed|cedar|rego|casbin|postgres|redis|sqlite|dynamo|keto|permify'` → exit 1).
- **Deregistered resources and superseded records.** A deregistered resource stops resolving as a parent and as a subject of a check; a superseded policy or model is skipped by `current_policy` / `current_model`.
- **`precedence::combine` order-independence** for non-empty inputs: the minimum-rank refusal makes it commutative, and `DenialReason::VARIANTS` puts `Denied` first, so a real denial is never masked by an `Unavailable`.
- The implementor's "revision issued only by `WriteRelationship`" is loose — the double advances on register, deregister, remove, revoke and `record_grant` too — but `topology.rs:52-57` documents that deliberately and `WriteRelationship` is the only contract-declared `revision` response. Not a finding.

## 6. Paths written outside the worktree

`<scratch>/` — 114M, the assigned scratch root, nothing outside it and nothing under `/tmp`:

- `mutant-graph/src/`, `mutant2-graph/src/` — copies of `crates/mandate-graph/src/` with one guard deleted each
- `libmandate_graph_mutant.rlib`, `libmandate_graph_mutant2.rlib` — the mutated crates built with `rustc`
- `mutant_*.bin`, `mutant2_*.bin`, `advmut1.bin`, `advmut2.bin` — the implementor's and my test files compiled against those (110M of the 114M)
- `seal_probe_graph.rs`, `seal_probe_policy.rs` — the seal probes (they do not compile, by design)
- `suite.log`, `suite-nff.log`, `suite-final.log`

```findings
- file: crates/mandate-policy/src/double.rs
  line: 182
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "PolicyDouble::evaluate answers with the first matching rule, so an allow recorded before a deny for the identical request answers Allow while the double holds that deny, against combined.md:53 which its own module header cites."
- file: crates/mandate-graph/src/double.rs
  line: 420
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "GraphRead::check consults no membership, so a grant recorded for a subject the double was never told about is answered as an allow, where double.rs:7-9 promises a refusal and port.rs:86-87 declares SubjectUnresolved as a reason check cannot answer."
- file: crates/mandate-graph/src/double.rs
  line: 126
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the double keys a resource by ResourceRef when registering and by ResourceId when deregistering, so one declared identity becomes two records and one DeregisterResource moves both while reporting one move."
- file: crates/mandate-policy/src/precedence.rs
  line: 95
  category: property
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "combine is documented as associative but an empty group folds to Denied and poisons a combination that flattening would allow."
- file: crates/mandate-graph/src/double.rs
  line: 165
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "deleting the space-confinement guard leaves all 52 existing cases green, so nothing in the suite was holding the fail-closed behaviour the implementor reports as a deliverable."
- file: crates/mandate-graph/src/double.rs
  line: 163
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "deleting both tenancy comparisons in holds also leaves all 52 cases green, because every tenancy case in the suite is refused earlier by placement or admits and none reaches holds."
- file: crates/mandate-graph/src/relationship.rs
  line: 92
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "admit trims the relation name only to test emptiness and stores it untrimmed, so a whitespace-padded name is a distinct relation that reads identically in a log and never matches a check."
```