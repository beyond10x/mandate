---
format: aep.planning-md/1
id: review-result:wave2-tenancy-topology-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:tenancy-topology
tags:
- model-deviation-opus
relations:
- reviews: story:tenancy-topology
revision: 1
---
```
unit: story:tenancy-topology — working tree of impl/tenancy-topology, base 11ce4818f1280791b77a99577680c888d37af69f, implementation uncommitted
verdict: NEEDS-CHANGE
cases: executed 32→34, red 2
origin: introduced 7 / pre-existing 2 / undecided 0
wrote-outside-worktree: none
needs-coordinator: whether `cross-tenant-resource` discharges here or in story:check-api; routing the event-payload gap to story:domain-runtime (systems/mandate is this story's exclusion)
```

## 1. What I touched

```
$ git --no-pager diff --stat
 crates/mandate-model/src/lib.rs | 3 +++
 1 file changed, 3 insertions(+)
```

That diff is the implementor's, not mine — their work is uncommitted and mostly untracked, so the bound has to be read off `git status --porcelain`:

```
 M crates/mandate-model/src/lib.rs                        implementor
?? crates/mandate-model/src/graph.rs                      implementor
?? crates/mandate-model/src/tenancy.rs                    implementor
?? crates/mandate-model/tests/adversary_tenancy_topology.rs   MINE — test file
?? crates/mandate-model/tests/graph.rs                    implementor
?? crates/mandate-model/tests/projections.rs              implementor
?? crates/mandate-model/tests/tenancy.rs                  implementor
?? target                                                 build dir, untouched
```

One path is mine and it is under `tests/`. No implementation file, no existing test file, no file outside the crate was changed; no mutation was applied to any file under attack.

## 2. The cases I added — `crates/mandate-model/tests/adversary_tenancy_topology.rs`

Both red now. Red output below is the run of each case **alone**, before the suite.

**Case 1 — `every_required_projection_field_is_carried_by_a_declared_event`** (`:124`). Asserts the claim at `crates/mandate-model/src/tenancy.rs:7` and ADR 0009: every field the compiled entity marks `required` is carried by some event of its own domain. Reads `generated/schema/entities` and `generated/schema/events`. Deliberately generous — it unions *every* event of a domain, and exempts `state` (derived from the declared `moves`) and `organization_id` (read from `context.organization`, as `src/tenancy.rs:349` and `src/graph.rs:143` do).

```
$ cargo test -p mandate-model --locked --test adversary_tenancy_topology -- --exact every_required_projection_field_is_carried_by_a_declared_event
running 1 test
test every_required_projection_field_is_carried_by_a_declared_event ... FAILED

---- every_required_projection_field_is_carried_by_a_declared_event stdout ----
thread 'every_required_projection_field_is_carried_by_a_declared_event' (3487951) panicked at crates/mandate-model/tests/adversary_tenancy_topology.rs:143:5:
assertion `left == right` failed: required projection state that no event of its domain carries: the fold cannot be rebuilt from the log, so it is authoritative and not droppable
  left: ["mandate.tenancy.Organization.display_name", "mandate.tenancy.Team.display_name", "mandate.tenancy.Space.display_name", "mandate.graph.Resource.resource_type"]
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s
EXIT=101
```

**Case 2 — `a_platform_written_membership_replays_from_its_declared_event_alone`** (`:167`). Builds the contract's own "how the organization is first populated" history (`tenancy.yaml:231`) through `MembershipAuthority::PlatformOrganizationAdministration`, then replays it from the four fields `mandate.tenancy.OrganizationMembershipAdded` declares.

```
$ cargo test -p mandate-model --locked --test adversary_tenancy_topology -- --exact a_platform_written_membership_replays_from_its_declared_event_alone
running 1 test
test a_platform_written_membership_replays_from_its_declared_event_alone ... FAILED

---- a_platform_written_membership_replays_from_its_declared_event_alone stdout ----
thread 'a_platform_written_membership_replays_from_its_declared_event_alone' (3487975) panicked at crates/mandate-model/tests/adversary_tenancy_topology.rs:214:10:
the declared event carries no authority path, so replaying it must not need one: Denied { reason: Denied }

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s
EXIT=101
```

## 3. The suite, after the cases existed

```
$ cargo test -p mandate-model --locked --no-fail-fast
     Running unittests src/lib.rs                test result: ok.     0 passed; 0 failed
     Running tests/adversary.rs                  test result: ok.     2 passed; 0 failed
     Running tests/adversary_tenancy_topology.rs test result: FAILED. 0 passed; 2 failed
     Running tests/conformance.rs                test result: ok.     6 passed; 0 failed
     Running tests/graph.rs                      test result: ok.     7 passed; 0 failed
     Running tests/projections.rs                test result: ok.     7 passed; 0 failed
     Running tests/tenancy.rs                    test result: ok.     8 passed; 0 failed
   Doc-tests mandate_model                       test result: ok.     1 passed; 0 failed
                                                 test result: ok.     1 passed; 0 failed
EXIT=101
```

`<before>` = 32, measured by a second run with my target deselected (`--lib --test adversary --test conformance --test graph --test projections --test tenancy`, then `--doc`): 0+2+6+7+7+8+2 = 32, exit 0. It agrees with the `cases: 32` the implementing state reported. `<after>` = 34.

Gate still green on everything but my file: `cargo clippy -p mandate-model --all-targets --locked -- -D warnings` exit 0; `cargo fmt -p mandate-model -- --check` exit 0 (I ran `rustfmt` on my own file only).

## 4. Findings — working tree of `impl/tenancy-topology`, base `11ce4818`

| # | file:line | what is wrong | measured | reaches it | verdict | origin |
|---|---|---|---|---|---|---|
| 1 | `crates/mandate-model/src/tenancy.rs:7` | "a `Tenancy` is derived, droppable and rebuildable, never authoritative" is false. Four fields the compiled entities mark `required` are declared by no event of their domain: `Organization.display_name`, `Team.display_name`, `Space.display_name`, `Resource.resource_type`. The module named the mirror-image gap for `space_id` in its own section (`src/graph.rs:20-26`) and said nothing here; instead `display_name` became a method argument (`:229`, `:340`, `:449`) and `resource_type` is read off `ResourceRef` (`src/graph.rs:144`), neither of which any event carries | case 1, `adversary_tenancy_topology.rs:143`, exit 101 | ADR 0009 is accepted and says every read is a fold over the log; a rebuild loses all four. No backend is chosen yet, so no deployment is shown to rebuild today | NEEDS-CHANGE | introduced |
| 2 | `crates/mandate-model/src/tenancy.rs:75` | `MembershipAuthority` is a fold input that decides the outcome and that no declared event carries, so the contract's own first-membership history cannot be replayed. Deriving it from `organization_id != context.organization` means inferring the authority from the mismatch the authority was needed to write — the inference `:280-284` exists to refuse | case 2, `adversary_tenancy_topology.rs:214`, exit 101 | same as #1 | CONFIRMED | introduced |
| 3 | `systems/mandate/domains/tenancy.yaml:377` (also `:399`, `:429`, `graph.yaml:223`) | the create/register events carry no `display_name` and no `resource_type`; `ResourceRegistered` declares `context` alone | same as #1; the five schemas are byte-identical to `git show 11ce4818:…` | — | INFEASIBLE — `systems/mandate` is this story's exclusion and `story:domain-runtime`'s scope | pre-existing |
| 4 | `crates/mandate-model/src/lib.rs:7` | the crate doc's "# Credential containment — **Every record here** is declared through `mandate_types::canonical_record`, which requires each field to be a `PersistedValue`" is no longer true: six projections, seven state enums and two `Denied` structs are plain derives two lines below it. `crates/mandate-types/src/marker.rs:22` points at this crate as where that rule is pinned | read; `entries()` (`:397-404`) is unchanged, the new types never reach the macro | the next field added to any projection is outside the compile-time boundary. Nothing today names a transient type | NEEDS-CHANGE — narrow the sentence, or add a `PersistedValue` assertion for the six | introduced |
| 5 | `crates/mandate-model/tests/graph.rs:243` | doc comment "a child takes the space its parent is bound to" describes inheritance the fold does not implement and that the sibling test at `:288-316` proves absent — `space_id` is `None` for parent and child alike (`src/graph.rs:146`) | read; contradicted 45 lines later in the same file | a reader adding the space writer will believe inheritance exists and is covered | CONFIRMED — delete the clause | introduced |
| 6 | `crates/mandate-model/src/tenancy.rs:5` | "Each command's accepted outcome has a record half … and that half is one method here" overstates. `AddTeamMembership`'s accepted outcome records the manual `MembershipContribution` atomically with the membership (`tenancy.yaml:301`) and returns its identity (`:308`); `add_team_membership` takes neither and records neither, and the module never names the omission | read; method signature `src/tenancy.rs:380-386` vs `generated/schema/responses/mandate.tenancy.AddTeamMembership.schema.json` | `mandate.directory.MembershipContribution` is `story:directory-provenance`'s, so the missing thing is the record of the gap, not the record | NEEDS-CHANGE — one sentence, like the `space_id` section | introduced |
| 7 | `crates/mandate-model/src/graph.rs:126` | `src/graph.rs:16-18` claims "a distinguishable refusal would tell a caller that a resource it cannot read exists". The reason channel is closed; the accept/deny channel is not — registering a `ResourceId` another organization holds is refused, a free one is accepted, so registration is an existence oracle over the whole id space. The unit's own `tests/graph.rs:330-336` asserts exactly that outcome | read; no case written — the only assertion that would be red asserts per-tenant keying, which `graph.yaml:8-11` forbids | nothing found: no caller exists in this wave, and a `ResourceId` is a random UUID | INFEASIBLE — global `id` is the declared identity; not fixable in this story | introduced |
| 8 | `crates/mandate-model/src/tenancy.rs:483` | `Tenancy` exposes no tenant-scoped reader. `Topology` has the pair — `resolve` (`graph.rs:178`) filters organization and state, `record` (`:189`) does not — but all five `Tenancy` accessors are context-free and documented "in whatever state it holds", and `is_member`/`members_of`/`organizations_of` take no context either. `combined.md:17` ("Every tenant-owned record resolves to exactly one organization") has no expression in the tenancy API | read; asserting the missing method is a compile error, not a case, so no red | the declared consumers `story:check-api` and `story:graph-policy` must hand-roll the check `Topology` hands them | CONFIRMED | introduced |
| 9 | `tests/security/cases.json:596` | the `cross-tenant-resource` case declares `commands: ["mandate.authorization.Check"]` only — exactly like `graph-revocation`, which `.engineering/planning/story/graph-policy.md:109` routes out to `story:check-api`'s crate. This story claims it as its single case and realizes it as a `mandate-model` fold test | read; the corpus is unmodified from base | decides where the acceptance is discharged | CONFIRMED | pre-existing |

## 5. What I attacked and could not break

- The acceptance itself — `cross_tenant_resource` holds, and the guard is live: dropping the organization half of `Topology::resolves_in` reddens it, dropping the state half reddens `a_deregistered_resource_…`.
- Fail-closed — all fifteen refusal paths in both folds compute every guard before any mutation; I found no path that writes and then refuses.
- Terminal states — all six transitions guard on the initial state; none moves twice.
- Identity overwrite — all six creators check `contains_key` before insert; no overwrite in either direction across the tenant boundary.
- Dangling `parent` — `deregister` refuses while a `Recorded` child points at the record and `register` refuses a `Deregistered` parent, so I could not construct a resolving resource whose parent does not resolve.
- Cycles — a parent must already be `Recorded` and a new id must be free, so the topology is a forest by construction.
- `CloseOrganization` — `admits` gates membership, team, space and resource creation; `tenancy.yaml:208` says memberships are *preserved*, so `is_member` still answering true is the contract, not a leak.
- `RetireTeam` with an active membership — `tenancy.yaml:276` preserves memberships explicitly; the surviving `Recorded` record is correct.
- `AddOrganizationMembership` naming a foreign organization without platform authority — refused at `src/tenancy.rs:280-284`.
- Credential leakage — none of the six names a `CredentialSecret`/`CredentialProof` in any wrapper; each encodes exactly its entity's declared properties.
- `Owner::Model == 4` — `projections.rs:136` does only assert a constant from another crate, but `projections.rs:119` compares `conformance::cases()` name by name, so an entry added to `entries()` does redden this package.
- The six projections against the compiled entities — required present, no undeclared key, every state a declared variant, `deny_unknown_fields` + `value::present` matching wave 1's precedent.

## 6. Paths written outside the worktree

None. The assigned scratch directory `wave2/tenancy-topology/adversary/` was not used; no file was created anywhere outside `crates/mandate-model/tests/`.

## 7. Findings block

```findings
- file: crates/mandate-model/src/tenancy.rs
  line: 7
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the module claims the fold is derived, droppable and rebuildable, but four fields the compiled entities require are carried by no event of their domain, so a rebuild loses Organization/Team/Space display_name and Resource resource_type."
- file: crates/mandate-model/src/tenancy.rs
  line: 75
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "MembershipAuthority decides the outcome of add_organization_membership and is declared by no event, so the contract's own first-membership history cannot be replayed from the log."
- file: systems/mandate/domains/tenancy.yaml
  line: 377
  category: contract-drift
  severity: warning
  verdict: INFEASIBLE
  origin: pre-existing
  message: "OrganizationCreated, TeamCreated, SpaceCreated and ResourceRegistered omit the entity fields their projections require, and systems/mandate is this story's exclusion and story:domain-runtime's scope."
- file: crates/mandate-model/src/lib.rs
  line: 7
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the crate doc still says every record here is declared through canonical_record and so bounded by PersistedValue, which the six new projections and their state enums are not."
- file: crates/mandate-model/tests/graph.rs
  line: 243
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "the doc comment promises that a child takes the space its parent is bound to, which the fold never does and the sibling test 45 lines later proves absent."
- file: crates/mandate-model/src/tenancy.rs
  line: 5
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the module says each accepted outcome's record half is one method here, but AddTeamMembership also records the manual MembershipContribution and returns its identity, and the omission is nowhere named."
- file: crates/mandate-model/src/graph.rs
  line: 126
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "registration refuses an identity another organization holds and accepts a free one, which is the cross-tenant existence oracle the module says it closed, and per-tenant keying would contradict the globally declared ResourceId identity."
- file: crates/mandate-model/src/tenancy.rs
  line: 483
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "Tenancy offers no tenant-scoped reader to pair with Topology::resolve, so every tenancy accessor is context-free and the isolation rule combined.md:17 states has no expression in the API its declared consumers will use."
- file: tests/security/cases.json
  line: 596
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: "the cross-tenant-resource case names mandate.authorization.Check only, like graph-revocation which story:graph-policy routes out to story:check-api, yet this story claims it and realizes it as a mandate-model fold test."
```