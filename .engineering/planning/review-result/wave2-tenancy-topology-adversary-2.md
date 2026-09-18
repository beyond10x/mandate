---
format: aep.planning-md/1
id: review-result:wave2-tenancy-topology-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:tenancy-topology
tags:
- model-deviation-opus
relations:
- reviews: story:tenancy-topology
revision: 1
---
```
unit: story:tenancy-topology — working tree of impl/tenancy-topology after correction-1, base 11ce4818f1280791b77a99577680c888d37af69f, implementation uncommitted
verdict: NEEDS-CHANGE
cases: executed 37→40, red 1
origin: introduced 5 / pre-existing 0 / undecided 0
wrote-outside-worktree: 14 paths under <scratch>/ (part 6)
needs-coordinator: none — the one blocker is a one-line fix inside src/tenancy.rs, which is the implementor's
```

## 1. What I touched

```
$ git --no-pager diff --stat
 crates/mandate-model/src/lib.rs | 20 +++++++++++++++++---
 1 file changed, 17 insertions(+), 3 deletions(-)
```

That diff is the implementor's. Their work is untracked, so the bound is read off `git status --short`:

```
 M crates/mandate-model/src/lib.rs                            implementor
?? crates/mandate-model/src/graph.rs                          implementor
?? crates/mandate-model/src/tenancy.rs                        implementor
?? crates/mandate-model/tests/adversary_tenancy_topology.rs   MINE — test file
?? crates/mandate-model/tests/graph.rs                        implementor
?? crates/mandate-model/tests/projections.rs                  implementor
?? crates/mandate-model/tests/tenancy.rs                      implementor
?? target                                                     build dir, untouched
```

One path is mine and it is under `tests/`. `src/tenancy.rs`, `src/graph.rs` and `src/lib.rs` are byte-identical to the copies I took before the first probe (`diff` clean, part 6). Every mutation ran on a scratch copy. Pass 1's two cases, including the coordinator's tripwire assertion, are unchanged; I added imports, two id helpers and three cases.

## 2. The cases I added — `crates/mandate-model/tests/adversary_tenancy_topology.rs`

**Case 3 — `a_closed_organization_admits_no_membership_through_the_half_that_writes` (`:259`) — RED.** Run alone, before the suite:

```
$ cargo test -p mandate-model --locked --test adversary_tenancy_topology -- --exact a_closed_organization_admits_no_membership_through_the_half_that_writes
running 1 test
test a_closed_organization_admits_no_membership_through_the_half_that_writes ... FAILED

---- a_closed_organization_admits_no_membership_through_the_half_that_writes stdout ----
thread '...' panicked at crates/mandate-model/tests/adversary_tenancy_topology.rs:276:10:
a closed organization admits no new membership: ()

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
EXIT=101
```

`: ()` is the `Ok(())` the fold returned: it wrote an `Active` membership into a `Closed` organization.

**Case 4 — `a_removal_is_confined_to_the_verified_organization` (`:315`) — GREEN now, red under two described mutants.**
**Case 5 — `a_closed_organization_admits_no_new_team_membership` (`:390`) — GREEN now, red under one described mutant.**
These pin three guards that the unit's 37 cases do not execute. Each mutant was applied to the scratch copy, run, and reverted; the copies are back to the worktree source:

```
### MUTANT D2 — remove_organization_membership: `membership.organization_id != context.organization` deleted (src/tenancy.rs:409)
test a_removal_is_confined_to_the_verified_organization ... FAILED
panicked at .../adversary_tenancy_topology.rs:344:14:
a membership of another organization is not the outsider's to remove: ()
  existing tenancy       ok. 11 passed; 0 failed
  existing graph         ok. 7 passed; 0 failed
  existing projections   ok. 7 passed; 0 failed

### MUTANT D3 — remove_team_membership: same guard deleted (src/tenancy.rs:519)
test a_removal_is_confined_to_the_verified_organization ... FAILED
panicked at .../adversary_tenancy_topology.rs:359:14:
a team membership of another organization is not the outsider's to remove: ()
  existing tenancy       ok. 11 passed; 0 failed   (graph 7/0, projections 7/0)

### MUTANT D1 — add_team_membership: `!self.admits(context.organization)` deleted (src/tenancy.rs:478)
test a_closed_organization_admits_no_new_team_membership ... FAILED
panicked at .../adversary_tenancy_topology.rs:419:14:
a closed organization admits no new team membership: ()
  existing tenancy       ok. 11 passed; 0 failed   (graph 7/0, projections 7/0)
```

## 3. The suite, after all three cases existed

```
$ cargo test -p mandate-model --locked --no-fail-fast
     Running unittests src/lib.rs                running 0 tests   test result: ok.      0 passed; 0 failed
     Running tests/adversary.rs                  running 2 tests   test result: ok.      2 passed; 0 failed
     Running tests/adversary_tenancy_topology.rs running 5 tests   test result: FAILED.  4 passed; 1 failed
       test a_closed_organization_admits_no_membership_through_the_half_that_writes ... FAILED
     Running tests/conformance.rs                running 6 tests   test result: ok.      6 passed; 0 failed
     Running tests/graph.rs                      running 7 tests   test result: ok.      7 passed; 0 failed
     Running tests/projections.rs                running 7 tests   test result: ok.      7 passed; 0 failed
     Running tests/tenancy.rs                    running 11 tests  test result: ok.     11 passed; 0 failed
   Doc-tests mandate_model                       running 1 test    test result: ok.      1 passed; 0 failed
                                                 running 1 test    test result: ok.      1 passed; 0 failed
error: 1 target failed:  `-p mandate-model --test adversary_tenancy_topology`
EXIT=101
```

`<after>` = 40. `<before>` = 37, the `cases:` line the implementing state reported when it declared the work green; it reconciles exactly (40 − 3). `cargo clippy -p mandate-model --all-targets --locked -- -D warnings` exit 0; `cargo fmt -p mandate-model -- --check` exit 0.

## 4. Findings — working tree of `impl/tenancy-topology`, base `11ce4818`

| # | file:line | what is wrong | measured | what reaches it | verdict | severity | origin |
|---|---|---|---|---|---|---|---|
| 1 | `crates/mandate-model/src/tenancy.rs:376` | `add_organization_membership` — the only method that writes the row — tests `self.organizations.contains_key(&organization_id)` where `create_team` (`:433`), `create_space` (`:542`) and `add_team_membership` (`:478`) test `self.admits(...)`. `tenancy.yaml` denies AddOrganizationMembership when "the named organization is closed"; CloseOrganization: "The tenant stops admitting authority." The closed rule is not the authority rule and the correction's reason does not reach it: `OrganizationClosed` declares `id`, so a replayer can evaluate it, which is the test `src/tenancy.rs:52-54` sets for a guard that may stay in the fold. Correction-1 moved it out anyway, and pass 1 had recorded `admits` as gating membership. **Fix: `if !self.admits(organization_id)` at `:376`** | case 3, `adversary_tenancy_topology.rs:276`, exit 101. With that one line applied to a scratch copy: my case goes green and all 25 cases of `tests/{tenancy,graph,projections}.rs` stay green, pass-1's replay case included | the module's own decide-then-apply protocol (`:46-50`) with a closure between the two calls; also any caller of the apply half alone, which is 10 of the unit's own 13 apply call sites. No caller outside this crate exists yet | CONFIRMED | blocker | introduced |
| 2 | `crates/mandate-model/src/tenancy.rs:365-378` | the apply half accepts `context` and `authority` and reads neither (`let _ = (context, authority);`). Nothing enforces the pair — no witness type, no state, no assertion — so the signature advertises a decision it does not make, and the one rule that is genuinely un-replayable is enforced only if a caller volunteers to call `may_` first | census of the unit's own tests: 10 apply call sites, 5 decide call sites, and exactly one test (`tests/tenancy.rs:489`) applies after deciding; `grep -rn add_organization_membership crates/` finds no caller outside `crates/mandate-model/tests/` | nothing outside this crate today. Fix #1 removes the sharp edge; the misleading signature stays. Fix: drop the two unread parameters, or have `may_` return a `Decided` witness the apply half consumes | CONFIRMED | warning | introduced |
| 3 | `crates/mandate-model/src/tenancy.rs:409`, `:478`, `:519` | three guards no case executes, two of them the tenant-isolation guard on a removal — `remove_organization_membership` and `remove_team_membership` refusing a caller verified in another organization (`tenancy.yaml`: "membership is outside the verified organization"), and `add_team_membership` refusing a closed organization. `a_closed_organization_admits_no_new_membership_team_or_space` covers membership, team and space and not team membership | mutants D1/D2/D3 in part 2: each deleted guard leaves all 25 cases of `tests/{tenancy,graph,projections}.rs` green | the story's own subject. Cases 4 and 5 now pin all three; the action owed is to keep them | CONFIRMED | warning | introduced |
| 4 | `crates/mandate-model/src/tenancy.rs:72-79` | "# Every refusal carries one reason" says a cross-tenant and an unrecorded record "refuse identically here" and stops, which is the claim correction row 7 made `src/graph.rs:17-33` extend: the **reason** channel is closed, the **accept/deny** channel is not. It is not closed in this module either — `create_team`/`create_space`/`add_*_membership` all key `contains_key` globally, so a caller learns whether a `TeamId`, `SpaceId` or membership id is held by another tenant. The twin was corrected and this one was not | read; `:433`, `:542`, `:376`, `:487` are all global `contains_key`. No case written: the only red assertion would demand per-organization keying, which the declared identities forbid, exactly as `graph.yaml:8-11` forbids it for `ResourceId` | a UUID id space bounds it, as `src/graph.rs:30-33` already says. Fix is the same paragraph graph.rs now carries | CONFIRMED | note | introduced |
| 5 | `crates/mandate-model/src/tenancy.rs:60-69` | CreateOrganization, CreateTeam and CreateSpace each deny when "the display name is not admitted" and the fold admits every string, `""` included, untrimmed; the module names the `MembershipContribution` omission and the four-field gap and does not name this one. Nothing compares display names, so no whitespace-padded duplicate arises today | read; `generated/schema/entities/mandate.tenancy.Organization.schema.json` declares `display_name` as a bare `{"type":"string"}`, so nothing is violated — the rule is undefined, not broken | nothing found: no admission rule exists anywhere to implement. Owed is one sentence naming it, like the `space_id` and `MembershipContribution` sections | INFEASIBLE — the rule the contract denies on is not specified anywhere, so it cannot be implemented here | note | introduced |

## 5. What I attacked and could not break

- **The acceptance.** `cross_tenant_resource` holds, and the guard is live after the correction: deleting the organization half of `Topology::resolves_in` reds it plus two more (4 passed/3 failed); deleting the state half reds `a_deregistered_resource_…` (6/1).
- **The compile-time boundary (correction row 4).** Both halves enforce. A field added to `Organization` and not named in the `const _` block: `error[E0027]: pattern does not mention field 'probe'`. The same field named in the block, of a local type with no `PersistedValue` impl: `error[E0277]: the trait bound 'NotPersistable: PersistedValue' is not satisfied`. The claim at `src/lib.rs:8-18` is exact.
- **`RegisterResource`'s unrecoverable fields.** `generated/schema/events/mandate.graph.ResourceRegistered.schema.json` declares `context` and nothing else, and the accepted outcome carries no `moves` and no `instance`; `src/graph.rs:43-52` is true as written.
- **Fold order across organizations.** Two organizations' streams sharing one principal, folded sequentially, interleaved and reversed, produce equal `Tenancy` values (scratch probe). Not order-sensitive across tenants.
- **A duplicated event on replay.** Refused, and the fold is unchanged — non-idempotent but safe; a replayer must tolerate `Err`, which no doc says. Within one organization the fold does require its log in order: a `TeamCreated` applied before its `OrganizationCreated` is refused and lost, with no repair when the organization arrives.
- **`resolve_*` (correction row 8).** `None` for absent and for another tenant's alike, and `None` once a record reaches its terminal state; the record readers still answer. `is_member`/`members_of` answering for a closed organization is the contract (memberships are preserved), as pass 1 found.
- **Deleted space-inheritance clause (row 5), `MembershipContribution` omission (row 6), `graph.rs` existence-oracle correction (row 7), the four-field module doc (row 1)** — all present and accurate.
- **decide→apply disagreement in the other direction.** No state where `may_` returns `Ok` and apply refuses; the identity is minted for the event `may_` admits.
- **Fail-closed** — every guard in both folds computes before any mutation; no path writes and then refuses.

## 6. Paths written outside the worktree

All under the assigned scratch root `<scratch>/` (48M total, dominated by the rlib and five test binaries):

```
<scratch>/mutant/lib.rs
<scratch>/mutant/tenancy.rs
<scratch>/mutant/tenancy.rs.orig
<scratch>/mutant/graph.rs
<scratch>/mutant/graph.rs.orig
<scratch>/probe.sh
<scratch>/replay_probe.rs
<scratch>/out/libmandate_model.rlib
<scratch>/out/t_tenancy
<scratch>/out/t_graph
<scratch>/out/t_projections
<scratch>/out/t_adversary_tenancy_topology
<scratch>/out/t_adv
<scratch>/out/replay_probe
```

No `CARGO_TARGET_DIR` was set; the mutants were compiled with `rustc` directly against the worktree's already-built `libmandate_types`/`libserde` rlibs, writing only into the scratch `out/` directory. Nothing under `/tmp`. Lease `adversary-tenancy-topology-2` taken at start, heartbeat once, `session-end` run.

## 7. Findings block

```findings
- file: crates/mandate-model/src/tenancy.rs
  line: 376
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "add_organization_membership tests contains_key where its three siblings test admits, so the only method that writes the row records an Active membership into a Closed organization, which tenancy.yaml denies and no accepted history produces; the one-line fix to !self.admits(organization_id) keeps all 25 existing cases green."
- file: crates/mandate-model/src/tenancy.rs
  line: 365
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "the apply half accepts context and authority and reads neither, and nothing in the type system or the crate enforces decide-then-apply: 10 of the unit's 13 apply call sites never call may_add_organization_membership first."
- file: crates/mandate-model/src/tenancy.rs
  line: 409
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "three guards execute in no case - the verified-organization guard on both removals and the closed-organization guard on add_team_membership - and deleting any of them leaves all 37 cases green; cases 4 and 5 in tests/adversary_tenancy_topology.rs now pin them."
- file: crates/mandate-model/src/tenancy.rs
  line: 72
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "the refusal section makes the same partial claim correction row 7 forced src/graph.rs to extend: the reason channel is closed and the accept/deny channel is not, because create_team, create_space and the membership writers all key contains_key globally."
- file: crates/mandate-model/src/tenancy.rs
  line: 60
  category: acceptance
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "three commands deny when the display name is not admitted and the fold admits every string including the empty one, unnamed in a module doc that names its other two omissions; the admission rule is specified nowhere, so it cannot be implemented here."
```