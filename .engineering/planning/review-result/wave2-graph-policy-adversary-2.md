---
format: aep.planning-md/1
id: review-result:wave2-graph-policy-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:graph-policy
tags:
- model-deviation-opus
relations:
- reviews: story:graph-policy
revision: 1
---
```
unit: story:graph-policy, pass 2 — working tree <worktree> (branch impl/graph-policy, uncommitted; base 11ce4818f1280791b77a99577680c888d37af69f)
verdict: NEEDS-CHANGE (2 blocker, 3 warning, 3 note)
cases: executed 121→128, red 6
origin: introduced 8 / pre-existing 0 / undecided 0
wrote-outside-worktree: 26 paths under <scratch>/ (65M) — listed in part 6
needs-coordinator: none
```

## 1. `git --no-pager diff --stat` — proof of what I touched

```
 crates/mandate-graph/src/lib.rs  | 77 ++++++++++++++++++++++++++++++++++++++--
 crates/mandate-policy/src/lib.rs | 62 ++++++++++++++++++++++++++++++--
 2 files changed, 135 insertions(+), 4 deletions(-)
```

**Those two non-test paths are not mine.** The unit's implementation is uncommitted *and largely untracked*, so `git diff --stat` shows only the two `lib.rs` files the implementor modified; every other implementation file is `??`. My additions are untracked too and therefore invisible to `diff --stat`, so the honest proof is the mtimes: every file under `crates/mandate-{graph,policy}/src/` is stamped 21:49 or earlier, my lease was taken at 21:52, and the only paths stamped inside my window are the two test files I created (`crates/mandate-policy/tests/adversary_precedence_2.rs` 22:02, `crates/mandate-graph/tests/adversary_double_2.rs` 22:06). No `src/**` file and no implementor test file was written by this session. `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` both exit 0 with my files in the tree.

## 2. The cases I added, and their red output when written

Both files are new and mine. Each case below was run **alone** before the suite, in the order written.

**`crates/mandate-graph/tests/adversary_double_2.rs`** (5 cases: 4 red, 1 green)

| case | asserts | now |
|---|---|---|
| `a_repeat_registration_naming_a_parent_that_does_not_resolve_is_still_refused` | `RegisterResource` naming an unresolved parent is refused whether or not the id is already recorded | red |
| `a_registration_reported_as_already_recorded_recorded_the_move_that_was_asked_for` | `AlreadyRecorded` ⇒ the move reported is the move asked for (a refusal also passes) | red |
| `a_relation_name_the_write_path_refuses_is_not_answered_for_by_the_read_path` | `check` does not answer authority for `""`, `"   "`, `" editor "` | red |
| `an_identity_that_was_deregistered_cannot_be_registered_again` | the terminal state has no way back | **green** — mutant-catcher, see part 3 |
| `a_subject_the_double_holds_elsewhere_is_refused_as_a_decision_not_as_an_outage` | `admits` answers `Denied` for a subject held under another organization, as `relationship.rs:54-56` declares | red |

```
---- a_repeat_registration_naming_a_parent_that_does_not_resolve_is_still_refused stdout ----
panicked at crates/mandate-graph/tests/adversary_double_2.rs:114:5:
graph.yaml:169 declares an unresolved parent a refusal of RegisterResource, and double.rs:251-263 refuses it for an identity that is not recorded yet (refused here: true); for a recorded identity the parent argument is never looked at and the same call answered Ok(Registration { resource: ResourceRef { resource_type: ResourceType("document"), resource_id: ResourceId(Uuid([11, ...])) }, parent: Some(ResourceId(Uuid([10, ...]))), outcome: AlreadyRecorded, revision: AuthzRevision("2") })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out

---- a_registration_reported_as_already_recorded_recorded_the_move_that_was_asked_for stdout ----
panicked at crates/mandate-graph/tests/adversary_double_2.rs:161:29:
assertion `left == right` failed: port.rs:141-147 says AlreadyRecorded means the move was already recorded and this call changed nothing; this call asked for ResourceRef { ... resource_id: ResourceId(Uuid([11, ...])) } with no parent, was answered AlreadyRecorded naming parent Some(ResourceId(Uuid([10, ...]))), and the inherited authority the caller asked to detach is still answered: true
  left: Some(ResourceId(Uuid([10, ...])))
 right: None
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out

---- a_relation_name_the_write_path_refuses_is_not_answered_for_by_the_read_path stdout ----
panicked at crates/mandate-graph/tests/adversary_double_2.rs:212:9:
the write path refuses the relation name "" and the read path answers authority for it: a grant recorded under that same name is an allow, so the name the log cannot read back is the one the check is decided on
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out

---- a_subject_the_double_holds_elsewhere_is_refused_as_a_decision_not_as_an_outage stdout ----
panicked at crates/mandate-graph/tests/adversary_double_2.rs:248:5:
relationship.rs:54-56 declares Denied for a subject that resolves but is outside the organization; the double answered CouldNotAnswer(SubjectUnresolved) (reported as Unavailable), which is the same value it answers for a subject it has never heard of (CouldNotAnswer(SubjectUnresolved))
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out
```

**`crates/mandate-policy/tests/adversary_precedence_2.rs`** (2 cases, both red)

```
---- the_challenge_material_does_not_depend_on_the_order_the_rules_were_recorded_in stdout ----
panicked at crates/mandate-policy/tests/adversary_precedence_2.rs:141:5:
assertion `left == right` failed: double.rs:184-187 says the answer must not depend on the order the rules were recorded in; the same two approval rules answer Some(Challenge { requirement: Reauthentication, correlation: CorrelationId("correlation") }) recorded one way and Some(Challenge { requirement: Approval, correlation: CorrelationId("correlation") }) recorded the other, so which party has to clear the challenge is decided by list position
  left: Some(Challenge { requirement: Reauthentication, correlation: CorrelationId("correlation") })
 right: Some(Challenge { requirement: Approval, correlation: CorrelationId("correlation") })
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out

---- a_combination_that_is_not_an_allow_names_the_reason_the_caller_is_told stdout ----
panicked at crates/mandate-policy/tests/adversary_precedence_2.rs:170:5:
assertion `left == right` failed: precedence.rs:87-99 is where a caller reads what it is told, and DenialReason::ApprovalRequired is one of the four the story's line 113 names as this story's output; ApprovalRequired answers allowed() false and denial_reason() None, which is a state with no report in it
  left: None
 right: Some(ApprovalRequired)
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out
```

## 3. The suite run (after the cases in part 2 existed)

`env RUSTC_WRAPPER=/usr/bin/sccache cargo test -p mandate-graph -p mandate-policy --locked --no-fail-fast` → **exit 101**

```
Running tests/adversary_double.rs      running 4 tests   ok. 4 passed          (pass 1's cases, still green)
Running tests/adversary_double_2.rs    running 5 tests   FAILED. 1 passed; 4 failed
Running tests/boundary.rs   2 ok · tests/double.rs 18 ok · tests/port.rs 8 ok · tests/record.rs 6 ok
Running tests/relationship.rs 7 ok · tests/revocation.rs 11 ok · tests/topology.rs 9 ok
Running tests/adversary_precedence.rs  running 2 tests   ok. 2 passed          (pass 1's cases, still green)
Running tests/adversary_precedence_2.rs running 2 tests  FAILED. 0 passed; 2 failed
Running tests/boundary.rs 2 ok · tests/double.rs 19 ok · tests/port.rs 7 ok · tests/precedence.rs 16 ok · tests/record.rs 6 ok
Doc-tests mandate-graph 2 ok · Doc-tests mandate-policy 2 ok
error: 2 targets failed:
    `-p mandate-graph --test adversary_double_2`
    `-p mandate-policy --test adversary_precedence_2`
```

executed 128 (`121` as reported by the implementing state, + my 7). `cargo fmt --check` exit 0; `cargo clippy --all-targets --locked -- -D warnings` exit 0.

**Mutation probe, run on a copy and never on the tree.** `crates/mandate-graph/src/` was copied to my scratch directory, `double.rs:238-240` (the deregistered-state guard in `register_resource`) deleted there, the copy built with `rustc` into a scratch rlib, and the eight existing graph test binaries compiled against it: `double 18 ok · port 8 ok · topology 9 ok · relationship 7 ok · revocation 11 ok · record 6 ok · boundary 2 ok · adversary_double 4 ok` — **all 65 green with the guard gone.** My `an_identity_that_was_deregistered_cannot_be_registered_again` is green in the tree and red against that rlib (`the double answered Ok(Registration { ... outcome: AlreadyRecorded ... }) for an identity whose reference resolves: false`).

## 4. Findings

Every finding is against the working tree above. Origin is `introduced` for all of them without guessing: `git show 11ce4818:<path>` reports every implementation file *absent at base*, so nothing here reproduces against the base.

| # | file:line | what is wrong | verdict / severity / origin | what was measured | what reaches it |
|---|---|---|---|---|---|
| 1 | `crates/mandate-graph/src/double.rs:243` | `register_resource` reports `MutationOutcome::AlreadyRecorded` for a move it did not record: for a recorded id it returns at :234-249 before the `parent` argument is read, so a call asking for the resource **with no parent** is answered `Ok(AlreadyRecorded)` while the fold keeps the old parent edge — and the inherited authority the caller asked to detach still answers `Ok` from `check`. `port.rs:141-147` defines that outcome as "The move was already recorded; this call changed nothing" | CONFIRMED / **blocker** / introduced | `adversary_double_2.rs:161`, `left: Some(ResourceId(10)) right: None`, `still_inherits: true`; suite exit 101 | `graph.yaml:146-169` declares `parent: Optional<ResourceId>` on `RegisterResource` and declares **no** reparent command, so re-registration is the only way a caller can express a changed parent; a product re-syncing a moved resource takes this path |
| 2 | `crates/mandate-graph/src/double.rs:234` | the same early return skips the parent checks entirely, so `RegisterResource` naming a parent that does not resolve is accepted for a recorded id and refused (`double.rs:251-263`) for a new one. `graph.yaml:169` declares an unresolved parent a `denied` outcome with no such exception | CONFIRMED / warning / introduced | `adversary_double_2.rs:114`; the same call refuses for a new identity (`true`) and answers `Ok(AlreadyRecorded)` for a recorded one | same command, same declared refusal; whether it fires depends only on whether the id happens to be recorded |
| 3 | `crates/mandate-policy/src/double.rs:213` | the round-1 fix folded the *effect* through `precedence::combine` but left the challenge material on `Iterator::find` over the same list, so of two `ApprovalRequired` rules for one tuple the one recorded **first** decides what the caller must satisfy. Recording an `Approval` rule after a `Reauthentication` rule leaves the caller able to clear the answer alone; the two orders answer differently for identical rule sets. `double.rs:184-187` is the unit's own statement that the answer must not depend on recording order, and `Component` carries no requirement, so nothing in `precedence` — "the single home" (`lib.rs:6`) — decides this | CONFIRMED / **blocker** / introduced | `adversary_precedence_2.rs:141`, `Reauthentication` vs `Approval` from the same two rules | `require_approval` is public and two approval rules for one request is an ordinary policy set; this is the pass-1 defect moved one field over, not removed |
| 4 | `crates/mandate-graph/src/double.rs:457` | `GraphRead::check` applies no rule to `GraphQuery.relation`, so the read path answers authority for exactly the names the write path refuses. A grant with role `""` and a check for relation `""` is `Ok(Observed)`; `write_relationship` with `""` is `Err(Denied)`. `relationship.rs:75-86` calls refusing these "the closed direction"; `double.rs:94-98` accounts only for the check that asks the *trimmed* name, not the one that asks the untrimmed one | CONFIRMED / warning / introduced | `adversary_double_2.rs:212`, red on the first of `["", "   ", " editor "]` | `record_grant` is the only grant path and validates nothing by design (documented, `graph.yaml` declares no grant-creation command); `relation` is caller-supplied and unvalidated on the read port. No in-tree caller yet — `story:check-api` is the declared consumer |
| 5 | `crates/mandate-graph/src/double.rs:329` | `SubjectAdmission::admits` declares two errors (`relationship.rs:54-56`): `Denied` when the subject resolves but is outside the organization, `CouldNotAnswer(SubjectUnresolved)` when it does not resolve. The only implementor answers the second for both, so a subject the double *holds under another organization* is reported to the caller as `DenialReason::Unavailable` — an outage that is not happening — and the distinction `port.rs:1-9` is built around is not made. The doc and the code cannot both be right | NEEDS-CHANGE / warning / introduced | `adversary_double_2.rs:248`; both cases answer the identical `CouldNotAnswer(SubjectUnresolved)` | `check` calls `admits` on every read (`double.rs:454`). The fix may equally be the doc: the tenant-existence oracle `Denied` would open is a real argument for keeping the code and deleting the declared error — but `port.rs:86` and `relationship.rs:54` currently say different things |
| 6 | `crates/mandate-policy/src/precedence.rs:93` | `Combined::ApprovalRequired` answers `false` to `allowed()` and `None` to `denial_reason()`, so a caller holding the ordinary approval answer is told neither that it is allowed nor any reason it is not. `DenialReason::ApprovalRequired` occurs nowhere in either crate's `src/`, though story line 113 names it among the four this story owes `story:check-api` and line 102 makes `precedence` the single home | NEEDS-CHANGE / warning / introduced | `adversary_precedence_2.rs:170`, `left: None right: Some(ApprovalRequired)`; `grep -rn "DenialReason::" crates/mandate-*/src` produces only `Denied`, `TenantMismatch`, `Unavailable` | `double.rs:205-209` folds to `Combined::ApprovalRequired` on the ordinary path. The fix may be a doc line assigning the fourth mapping to `story:check-api` instead of the accessor |
| 7 | `crates/mandate-graph/src/double.rs:238` | the guard that makes `Deregistered` terminal is held by nothing in the suite: deleted from a scratch copy, all 65 existing graph cases stay green and `register_resource` answers `Ok(AlreadyRecorded)` for an identity `placement` refuses as `ResourceUnresolved` | CONFIRMED / note / introduced | the mutant run in part 3; my case is green in-tree and red against the mutant rlib | the mutant does not exist in the tree — this is a coverage finding, now held by `an_identity_that_was_deregistered_cannot_be_registered_again` |
| 8 | `crates/mandate-policy/src/precedence.rs:55` | judgement, no case. `Combined::Nothing` is documented as *both* "a refusal to the caller" and "the identity of `combine`". It is therefore indistinguishable from a real denial through the two accessors a caller has — `combine(&[]).allowed() == combine(&[Denied(Denied)]).allowed() == false` and both `denial_reason()` answer `Some(Denied)` — yet they compose to opposite answers: `combine(&[Nothing.component(), Allowed])` is `Allowed`, `combine(&[Denied(Denied).component(), Allowed])` is `Denied`. Whether a source with zero applicable rules denies depends on *where* the consumer reads it, and nothing tells `story:check-api` which reading is the decision | CONFIRMED / note / introduced | read from `precedence.rs:131-156` and `:93-99`; no case added, this is residue | `story:check-api` composes these (story line 113). `evaluate` reads at the leaf and maps `Nothing → Deny`, so the in-tree path is closed; the hazard is the exported composition |
| 9 | `crates/mandate-graph/src/double.rs:176` | judgement, no case. `double.rs:132-137` claims "Every path here keys on that id and nothing else, so the write path and the deregister path cannot disagree about what one resource is". `holds` is a path here and does not: relations are matched on `resource_id` (:166), grants on the whole `ResourceRef` via `scope.resources.contains` (:176). The direction is closed (a grant naming the right id under the wrong type confers nothing), but the claim is wider than the code and the round-1 identity fix did not reach this line | CONFIRMED / note / introduced | read from `double.rs:157-177`; no case added | `record_grant` takes `AuthorityScope.resources` as given, so a grant carrying a stale `resource_type` silently stops conferring with no refusal anywhere |

**On pass 1's seven fixes:** all six pass-1 cases are green, and the seventh (relation-name trim) is enforced at `relationship.rs:84` and tested. Four of the seven left residue immediately adjacent to the fix, which is findings 1–4 above: the identity fix (#3) moved the disagreement from two records into a `MutationOutcome` that reports a move nobody made; the fold fix (#1) moved order-dependence from the effect into the challenge; the name fix (#7) closed the write path and left the read path open; the associativity fix (#4) left `Nothing` with two readings. None of pass 1's findings needed repeating verbatim.

## 5. What I attacked and could not break

- **The acceptance statement** — `tests/revocation.rs:153` `inherited_access_is_denied_at_the_revision_the_grant_was_revoked_at` asserts it directly, plus `:180` at an earlier floor; that suite is 11 green.
- **The sealed-port `compile_fail` doctests** — I compiled both snippets standalone against the built rlibs: `error[E0277]: the trait bound BackendToken: port::sealed::Sealed is not satisfied ... required by a bound in Revision` and the same for `BackendRow`/`AttributeInput`. They fail for exactly the reason they claim, the seal, not an unrelated bound.
- **`Combined::Nothing` leaking upward as an allow** — no path: `evaluate` maps `Nothing → Deny` (`double.rs:208`), and `Nothing` cannot turn an allow on that was not already there. Residue is finding 8, not a leak.
- **`record_grant` validating nothing** — a grant on an unregistered, deregistered or cross-organization resource, or with a space, is refused on the read path by `placement`/`ancestry`/`holds`; pass-1's two guard cases hold the last two. The only hole is the degenerate role name (finding 4).
- **`check`'s new order** — `require_revision → admits → ancestry`: an unadmitted subject learns nothing about resources, a subject admitted in one organization does not pass `admits` in another, and a stale reader is refused first by design (`tests/double.rs:396`).
- **`AlreadyRecorded` on a type disagreement as an oracle** — the standing type is disclosed only inside the caller's own organization (a cross-organization id answers `TenantMismatch` first), and `DeregisterResource` names no type so it cannot move the wrong record.
- **`ancestry` over a broken parent link** — unreachable: a stored parent ref is the recorded ref, `deregister_resource` refuses while a resolving child exists, and a deregistered id cannot be re-registered. No silent stop, no spurious `HierarchyUnbounded`.
- **`Unanswered::ALL`** — `port.rs:94-99` matches `tests/port.rs:203`'s produced set exactly, in declaration order.
- **`combine` associativity and the reason ranking** — I could not find an input where grouping changes the answer, including empty groups, and `rank` is a min over a fixed order so it is commutative and associative.
- **Idempotency and revisions** — repeated revoke/remove/deregister/write each record one move and one revision; `record_grant` on a held id advances nothing.

## 6. Every path I wrote outside the worktree

All under `<scratch>/` (65M total, mine to be cleaned):

- `suite.log`, `suite2.log`, `suite-final.log` — the three full-suite runs
- `seal_graph.rs`, `seal_policy.rs` — the two `compile_fail` snippets, extracted for the reason probe (no binaries were produced; both failed to compile, as intended)
- `mutant-src/` — a copy of `crates/mandate-graph/src/` with `double.rs:238-240` deleted
- `libmandate_graph_mutant.rlib` — that copy, built
- `t_double`, `t_port`, `t_topology`, `t_relationship`, `t_revocation`, `t_record`, `t_boundary`, `t_adversary_double`, `t_adv2` and their nine `*.build.log` files — the existing test binaries compiled against the mutant

Nothing was written to `/tmp`, nothing to the planning store, no `aep` command was run, no git write, and the worktree lease `adversary-graph-policy-2` was released with `worktree hook session-end`.

## 7. Findings block

```findings
- file: crates/mandate-graph/src/double.rs
  line: 243
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "register_resource returns AlreadyRecorded for a move it never recorded: a repeat naming a different parent is answered Ok while the fold keeps the old parent edge, so inherited authority the caller asked to detach is still answered by check."
- file: crates/mandate-graph/src/double.rs
  line: 234
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "the recorded-id early return skips the parent checks, so RegisterResource naming an unresolved parent is accepted for a recorded id and refused for a new one, against the single denied outcome graph.yaml:169 declares."
- file: crates/mandate-policy/src/double.rs
  line: 213
  category: property
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: "the challenge material is still resolved with Iterator::find over the rule list, so two ApprovalRequired rules for one request answer Reauthentication or Approval depending only on recording order, which is the defect the fold was written to remove."
- file: crates/mandate-graph/src/double.rs
  line: 457
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "check applies no rule to GraphQuery.relation, so the read path answers authority for the empty and untrimmed names write_relationship refuses at admission, from a grant carrying the same name."
- file: crates/mandate-graph/src/double.rs
  line: 329
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "SubjectAdmission::admits declares Denied for a subject that resolves outside the organization and the only implementor never produces it, so a subject held under another organization is reported to the caller as Unavailable."
- file: crates/mandate-policy/src/precedence.rs
  line: 93
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "Combined::ApprovalRequired answers allowed() false and denial_reason() None, and DenialReason::ApprovalRequired is produced nowhere in either crate, though story line 113 names it among the four mappings this story owes story:check-api."
- file: crates/mandate-graph/src/double.rs
  line: 238
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "deleting the deregistered-state guard from a scratch copy leaves all 65 existing graph cases green while register_resource answers Ok(AlreadyRecorded) for an identity placement refuses as ResourceUnresolved."
- file: crates/mandate-policy/src/precedence.rs
  line: 55
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "Combined::Nothing is documented as both a refusal to the caller and the identity of combine, so it is indistinguishable from Denied(Denied) through allowed() and denial_reason() yet composes to the opposite answer, and nothing tells story:check-api which reading is the decision."
- file: crates/mandate-graph/src/double.rs
  line: 176
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "double.rs:132-137 claims every path here keys on the resource id alone, but holds matches relations on resource_id and grants on the whole ResourceRef, so a grant carrying a stale resource_type silently confers nothing with no refusal anywhere."
```