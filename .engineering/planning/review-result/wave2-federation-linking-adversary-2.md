---
format: aep.planning-md/1
id: review-result:wave2-federation-linking-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:federation-linking
tags:
- model-deviation-opus
relations:
- reviews: story:federation-linking
revision: 1
---
```
unit: story:federation-linking — worktree impl/federation-linking, uncommitted tree over base 11ce4818f1280791b77a99577680c888d37af69f
verdict: NEEDS-CHANGE
cases: executed 54→58, red 4
origin: introduced 8 / pre-existing 0 / undecided 0
wrote-outside-worktree: 4 paths (part 6)
needs-coordinator: two rulings, not implementor defects — (a) finding 1 is a hole in the coordinator's own J2 ruling, not a deviation from it; (b) whether `jit_provisioning: false` bounds a connection's identity space or only the command (part 5)
```

## 1. `git --no-pager diff --stat`

```
 crates/mandate-federation/src/lib.rs | 393 ++++++++++++++++++++++++++++++++++-
 1 file changed, 390 insertions(+), 3 deletions(-)
```

**That non-test path is not mine**, and I name it myself. The implementation is uncommitted, so `src/lib.rs` is the implementor's own modification, present when I was handed the tree; the four `src/*.rs` and six `tests/*.rs` are untracked for the same reason. My only added path is one untracked test file:

```
git --no-pager status --porcelain --untracked-files=all   (my line only)
?? crates/mandate-federation/tests/adversary_pass2.rs
```

I changed no implementation file, mutated nothing in place, and edited neither `tests/adversary_pass1.rs` nor any implementor test. `cargo fmt -p mandate-federation -- --check` exit 0, `cargo clippy -p mandate-federation --all-targets --locked -- -D warnings` exit 0, `cargo xtask boundaries` exit 0 ("20 packages satisfy metadata and dependency boundaries") with my file present.

## 2. Cases added — `crates/mandate-federation/tests/adversary_pass2.rs`, 4 cases, all red now

Captured from the run of that target alone (`cargo test -p mandate-federation --locked --test adversary_pass2`), before any suite run. One `Debug` dump trimmed at `[…]`; nothing else altered.

```
running 4 tests
test a_foreign_organization_may_copy_a_conditional_rule_and_end_the_incumbents_logins ... FAILED
test an_unlinked_row_holds_no_key_for_two_commands_and_blocks_the_third ... FAILED
test the_link_that_wins_one_key_changes_with_the_order_the_streams_are_replayed_in ... FAILED
test the_principal_a_lost_provision_created_is_answerable_by_nothing ... FAILED

---- a_foreign_organization_may_copy_a_conditional_rule_and_end_the_incumbents_logins stdout ----
panicked at crates/mandate-federation/tests/adversary_pass2.rs:299:5:
organization 11's connection copies the rule organization 10 already resolves the issuer with, and
register_federation_connection admits it: the guard tests only whether a rule is unconditional, so
two equal conditional rules produce exactly the configuration its comment refuses to admit.
Organization 10's login, which resolved a moment ago, now returns Some(Err(Denied { reason:
TenantMismatch, clause: TenantAmbiguous })), and there is no command that un-registers organization
11's connection

---- an_unlinked_row_holds_no_key_for_two_commands_and_blocks_the_third stdout ----
panicked at crates/mandate-federation/tests/adversary_pass2.rs:469:5:
the row the port returned is in the terminal Unlinked state. authenticate_federation reads that
state and denies (Err(Denied { reason: Denied, clause: LinkAbsent })); link_external_principal reads
it and admits a relink over the key (Ok(Linked { external_principal_id: […] })); 
provision_external_principal reads only is_some() and denies (Err(Denied { reason: Denied, clause:
ExternalKeyExists })). One key, one store, one moment, three answers — and the adapter sequence
decision-blocker:jit-provisioning declares, authenticate then provision then authenticate, never
terminates

---- the_link_that_wins_one_key_changes_with_the_order_the_streams_are_replayed_in stdout ----
panicked at crates/mandate-federation/tests/adversary_pass2.rs:366:5:
assertion `left == right` failed: one set of events, two rebuilds, two different principals for the
one canonical key: record_link decides the winner by its position in the slice and reads linked_at
for nothing, so the link that lost the write race becomes the one the key resolves to as soon as a
replay presents the two aggregates in the other order. A session already issued to the loser names a
principal the key no longer resolves to
  left: Some(PrincipalId(Uuid([33, …])))
 right: Some(PrincipalId(Uuid([34, …])))

---- the_principal_a_lost_provision_created_is_answerable_by_nothing stdout ----
panicked at crates/mandate-federation/tests/adversary_pass2.rs:541:5:
assertion `left == right` failed: the event that lost the key is the creation record of principal
0xa2 in organization 10, and the projection answers None for it: the conflict entry keeps the key
and the external-principal id and drops the principal the event created. Nothing in src/ reads
conflicts(), so the loss is surfaced to no caller and no denial, and an administrator trying to give
that principal a link of its own is refused for a principal that does not exist: Err(Denied {
reason: TenantMismatch, clause: PrincipalMismatch })
  left: None
 right: Some(OrganizationId(Uuid([10, …])))

test result: FAILED. 0 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out
```

## 3. Suite run, after the cases in part 2 existed

`cargo test -p mandate-federation --locked --no-fail-fast`, exit **101**:

```
     Running unittests src/lib.rs      test result: ok. 0 passed; 0 failed
     Running tests/adversary_pass1.rs  test result: ok. 5 passed; 0 failed
     Running tests/adversary_pass2.rs  test result: FAILED. 0 passed; 4 failed
     Running tests/authenticate.rs     test result: ok. 15 passed; 0 failed
     Running tests/link.rs             test result: ok. 11 passed; 0 failed
     Running tests/record.rs           test result: ok. 17 passed; 0 failed
     Running tests/verifier.rs         test result: ok. 6 passed; 0 failed
error: 1 target failed
```

`<before>` = 54 = 5+15+11+17+6, this same run with my target deselected from the sum; it equals the count the implementing state declared. `<after>` = 58. **All five pass-1 cases are green**: each pass-1 fix held rather than moved (checked individually in part 5).

## 4. Findings — worktree `impl/federation-linking`, uncommitted, over base `11ce4818`

| # | file:line | what is wrong | verdict / severity / origin | what was measured | what reaches it |
|---|---|---|---|---|---|
| 1 | `crates/mandate-federation/src/record.rs:576-594` | The new cross-organization guard tests only whether a rule is **unconditional**. Two *conditional* rules naming the same claim and value make every login on that issuer ambiguous in exactly the way the guard's own comment refuses to admit ("Refuse the configuration rather than the logins"). `{org: acme}` is the canonical sample rule (`crates/mandate-model/src/lib.rs:82-86`). Org 11 copies org 10's rule onto itself and every org-10 login on that issuer denies `TenantAmbiguous` from then on. Org 10 cannot recover: `DisableFederationConnection` on org 11's connection is "outside the verified organization", and there is no un-register. | NEEDS-CHANGE / **blocker** / introduced | `adversary_pass2.rs:299` asserts the registration is refused; got `Ok`, and org 10's authentication, which returned `Ok` one line earlier, returned `Err(Denied{TenantMismatch, TenantAmbiguous})` | `RegisterFederationConnection` with caller-chosen `issuer` and `tenant_resolution`; its only organization constraint (the rule resolves to the caller's own org) is satisfied. Any federation admin of any organization, against any other organization on a shared multi-tenant IdP, where the claim value is public |
| 2 | `crates/mandate-federation/src/authenticate.rs:140` | Of the three commands that read `LinkStore`, two honour `ExternalPrincipal::state` and one does not. `src/lib.rs:238-246` states the port contract: "An implementation may return a row in any lifecycle state. **Every** command that reads this port honours `record::ExternalPrincipal::state` itself". `provision_external_principal` tests `is_some()`. The same row that holds no key for `authenticate_federation` (`:85-88`) and none for `link_external_principal` (`src/link.rs:104-107`) blocks provisioning, so the adapter sequence `decision-blocker:jit-provisioning` declares — authenticate, on absent-link provision, authenticate — has no exit. | CONFIRMED / warning / introduced | `adversary_pass2.rs:469`: one store, one key, one moment, three answers — `LinkAbsent`, `Ok(relink)`, `ExternalKeyExists` | the port's own documented contract, which this correction made two of the three call sites honour. **No in-tree implementation returns an `Unlinked` row** — the fold cannot produce one and `UnlinkExternalPrincipal` is excluded from this story — so the deadlock needs that command or an external adapter. The doc/code disagreement holds today either way |
| 3 | `crates/mandate-federation/src/record.rs:425-435` | "First wins" is first-in-slice. `record_link` decides by position; `linked_at`, the only ordering datum the events carry, is read by nothing, and `Projection::fold`'s doc (`:246-252`) says "the first link wins" without saying first relative to what. Two link events on two different `ExternalPrincipal` aggregates through two connections of one organization — the configuration `tests/record.rs:533` newly admits — have no defined relative order under ADR 0009's per-aggregate compare-and-set append, and the ADR calls projections "derived, droppable, rebuildable". | INFEASIBLE / warning / introduced | `adversary_pass2.rs:366`: one event set, two rebuilds, `Some(0x21)` vs `Some(0x22)` for one canonical key | **I built the reordering.** No store adapter exists in-tree (the eventlog kit is unwired per ADR 0009) and every in-tree caller of `fold` is a test building its own slice, so I cannot show which order a rebuild presents. Only the domain can fix it — the tie-break datum is in the event |
| 4 | `crates/mandate-federation/src/record.rs:425-435`, `:466-470` | `conflicts()` is a silent shadow: written by the fold, read by nothing in `src/` (grep), named by no denial. `ExternalKeyConflict` keeps the key and the external-principal id and **drops `principal_id`** — but `federation.yaml:258` makes the losing `ExternalPrincipalProvisioned` "the creation record for both entities it names", one of them a `mandate.identity.Principal`. `src/lib.rs:248-258` says `Projection` answers `PrincipalStore` "for the principals this crate's own events created"; it answers `None`, because `organization_of` is folded over `links` alone. With the correction's new target-principal read, that principal can never be linked. | CONFIRMED / warning / introduced | `adversary_pass2.rs:541`: `organization_of(0xa2)` is `None`; `link_external_principal` for it returns `Err(Denied{TenantMismatch, PrincipalMismatch})` | the `jit-conflict` corpus case ("two simultaneous first logins"), which the first-wins change exists to serve and which the implementor's own `tests/authenticate.rs:442` folds |
| J1 | `crates/mandate-federation/src/lib.rs:255-258` | The new `PrincipalStore` port returns `Option<OrganizationId>` and nothing else, so `mandate.identity.Principal`'s declared `Disabled` terminal state (`identity.yaml`, `DisablePrincipal`) is inexpressible here. `link_external_principal` links to a disabled principal, and `authenticate_federation` reads no principal at all and mints it a session — so `DisablePrincipal`, whose denial text turns on "session/credential invalidation", is undone by the leaver's next SSO login. The only place left to catch it is inside a `SessionIssuer` adapter, and `DenialClause` gives it no variant to say why. | CONFIRMED / warning / introduced | read: the port signature at `:257`, the absence of any principal read in `authenticate_federation` (`src/authenticate.rs:71-113`), and the 18 `DenialClause` variants (`src/lib.rs:86-133`) | `mandate.identity.DisablePrincipal` is declared; this crate is the one that mints sessions from federation |
| J2 | `crates/mandate-federation/src/record.rs:566-594` | The guard is a read-then-write check with no storage obligation behind it. `federation.yaml:2` tells storage to enforce "the composite external key and organization/connection consistency atomically" and names nothing about tenant resolution, so two organizations registering on one issuer simultaneously both read a store without the other and both are admitted — the exact state the guard forbids, with no un-register. | CONFIRMED / note / introduced | read: `federation.yaml:2` against `src/record.rs:582-594` | two organizations onboarding one public IdP concurrently; the same class the story routes to the storage adapter for the external key, but with no contract line to route it under |
| J3 | `crates/mandate-federation/src/verifier.rs:96-113` | `ConstructedVerifier::admitting` — a verifier that admits every proof by construction and performs no cryptography — is `pub` in a library crate, behind no feature and no `cfg`. Same for `SequentialAllocator`, `RecordingSessionIssuer`, `RecordedPrincipals`. Nothing marks them un-shippable, and `cargo xtask boundaries` checks dependencies, not exported doubles. | CONFIRMED / note / introduced | grep: nothing in `src/` constructs any of the four doubles; the story forces `pub` because `tests/*.rs` are separate crates | any crate depending on `mandate-federation`, including `story:signing-and-verification`'s real implementation landing beside it at the same trait |
| J4 | `crates/mandate-federation/src/authenticate.rs:223`, `src/link.rs:89`, `src/record.rs:414` | `trim()` decides emptiness and never canonicalizes. The key stores the raw subject, so `"s"` and `" s"` are two identities under one issuer: an admin link on `"s"` does not conflict with a JIT provision of `" s"`, and `EmptySubject` is the only normalization the canonical key has. `str::trim` also refuses a NBSP subject while admitting a zero-width-space one. | CONFIRMED / note / introduced | read: `subject.clone()` into `ExternalKey` at `src/authenticate.rs:238` and `src/link.rs:102` against the three `trim().is_empty()` guards | an issuer whose `sub` varies in whitespace. I found no in-tree producer, and the contract specifies no normalization — which is itself the gap |

Origin is `introduced` for all eight: at `11ce4818` the crate is a four-line scaffold with no `tests/` and no `src/*.rs` but `lib.rs` (`git ls-tree`).

**Named fixes, not applied.** 1 — extend the guard to any foreign rule that could match the same proof (name/value equality is decidable), or have the coordinator rule that conditional collisions are admitted and say so. 2 — `.filter(|held| held.state == LinkState::Linked)` at `src/authenticate.rs:140`, matching the other two call sites. 3 — tie-break `record_link` on `(linked_at, external_principal_id)`, or state in `fold`'s doc that the slice must be in append order and that a rebuild must preserve it. 4 — carry `principal_id` and `connection_id` on `ExternalKeyConflict`, and answer `PrincipalStore` from conflicts as well as links. J1 — widen `PrincipalStore` to return the principal's lifecycle state, and add the `DenialClause` variant.

## 5. Attacked and could not break

- **Pass-1 fix 1 held, not moved**: `resolve_tenant` requires `matches_validated` on the selected connection before the count (`src/authenticate.rs:259`), and the sibling case is pinned by the implementor at `tests/authenticate.rs:680`. The cross-organization *admission* stays closed by `organization_id != connection.organization_id` at `:306`.
- **Pass-1 fix 2 held**: `link_external_principal` refuses an absent or foreign target principal (`src/link.rs:71-76`); `RecordedPrincipals` answers the administrative case the projection alone cannot.
- **Pass-1 fixes 3, 4, 5 held**: `LinkState::Linked` filter at `src/authenticate.rs:87`; `EmptySubject` on both proof-driven commands, the administrative link and the fold; both `ExternalPrincipalProvisioned` literals refused by the fold (`src/record.rs:340-356`).
- `matches_validated` fails closed on every boundary asked: a missing claim, a case difference, a whitespace difference and half a rule all return `false`; only `(None, None)` matches unconditionally (`src/authenticate.rs:319-325`).
- `tenant_ambiguous` within one organization: `matched` is a `BTreeSet<OrganizationId>`, so two connections of one organization that both match collapse to one entry and resolve. That is the corpus's "two configured **tenants**" reading and I did not attack it.
- JIT cannot land outside the connection's organization: the provisioned key and context both take `resolved.organization_id`, which `resolve_tenant` has already equated to `connection.organization_id`. `jit_provisioning` is read from the selected connection, after `matches_validated`.
- Legitimately ordered histories fold: register → link → authenticate → disable, and register → disable → (link refused at the write path) all fold; the orphan refusals fire only on an event naming an instance no event created.
- The `PersistedValue` guard is still exhaustive over all six variants, with no `..` and no wildcard arm, every field named; adding a variant or a field cannot compile without a proof obligation.
- Nothing in `src/` constructs a double, and nothing in `src/` reads `conflicts()` — both greps returned only definitions.
- **Not measured, so not a finding — a contract question for the coordinator.** `jit_provisioning` gates the command, while the identity it creates is keyed `(organization, issuer, subject)` and is therefore shared by every connection of that organization on that issuer. Since `AuthenticateFederation` and `ProvisionExternalPrincipal` carry no caller context and the caller names the `connection_id`, a subject provisioned through a JIT-admitting connection appears to become a first login the JIT-refusing sibling admits. `federation.yaml:4` says such a connection "denies the first login and creates nothing"; `tests/authenticate.rs:680` asserts cross-connection resolution within one organization is correct. I wrote no case because the two readings are both defensible and the choice is the contract's.

## 6. Paths written outside the worktree

All four under the assigned scratch root `<scratch>/`:

- `<scratch>/suite.log`
- `<scratch>/clippy.log`
- `<scratch>/boundaries.log`
- `<scratch>/fmt.log` (empty)

Nothing under `/tmp`; no `CARGO_TARGET_DIR` set; no git write; no `aep` command of any kind. Lease taken with `session-start`, heartbeated once, released with `session-end`.

## 7. findings

```findings
- file: crates/mandate-federation/src/record.rs
  line: 576
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the cross-organization registration guard refuses only an unconditional rule, so any organization may copy another's conditional tenant rule verbatim onto its own connection on the same issuer and turn every one of the incumbent's logins into a TenantAmbiguous denial the incumbent cannot undo."
- file: crates/mandate-federation/src/authenticate.rs
  line: 140
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "provision_external_principal tests LinkStore::link with is_some() alone, against the port doc at src/lib.rs:238-246 saying every command honours ExternalPrincipal::state itself, so a terminal Unlinked row holds no key for authenticate_federation or link_external_principal and still blocks provisioning, leaving the declared JIT adapter sequence with no exit."
- file: crates/mandate-federation/src/record.rs
  line: 425
  category: property
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: "first-wins is first-in-slice and linked_at is read by nothing, so one event set replayed with two aggregates in the other order materializes the other link for the one canonical key; I built the reordering and no store adapter exists in-tree to show which order a rebuild presents."
- file: crates/mandate-federation/src/record.rs
  line: 466
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "conflicts() is read by nothing in src/ and ExternalKeyConflict drops principal_id, so the principal the losing ExternalPrincipalProvisioned authoritatively created is answered None by PrincipalStore and can never be linked afterwards."
- file: crates/mandate-federation/src/lib.rs
  line: 255
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "the new PrincipalStore port carries only the organization, so mandate.identity.Principal's declared Disabled state is inexpressible here and a disabled principal is both linkable and issued a fresh session on its next federated login."
- file: crates/mandate-federation/src/record.rs
  line: 582
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "the registration guard is a read-then-write check with no storage obligation behind it, because federation.yaml:2 names only the composite external key for atomic enforcement, so two organizations registering on one issuer at once both pass it."
- file: crates/mandate-federation/src/verifier.rs
  line: 96
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "ConstructedVerifier::admitting, which admits every proof and performs no cryptography, is pub in a library crate behind no feature or cfg, as are the three other doubles, and nothing in the gate distinguishes them from shippable code."
- file: crates/mandate-federation/src/authenticate.rs
  line: 223
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "trim() decides emptiness but never canonicalizes the key, so EmptySubject is the canonical key's only normalization and two subjects differing by whitespace are two identities under one issuer."
```