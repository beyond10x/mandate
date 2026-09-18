---
format: aep.planning-md/1
id: review-result:wave2-federation-linking-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:federation-linking
tags:
- model-deviation-opus
- scratch-path-redacted
relations:
- reviews: story:federation-linking
revision: 1
---
```
unit: story:federation-linking — worktree impl/federation-linking, uncommitted tree over base 11ce4818f1280791b77a99577680c888d37af69f
verdict: NEEDS-CHANGE
cases: executed 34→39, red 5
origin: introduced 10 / pre-existing 0 / undecided 0
wrote-outside-worktree: 4 paths (listed in part 6)
needs-coordinator: two contract questions, not implementation defects — (a) `DenialReason` has no link-conflict variant, owned by `story:domain-runtime`; (b) whether one organization may register a connection on an issuer another organization already uses (finding J2)
```

## 1. `git --no-pager diff --stat`

```
 crates/mandate-federation/src/lib.rs | 316 ++++++++++++++++++++++++++++++++++-
 1 file changed, 313 insertions(+), 3 deletions(-)
```

**That non-test path is not mine.** The implementation is uncommitted, so `src/lib.rs` appears as the implementor's own modification, present when I was handed the tree; the four new `src/*.rs` and four `tests/*.rs` are untracked for the same reason. I changed no implementation file and mutated nothing in place. My only added path is one untracked test file:

```
git --no-pager status --porcelain --untracked-files=all   (my line only)
?? crates/mandate-federation/tests/adversary_pass1.rs
```

`cargo fmt -p mandate-federation -- --check` exit 0 and `cargo clippy -p mandate-federation --all-targets --locked -- -D warnings` exit 0 with my file present.

## 2. Cases added — all in `crates/mandate-federation/tests/adversary_pass1.rs`, all red now

Red output captured from the run of that target alone (`cargo test -p mandate-federation --locked --test adversary_pass1`), before any suite run. Long `Debug` dumps trimmed where marked `[…]`; nothing else altered.

```
running 5 tests
test a_proof_that_fails_the_selected_connections_tenant_rule_still_authenticates ... FAILED
test a_target_principal_recorded_in_another_organization_is_linked_without_refusal ... FAILED
test an_empty_validated_subject_collapses_two_external_identities ... FAILED
test an_unlinked_external_principal_returned_by_the_port_still_issues_a_session ... FAILED
test the_fold_admits_a_provisioned_link_whose_method_is_not_configured_federation ... FAILED

---- a_proof_that_fails_the_selected_connections_tenant_rule_still_authenticates stdout ----
panicked at crates/mandate-federation/tests/adversary_pass1.rs:216:5:
connection 1 is configured to resolve its tenant from the verified claim org=acme; this proof does
not carry it, and the only rule that matched belongs to connection 2. The authentication was
admitted anyway: Ok(Authenticated { session_id: SessionId([…]), organization_id:
OrganizationId(Uuid([10, …])), principal_id: PrincipalId(Uuid([33, …])), event:
FederationAuthenticated { […] } }), sessions issued: [(PrincipalId(Uuid([33, …])), […])]

---- a_target_principal_recorded_in_another_organization_is_linked_without_refusal stdout ----
panicked at crates/mandate-federation/tests/adversary_pass1.rs:314:5:
the target principal is recorded in organization 11 and the connection is organization 10's, which
`federation.yaml:166` denies as "organization or target principal mismatches"; the authenticated
context is Ok((OrganizationId(Uuid([10, …])), PrincipalId(Uuid([160, 1, 40, 186, …]))))

---- an_unlinked_external_principal_returned_by_the_port_still_issues_a_session stdout ----
panicked at crates/mandate-federation/tests/adversary_pass1.rs:387:5:
the external principal is in the terminal Unlinked state, so there is no explicitly linked
principal to form a context with: Ok(Authenticated { session_id: SessionId([…]), […] })

---- an_empty_validated_subject_collapses_two_external_identities stdout ----
panicked at crates/mandate-federation/tests/adversary_pass1.rs:448:5:
the empty string is not an external subject: it makes the canonical key collapse across identities;
a second identity with an empty subject authenticated as Ok(PrincipalId(Uuid([160, 1, 40, 186, …]))),
the principal provisioned for the first (PrincipalId(Uuid([160, 1, 40, 186, …])))

---- the_fold_admits_a_provisioned_link_whose_method_is_not_configured_federation stdout ----
panicked at crates/mandate-federation/tests/adversary_pass1.rs:500:5:
ExternalPrincipalProvisioned pins link_method to ConfiguredFederation, and the fold recorded
[SecuritySupport]

test result: FAILED. 0 passed; 5 failed; 0 ignored; 0 measured; 0 filtered out
```

Two rustfmt-only reflows were applied to my file afterwards (line numbers shifted by ~6); re-run confirms the same five failures at `:215`, `:308`, `:381`, `:442`, `:494`.

## 3. Suite run, after the cases existed

`cargo test -p mandate-federation --locked --no-fail-fast`, exit **101**:

```
     Running unittests src/lib.rs        running 0 tests   test result: ok. 0 passed; 0 failed
     Running tests/adversary_pass1.rs    running 5 tests   test result: FAILED. 0 passed; 5 failed
     Running tests/authenticate.rs       running 13 tests  test result: ok. 13 passed; 0 failed
     Running tests/link.rs               running 6 tests   test result: ok. 6 passed; 0 failed
     Running tests/record.rs             running 9 tests   test result: ok. 9 passed; 0 failed
     Running tests/verifier.rs           running 6 tests   test result: ok. 6 passed; 0 failed
```

`<before>` = 34 (13+6+9+6, the implementing state's declared count, reproduced by this run with `adversary_pass1` excluded from the sum). `<after>` = 39. Plain `cargo test` without `--no-fail-fast` stops at my target, so the count needs that flag.

## 4. Findings

| # | file:line | what is wrong | what was measured | what reaches it | verdict / origin |
|---|---|---|---|---|---|
| 1 | `crates/mandate-federation/src/authenticate.rs:235-281` | `resolve_tenant` never consults the **selected** connection's own `TenantResolutionRule`. It counts the organizations of every enabled connection for the issuer whose rule matched, and admits when that set has one element. A proof failing the selected connection's configured claim rule authenticates through it anyway. Step 6 of the mandated order is *validate* the selected trust relationship's binding. | `adversary_pass1.rs:215` asserts denial; got `Ok(Authenticated{organization_id: org10, principal_id: 0x21})`, one session issued | one organization with two enabled connections on one issuer — the configuration `ConnectionStore::enabled_for_issuer` (`src/lib.rs:218-224`) exists to serve, and which the crate's own `tenant_ambiguous` test builds across organizations | NEEDS-CHANGE / introduced |
| 2 | `crates/mandate-federation/src/link.rs:59-66` | `federation.yaml:166` / `command-obligations.md:28` deny on "organization or **target principal** mismatches". Only the caller-organization half is realized; no port reads the target principal. The crate's own `tests/link.rs:420` cites that line while covering only that half. | `adversary_pass1.rs:308` asserts denial; got `Ok`, and the follow-on authentication yields context `(org 10, principal 0xa0…)` — a principal the crate's own projection records in org 11 | `LinkExternalPrincipal`'s declared input surface: an org-10 linking caller naming any `PrincipalId`. No in-tree adapter exists yet; the command surface is this unit's deliverable | NEEDS-CHANGE / introduced |
| 3 | `crates/mandate-federation/src/authenticate.rs:80-88` | `authenticate_federation` never reads `ExternalPrincipal.state`. The terminal `Unlinked` guard lives only in `Projection`'s `LinkStore` impl (`src/record.rs:403-410`); the port doc (`src/lib.rs:228-231`) asks no implementor to filter, and hands back a value carrying `state`. Acceptance requires an *explicitly linked* principal. | `adversary_pass1.rs:381` asserts denial; got `Ok(Authenticated{…})` with a session issued for an `Unlinked` row | any `LinkStore` implementation other than `Projection`, written to the port's documented contract. **I built the store**; no adapter exists in-tree yet | CONFIRMED / introduced |
| 4 | `crates/mandate-federation/src/authenticate.rs:144` | Neither command requires a non-empty subject, and `ExternalSubject` is an unconstrained string whose conformance samples include `""`. An empty validated subject becomes a whole key component and a `display_name`. | `adversary_pass1.rs:442`: provisioning with subject `""` accepted; a second identity with an empty subject authenticated as the *first* one's principal | a `FederationVerifier` returning an empty validated subject. Nothing in-tree does; the port doc forbids nothing. **Constructed** | INFEASIBLE / introduced |
| 5 | `crates/mandate-federation/src/record.rs:274-295` | `ExternalPrincipalProvisioned` pins `link_method: ConfiguredFederation` as a payload **literal** (`federation.yaml`, and `:4`), but the event type carries it as a free field and the fold copies whatever it finds — a JIT link can be recorded with an administrative provenance. | `adversary_pass1.rs:494`: fold of a log with `link_method: SecuritySupport` records `[SecuritySupport]` | a hand-built log; the one in-crate producer writes the literal. **Constructed** | INFEASIBLE / introduced |
| J1 | `crates/mandate-federation/src/record.rs:209` | `Projection::fold` fails the **whole** log on one duplicate key, so a single poison event makes every read of every connection permanently unbuildable. ADR 0009 requires projections to be droppable and rebuildable; the index is on the projection, not the append, so the `jit-conflict` race is exactly how such a log arises. | the implementor's own `tests/authenticate.rs:445` asserts `fold(&both)` is `Err` | two appended provision events for one key — the race the corpus case names | CONFIRMED / introduced |
| J2 | `crates/mandate-federation/src/authenticate.rs:289` | `matches_validated` returns `true` for a rule naming no claim, and resolution ranges over every enabled connection for the issuer **across organizations**, with no guard in `register_federation_connection`. Any organization registering a connection on a shared issuer (an unconditional rule suffices) turns every other organization's logins on that issuer into `TenantAmbiguous` denials. | `tests/authenticate.rs:258` is that configuration, asserted as correct behaviour | any two tenants using one public IdP. No failing case written: the corpus `tenant-ambiguous` expectation endorses the denial, so the question is the contract's, not the code's | CONFIRMED / introduced |
| J3 | `crates/mandate-federation/src/record.rs:320-326` | `record_link` returns `Ok(())` when the link event names a connection the projection does not hold: a **creation** record is silently dropped, and with it its entry in the uniqueness index. The comment above justifies the no-op for *transitions*, which these two events are not. | read; no in-crate producer emits it (both commands refuse an unknown connection first) | a truncated or per-aggregate-filtered replay | CONFIRMED / introduced |
| J4 | `crates/mandate-federation/src/lib.rs:145` | `RequestContext.credential` is caller-supplied and lands verbatim in the persisted `ExternalPrincipalProvisioned` verified context — on the one command that by construction has no verified caller. The implementor documents that the contract names no source; that is a contract gap worth routing, not a silent choice. | read | the adapter, on every first login | CONFIRMED / introduced |
| J5 | `crates/mandate-federation/src/link.rs:53-58` | The disabled-connection denial in `link_external_principal` is never taken by any test: `link_external_principal` is reached only from `tests/link.rs` (grep), and no test in that file folds a `FederationConnectionDisabled` event (grep). Deleting the branch cannot change a test outcome. The behaviour is correct today; the guard is unguarded. | two greps over `tests/`; `tests/authenticate.rs:477` covers only the two proof-driven commands | the mutant survives; no defect in current behaviour | CONFIRMED / introduced |

Origin for every row is `introduced`: at base `11ce4818` the crate was a four-line scaffold (`git show 11ce4818:crates/mandate-federation/src/lib.rs`), with no `tests/` and no `src/*.rs` beyond `lib.rs`.

Named fixes (not applied): **1** — require `matches_validated(&connection.tenant_resolution, verified)` before the cross-connection count; a fix in that shape leaves `tenant-valid`, `tenant-zero`, `tenant-ambiguous` and `tenant-unverified` green. **2** — declare a `PrincipalStore` read port in `src/lib.rs` with a test double, as `FederationVerifier` and `SessionIssuer` already are, and refuse a target principal outside the connection's organization. **3** — check `link.state == LinkState::Linked` in `authenticate_federation`, or state the filter in the `LinkStore` doc. **5** — drop `link_method` from the provisioned event variant, or have the fold refuse any other value.

## 5. Attacked and could not break

- The eleven corpus ids all execute by name and each assertion matches its `expected` string in `tests/security/cases.json`, including `jit-conflict`'s "the denied caller's retried authentication succeeds".
- Caller-supplied issuer never reaches the key; `AuthenticateFederation`/`ProvisionExternalPrincipal` take only `connection_id` + opaque proof, and the key's issuer is read from the connection (`src/authenticate.rs:220`).
- Mismatched audience/client denies at step 4, before tenant resolution (`src/authenticate.rs:207-213`).
- A disabled connection denies at both proof-driven commands (`src/authenticate.rs:192`) and at `link_external_principal` (see J5 for its coverage, not its correctness).
- `jit_provisioning: false` denies, and the key-exists path denies, in that order; a denial appends no event and mints no identity.
- No unverified hint reaches resolution: `unverified_hint` is read only by `matches_unvalidated`, whose result only selects which refusal clause is named.
- Every read port takes `&self`; `&mut self` appears only on the two writing ports.
- `Projection::fold(&[])` yields no rows; no projection row exists without an event.
- The `PersistedValue` exhaustive match is real: `CredentialProof`/`CredentialSecret` are `Transient` with no `PersistedValue` impl and the orphan rule blocks adding one, so a transient field in an event fails to compile. Its width is narrower than the comment implies — `String` is `PersistedValue`, so a `String`-typed secret would pass; I did not raise that as a finding because no such field exists.
- `ConstructedVerifier`'s allowlist rejects the empty set at construction and is otherwise inert, which is what `decision-blocker:algorithm-policy` and the story ask for.
- I did not reproduce a cross-organization *admission* (as opposed to denial) through tenant resolution: the `organization_id != connection.organization_id` check at `src/authenticate.rs:274` closes it.

## 6. Paths written outside the worktree

All four under the assigned scratch root `<scratch>/federation-linking/adversary/`:

- `<scratch>/federation-linking/adversary/suite-after.log`
- `<scratch>/federation-linking/adversary/suite-after-nofailfast.log`
- `<scratch>/federation-linking/adversary/suite-final.log`
- `<scratch>/federation-linking/adversary/clippy.log`

No other write outside the worktree; nothing under `/tmp`; no git write command, no `aep` command; lease taken, heartbeated twice, and released with `session-end`.

## 7. findings

```findings
- file: crates/mandate-federation/src/authenticate.rs
  line: 235
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "tenant resolution never requires the selected connection's own TenantResolutionRule to match, so a proof failing that connection's configured claim authenticates through it whenever another connection of the same organization matches."
- file: crates/mandate-federation/src/link.rs
  line: 59
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "LinkExternalPrincipal realizes only the caller-organization half of the declared \"organization or target principal mismatches\" denial, so an administrator can bind an external subject to a principal this crate's own projection records in another organization and then authenticate it into theirs."
- file: crates/mandate-federation/src/authenticate.rs
  line: 80
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "authenticate_federation never reads ExternalPrincipal.state, so a LinkStore implementation that returns a terminal Unlinked row per the port's documented contract gets a session for it."
- file: crates/mandate-federation/src/authenticate.rs
  line: 144
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: "an empty validated subject is admitted as a canonical key component, collapsing every external identity from that issuer onto one principal; constructed, because no in-tree verifier produces an empty subject."
- file: crates/mandate-federation/src/record.rs
  line: 274
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "the fold copies ExternalPrincipalProvisioned's link_method instead of enforcing the ConfiguredFederation literal the contract pins, so only the single in-crate call site holds that literal."
- file: crates/mandate-federation/src/record.rs
  line: 209
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "Projection::fold fails the entire log on one duplicate key, so the race jit-conflict names leaves the whole read model permanently unbuildable rather than resolving to one surviving record."
- file: crates/mandate-federation/src/authenticate.rs
  line: 289
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "a rule naming no verified claim matches every proof and resolution ranges across organizations, so any tenant registering a connection on a shared issuer turns every other tenant's logins on it into TenantAmbiguous denials, with no guard at registration."
- file: crates/mandate-federation/src/record.rs
  line: 320
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "record_link silently drops a link creation event whose connection the projection does not hold, removing it from the uniqueness index without an error."
- file: crates/mandate-federation/src/lib.rs
  line: 145
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "RequestContext.credential is caller-supplied and is persisted verbatim in the ExternalPrincipalProvisioned verified context, on the one command that has no verified caller."
- file: crates/mandate-federation/src/link.rs
  line: 53
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "no test folds a disabled connection before calling link_external_principal, so deleting that command's disabled-connection denial leaves the suite green."
```