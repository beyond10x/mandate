---
format: aep.planning-md/1
id: review-result:wave2-domain-runtime-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:domain-runtime
tags:
- model-deviation-opus
- scratch-path-redacted
relations:
- reviews: story:domain-runtime
revision: 1
---
unit: story:domain-runtime, correction round 1 — working tree of `impl/domain-runtime` (uncommitted; base `d47c0b54f5b887c55c3bf412c477499874413dae`)
verdict: NEEDS-CHANGE
cases: executed 29→34, red 6
origin: introduced 6 / pre-existing 0 / undecided 0
wrote-outside-worktree: 5 paths, all under the assigned scratch
needs-coordinator: nothing beyond what it already owns

## 1. `git --no-pager diff --stat`

The implementation is uncommitted, so the tracked diff is the implementor's, byte-identical to the one I was handed. My only touched path is untracked.

```
 crates/mandate-types/src/inventory.rs   |  13 +-
 crates/mandate-types/tests/inventory.rs |   7 +-
 systems/mandate/domains/audit.yaml      |  40 ++++-
 systems/mandate/domains/credential.yaml |  70 +++++++-
 systems/mandate/domains/delegation.yaml | 141 ++++++++++++++-
 systems/mandate/domains/directory.yaml  | 106 +++++++++++-
 systems/mandate/domains/federation.yaml |  88 +++++++++-
 systems/mandate/domains/graph.yaml      |  35 +++-
 systems/mandate/domains/identity.yaml   |  24 ++-
 systems/mandate/domains/policy.yaml     |  80 ++++++++-
 systems/mandate/domains/tenancy.yaml    | 292 +++++++++++++++++++++++++++++++-
 systems/mandate/domains/workload.yaml   |  45 ++++-
 12 files changed, 899 insertions(+), 42 deletions(-)

$ git status --short        # only the added path shown
?? crates/mandate-types/tests/contract_adversary.rs
?? target                   # the coordinator's symlink
```

The only path I wrote is `crates/mandate-types/tests/contract_adversary.rs` — a test file. No implementation file was touched. `ess specify validate --path systems/mandate` still reports `mandate v1 — 14 file(s), valid`.

**Assigned first edit, done first:** `rustfmt --edition 2024` on that file only; `cargo fmt -p mandate-types -- --check` now exits **0**. (It failed on `:51` and `:258` as briefed.) One later reader fix and three comment line-number corrections were reformatted the same way; the final `cargo fmt -p mandate-types -- --check` exits 0 and `cargo clippy -p mandate-types --all-targets --locked` is clean.

## 2. Cases added — `crates/mandate-types/tests/contract_adversary.rs`

I added a second reader (input/response types, denial text, accepted summary, event field types, `moves`, `emits`) with its own guard, and four cases. I changed nothing in pass 1's four cases or its reader. Guard `the_second_reader_sees_the_contract_it_claims_to_see` is **green** and asserts 36 entities / 59 commands / 65 events against `ess specify compile`, plus that the recogniser used by case D1 sees the correction's own `"the bound client is disabled"` clause — so a reader bug cannot be mistaken for a finding.

One honest note on order: case D3 first failed on a reader bug (`mandate.audit.RecordAuditEvent` names its success outcome `recorded`, not `accepted`). That was a typo, not a finding; I fixed the helper and re-ran. The red output below is the run after that fix. Everything else is first-execution output.

**Case D1 — `an_off_state_this_unit_declares_is_refused_by_the_commands_that_admit_into_it`** (red now). Run alone:

```
running 1 test
test an_off_state_this_unit_declares_is_refused_by_the_commands_that_admit_into_it ... FAILED

thread '...' panicked at crates/mandate-types/tests/contract_adversary.rs:909:5:
assertion `left == right` failed: a state this unit made reachable is admitted into by a command that never refuses it. mandate.federation.DisableOAuthClient's accepted summary says "No new authorization code is issued to it", and the two commands that issue an authorization code both take an OAuthClientId and refuse only a client that is "not a registered public client" — which a disabled one still is, because the same summary says "The registration record is kept". Not asserted on, because the identity type does not name one moving record: ["mandate.delegation.Agent (mandate.core.PrincipalId)"]
  left: ["mandate.directory.DirectoryGroup rests in [\"Retired\"] and mandate.directory.CreateDirectoryGroupTeamMapping (directory.yaml:265) reads it as [\"group_id\"] without refusing it there — its whole denial is: Caller lacks mapping authority, group/team is unknown, either target is outside the verified organization, or provenance-preserving contribution reconciliation fails.", "mandate.directory.DirectoryGroup rests in [\"Retired\"] and mandate.directory.SyncDirectoryMembership (directory.yaml:288) reads it as [\"group_id\"] without refusing it there — its whole denial is: Caller is not an admitted provisioning source, group/member organization mismatches, or synchronization would grant authority without an explicit valid team mapping.", "mandate.federation.OAuthClient rests in [\"Disabled\"] and mandate.credential.IssueAuthorizationCode (credential.yaml:363) reads it as [\"client_id\"] without refusing it there — its whole denial is: Trusted control-plane caller/session context, registered public client, exact redirect URI, S256 policy, tenant/target agreement, authority narrowing or bounded expiry validation fails.", "mandate.federation.OAuthClient rests in [\"Disabled\"] and mandate.federation.AuthorizePublicClient (federation.yaml:257) reads it as [\"client_id\"] without refusing it there — its whole denial is: Session proof is invalid/stale, client is not a registered public client, exact redirect URI or state/applicable nonce binding fails, S256 challenge is absent/invalid, target is unregistered/outside tenant, or STS code issuance/narrowing is refused.", "mandate.tenancy.Team rests in [\"Retired\"] and mandate.directory.CreateDirectoryGroupTeamMapping (directory.yaml:265) reads it as [\"team_id\"] without refusing it there — its whole denial is: Caller lacks mapping authority, group/team is unknown, either target is outside the verified organization, or provenance-preserving contribution reconciliation fails.", "mandate.tenancy.Team rests in [\"Retired\"] and mandate.tenancy.AddTeamMembership (tenancy.yaml:277) reads it as [\"team_id\"] without refusing it there — its whole denial is: Caller lacks team-administration authority, team or principal is unresolved or outside the verified organization, the principal is not a member of that organization, the principal is already a member of that team, or the membership cannot be recorded as a manual one without implying a directory-mapped contribution."]
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out
```

**Case D2 — `the_event_that_records_the_provisioning_gate_names_the_connection_it_gates`** (red now). Run alone:

```
running 1 test
test the_event_that_records_the_provisioning_gate_names_the_connection_it_gates ... FAILED

thread '...' panicked at crates/mandate-types/tests/contract_adversary.rs:973:5:
assertion `left != right` failed: mandate.federation.FederationConnectionCreated (federation.yaml:328) carries ["jit_provisioning"], a per-connection setting of mandate.federation.FederationConnection (federation.yaml:52), and no field of type mandate.core.FederationConnectionId — so the event that records which connections admit just-in-time provisioning says nothing about which connection it is, and the gate mandate.federation.ProvisionExternalPrincipal's denial turns on ("connection does not admit provisioning") cannot be folded from the log ADR-0009 calls the record. mandate.federation.RegisterFederationConnection declares response ["connection_id"] of exactly that type, and the same file's ExternalPrincipalProvisioned binds its created identity from the response already. The event carries the issuer, client and tenant-resolution rule no more than it carries the identity: its full field list is ["context: mandate.core.VerifiedContext", "jit_provisioning: Boolean"]
  left: []
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out
```

**Case D3 — `the_contribution_two_new_tenancy_commands_rest_on_is_created_by_a_declared_command`** (red now). Run alone:

```
running 1 test
test the_contribution_two_new_tenancy_commands_rest_on_is_created_by_a_declared_command ... FAILED

thread '...' panicked at crates/mandate-types/tests/contract_adversary.rs:1057:5:
assertion `left != right` failed: no declared command creates a mandate.directory.MembershipContribution (directory.yaml:6): none names mandate.core.MembershipContributionId in a response and none emits an event carrying it. mandate.directory declares eight commands and the only one that touches a contribution is RemoveMembershipContribution, which moves an existing one to Removed. So mandate.tenancy.AddTeamMembership (tenancy.yaml:277) attributes the record to commands that do not exist, and mandate.tenancy.RemoveTeamMembership (tenancy.yaml:303) refuses a removal on a condition nothing in this contract can ever make true — the protection its summary promises, that "a retracted mapping never removes a membership a manual decision still holds up", is a guard over an empty set
  left: []
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out
```

**Case D4 — `an_organization_this_contract_creates_can_be_named_by_a_command_that_writes_in_it`** (red now). Run alone:

```
running 1 test
test an_organization_this_contract_creates_can_be_named_by_a_command_that_writes_in_it ... FAILED

thread '...' panicked at crates/mandate-types/tests/contract_adversary.rs:1127:5:
assertion `left != right` failed: mandate.tenancy.CreateOrganization (tenancy.yaml:170) returns ["organization_id"], and the only command in all 59 that takes a mandate.core.OrganizationId as an input is the one that closes the organization again. Every command that would put a membership, team, space, grant, connection or resource inside an organization resolves it from input.context, whose organization field is the caller's own — mandate.tenancy.AddOrganizationMembership even denies when "the principal is already a member of the verified organization". So the isolation root this command creates admits nothing and is reachable by nothing, and its own summary — "The isolation root every other tenant-owned record resolves to. It is created empty, and no membership, team, space or grant exists inside it until that record's own command writes one." — names four records none of whose commands can say which organization to write into
  left: []
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 8 filtered out
```

## 3. The suite, after the cases existed

`executed <before>`, from a second run with **my five cases deselected by name** (`--skip the_second_reader_sees_the_contract_it_claims_to_see`, `--skip an_off_state_…`, `--skip the_event_that_records_…`, `--skip the_contribution_two_new_tenancy_commands_…`, `--skip an_organization_this_contract_creates_…`). Pass 1's four cases are in the same file and are not mine to deselect, so the exclusion is case-level, not file-level.

```
$ cargo test -p mandate-types --locked --lib --test adversary --test conformance \
    --test contract_adversary --test inventory --no-fail-fast -- --skip <my five>
running 0 tests   → ok. 0 passed                       (src/lib.rs)
running 2 tests   → ok. 2 passed                       (tests/adversary.rs)
running 13 tests  → ok. 13 passed                      (tests/conformance.rs)
running 4 tests   → FAILED. 3 passed; 1 failed         (tests/contract_adversary.rs, 5 filtered out)
running 10 tests  → FAILED. 9 passed; 1 failed         (tests/inventory.rs)
error: 2 targets failed
```
executed before = **29**, red 2 — pass 1's case C (`every_field_an_entity_invariant_bounds_is_bounded_in_the_projected_schema`, the ESS projection gap the coordinator filed as its own story) and `tests/inventory.rs:149`, the unit's own expected-red staleness tripwire.

Full suite:

```
$ cargo test -p mandate-types --locked --no-fail-fast
running 0 tests   → ok. 0 passed
running 2 tests   → ok. 2 passed
running 13 tests  → ok. 13 passed
running 9 tests   → FAILED. 4 passed; 5 failed        (tests/contract_adversary.rs)
running 10 tests  → FAILED. 9 passed; 1 failed        (tests/inventory.rs)
   Doc-tests mandate_types → ok. 7 passed
error: 2 targets failed
```
executed after = **34** on the same five binaries pass 1 counted (doc-tests excluded from both numbers for comparability; pass 1's fail-fast run never reached them). Red **6** — my 4, plus case C, plus the unit's tripwire.

**Pass 1's cases A and B are green.** `the_field_that_gates_provisioning_is_settable_by_a_declared_command` and `every_declared_state_is_the_initial_state_or_a_declared_resting_state` both pass.

## 4. Findings

Covering the working tree of `impl/domain-runtime` over base `d47c0b54f5b887c55c3bf412c477499874413dae`. Origins were established by reading the base with `git show <base>:systems/mandate/domains/*.yaml`; none required moving the tree.

| # | file:line | what is wrong | measured / reaches | verdict | origin |
|---|---|---|---|---|---|
| **1** | `systems/mandate/domains/federation.yaml:286` | `DisableOAuthClient`'s accepted summary (`:307`) states the control: "No new authorization code is issued to it." Both commands that issue one — `AuthorizePublicClient` (`:286`) and `IssueAuthorizationCode` (`credential.yaml:395`) — take an `OAuthClientId` and refuse only a client that is "not a registered public client", which a disabled one still is because the same summary says "The registration record is kept". The security control the unit added is declared and not enforced. Its own denial (`:309`) even refuses when "disablement cannot stop the issuance of new authorization codes to it" — a condition no declared command makes false. **Fix:** add "the client is disabled" to `federation.yaml:286` and `credential.yaml:395`, exactly as the correction did for `RedeemAuthorizationCode`. | measured: `contract_adversary.rs:909`, exit 101 · reaches: the documented purpose of the command — a public client whose redirect surface is no longer trusted | NEEDS-CHANGE | introduced (`OAuthClient` was `Recorded`-only at base) |
| **2** | `systems/mandate/domains/tenancy.yaml:298` | `RetireTeam`'s summary (`:273`) says a retired team "stops resolving as an authorization subject", and `AddTeamMembership` (`:277`), added in the same diff, admits a membership into one: its denial names "team … unresolved" but never "retired". `CreateDirectoryGroupTeamMapping` (`directory.yaml:283`) does the same. `RetireDirectoryGroup`'s summary (`directory.yaml:323`) says a retired group "stops contributing authority", and `SyncDirectoryMembership` (`directory.yaml:305`) and `CreateDirectoryGroupTeamMapping` both still sync into it. **Fix:** name the off state in those four denials. | measured: `contract_adversary.rs:909`, same assertion, rows 1–2 and 5–6 · reaches: `story:tenancy-topology` and `story:directory-provenance` both build on these commands | NEEDS-CHANGE | introduced (`Team`, `DirectoryGroup` were `Recorded`-only at base) |
| **3** | `systems/mandate/domains/federation.yaml:328` | Correction A put `jit_provisioning` on `RegisterFederationConnection`'s input and carried it into `FederationConnectionCreated` — an event that carries `{context, jit_provisioning}` and **names no connection**. Under ADR-0009 the gate `ProvisionExternalPrincipal`'s denial turns on ("connection does not admit provisioning") cannot be folded, because the flag is attached to nothing; nor can the composite key its other clause needs, since the event omits `issuer`, `client_id` and `tenant_resolution`, all of which are inputs. Every one of the six creation commands this unit *added* carries the created identity via `response:`, including `ExternalPrincipalProvisioned` in the same file. The one it *changed* does not. **Fix:** `connection_id: {response: connection_id}` on the event, and carry the three input fields. | measured: `contract_adversary.rs:973` · reaches: the fix for pass-1 finding A is what put a per-connection field there; at base the event carried only `context` | NEEDS-CHANGE | introduced |
| **4** | `systems/mandate/domains/tenancy.yaml:321` | Correction H reworded `AddTeamMembership`'s summary to say a contribution "is mandate.directory's own record, written by that domain's commands" — `mandate.directory` declares eight commands and none creates a `MembershipContribution`; only `RemoveMembershipContribution` exists, which moves one to `Removed`. `RemoveTeamMembership` (`:303`, new in this diff) denies while "a mandate.directory mapping contribution still supports it", a condition nothing can make true, so the protection its summary promises is a guard over an empty set. The false claim moved from one command to two; it was not removed. **Fix:** drop the contribution clause from `RemoveTeamMembership`'s denial and the attribution from `AddTeamMembership`'s summary, or record that both wait on `story:directory-provenance`. | measured: `contract_adversary.rs:1057` · reaches: the coordinator copies these denials verbatim into `docs/architecture/command-obligations.md` | NEEDS-CHANGE | introduced (neither command exists at base; base tenancy declares only `RemoveOrganizationMembership`) |
| **5** | `systems/mandate/domains/tenancy.yaml:170` | `CreateOrganization` returns `organization_id`, and it is the only command in all 59 that touches an `OrganizationId` as anything but an output — the sole input of that type in the contract is `CloseOrganization`'s. Every command that would write inside an organization resolves it from `input.context`, and `mandate.core.VerifiedContext` (`core.yaml:211-219`) carries exactly one `organization`, the caller's. So the isolation root this command creates can be closed and nothing else; its own summary (`:185`) names four records "until that record's own command writes one", and none of those commands can say which organization. **Fix:** give `AddOrganizationMembership` an explicit `organization_id` input, or record in the report that the first membership is a platform bootstrap outside this contract. | measured: `contract_adversary.rs:1127` · reaches: the story's own "Creation commands the tenancy story needs", and `story:tenancy-topology`'s "Create org memberships, teams and spaces" | NEEDS-CHANGE | introduced (no command took an `OrganizationId` input at base, and `CreateOrganization` did not exist) |
| **6** | `systems/mandate/domains/tenancy.yaml:298` | Judgement, no case of its own. `AddOrganizationMembership` (`:230`), new in this diff, denies when "the principal is unresolved **or disabled**". `AddTeamMembership` (`:298`), new in the same diff and file, denies only "team or principal is unresolved" — so a disabled principal can be added to a team but not to an organization. My class case cannot assert this: `Agent` and `Principal` share `mandate.core.PrincipalId`, so "which record does this command read" is not decidable from the input type, and the case reports that row as undecidable rather than red. | measured: the two deny texts, read side by side · reaches: `story:tenancy-topology` | CONFIRMED | introduced |
| **7** | `systems/mandate/domains/federation.yaml:247` | Judgement. `ExternalPrincipalProvisioned.subject` is bound `{generated: true}` — the system invents it — while the outcome's own summary (`:250`) says the composite key is "(organization, connection issuer, external subject)" with the subject coming from the validated proof, and the file's header forbids fallbacks "from unverified selectors". ESS's binding vocabulary has only `input`, `response` and `generated`, and `subject` is neither an input nor a response field, so `generated` is the only thing the author could have written — which is why this is `INFEASIBLE` here rather than a change. The honest fix is to add `subject` to the command's response, as the correction did for `external_principal_id`. | measured: compiled binding `{"kind":"generated"}` on a field the summary sources from the proof · reaches: a fold reading the event has no way to know the subject is not invented | INFEASIBLE | introduced |
| **8** | `systems/mandate/domains/federation.yaml:250` | Judgement. `ProvisionExternalPrincipal`'s summary says "exactly one Principal and one ExternalPrincipal are created". It emits one event; `principal_id` is `{generated: true}`; `mandate.identity` declares five commands and none creates a `Principal`, and no event anywhere records one. Under ADR-0009 the Principal this command claims to create is not in the log and `Principal.kind` is set by nothing. The gap is the base's; the claim that this command closes it is new. | measured: the compiled command and event sets for `mandate.identity` · reaches: the JIT first-login path this unit exists to declare | CONFIRMED | introduced (the claim) over a pre-existing gap |

## 5. Attacked and could not break

- **Pass-1 A held.** `jit_provisioning` is an input of `RegisterFederationConnection` (`:190`); pass 1's case A is green. What it records is finding 3, not a re-break of A.
- **Pass-1 B held.** `SigningKey` declares `terminal: [Retired, Revoked]`; pass 1's case B is green, and no entity in the tree now has a non-initial non-terminal state.
- **Pass-1 F held at redemption.** `AuthorizationCode.client_id` exists, so "the bound client" is a real binding, and `RedeemAuthorizationCode`'s denial names it. The outstanding-code hole is closed; the issuance half of the same summary is finding 1.
- **Pass-1 G held.** "principal linking is conflicting" is back at `federation.yaml:252`, alongside the two JIT-specific clauses.
- **Pass-1 I held.** All 25 of this unit's commands now carry an accepted summary.
- **Pass-1 D held.** `ExternalPrincipalProvisioned` carries `external_principal_id`, `subject` and `link_method`. The literal `ConfiguredFederation` compiles to `{"kind":"literal","value":"ConfiguredFederation"}`, and **ESS type-checks it**: a scratch copy with `link_method: NotARealVariantAtAll` is refused `ESS-COMMAND-002 type_mismatch` listing the five variants. The binding is checkable, not a free string.
- **Pass-1 E held, and held exactly.** All 19 new move-events carry the moved record's identity, and **all 19 are typed with the entity's own identity type** — including `AgentRetired.id: PrincipalId`, which is `Agent`'s declared identity and not a slip. No wrong identity type anywhere in the 18 added `id` fields.
- The 6 creation commands this unit adds all carry the created record's identity on their event. The 6 that do not are `RegisterResourceServer`, `CreateDelegation`, `CreateDirectoryGroupTeamMapping`, `AuthenticateFederation`, `LinkExternalPrincipal`, `RefreshSession` — all base commands, all `story:event-payloads-for-folds`.
- Still true after the correction: one accepted and one denied outcome per command, one emit per accepted, no denied outcome emits, every transition moved by exactly one command, no destructive transition, no terminal state with an outgoing transition, 110 types / 74 authored / 36 entities / 59 commands / 65 events, `core.yaml` unmodified, `ess specify validate` clean.
- `ExchangeCredential`, `IssueReferenceCredential` and `IssueSelfContainedCredential` do refuse a disabled `ResourceServer`; `AuthenticateFederation` does refuse a disabled `FederationConnection`. The convention finding 1 tests for is the contract's own, followed everywhere the state predates this unit.
- `cargo clippy -p mandate-types --all-targets --locked` is clean with the new cases in the tree.

## 6. Paths written outside the worktree

All five under the assigned scratch root `<scratch>/adversary-2/`:

- `compiled.json`, `compile.err` — my own `ess specify compile --format json`
- `sweep-id-types.txt`, `sweep-creation.txt`, `sweep-disabled-denials.txt` — probe output
- `suite-after.log`, `suite-before.log` — the two suite runs in part 3
- `base-check.sh` — the `git show <base>:…` script behind the origin column
- `probe/mandate/**` — a **mutated copy** of `systems/mandate` (`link_method` changed to a non-variant) used to probe ESS's enum-literal validation; the worktree was never mutated

## 7. Findings block

```findings
- file: systems/mandate/domains/federation.yaml
  line: 286
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "DisableOAuthClient's summary states that no new authorization code is issued to a disabled client, and neither AuthorizePublicClient nor IssueAuthorizationCode refuses one, so the control the unit added is declared and not enforced."
- file: systems/mandate/domains/tenancy.yaml
  line: 298
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "AddTeamMembership and CreateDirectoryGroupTeamMapping admit into a Retired team, and SyncDirectoryMembership and CreateDirectoryGroupTeamMapping into a Retired directory group, though the retirement summaries say both stop resolving."
- file: systems/mandate/domains/federation.yaml
  line: 328
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "FederationConnectionCreated now carries jit_provisioning but names no connection and omits issuer, client and tenant resolution, so the gate ProvisionExternalPrincipal's denial turns on cannot be folded from the log ADR-0009 calls the record."
- file: systems/mandate/domains/tenancy.yaml
  line: 321
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "the correction moved the MembershipContribution claim from AddTeamMembership's denial to its summary and to RemoveTeamMembership's denial, and no command in mandate.directory creates such a record, so the removal guard is over an empty set."
- file: systems/mandate/domains/tenancy.yaml
  line: 170
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "CreateOrganization returns an organization_id that no command but CloseOrganization accepts as input, and every command that would write inside an organization resolves it from the caller's own VerifiedContext, so the isolation root is created and cannot be populated."
- file: systems/mandate/domains/tenancy.yaml
  line: 298
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "AddOrganizationMembership refuses a disabled principal and AddTeamMembership, added in the same diff and file, does not, so a disabled principal can be added to a team but not to an organization."
- file: systems/mandate/domains/federation.yaml
  line: 247
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: "ExternalPrincipalProvisioned binds subject as generated while its own summary sources the external subject from the validated proof, and ESS's binding vocabulary offers no truthful alternative unless subject is added to the command's response."
- file: systems/mandate/domains/federation.yaml
  line: 250
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "ProvisionExternalPrincipal's summary claims one Principal is created, and no command or event in mandate.identity creates or records a Principal, so under ADR-0009 that Principal is not in the log and its kind is set by nothing."
```