---
format: aep.planning-md/1
id: review-result:wave2-domain-runtime-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:domain-runtime
tags:
- model-deviation-opus
relations:
- reviews: story:domain-runtime
revision: 1
---
unit: story:domain-runtime — working tree of `impl/domain-runtime` (uncommitted; base `d47c0b54f5b887c55c3bf412c477499874413dae`)
verdict: NEEDS-CHANGE
cases: executed 25→29, red 4
origin: introduced 7 / pre-existing 3 / undecided 0
wrote-outside-worktree: 6 path groups, all under the assigned scratch
needs-coordinator: `unmapped.md:7` rewrite, `components.yaml` wiring for 25 new commands/events, obligations rows, regeneration — all already assigned to it by the story

## 1. `git --no-pager diff --stat`

The implementation is **uncommitted**, so `git diff --stat` shows the implementor's 12 files, not mine. My addition is untracked. Both, verbatim:

```
 crates/mandate-types/src/inventory.rs   |  13 +-
 crates/mandate-types/tests/inventory.rs |   7 +-
 systems/mandate/domains/audit.yaml      |  40 ++++-
 systems/mandate/domains/credential.yaml |  61 ++++++-
 systems/mandate/domains/delegation.yaml | 129 ++++++++++++++-
 systems/mandate/domains/directory.yaml  |  97 ++++++++++-
 systems/mandate/domains/federation.yaml |  66 +++++++-
 systems/mandate/domains/graph.yaml      |  32 +++-
 systems/mandate/domains/identity.yaml   |  24 ++-
 systems/mandate/domains/policy.yaml     |  74 ++++++++-
 systems/mandate/domains/tenancy.yaml    | 279 +++++++++++++++++++++++++++++++-
 systems/mandate/domains/workload.yaml   |  42 ++++-
 12 files changed, 824 insertions(+), 40 deletions(-)

$ git status --short
 M crates/mandate-types/src/inventory.rs
 M crates/mandate-types/tests/inventory.rs
 M systems/mandate/domains/audit.yaml
 M systems/mandate/domains/credential.yaml
 M systems/mandate/domains/delegation.yaml
 M systems/mandate/domains/directory.yaml
 M systems/mandate/domains/federation.yaml
 M systems/mandate/domains/graph.yaml
 M systems/mandate/domains/identity.yaml
 M systems/mandate/domains/policy.yaml
 M systems/mandate/domains/tenancy.yaml
 M systems/mandate/domains/workload.yaml
?? crates/mandate-types/tests/contract_adversary.rs
?? target
```

The only path I added is `crates/mandate-types/tests/contract_adversary.rs` — a test file. `target` is the coordinator's symlink. No implementation file was touched; `ess specify validate --path systems/mandate` still reports `mandate v1 — 14 file(s), valid`.

## 2. Cases added — `crates/mandate-types/tests/contract_adversary.rs`

The cases read `systems/mandate/domains/*.yaml`, not `generated/`, on purpose: `generated/` in this tree predates the change, so a case reading it would be red from staleness and prove nothing. A guard case (`the_reader_sees_the_contract_it_claims_to_see`, **green**) asserts the reader sees 36 entities / 59 commands and five known-true controls, so a reader bug can never be mistaken for a finding.

**Case A — `the_field_that_gates_provisioning_is_settable_by_a_declared_command`** (red now). Run alone, first execution:

```
running 1 test
test the_field_that_gates_provisioning_is_settable_by_a_declared_command ... FAILED

thread 'the_field_that_gates_provisioning_is_settable_by_a_declared_command' (3392605) panicked at crates/mandate-types/tests/contract_adversary.rs:252:5:
assertion `left == right` failed: mandate.federation.FederationConnection (federation.yaml) declares ["jit_provisioning"], which no declared command takes as input. RegisterFederationConnection (federation.yaml, inputs {"client_id", "context", "issuer", "tenant_resolution"}) is the only command that creates a connection and there is no UpdateFederationConnection, so no connection this contract can produce ever admits just-in-time provisioning and mandate.federation.ProvisionExternalPrincipal is unreachable on its accepted outcome
  left: ["jit_provisioning"]
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out
```

**Case B — `every_declared_state_is_the_initial_state_or_a_declared_resting_state`** (red now). Run alone, first execution:

```
running 1 test
test every_declared_state_is_the_initial_state_or_a_declared_resting_state ... FAILED

thread 'every_declared_state_is_the_initial_state_or_a_declared_resting_state' (3392636) panicked at crates/mandate-types/tests/contract_adversary.rs:290:5:
assertion `left == right` failed: a state that is neither the initial state nor terminal declares that no instance may rest there. mandate.credential.RetireSigningKey's own accepted summary says a retired key "remains admitted for verifying credentials already issued under it until they expire" — it rests in Retired, and expiry is not a recorded move — while the only terminal state is Revoked, which the same file calls the emergency procedure that refuses the credentials the key signed
  left: {"mandate.credential.SigningKey (credential.yaml)": ["Retired"]}
 right: {}

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out
```

**Case C — `every_field_an_entity_invariant_bounds_is_bounded_in_the_projected_schema`** (red now). Run alone, first execution:

```
running 1 test
test every_field_an_entity_invariant_bounds_is_bounded_in_the_projected_schema ... FAILED

thread 'every_field_an_entity_invariant_bounds_is_bounded_in_the_projected_schema' (3392711) panicked at crates/mandate-types/tests/contract_adversary.rs:358:5:
assertion `left == right` failed: an entity invariant that bounds a field is projected into no constraint on that field, so a consumer validating a record against generated/schema/entities accepts a value the contract forbids. Not yet in the projection, and so not asserted on here: ["mandate.identity.PrincipalSecurityEpoch.generation (generation >= 0)", "mandate.identity.OrganizationSecurityEpoch.generation (generation >= 0)", "mandate.identity.FederationSecurityEpoch.generation (generation >= 0)"]
  left: ["mandate.delegation.Delegation.transitive declares `transitive == false` and projects as {\"type\":\"boolean\"}"]
 right: []

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out
```

Case C is red on a pair that is **already in** `generated/` (`Delegation.transitive`), so its redness is the finding and not staleness. The three epoch rows are listed, not asserted on. Evidence that they will be unbounded after regeneration: I ran `ess generate --kind schema --out <scratch>` (never into the worktree) and the regenerated `mandate.identity.PrincipalSecurityEpoch.schema.json` carries `"generation": {"type": "integer"}` — no `minimum`.

## 3. Suite run, after the cases existed

`executed <before>` from a second run with my target deselected, naming the exclusion:

```
$ cargo test -p mandate-types --locked --lib --test adversary --test conformance --test inventory
running 0 tests  → ok. 0 passed
running 2 tests  → ok. 2 passed      (tests/adversary.rs, pre-existing)
running 13 tests → ok. 13 passed     (tests/conformance.rs)
running 10 tests → FAILED. 9 passed; 1 failed   (tests/inventory.rs)
```
executed before = **25**, red 1 — `the_three_generation_records_carry_exactly_the_declared_generation` at `crates/mandate-types/tests/inventory.rs:149`, the unit's own expected-red tripwire against stale `generated/`.

Full suite:

```
$ cargo test -p mandate-types --locked
running 0 tests  → ok. 0 passed
running 2 tests  → ok. 2 passed
running 13 tests → ok. 13 passed
running 10 tests → FAILED. 9 passed; 1 failed
running 4 tests  → FAILED. 1 passed; 3 failed
error: test failed, to rerun pass `-p mandate-types --test contract_adversary`
EXIT=101
```
executed after = **29**, red **4** (3 mine + the unit's staleness tripwire).

## 4. Findings

| # | file:line | what is wrong | measured / reaches | verdict | origin |
|---|---|---|---|---|---|
| A | `systems/mandate/domains/federation.yaml:65` | `jit_provisioning` is a required field of `FederationConnection` that **no declared command can set**. `RegisterFederationConnection` (`:180`) takes `{context, issuer, client_id, tenant_resolution}`; the story states there is no `UpdateFederationConnection`; `FederationConnectionCreated` carries only `context`, so no event sets it either. The gate `decision-blocker:jit-provisioning` put in front of JIT is stuck closed, and `ProvisionExternalPrincipal` (`:224`) is unreachable on its accepted outcome — the whole feature this unit shipped is dead. **Fix:** add `jit_provisioning` to `RegisterFederationConnection`'s input (unit's own file), or declare a command that sets it. | measured: `contract_adversary.rs:252`, exit 101 · reaches: the operator's own required evidence, "a first-time user on a connection with `jit_provisioning: true`", has no declared path to that connection | NEEDS-CHANGE | introduced |
| B | `systems/mandate/domains/credential.yaml:96` | `SigningKey` declares `terminal: [Revoked]` while `Retired` is neither initial nor terminal — the only such state in all 36 entities. ESS's own generated prose defines terminal as "an instance may rest there forever… declared rather than inferred from having no way out". `RetireSigningKey`'s summary (`:416`) says a retired key rests until credentials expire, and expiry is not a recorded move; the only declared exit is `RevokeSigningKey`, which the same file calls the emergency procedure that refuses the credentials the key signed. Following the lifecycle destroys what retirement preserves. **Fix:** `terminal: [Retired, Revoked]`. | measured: `contract_adversary.rs:290` · reaches: ordinary key rotation; the regenerated `generated/docs/domains/mandate-credential.md` renders `Revoked --> [*]` as the only exit | NEEDS-CHANGE | introduced |
| C | `systems/mandate/domains/identity.yaml:175` | `invariants: [generation >= 0]` projects into no JSON Schema constraint. `identity.yaml:3` claims the field is "constrained non-negative by its entity invariant" and `src/inventory.rs` says "the contract declares the generation as a non-negative Integer"; the machine-readable contract says `{"type":"integer"}` and accepts `-1`. The invariant reaches prose only (`generated/docs`, `docs-ir`). | measured: `contract_adversary.rs:358` on `Delegation.transitive`, present in today's `generated/` · reaches: any consumer validating against `generated/schema/entities/**`; scratch regeneration confirms `generation` lands unbounded | CONFIRMED | pre-existing |
| D | `systems/mandate/domains/federation.yaml:328` | `ExternalPrincipalProvisioned` carries `{context, connection_id, principal_id}` — not the `external_principal_id` the command responds with (`:246`), not `subject`, not `link_method`. Under ADR-0009 ("the events are the record; every read is a fold") the `ExternalPrincipal` the decision requires, with `link_method: ConfiguredFederation`, cannot be folded from the log. The summary at `:241` asserts the link method; nothing in the contract carries it. | measured: compiled event fields vs `ExternalPrincipal`'s six fields · reaches: the identical shape of `ExternalPrincipalLinked` reproduces at base | CONFIRMED | pre-existing |
| E | `systems/mandate/domains/tenancy.yaml:371` | 18 of the 19 new lifecycle events carry only `context` and never the identity of the record whose state they change (`OrganizationClosed`, `TeamRetired`, `SpaceRetired`, `SigningKeyRetired`, `AgentRetired`, …). `AuditEventRedacted` (`audit.yaml:120`), added in the same diff, carries `id` — the implementor demonstrates the right shape once and omits it 18 times. | measured: compiled payloads, 18/19 · reaches: 15/15 base move-events do the same, so ADR-0009 (accepted 2026-09-18) is what newly makes it a defect | CONFIRMED | pre-existing |
| F | `systems/mandate/domains/federation.yaml:297` | `DisableOAuthClient`'s summary says codes already issued "are refused through the code record's own one-use consumption", and its denial (`:299`) requires disablement to "refuse the codes already issued to it". One-use consumption prevents replay; it does not refuse an outstanding code. `AuthorizationCode` declares `[Issued, Consumed]` and one transition, `consume` — no declared move invalidates an outstanding code when its client is disabled. | measured: `AuthorizationCode` lifecycle in the compiled contract · reaches: any code issued by `AuthorizePublicClient` before the client is disabled | CONFIRMED | introduced |
| G | `systems/mandate/domains/federation.yaml:243` | The JIT denial mirrors `AuthenticateFederation`'s (`:219`) but **replaces** "principal linking is absent/conflicting" instead of adding to it. Dropping *absent* is right (it is the precondition); dropping *conflicting* is not: a subject already linked under a different connection's issuer in the same organization does not collide with the composite (organization, configured issuer, subject) key, so the declared denial does not cover it and a second principal is created for the same human. | measured: deny-text comparison, `:219` vs `:243` · reaches: an organization with two federation connections, which nothing in the contract forbids | CONFIRMED | introduced |
| H | `systems/mandate/domains/tenancy.yaml:293` | `AddTeamMembership`'s summary describes "one membership record with one contribution recording where it came from" and its denial turns on the two being "recorded together" — but the command emits exactly one event, `TeamMembershipAdded`, and **no command in the contract creates a `MembershipContribution`** (only `RemoveMembershipContribution` exists). The summary describes a record the contract cannot produce. | measured: compiled command/event set · reaches: the summary is the coordinator's source for the obligations row | CONFIRMED | introduced |
| I | `systems/mandate/domains/tenancy.yaml:170` | `CreateOrganization` is the only one of the 25 new commands whose accepted outcome carries no `summary` — and it is the command that creates the isolation root. | measured: compiled outcomes, 24/25 have one · reaches: documentation only | CONFIRMED | introduced |
| J | `<scratch>/new-commands-table.md` | The `RevokeSigningKey` row contains an unescaped `\|` inside its moves cell (`(Recorded \| Retired to Revoked)`), splitting that row into five cells. The coordinator copies deny text "verbatim" from this table into `docs/architecture/command-obligations.md`; a program parsing it reads the event name as the deny text. Verified: my parser did exactly that. | measured: markdown table parse, 24/25 rows matched the contract verbatim, this one did not · reaches: the coordinator's documented use of the table | CONFIRMED | introduced |

Origins for A and B were established by reading the base with `git show d47c0b5:systems/mandate/domains/*.yaml` into scratch: at base, `FederationConnection` has no `jit_provisioning` and **no entity anywhere** has a non-initial non-terminal state — both cases are green at base. C is red at base.

## 5. Attacked and could not break

- All 59 commands have exactly one accepted outcome emitting exactly one event and exactly one denied outcome. No denied outcome emits.
- 34 declared transitions, each moved by exactly one command; no `moves` names an undeclared transition; no transition is moved twice.
- No destructive transition anywhere; every terminal state has no outgoing transition; `SupersedePolicy`, `SupersedeAuthorizationModel`, `SupersedeAgentCapabilityCeiling` and `ConsumeApproval` are one-way — no superseded version reactivates, no approval is reused.
- `mandate.policy.Denied` and `mandate.workload.Denied` match the other nine exactly: same summary sentence, one `reason: DenialReason` field.
- No new entity or event references `CredentialSecret` or `CredentialProof` — checked against a **scratch regeneration**, not the stale tree.
- Every existing tripwire goes green after regeneration: 110 types / 74 authored / 36 entities / 36 state enums, pattern set unchanged, epoch properties `{id, state, generation}`. `core.yaml` is unmodified.
- Organization/tenant check present in every new denial that acts on a tenant-owned record; absent only on `RetireSigningKey`/`RevokeSigningKey`, where `SigningKey` declares no `organization_id` and is platform-scoped — correct.
- `CloseOrganization`, `RetireTeam`, `RetireSpace`, `DeregisterResource` each name what they invalidate and what they preserve. `RedactAuditEvent` cannot be read as deletion: `AuditEvent` has only `Recorded`/`Redacted` and no command removes one.
- `ProvisionExternalPrincipal`'s denial does cover `jit_provisioning` false and composite-key-exists.
- `OrganizationMembership` is not a `Recorded`-only orphan — it already had `Active`/`Removed` at base. Only `SecurityEpochSnapshot` and the three epoch records remain `Recorded`-only, and `identity.yaml:1-6` prohibits their mutation explicitly.
- ESS does validate invariant field references: a scratch copy with `no_such_field >= 0` is refused as `ESS-ENTITY-003 unobservable_fact`.
- 24 of 25 rows in the implementor's command table match the compiled contract verbatim.

## 6. Paths written outside the worktree

All under the assigned scratch root `<scratch>` = the wave-2 `domain-runtime` scratch directory, in a new `adversary/` subdirectory:

- `<scratch>/adversary/compiled-adv.json`, `<scratch>/adversary/compile.err` — my own `ess specify compile` output
- `<scratch>/adversary/suite.log` — the full suite run
- `<scratch>/adversary/probe/mandate/**` — a **mutated copy** of `systems/mandate` (invariant changed to `no_such_field >= 0`) used to probe ESS's invariant validation; the worktree was never mutated
- `<scratch>/adversary/regen/docs/**` and `<scratch>/adversary/regen/schema/**` — post-regeneration artifacts from `ess generate --out`, written to scratch and never into `generated/`
- `<scratch>/adversary/base/*.yaml` — 12 files from `git show <base>:…`, for origin determination

```findings
- file: systems/mandate/domains/federation.yaml
  line: 65
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "jit_provisioning is a required FederationConnection field that no declared command can set, so no connection admits just-in-time provisioning and ProvisionExternalPrincipal is unreachable on its accepted outcome."
- file: systems/mandate/domains/credential.yaml
  line: 96
  category: boundary
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "SigningKey declares Retired as the only non-initial non-terminal state in the system, so the contract forbids a rotated key resting there and obliges the emergency revocation that refuses the credentials retirement was meant to keep verifying."
- file: systems/mandate/domains/identity.yaml
  line: 175
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: "the entity invariant generation >= 0 projects into no JSON Schema constraint, so the machine-readable contract the unit's comments call non-negative accepts a negative generation."
- file: systems/mandate/domains/federation.yaml
  line: 328
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: "ExternalPrincipalProvisioned omits the external_principal_id, subject and link_method of the record it creates, so under ADR-0009 the ConfiguredFederation link the decision requires cannot be folded from the event log."
- file: systems/mandate/domains/tenancy.yaml
  line: 371
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: "eighteen of the nineteen new lifecycle events carry only context and never the identity of the record whose state they change, while AuditEventRedacted in the same diff carries it."
- file: systems/mandate/domains/federation.yaml
  line: 297
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "DisableOAuthClient promises to refuse authorization codes already issued and attributes that to one-use consumption, which prevents replay rather than refusal, and no declared transition invalidates an outstanding code."
- file: systems/mandate/domains/federation.yaml
  line: 243
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: "the JIT denial replaces rather than extends AuthenticateFederation's clause, dropping conflicting linking, which the composite key does not cover when the same subject is already linked through a different connection issuer in the organization."
- file: systems/mandate/domains/tenancy.yaml
  line: 293
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "AddTeamMembership's summary and denial describe a MembershipContribution recorded alongside the membership, but the command emits one event and no command in the contract creates a MembershipContribution."
- file: systems/mandate/domains/tenancy.yaml
  line: 170
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "CreateOrganization is the only one of the twenty-five new commands whose accepted outcome carries no summary, and it is the command that creates the isolation root."
- file: <scratch>/new-commands-table.md
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: "the RevokeSigningKey row carries an unescaped pipe inside its moves cell, so a program reading the handoff table the coordinator copies deny text verbatim from reads the event name as the deny text."
```