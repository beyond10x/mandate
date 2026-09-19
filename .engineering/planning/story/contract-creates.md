---
format: aep.planning-md/1
id: story:contract-creates
kind: story
status: implemented
title: Declare creators and wrong-state outcomes so the specification can synthesize its scenarios
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: inferred
  path: docs/architecture/command-obligations.md
- confidence: inferred
  path: docs/architecture/federated-login.md
- confidence: cited
  path: systems/mandate/domains/audit.yaml
- confidence: cited
  path: systems/mandate/domains/authorization.yaml
- confidence: cited
  path: systems/mandate/domains/core.yaml
- confidence: cited
  path: systems/mandate/domains/credential.yaml
- confidence: cited
  path: systems/mandate/domains/delegation.yaml
- confidence: cited
  path: systems/mandate/domains/directory.yaml
- confidence: cited
  path: systems/mandate/domains/federation.yaml
- confidence: cited
  path: systems/mandate/domains/graph.yaml
- confidence: cited
  path: systems/mandate/domains/identity.yaml
- confidence: cited
  path: systems/mandate/domains/policy.yaml
- confidence: cited
  path: systems/mandate/domains/tenancy.yaml
- confidence: cited
  path: systems/mandate/domains/workload.yaml
revision: 11
---
## Acceptance

Given `systems/mandate`, when `ess verify conform synthesize --path systems/mandate` runs, then every entity that has a creating command carries `creates: <entity>` and `instance: <identity field>` on that command's accepted outcome, every moving command declares a `wrong-state` outcome, the refusals drop from 106 to exactly the creator-less set named below, and `ess specify validate` still reports valid.

## Why

`ess verify conform synthesize` refuses 106 lifecycle scenarios with `ESS-SYNTH-004` because no outcome declares `creates:`; the specification is missing semantics it must state, not being weakened. `ESS-SYNTH-012` follows for every `state/<Terminal>/refuses/<Cmd>` scenario until the command declares a `wrong-state` outcome.

## Scope

All twelve files under `systems/mandate/domains/` — cited. ESS syntax (`ess-domain/src/command.rs:2681-2760, 3088-3165`): on an accepted outcome `creates: <qualified entity>` + `instance: <top-level event field carrying the new identity>`; one of `creates/moves/updates` per outcome; refusal outcomes carry no subject; `wrong-state` outcome = `wrong_state: true`, `error: mandate.<domain>.Denied`, one per moving command, not combinable with `external:`.

Creators to declare: federation — `RegisterFederationConnection → FederationConnection/connection_id`, `LinkExternalPrincipal → ExternalPrincipal/external_principal_id`, `ProvisionExternalPrincipal → ExternalPrincipal/external_principal_id` (one subject; the header's "creates a Principal too" wording is corrected — the Principal record is `story:declared-writers`'), `AuthenticateFederation → mandate.identity.Session/session_id` (a login mints the session — `docs/architecture/federated-login.md` step 9; `identity.yaml` header line 6 rewritten); tenancy — `CreateOrganization`, `CreateTeam`, `CreateSpace`, `AddOrganizationMembership`, `AddTeamMembership`; graph — `RegisterResource → Resource` (`ResourceRegistered` gains a top-level `resource_id: mandate.core.ResourceId` beside `resource`), `WriteRelationship → Relation`; credential — `RegisterResourceServer`, `IssueAuthorizationCode → AuthorizationCode/code_id`, `IssueReferenceCredential`, `IssueSelfContainedCredential`, `ExchangeCredential → AccessCredential`; delegation — `CreateDelegation`; directory — `CreateDirectoryGroupTeamMapping`; audit — `RecordAuditEvent.recorded → AuditEvent`.

Remain creator-less, uncovered and named (never skipped): Principal, RefreshCredential, OAuthClient, Grant, SigningKey, Agent, AgentCapabilityCeiling, Execution, Approval, SyncJob, DirectoryGroup, DirectoryGroupMembership, MembershipContribution, Policy, AuthorizationModel, WorkloadIdentity — `story:declared-writers`.

### Units

| Unit | Owns | Validation |
|---|---|---|
| A | `federation.yaml`, `identity.yaml`, `tenancy.yaml` | `ess specify validate --path systems/mandate` |
| B | `graph.yaml`, `credential.yaml`, `delegation.yaml`, `directory.yaml`, `audit.yaml` (+ `wrong-state` on moving commands in `policy.yaml`, `workload.yaml`) | same |
| coordinator | `xtask/src/main.rs:147-151` (`obligations()` selects the outcome with an external cause, not the first error outcome); `cargo xtask generate`; regeneration | `cargo xtask corpus`, `cargo xtask contracts` |

One agent runs A then B. Probe first with `ess specify validate` whether a `when:` guard admits path-to-path equality; if not, record it and do not invent a predicate.

### Excluded

`generated/`, `components.yaml`, `core.yaml` types, `xtask/`, `docs/architecture/command-obligations.md` (the denial texts do not change), every crate.

### Gate

`ess specify validate --path systems/mandate`; `ess specify compile --path systems/mandate --format json` exit 0 with commands 59, events 72, types 110, entities 36; `ess verify conform synthesize --path systems/mandate --target ir --out <scratch>` — report the scenario count and the exact remaining refusals.

## Coordinator rulings after critic round 1, 2026-09-19

- `generated/ir/system.json` is pre-landed by the coordinator in the opening commit (a fifth `cargo xtask generate` kind: `ess specify compile --format json`), so every E1 story reads a file that exists at the wave base; the emitter story adds only the Rust kind (parallel-safety PS1, design D1).
- Merge order in E1 is fixed: `contract-shapes` first (wiring the Rust kind), then `contract-creates`, then the coordinator regenerates every kind and commits the regeneration; `cargo xtask contracts` is expected red between those two merges and green after (PS2, D3).
- `tenancy-graph-events` emits one payload for `ResourceRegistered`: `{context, resource_id, resource, parent}` — the shape after `contract-creates` lands (which adds `resource_id` as `instance:` for `creates: Resource`); the coordinator verifies the name at regeneration and aligns if the yaml differs (PS3, D2).
- The `realizes!` macro and `ESS_REALIZATIONS` registry are pre-landed by the coordinator in `crates/mandate-types/src/macros.rs` in the opening commit; `coverage-map` owns the step, the manifest, the receipt and the authz/graph/policy registrations; federation, identity and model register in their own stories using the one macro (D4).
- `conformance-target` produces the first `generated/conformance/{suite,report,run,injections}.json` as part of its deliverable; `conform-gate` owns `expected-outcomes.json` and the byte-compare step (D5).
- The `obligations()` outcome-selection change (external cause, not the first error outcome) is pre-landed by the coordinator in the opening commit with a test, before `wrong-state` outcomes arrive (D6).
- `story:declared-writers` gains `depends_on story:contract-creates`; its later creators change the residue after this story's acceptance was evaluated at close, which is the intended order (D7).

## Coordinator rulings at integration, 2026-09-19

- `RegisterResource → creates: mandate.graph.Resource`: ESS 0.26.0's payload grammar has no path form (`input.resource.resource_id` is refused with `ESS-COMMAND-001`), so the command's response gains `resource_id: mandate.core.ResourceId` and `ResourceRegistered.resource_id` is sourced from the response — the shape 13 of the other creators use. A `conversions:` entry (`ResourceRef → ResourceId`) was measured equivalent (132 scenarios / 59 refusals either way) and rejected as a system-wide type widening for one command.
- Entities without a creator are 20, not 16: the four epoch records `mandate.identity.SecurityEpochSnapshot`, `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch`, `FederationSecurityEpoch` declare no transition (initial == terminal == `Recorded`), so no synthesized scenario asks for an instance and they contributed 0 of the 106 baseline refusals. They are adapter-seeded (`EpochSnapshotRecorded`, `SecurityEpochRecorded`) and belong with the 16 under `story:declared-writers`.
- New refusal class `ESS-SYNTH-011` (2): `mandate.delegation.Delegation`'s invariant `transitive == false` cannot be observed after `CreateDelegation`/`RevokeDelegation` because `systems/mandate` declares no views. Every entity that gains both a creator and an invariant joins this class (the three `SecurityEpoch` records with `generation >= 0` when `declared-writers` lands). Closing it is a `views:` addition to the contract, outside this story; `story:conform-gate` names these ids in `expected-outcomes.json` with `blocked_on`.
- Three credential events gained `credential_id` with source `generated` (`CredentialReferenceIssued`, `CredentialSelfContainedIssued`, `TokenExchangeAllowed`): the issuer mints the id and neither input nor response determines it. Consequence: `crates/mandate-types/tests/adversary_fold_inputs.rs:393` pins `AccessCredential`'s closest carrier by the example word `descriptor`; the closest carrier is now `CredentialReferenceIssued` (missing `reference_verifier`, `epochs`, `issued_at`). The coordinator applies the one-line pin change in the regeneration commit; the residue set is unchanged (14 → 14, one row moved).

## Coordinator rulings after adversary pass 1, 2026-09-19

- Replayed authorization code (adversary A1-9b, blocker): a consumed `AuthorizationCode` is the terminal state `Consumed`, so its refusal is the `wrong-state` outcome; "code is consumed" leaves `RedeemAuthorizationCode`'s `external:` text, and `docs/architecture/command-obligations.md` row 16 changes with it (the document joins this story's scope for that row; `cargo xtask corpus` still matches verbatim). The Rust refusal reason `CodePreviouslyRedeemed` maps to the wrong-state outcome in `story:conformance-target`; no implementation change now.
- Login creates the Session (A1-8, blocker; A1-11): `FederationAuthenticated` carries the whole Session record — it gains `organization_id: mandate.core.OrganizationId` and `expires_at: Timestamp` from a widened response (`AuthenticateFederation.response` gains both; a client learns which organization it is in and when the session ends) and `epochs: mandate.core.EpochSnapshotRef` as `generated`. `identity.yaml`'s header states that the identity fold materializes a Session from `FederationAuthenticated`; `SessionOpened` is reserved for a session opened by a path that is not a federated login (none declared today) and a `SessionOpened` naming a session already opened is refused by the fold. Aligning `IdentityLog` to open a session from `FederationAuthenticated` is `story:federation-identity-alignment`.
- Creating events carry the record (A1-2): every creator's event carries each field of the record it creates, except transient secrets (`CredentialSecret`, `CredentialProof` never appear on an event; a `CredentialVerifier` is a verifier, not the secret, and may). Sources are truthful: from the input where the caller supplied it, from the response where the client is told it, `generated` where the implementation mints it. Events stay 72; responses may grow. Where a field cannot be sourced truthfully the unit reports it rather than inventing a source, and that entity stays in the unfoldable residue by name. The `UNFOLDABLE` pin in `crates/mandate-types/tests/adversary_fold_inputs.rs` shrinks accordingly in the coordinator's regeneration commit.
- Generated identities pinned by the response (A1-3): the three issuance commands and `WriteRelationship` return their new identity (`credential_id`, `id`) in the response and the event sources it from there, as `RegisterResource` does, so the suite cross-checks the value.
- Wrong-state accounting (A1-10): `command-obligations.md` gains one header sentence stating that every moving command also declares a wrong-state refusal (HTTP 409 in the OpenAPI projection) for its entity's terminal states; the per-command account is `story:obligation-registry`'s (`contracts/obligations.json`, both outcomes per command).
- Acceptance restated (A1-1): the refusals drop to exactly the creator-less set (20, named) plus the invariant-without-view class (`SYNTH-011`, 2 on `Delegation`, named for `conform-gate`); both are named residue, neither is skipped.
- `docs/architecture/federated-login.md` (A1-12) joins the scope for one sentence and one diagram label: provisioning creates one record, the `ExternalPrincipal`; the Principal record's writer is `story:declared-writers`.
- ESS gap (A1-6b): `ess specify validate` checks an `instance:` field's type, not the entity, so two entities sharing an identity type (`Principal`/`Agent`, `Organization`/`OrganizationSecurityEpoch`, `FederationConnection`/`FederationSecurityEpoch`) are indistinguishable to it. Filed for the ESS wave (`creates-entity-discrimination`).

## Coordinator rulings after adversary pass 2, 2026-09-19

- Truthful sources, restated (A2-3, A2-10, and the `generated` rows): `generated` is truthful only where the implementation mints the value inside the same outcome — the identity of a record it creates, a timestamp, a verifier, the epoch snapshot the login mints. A reference to a record that already exists (a Principal, a Space, an Organization) comes from the input or the response, or the field leaves the event and the entity stays in the unfoldable residue by name. Consequences: `ResourceRegistered` loses `space_id` (the space input is `story:declared-writers`' deliverable; `Resource` returns to the residue); `AuthenticateFederation`'s response gains `principal_id` and `FederationAuthenticated.principal_id` reads it; `ExternalPrincipalProvisioned.organization_id` reads the response or the input context, whichever the yaml makes true.
- Wrong-state, defined ESS's way (A2-6, A2-7): `command-obligations.md`'s header says a wrong-state refusal is taken when the subject is in a state none of the command's declared moves start from, and that the per-command account is `contracts/obligations.json` (`story:obligation-registry`); "terminal states" is withdrawn (`SigningKey.revoke` starts from the terminal `Retired`).
- Two creators of one code (A2-12): `AuthorizePublicClient` either declares `creates: mandate.credential.AuthorizationCode / code_id` (two commands may each create the entity; ESS refuses two subjects on one outcome only) with the event carrying the record, or its event stops carrying a minted `code_id` and names the code `IssueAuthorizationCode` returns. The unit reads `federated-login.md` and the yaml and takes the option that is true of the flow; if neither is true today, it reports.
- Contract-versus-implementation drift surfaced (A2-8, A2-9): the contract is right and explicit; the five crate sites are aligned by the code stories — `crates/mandate-federation/src/authorize.rs` (consumed code → wrong-state) by `story:federation-identity-alignment`; the four idempotent-accept records in `mandate-graph` and `mandate-policy` by `story:graph-policy-adapter`. Recorded on both stories.
- Residue pins (A2-1, A2-2): re-measured after this round and re-pinned in the coordinator's regeneration commit; `Resource` returns, `AccessCredential` and `AuthorizationCode` stay foldable.
- Prose (A2-15, A2-16, A2-17, A2-19): the identity header withdraws "a second open is refused" and states that `SessionOpened` names the record by `id` and `FederationAuthenticated` by `session_id`, with the fold's treatment of both `story:federation-identity-alignment`'s; `federated-login.md`'s step table carries the widened response and one created record, and its line citations are refreshed or dropped.
- Acceptance restated (A2-13): the refusals drop to exactly the creator-less set (20, named) plus the invariant-without-view class (2, named), never skipped.
- Optional generated fields (A2-14): the entity declares them optional, so the contract admits absence; where the security model requires presence (`AccessCredential.epochs`), an authored scenario pins it (`story:authored-denial-scenarios`).
- ESS gap `creates-record-carriage`: `ess specify validate` accepts a creator whose event cannot materialize the record; filed for the ESS wave beside `creates-entity-discrimination`.
