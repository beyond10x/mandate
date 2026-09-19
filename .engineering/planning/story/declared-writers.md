---
format: aep.planning-md/1
id: story:declared-writers
kind: story
status: draft
title: Every record has a declared writer
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:domain-runtime
- depends_on: story:contract-creates
scope:
- confidence: cited
  path: crates/mandate-types/tests/contract_adversary.rs
- confidence: cited
  path: docs/architecture/command-obligations.md
- confidence: cited
  path: generated
- confidence: inferred
  path: systems/mandate/components.yaml
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
  path: systems/mandate/domains/workload.yaml
revision: 6
---
# Every record has a declared writer

## Acceptance

Given the compiled contract, when every entity's initial record is traced to the command whose accepted outcome creates it, then each of the 36 entities either names such a command or carries a declaration that its writer is an adapter or another system, and no field of a created record is left with no writer.

## Required observations

Read from the 59 command names in `systems/mandate/domains/*.yaml` on `integration/wave-20260918-003`, 2026-09-18. The contract declares a terminal move and no creation for: `mandate.credential.SigningKey` (retire, revoke; no registration or rotation), `mandate.delegation.Agent` (retire), `mandate.delegation.AgentCapabilityCeiling` (supersede; the first ceiling has no writer), `mandate.delegation.Execution` (complete; no start), `mandate.delegation.Approval` (consume; no grant), `mandate.directory.SyncJob` (complete, fail; no start), `mandate.federation.OAuthClient` (disable; found by the wave-2 `story:federation-linking` implementor — any log containing `OAuthClientDisabled` is unreadable to a fold that refuses orphan events), `mandate.graph.Grant` (revoke; found by the wave-2 `story:graph-policy` implementor — `record_grant` cannot refuse a padded role because no port admits one), `mandate.policy.Policy` and `mandate.policy.AuthorizationModel` (supersede; the first version has no writer), `mandate.workload.WorkloadIdentity` (revoke). Two fields have no writer at all: `mandate.graph.Resource.space_id` (`RegisterResource` takes no space; `review-result:wave2-tenancy-topology-adversary-1`) and the first `generation` of the three security-epoch entities (`IncrementSecurityEpoch` is an adapter obligation and the seeding record is undeclared; `review-result:wave2-session-epochs-adversary-1` F5). `mandate.identity.Principal` is created only by `ProvisionExternalPrincipal`; a non-federated principal has no writer. `mandate.identity.SecurityEpochSnapshot` is written by session issuance in another domain with no declared event.

Per entity the decision is one of two: a command in the contract with one accepted and one denied outcome and one event that is the creation record, carrying every required field of the record (`story:event-payloads-for-folds`); or a header declaration in the domain file naming the adapter or system that writes it and the event a fold consumes. A fold under `docs/adr/0009-event-sourced-persistence.md` refuses an event naming an instance no event created, so an undeclared writer is an unreadable log, not a gap in prose.

## Scope

Derived 2026-09-18 by `story-scoper`. Every line is **cited** (read from the story or the tree) or **inferred** (a reading that could be wrong).

- **Primary surface:** `systems/mandate/domains/` — eight of its twelve files — cited, the story's own Scope line
- **Files:** `credential.yaml:77`, `delegation.yaml:70,97,137,196`, `directory.yaml:171`, `federation.yaml:85`, `graph.yaml:85` and `:19-20`, `identity.yaml:161,176,191` (header `:1-6`), `policy.yaml:6,35`, `workload.yaml:5` — cited, every entity found at that line
- **Symbols:** the eleven entities, `mandate.graph.Resource.space_id`, `generation` on the three epoch entities — cited
- **Documents:** `docs/architecture/command-obligations.md` — cited; one row per new command, 59 rows today
- **Also, coordinator-owned:** `systems/mandate/components.yaml` — inferred; 124 `- mandate.*` entries under `accepts:`/`publishes:` = 59 commands + 65 events, so each new command and event is wired there (precedent: `story:domain-runtime`'s coordinator row for `ProvisionExternalPrincipal`)
- **Also, coordinator-owned:** `crates/mandate-types/tests/contract_adversary.rs:172-176,704-712` — cited; pins 59 commands and 65 events, see *Bounding invariant*
- **Also, coordinator-owned:** `generated/` — cited; regenerated, never hand-edited
- **Confidence:** high — the story names all eleven entities by domain and every one resolves to a declaration line in the tree
- **Would collide with:** any unit editing `credential`, `delegation`, `directory`, `federation`, `graph`, `identity`, `policy` or `workload.yaml`; any unit editing `systems/mandate/components.yaml`, `docs/architecture/command-obligations.md`, `generated/` or `crates/mandate-types/tests/contract_adversary.rs`

### Entities, by domain file

All lines cited.

| File (sections) | Entity | Declared | Fields | Terminal-only moves | Existing move event |
|---|---|---|---|---|---|
| `systems/mandate/domains/credential.yaml` (`commands: :160`, `events: :442`; header `:7` "no command deletes a key") | `mandate.credential.SigningKey` | `:77` | `:82-89` | retire `:100-103`, revoke `:104-108` | `SigningKeyRetired :513`, `SigningKeyRevoked :519` |
| `systems/mandate/domains/delegation.yaml` (`:248`, `:376`) | `mandate.delegation.Agent` | `:70` | `:75-78` | retire `:87-90` | `AgentRetired :385` |
| | `mandate.delegation.AgentCapabilityCeiling` | `:97` | `:102-113` | supersede `:122-125` | `AgentCapabilityCeilingSuperseded :391` |
| | `mandate.delegation.Execution` | `:137` | `:142-157` | complete `:166-169` | `ExecutionCompleted :397` |
| | `mandate.delegation.Approval` | `:196` | `:201-214` | consume `:223-226` | `ApprovalConsumed :403` |
| `systems/mandate/domains/directory.yaml` (`:211`, `:372`) | `mandate.directory.SyncJob` | `:171` | `:176-181` | complete `:192-195`, fail `:196-199` | `SyncJobCompleted :409`, `SyncJobFailed :415` |
| `systems/mandate/domains/federation.yaml` (`:116`, `:323`) | `mandate.federation.OAuthClient` | `:85` | `:90-97` | disable `:106-109` | `OAuthClientDisabled :382` |
| `systems/mandate/domains/graph.yaml` (`:116`, `:214`) | `mandate.graph.Grant` | `:85` | `:90-97` | revoke `:106-109` | `GrantRevoked :219` |
| | `mandate.graph.Resource.space_id` | `:19-20`, `Optional<mandate.core.SpaceId>` | — | `RegisterResource :153-160` takes `context, resource, parent` and no space; `ResourceRegistered :223-226` carries `context` only | — |
| `systems/mandate/domains/identity.yaml` (header `:1-6`, `:206`, `:297`) | first `generation` of `PrincipalSecurityEpoch :161`, `OrganizationSecurityEpoch :176`, `FederationSecurityEpoch :191` | `generation: Integer` at `:166-167`, `:181-182`, `:196-197` | — | `Recorded`-only; `IncrementSecurityEpoch :279-296` is an adapter obligation (`:6`, `:293`) | — |
| | `mandate.identity.Principal :9`, `mandate.identity.SecurityEpochSnapshot :128` | — | — | declaration only, per the story's Required observations | — |
| `systems/mandate/domains/policy.yaml` (`:64`, `:105`) | `mandate.policy.Policy` | `:6` | `:11-16` | supersede `:25-28` | `PolicySuperseded :106` |
| | `mandate.policy.AuthorizationModel` | `:35` | `:40-45` | supersede `:54-57` | `AuthorizationModelSuperseded :112` |
| `systems/mandate/domains/workload.yaml` (`:41`, `:62`) | `mandate.workload.WorkloadIdentity` | `:5` | `:10-17` | revoke `:26-29` | `WorkloadIdentityRevoked :63` |

The form a writer *declaration* takes already exists: header comments `identity.yaml:6` ("IncrementSecurityEpoch remains an adapter obligation") and `credential.yaml:4` ("STS alone owns authorization-code verifier storage and consumption") — cited.

`docs/architecture/command-obligations.md`: 59 rows today (lines `:7-65`; header `:5-6`) — cited. The check is `xtask/src/main.rs:137-186 fn obligations`: every compiled command needs a row (`:164-166`), the row's text must equal the command's `external:` denial verbatim (`:167-171`), no row may name an undeclared command (`:176-179`). It runs from `corpus()` at `:267`, which `check` calls at `:310` — cited. Each new command's `external:` text is therefore copied into one new row, alphabetical.

### Bounding invariant

`crates/mandate-types/tests/inventory.rs` — cited: `:35` 110 compiled type entries, `:40` 74 authored, `:46` 36 derived state enums, `:111` 36 entities. No new type (no new `core.yaml` entry) and no new entity.

**Commands and events are pinned** — cited, `crates/mandate-types/tests/contract_adversary.rs`: `:172-176` and `:704-708` assert 59 commands; `:709-712` asserts 65 events. Both readers run `ess specify compile --path systems/mandate` themselves (`:163`, `:693-694`), so `cargo test -p mandate-types` fails in a unit worktree the moment the first command is added, before any regeneration. Raising the pins is the coordinator's edit. `:1128` embeds "all 59" in an assertion message; it goes stale but does not fail.

### Type stop condition — none triggered

Whole-tree check, cited: every `type:` in `systems/mandate/domains/*.yaml` is `mandate.core.*`, a primitive, or `List<>`/`Optional<>` of one; no file but `core.yaml:2` has a `types:` section. Every command also takes `context: mandate.core.VerifiedContext` (`core.yaml:211`; pattern `graph.yaml:155-156`).

| Creating command for | Input types needed | In `core.yaml` at |
|---|---|---|
| `SigningKey` | `SigningKeyId`, `KeyReference`, `SigningAlgorithm`, `Timestamp` | `:90`, `:126`, `:312` |
| `Agent` | `PrincipalId`, `OrganizationId`, `String` | `:3`, `:6` |
| `AgentCapabilityCeiling` | `AgentCapabilityCeilingId`, `PrincipalId`, `Optional<OrganizationId>`, `List<ActionPattern>`, `AuthorityScope`, `Duration` | `:306`, `:3`, `:6`, `:138`, `:199` |
| `Execution` | `ExecutionId`, `OrganizationId`, `PrincipalId`, `Optional<DelegationId>`, `Optional<SessionId>`, `PolicyVersion`, `Timestamp` | `:36`, `:6`, `:3`, `:33`, `:60`, `:117` |
| `Approval` | `ApprovalId`, `OrganizationId`, `PrincipalId`, `Action`, `ResourceRef`, `Timestamp` | `:81`, `:6`, `:3`, `:96`, `:192` |
| `SyncJob` | `SyncJobId`, `OrganizationId`, `FederationConnectionId`, `CorrelationId` | `:93`, `:6`, `:42`, `:120` |
| `OAuthClient` | `OAuthClientId`, `OrganizationId`, `Boolean`, `List<RedirectUri>`, `PkceMethod` | `:84`, `:6`, `:132`, `:188` |
| `Grant` | `GrantId`, `OrganizationId`, `AuthoritySubject`, `AuthorityScope`, `String` | `:27`, `:6`, `:325`, `:199` |
| `Policy` | `PolicyId`, `OrganizationId`, `PolicyVersion`, `String` | `:72`, `:6`, `:117` |
| `AuthorizationModel` | `AuthorizationModelId`, `OrganizationId`, `PolicyVersion`, `String` — the entity's `version` is `PolicyVersion` (`policy.yaml:42-43`), not `AuthorizationModelVersion` (`core.yaml:309`) | `:75`, `:6`, `:117` |
| `WorkloadIdentity` | `WorkloadIdentityId`, `OrganizationId`, `PrincipalId`, `TrustDomain`, `ExternalSubject` | `:78`, `:6`, `:3`, `:135`, `:108` |
| `Resource.space_id` | `Optional<SpaceId>` added to `RegisterResource :154-160` and `ResourceRegistered :224-226` | `:21` |
| epoch `generation` | `Integer` — declaration, no command | — |

Stop condition only if an implementor introduces a per-command input struct (a new `mandate.core.*` entry); flat inputs need none — inferred.

### Priority for the customer login vertical

1. `mandate.federation.OAuthClient` — `systems/mandate/domains/federation.yaml:85` — cited. Consumed by `AuthorizePublicClient` (`federation.yaml:269`, input `client_id: mandate.core.OAuthClientId` `:271-272`; header `:3`), by `story:pkce-sessions`' registered-client lookup, and by `crates/mandate-federation/src/record.rs:244-245` whose `UnknownOAuthClient` exists "because the contract declares no command that creates an `OAuthClient`".
2. `mandate.credential.SigningKey` — `systems/mandate/domains/credential.yaml:77` — cited. Consumed by `story:credential-profiles`; `RetireSigningKey`'s denial requires "an overlapping replacement key" (`command-obligations.md:18`), so the creating command is also the rotation path (`credential.yaml:7`).

### Units

No file appears in two rows. Command and event names are placeholders — inferred; none exists anywhere in the tree today.

| Unit | Owns (yaml files) | Validation | Produces |
|---|---|---|---|
| A `login-writers` | `systems/mandate/domains/federation.yaml`, `systems/mandate/domains/credential.yaml` | `ess specify validate --path systems/mandate` | `OAuthClient` creating command + creation event; `SigningKey` registration/rotation command + event; the verbatim `external:` text of each, handed to the coordinator for the obligations rows |
| B `delegation-graph-writers` | `systems/mandate/domains/delegation.yaml`, `systems/mandate/domains/graph.yaml` | same | commands + events for `Agent`, `AgentCapabilityCeiling`, `Execution`, `Approval`, `Grant` (or adapter declarations where the story allows); `RegisterResource` gains the space input and `ResourceRegistered` carries it; row text |
| C `policy-directory-workload-identity` | `systems/mandate/domains/policy.yaml`, `systems/mandate/domains/directory.yaml`, `systems/mandate/domains/workload.yaml`, `systems/mandate/domains/identity.yaml` | same | commands + events for `Policy`, `AuthorizationModel`, `SyncJob`, `WorkloadIdentity` (or declarations); header declarations in `identity.yaml` for the first epoch `generation`, the non-federated `Principal`, and `SecurityEpochSnapshot`, in the `identity.yaml:6` form; row text |
| coordinator | `docs/architecture/command-obligations.md`; `systems/mandate/components.yaml`; `generated/**`; `crates/mandate-types/tests/contract_adversary.rs:172-176,704-712` | `cargo xtask generate`, `cargo xtask contracts`, `cargo test -p mandate-types --locked`, `cargo xtask corpus`, `task check` | the rows; the `accepts:`/`publishes:` wiring; regeneration; the two count pins raised; the closing report with the printed command count |

### Excluded

- `generated/` — coordinator regenerates (`xtask/src/main.rs:64-81`); no unit edits it.
- `tests/security/cases.json` — coordinator-owned; the corpus names `Agent` (`:544`) and `Grant` (`:617`) in `given` prose only. Whether a case per new writer is added is a coordinator call at dispatch.
- `Cargo.toml`, `Cargo.lock` — no crate changes.
- `xtask/` — the obligations check reads the document; it needs no edit.
- `crates/**` realizations — the story's own Exclusions; the two count pins in `contract_adversary.rs` are the one exception, and they are the coordinator's.

### Collision

- `story:event-payloads-for-folds` — its scope is seven domain yaml files and `generated/`. Overlap: `credential`, `delegation`, `directory`, `federation`, `graph`, `identity` plus `generated/`; on `graph.yaml`, the same `ResourceRegistered` event (`space_id` here, `resource_type` there). **The two never share a wave.** This story's creation events must carry every required field of the record, so `story:event-payloads-for-folds` goes first and this story writes its events to the fixed shape.
- `story:invariant-boundary-validation` — `crates/mandate-server/src/context.rs` only. No overlap.
- `story:testkit-doubles` — `crates/mandate-testkit/src/**`, four crates' `src`/`tests`/`Cargo.toml`, `dependency-boundaries.json`. No overlap.

### Gate

Unit: `ess specify validate --path systems/mandate` (`xtask/src/main.rs:84`). `task check` fails with "projection drift" (`:90-91`) until the coordinator regenerates, by design; `cargo test -p mandate-types` fails on the 59-command pin until the coordinator raises it.
Coordinator: `cargo xtask generate && cargo xtask contracts && cargo test -p mandate-types --locked && cargo xtask corpus && task check`.

### Not established

- Whether `ess specify validate` enforces that every command/event appears in `components.yaml` — not run; the evidence is the 124 = 59 + 65 count and `story:domain-runtime`'s coordinator row.
- Command/event names — none exists outside `generated/`; the unit table's names are placeholders.
- Which of `SyncJob`, `Execution`, `Approval` get a command versus an adapter declaration — the story leaves that per entity; the owning file is the same either way.

## Exclusions

`crates/**` realizations of the new commands are their owning stories'. This story is contract-only.

## Inherited from wave E1, 2026-09-19

- From `contract-creates` adversary pass 1 (A1-5): `mandate.identity.Principal` is created by `ProvisionExternalPrincipal`, whose accepted outcome already declares `creates: ExternalPrincipal`, and ESS refuses two subjects on one outcome. Declaring the Principal's creator therefore needs a second emitted event on a second outcome or a dedicated command, not a `creates:` on the existing outcome.
- The creator-less residue this story inherits is 20 entities: the 16 named in `story:contract-creates` plus `SecurityEpochSnapshot`, `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch`, `FederationSecurityEpoch` (no transitions, adapter-seeded).

## Inherited from wave E1 adversary pass 2, 2026-09-19

- From `contract-creates` adversary pass 2 (A2-3/A2-4): `ResourceRegistered` does not carry `space_id`; `Resource` stays in the unfoldable residue until this story adds the space input to `RegisterResource` and sources the event field from it.
