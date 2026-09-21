---
format: aep.planning-md/1
id: story:event-payloads-for-folds
kind: story
status: implemented
title: Every state-changing event carries the record identity a fold needs
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:domain-runtime
scope:
- confidence: cited
  path: crates/mandate-model/tests/adversary_tenancy_topology.rs
- confidence: cited
  path: crates/mandate-types/tests/adversary_fold_inputs.rs
- confidence: cited
  path: crates/mandate-types/tests/adversary_fold_inputs_2.rs
- confidence: cited
  path: generated
- confidence: cited
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
  path: systems/mandate/domains/tenancy.yaml
revision: 13
---
# Events carry the identity and fields a fold needs

## Acceptance

Given the event log alone, when the projections for every entity with a declared transition are rebuilt by folding, then each projection row can be produced from its events without reading any command input or response.

## Required observations

Every state-changing event names the identity of the record it changes; every creation event carries the fields the created record needs. Found by the wave-2 adversary against `story:domain-runtime`: the 15 move-events present at base carry only `context`; `ExternalPrincipalLinked` omits `external_principal_id`, `subject` and `link_method`. The 19 events that wave introduced were corrected in that wave. Under `docs/adr/0009-event-sourced-persistence.md` a record that cannot be folded from its events is a record the log does not hold.

## Scope

Derived 2026-09-18 by `story-scoper` on `integration/wave-20260918-004` (tree equals `main` 46167f6). Every line is **cited** (read from the story, the review-results, the yaml or the compiled schema) or **inferred** (a reading that could be wrong).

- **Primary surface:** `systems/mandate/domains/` — seven of the twelve domain files — cited (`review-result:wave2-domain-runtime-adversary-1` findings D and E; `review-result:wave2-tenancy-topology-adversary-1` findings 1 and 3; `review-result:wave2-session-epochs-adversary-1` F5)

### Files, and what changes in each

Every event below was read out of the yaml and cross-checked against `generated/schema/events/*.schema.json` on this tree. "+`id`" means the event today declares `context: mandate.core.VerifiedContext` and nothing else.

- `systems/mandate/domains/tenancy.yaml` — cited
  - `:377` `OrganizationCreated` {context, organization_id} +`display_name: String` (entity field `:12`, already a command input at `:174`)
  - `:399` `TeamCreated` {context, team_id} +`display_name` (entity `:65`, input `:242`)
  - `:429` `SpaceCreated` {context, space_id} +`display_name` (entity `:131`, input `:334`)
  - `:373` `OrganizationMembershipRemoved` +`id: mandate.core.OrganizationMembershipId`
  - `:389` `OrganizationMembershipAdded` — already {context, organization_id, principal_id, membership_id}; no yaml change
- `systems/mandate/domains/graph.yaml` — cited
  - `:223` `ResourceRegistered` {context} +`id: mandate.core.ResourceId`, +`resource_type: mandate.core.ResourceType` (entity `:8-15`; both are members of the command's `resource: mandate.core.ResourceRef` input at `:153`); +`parent: Optional<mandate.core.ResourceId>` — inferred. `space_id` (`:19`) has **no command input** and is `story:declared-writers`' — not this story.
  - `:215` `RelationRemoved` +`id: mandate.core.RelationId`
  - `:219` `GrantRevoked` +`id: mandate.core.GrantId`
- `systems/mandate/domains/federation.yaml` — cited
  - `:332` `ExternalPrincipalLinked` {context, connection_id, principal_id} +`external_principal_id` (response `:153ff`), +`subject: mandate.core.ExternalSubject` (input `external_subject`), +`link_method: mandate.core.ExternalLinkMethod` (input `method`), +`linked_at: Timestamp` (entity `:22`) — finding D's "identical shape at base"
  - `:360` `ExternalPrincipalProvisioned` +`linked_at: Timestamp`
  - `:354` `FederationAuthenticated` and `:360` `ExternalPrincipalProvisioned` — `context: mandate.core.VerifiedContext` is `generated: true` (`:246`) and `VerifiedContext.credential` is required (compiled type), but `ProvisionExternalPrincipal` (`:233`, input {connection_id, proof}) mints no credential — `crates/mandate-federation/src/lib.rs:147-163` `RequestContext.credential` documents the gap. The fix shape is bounded by the stop condition below.
  - `:324` `ExternalPrincipalUnlinked` +`id: mandate.core.ExternalPrincipalId`
  - `:328` `FederationConnectionDisabled` +`id: mandate.core.FederationConnectionId`
- `systems/mandate/domains/identity.yaml` — cited
  - new `events:` entries after `:297` — `SessionOpened` (fields of `Session` `:31-44`: `id: SessionId`, `principal_id`, `organization_id`, `connection_id: Optional<FederationConnectionId>`, `epochs: EpochSnapshotRef`, `expires_at: Timestamp`), `EpochSnapshotRecorded` (fields of `SecurityEpochSnapshot`: `id: EpochSnapshotRef`, `principal_id`, `organization_id`, `connection_id: Optional<…>`), `SecurityEpochRecorded` (`target: SecurityEpochTarget`, `generation: Integer`) — the three constructors at `crates/mandate-identity/src/port.rs:157`, `:166`, `:178-183`, marked `#[doc(hidden)]` "pending `story:event-payloads-for-folds`" (`port.rs:135-137`). They seed `Session`, `SecurityEpochSnapshot` and the three `*SecurityEpoch` entities. Precedent for an event no command emits: `audit.yaml:94-110` (five events, no `emits:`). Their writer is `AuthenticateFederation` (`federation.yaml:212`) — a header declaration naming it, in the style of `identity.yaml:1-6` — inferred.
  - `:298` `PrincipalDisabled` +`id: mandate.core.PrincipalId`; `:302` `SessionRevoked` +`id: mandate.core.SessionId`; `:306` `RefreshCredentialRevoked` +`id: mandate.core.RefreshCredentialId`
  - `:310` `SessionRefreshed` {context} — the 15th of the "15 base move-events" +`session_id` — inferred
- `systems/mandate/domains/credential.yaml` — cited
  - `:443` `ResourceServerDisabled` +`id: mandate.core.ResourceServerId`; `:447` `AccessCredentialRevoked` +`id: mandate.core.CredentialId`
- `systems/mandate/domains/delegation.yaml` — cited
  - `:377` `DelegationRevoked` +`id: mandate.core.DelegationId`
- `systems/mandate/domains/directory.yaml` — cited
  - `:373` `MembershipContributionRemoved` +`id: mandate.core.MembershipContributionId`; `:377` `DirectoryGroupMembershipRemoved` +`id: mandate.core.DirectoryGroupMembershipId`; `:381` `DirectoryGroupTeamMappingRemoved` +`id: mandate.core.DirectoryGroupTeamMappingId`
- **Untouched:** `audit.yaml`, `authorization.yaml`, `core.yaml`, `policy.yaml`, `workload.yaml` — cited (every event in them already carries `id`, `record` or `decision`; `core.yaml` must stay untouched, see the invariant)
- **Coordinator-owned, not story scope:** `generated/**` — regenerated by `cargo xtask generate` (`xtask/src/main.rs:64-81`) and byte-compared by `cargo xtask contracts` (`:83-94`) — cited
- **Symbols:** `IdentityEvent::{SessionOpened, EpochSnapshotRecorded, SecurityEpochRecorded}` (`port.rs:157,166,178`), `RequestContext.credential` (`mandate-federation/src/lib.rs:159`) — cited
- **Confidence:** high — the story, two review-results and the coordinator's tripwire name the events; the compiled schemas confirm every gap on this tree
- **Would collide with:** any unit editing `systems/mandate/domains/{tenancy,graph,federation,identity,credential,delegation,directory}.yaml`, and any unit that reads a compiled event's property list out of `generated/schema/events/`

### The bounding invariants

`crates/mandate-types/tests/inventory.rs` pins the compiled model: `:35` 110 compiled type entries, `:40` 74 authored, `:46` 36 derived state enums, `:111` 36 entities. It reads `events` once, at `:211-227`, only to assert no event references `mandate.core.CredentialSecret` or `mandate.core.CredentialProof`. **New events and new fields on existing events do not move these; a new `mandate.core.*` type or a new entity does, and an event may not carry `proof`.**

`crates/mandate-types/tests/contract_adversary.rs:709-712` pins **65 events** (and `:172-176`, `:704-708` pin 59 commands); both readers run `ess specify compile` themselves. The three seeding events make 68: the coordinator raises that pin at integration, as `story:domain-runtime`'s coordinator did for `inventory.rs`.

Every field named above resolves to an existing type (all in the 110) or an ESS primitive. `EpochSnapshotRef` is not on the wire today but is in `mandate-proto`'s `WIRE_CONTRACTS` (`crates/mandate-proto/src/lib.rs:214`), so `mandate-proto/tests/adversary.rs:129` stays green. **No payload field in the enumerated instances needs a new type.**

**Stop condition — one, conditional:** the `RequestContext.credential` fix on `FederationAuthenticated`/`ExternalPrincipalProvisioned` has three shapes. (a) Replace the `context: VerifiedContext` field on those two events with explicit fields (`session_id`, `principal_id`, `audience`, `correlation` — all existing types): free. (b) Make `VerifiedContext.credential` optional: edits `core.yaml` and `crates/mandate-types`' struct — a crate change outside this story. (c) A new `mandate.core.RequestContext` type: 111 ≠ 110 at `inventory.rs:35` — **stop; escalate before writing it.** Coordinator ruling for wave 3: shape (a).

### Units

| Unit | Owns (yaml) | Test / validation | Produces |
|---|---|---|---|
| A — tenancy and graph creation payloads | `tenancy.yaml`, `graph.yaml` | `ess specify validate --path systems/mandate`; after the coordinator regenerates, `cargo test -p mandate-model --locked --test adversary_tenancy_topology` with the tripwire retired | `display_name` on the three creation events; `id`+`resource_type` on `ResourceRegistered`; `id` on `OrganizationMembershipRemoved`, `RelationRemoved`, `GrantRevoked` |
| B — federation/identity proof-driven path | `federation.yaml`, `identity.yaml` | `ess specify validate --path systems/mandate`; after regeneration, `cargo test -p mandate-types --locked --test inventory` | four fields on `ExternalPrincipalLinked`, `linked_at` on both link events, the `context` resolution on the two proof-driven events (shape (a)), `id` on five move-events + `SessionRefreshed`, three declared seeding events + their writer header |
| C — mechanical record identity | `credential.yaml`, `delegation.yaml`, `directory.yaml` | `ess specify validate --path systems/mandate` | `id` on the six `context`-only move-events |

B is one unit, not two, because `SessionOpened`'s payload must be producible by `AuthenticateFederation` — the same command whose `VerifiedContext` has no credential source. On the operator's instruction of one agent per story, A, B and C run serially in one agent; the files stay disjoint by construction.

**Tripwire to retire at integration:** `crates/mandate-model/tests/adversary_tenancy_topology.rs:134` `every_required_projection_field_is_carried_by_a_declared_event`, assertion at `:159-169`. It reads `generated/schema/events`, so it turns red only after regeneration; the comment at `:153-158` says it is retired by the coordinator at integration. The stale module docs `crates/mandate-model/src/tenancy.rs:15-31` and `src/graph.rs` ("not rebuildable from the log today") are doc-only residue for the coordinator.

### Excluded

- `generated/**` — coordinator: `cargo xtask generate` then `cargo xtask contracts` byte-compare (`xtask/src/main.rs:64-94`).
- `docs/architecture/command-obligations.md` — keyed on commands and denial text (`xtask/src/main.rs:137-185`); this story adds no command → zero rows.
- `tests/security/cases.json` — untouched.
- `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` — no crate changes.
- `crates/**` — contract-only story. Specifically not: `crates/mandate-identity/src/port.rs:135-157` (removing `#[doc(hidden)]` is a follow-up; `story:pkce-sessions` may own `mandate-identity` this wave), `crates/mandate-federation/src/lib.rs:147-163`, `crates/mandate-model/src/tenancy.rs:75-81`.

### Collisions with wave 3

| Story | Its scope | Collision |
|---|---|---|
| `story:check-api` | `crates/mandate-authz/**` | none |
| `story:pkce-sessions` | crate files only | none **provided this story touches no crate** |
| `story:directory-provenance` | `crates/mandate-provisioning`, `services/worker` | none; neither reads `generated/schema` today |
| `story:declared-writers` (**must not share a wave**) | eight domain yaml files, `docs/architecture/command-obligations.md`, `generated/` | **six shared files:** `credential`, `delegation`, `directory`, `federation`, `graph`, `identity`; plus `generated/` and, on `graph.yaml`, the same `ResourceRegistered` event (`space_id` is theirs, `resource_type` is ours) |

### Gate

Per unit, in its worktree (no regeneration there): `ess specify validate --path systems/mandate`.

Coordinator, after merging: `ess specify validate --path systems/mandate && cargo xtask generate && cargo xtask contracts`; `cargo test -p mandate-types --locked` (inventory 110/36; the 65-event pin raised to 68); `cargo test -p mandate-model --locked --test adversary_tenancy_topology` (after retiring `:159-169`); `cargo test -p mandate-proto --locked --test adversary`; then `task check`.

### Not established

- `SessionRefreshed` (`identity.yaml:310`) declares no `moves`; which record it creates is unstated — its payload is inferred.
- `AddOrganizationMembership` authority: the yaml already carries the full record (`tenancy.yaml:389`); the residue is `MembershipAuthority` as a fold input at `crates/mandate-model/src/tenancy.rs:75-81` — a crate change this story excludes. Unplaced.
- Class-fix breadth: five further thin creation events — `ResourceServerRegistered` (`credential.yaml:457`), `DelegationCreated` (`delegation.yaml:381`), `RelationshipWritten` (`graph.yaml:227`), `federation.AuthorizationCodeIssued` (`federation.yaml:378`), `DirectoryGroupTeamMappingCreated` (`directory.yaml:385`). Same seven files. Coordinator ruling for wave 3: **in** — the acceptance says every entity with a declared transition, and these are creation events of such entities.
- `crates/mandate-types/tests/contract_adversary.rs:668` parses the yaml with fixed `      - name: ` / `        type: ` prefixes; new fields must use the same indentation.

## Instances found in wave 2

Added by the wave-2 adversaries and implementors, 2026-09-18, each measured against the compiled contract on `integration/wave-20260918-003`:

- Creation events omit fields their projections require: `OrganizationCreated`, `TeamCreated`, `SpaceCreated` omit `display_name`; `ResourceRegistered` declares `context` alone and omits `resource_type` (and there is no writer for `Resource.space_id` at all). A rebuild of the tenancy fold loses all four (`review-result:wave2-tenancy-topology-adversary-1`, findings 1 and 3).
- `ExternalPrincipalLinked` carries `context`, `connection_id`, `principal_id` only; neither link event carries `linked_at` (`story:federation-linking` implementor report).
- `ProvisionExternalPrincipal`'s event carries a `VerifiedContext` whose `credential` is required, while the command has no verified caller and mints no credential; `AuthenticateFederation`'s event has the same shape. The contract names no source for that context.
- `mandate.identity` declares no event for session creation or epoch recording; `crates/mandate-identity` seeds its fold through three constructors — `SessionOpened`, `EpochSnapshotRecorded`, `SecurityEpochRecorded` — that no `events:` entry declares (`review-result:wave2-session-epochs-adversary-1`, finding F5). Session creation is `FederationAuthenticated`'s in another domain; the identity fold needs a declared event to consume.
- `AddOrganizationMembership`'s replay must need no authority: authority is a command precondition, not a fold input (`review-result:wave2-tenancy-topology-adversary-1`, finding 2).

The class fix: every creation event carries every required field of the record it creates; every move-event carries the record's identity; every fold input is a declared event. A test that reads `generated/schema/entities` and `generated/schema/events` and asserts the first two properties exists as a coordinator tripwire in `crates/mandate-model/tests/adversary_tenancy_topology.rs` and turns green when this story lands.

## Coordinator rulings for wave 3, 2026-09-18

- The `RequestContext.credential` resolution on `FederationAuthenticated` and `ExternalPrincipalProvisioned` takes shape (a): explicit existing-type fields replace the `context: VerifiedContext` field on those two events. Shape (c) is a stop; do not write it.
- The five thin creation events named under *Not established* are in: `ResourceServerRegistered`, `DelegationCreated`, `RelationshipWritten`, `federation.AuthorizationCodeIssued`, `DirectoryGroupTeamMappingCreated` (gains `mapping_id` and the contribution fields `source`, `team_membership_id`, `created_by`).
- The directory fold inputs `story:directory-provenance` found missing (its Scope, S5) are in, on unit C's `directory.yaml`: `DirectoryGroupMembershipChanged` carries the principal ids it changed; a `DirectoryGroupRecorded` seeding event for the SCIM-populated `DirectoryGroup` (`directory.yaml:2`) and a `SyncJobRecorded` seeding event for the queue-created `SyncJob` (`:3`), each declared with a writer header in the `identity.yaml:6` form, the way the three identity seeding events are. No new type, no new entity; new events raise the 65-event pin in `crates/mandate-types/tests/contract_adversary.rs:709-712`, which the coordinator edits at integration.
- One agent runs units A, B, C serially; the three file pairs stay disjoint by construction.
- `crates/mandate-model/tests/adversary_tenancy_topology.rs:159-169` is retired by the coordinator at regeneration, not by the unit.

## Coordinator ruling on design finding D1, 2026-09-18

- Design critic D1 (`review-result:wave3-design-r1`): the Rust fold in `crates/mandate-federation/src/record.rs` for `ExternalPrincipalLinked` is the coordinator's at integration, in the regeneration commit, bounded to carrying the four new fields (`external_principal_id`, `subject`, `link_method`, `linked_at`) on the crate's own event type and folding them; gate `cargo test -p mandate-federation --locked`. The same commit removes `#[doc(hidden)]` from the three identity seeding constructors (`crates/mandate-identity/src/port.rs:156,165,177`) once the events are declared; gate `cargo test -p mandate-identity --locked`. If either alignment exceeds that bound, it is recorded as residue on this story at close with a named follow-up story.

## Coordinator rulings after correction round 1, 2026-09-19

- Correction round 1 (`review-result:wave3-event-payloads-for-folds-adversary-1`): F1, F2, F3, F5, F7, F8 fixed; F4, F9, F10 no-op (pre-existing residue, recorded); F6 escalated to the coordinator's regeneration commit (the `crates/mandate-federation` event types for `FederationAuthenticated` and `ExternalPrincipalProvisioned` lose `context`, and `ExternalPrincipalLinked` gains four fields). Events are 72 (five seeding events from the unit, two per-row directory seeding events from F3). Accepted deviations, on the implementor's measurements: `RelationshipWritten` keeps `id: RelationId {generated: true}` (dropping it would lose the row's own identity; `Relation` stays in the residue either way); an event cannot carry `summary:` in ESS 0.25.0, so the F7 summaries sit on the emitting outcomes. The coordinator moved the adversary file's pins (events 70 → 72; residue prose fifteen → sixteen) by ruling; the measured residue is 16 entities, the addition being `mandate.graph.Relation.resource_id`, now inside the `resource: ResourceRef` struct the adversary's name-based reader does not descend into. Coordinator duties at integration: raise `crates/mandate-types/tests/contract_adversary.rs:709-712` to 72; retire the tenancy tripwire to `["mandate.graph.Resource.space_id"]` — re-measure after regeneration, since `Resource.resource_type` now travels inside `resource`.

## Coordinator rulings after correction round 2, 2026-09-19

- Correction round 2 (`review-result:wave3-event-payloads-for-folds-adversary-2`): G1–G4 fixed, G5 escalated to the regeneration commit, G6–G8 no-op (pre-existing residue; G7 with the reason that `ExchangeCredential`, `IntrospectCredential` and `RedeemAuthorizationCode` resolve a real credential from their proof). The round-1 host ruling (directory seeding events published by `mandate-worker`) was wrong and is reversed: `mandate-control-plane` owns `mandate.directory`, accepts its commands and publishes all four.
- The coordinator edited the two adversary files after the round: the publisher pin (`adversary_fold_inputs_2.rs:219`) and `RECORDED_RESIDUE` (16 → 14) moved with the rulings; `adversary_fold_inputs.rs`'s `best_carrier` gained the same one-level struct descent the second reader has (`carried_inside_a_struct`), so both readers measure the residue of 14 — eleven in the story's seven files, three in `policy.yaml` and `workload.yaml`. Lanes 9/9 and 6/6.
- Class noted for the wave protocol: three rounds in a row, a ruling moved a measured value and an assertion inside an adversary file still pinned the old one outside the round's authorization. A ruling that changes a measured value names, in the same round, every adversary assertion that pins it.

## Residue after wave 3

- Fourteen of the thirty-two entities with a declared transition still cannot be rebuilt from the event log, pinned by `crates/mandate-types/tests/adversary_fold_inputs.rs` (`UNFOLDABLE`) and `adversary_fold_inputs_2.rs` (`RECORDED_RESIDUE`): `credential.{AccessCredential, AuthorizationCode, SigningKey}`, `delegation.{Agent, AgentCapabilityCeiling, Approval, Execution}`, `federation.OAuthClient`, `graph.{Grant, Resource}`, `identity.RefreshCredential`, `policy.{AuthorizationModel, Policy}`, `workload.WorkloadIdentity`. Nine have no creation event anywhere (`story:declared-writers`); three miss only credential material, which stays out of the log by design (ADR 0009); `Resource.space_id` is `story:declared-writers`'.
- `ExchangeCredential`, `IntrospectCredential` and `RedeemAuthorizationCode` still mint a `VerifiedContext` with `generated: true` while taking no `context` input; they resolve a real credential from their proof, so the generated `credential` has a runtime source. Recorded, not changed.
- `mandate.identity.Principal` folds from `ExternalPrincipalProvisioned` with `kind` pinned to `User` and `display_name` generated — a rebuilt row carries a display name the runtime invented.
- `mandate.credential.TokenExchangeDenied` has no producing command (published by `mandate-sts`); thirteen events are producerless: the five audit events, this one, and the seven seeding events.
- `ess specify validate` enforces none of: component publish coverage, event producers, payload-source sanity, one-writer-per-row. The two adversary files are the only checks; `cargo doc`-level or `xtask`-level enforcement is unowned.
- The Rust event types in `crates/mandate-federation` and the identity constructors' `#[doc(hidden)]` are aligned in the coordinator's regeneration commit, not by this story.
- Residue of the adversary process itself: a ruling that moves a measured value must name, in the same round, every adversary assertion that pins it (three rounds hit this).
