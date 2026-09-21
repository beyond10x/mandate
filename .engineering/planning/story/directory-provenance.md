---
format: aep.planning-md/1
id: story:directory-provenance
kind: story
status: draft
title: Implement SCIM and source-aware team contributions
relations:
- decomposes: epic:enterprise-directory
- serves: vision:mandate
- depends_on: story:tenancy-topology
- depends_on: story:federation-linking
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-provisioning/src/lib.rs
- confidence: inferred
  path: crates/mandate-provisioning/src/log.rs
- confidence: inferred
  path: crates/mandate-provisioning/src/mapping.rs
- confidence: inferred
  path: crates/mandate-provisioning/src/record.rs
- confidence: inferred
  path: crates/mandate-provisioning/src/sync.rs
- confidence: inferred
  path: crates/mandate-provisioning/tests/log.rs
- confidence: inferred
  path: crates/mandate-provisioning/tests/mapping.rs
- confidence: inferred
  path: crates/mandate-provisioning/tests/record.rs
- confidence: inferred
  path: crates/mandate-provisioning/tests/sync.rs
- confidence: cited
  path: services/worker/src/main.rs
- confidence: inferred
  path: services/worker/tests/cli.rs
revision: 7
---
# Implement SCIM and source-aware team contributions

## Acceptance

Given manual and overlapping directory contributions to one team membership, when one mapping is removed, then effective membership retains exactly the remaining valid contributions.

## Required observations

All directory corpus cases pass with concurrent SCIM and mapping removal; contributions uniquely identify source; mappings and memberships share org. Manual/overlapping sources survive; SAML and enterprise lifecycle epic retains separate exit criteria.

## Scope

Derived 2026-09-18 by `story-scoper` on `integration/wave-20260918-004` (tree = `main` `46167f6` plus the event-log wiring). Every line is **cited** (read from the story or the tree) or **inferred** (a reading that could be wrong). Replaces the two directory entries.

- **Primary surface:** `crates/mandate-provisioning` — cited; `docs/architecture/ownership.md:10`. Today `Cargo.toml` and a 4-line `src/lib.rs`; no `tests/`.
- **Files, provisioning, coordinator:** `crates/mandate-provisioning/src/lib.rs` — cited; the crate's only source file.
- **Files, provisioning, units:** `crates/mandate-provisioning/src/record.rs`, `src/mapping.rs`, `src/sync.rs`, `src/log.rs` — inferred; do not exist; names on the `story:federation-linking` pattern.
- **Files, provisioning, tests:** `crates/mandate-provisioning/tests/record.rs`, `tests/mapping.rs`, `tests/sync.rs`, `tests/log.rs` — inferred.
- **Files, worker:** `services/worker/src/main.rs` — cited as the package's only source (`:1-10`: clap stub); what this story may add to it is **nothing dispatchable** until stop condition S2 clears. Whatever lands must keep `mandate-worker --help`/`--version` at exit 0 and `serve` non-zero (`xtask/src/main.rs:314-327`).
- **Files, worker, tests:** `services/worker/tests/cli.rs` — inferred; conditional on S2.
- **Symbols:** `MembershipSource { Manual, DirectoryMapping }` `crates/mandate-types/src/enumeration.rs:7`; `MembershipContributionId`, `TeamMembershipId` `crates/mandate-types/src/identifier.rs:8`; `DirectoryGroupId`, `DirectoryGroupMembershipId`, `DirectoryGroupTeamMappingId` `:11-12`; `SyncJobId` `:17` — cited.
- **Documents:** none written. Read only: `systems/mandate/domains/directory.yaml`, `tenancy.yaml:280-328`, `generated/schema/{entities,commands,events}/mandate.directory.*.schema.json`, `tests/security/cases.json:5-93`, `docs/adr/0009-event-sourced-persistence.md` — cited.
- **Confidence:** medium — the two directories and every contract line are cited; the file split is inferred, and five stop conditions decide whether the `log` unit and any worker unit can be dispatched at all.
- **Would collide with:** any unit touching `crates/mandate-provisioning/**` or `services/worker/**`; the coordinator's `Cargo.lock` / `dependency-boundaries.json` / `deny.toml` / workspace `Cargo.toml` widening commit (S1–S3); any unit regenerating `generated/schema/**/mandate.directory.*` (`story:event-payloads-for-folds`).

### Contract this story implements — `systems/mandate/domains/directory.yaml`, cited

- Header decisions `:1-4`: `:2` a `DirectoryGroup` is created by SCIM populating directory state, no control-plane command creates one; `:3` enqueue/claim/lease/retry belong to the worker queue behind its port; `:4` mapping-derived contributions are written by the two reconciling commands, the manual one by `AddTeamMembership`, all retracted by `RemoveMembershipContribution` alone.
- Entities: `MembershipContribution` `:7-54`; `DirectoryGroup` `:55-83`; `DirectoryGroupMembership` `:84-122`; `DirectoryGroupTeamMapping` `:123-170`; `SyncJob` `:171-210`. Every entity carries `organization_id` referencing `mandate.tenancy.Organization`.
- Commands (8): `RemoveMembershipContribution` `:212-229`; `RemoveDirectoryGroupMembership` `:230-247`; `RemoveDirectoryGroupTeamMapping` `:248-265`; `CreateDirectoryGroupTeamMapping` `:266-290`; `SyncDirectoryMembership` `:291-311`; `RetireDirectoryGroup` `:312-331`; `CompleteSyncJob` `:332-351`; `FailSyncJob` `:352-371`. Denial texts at `docs/architecture/command-obligations.md:27-34`.
- Events (8): `MembershipContributionRemoved` `:373`, `DirectoryGroupMembershipRemoved` `:377`, `DirectoryGroupTeamMappingRemoved` `:381` — **`context` only**; `DirectoryGroupTeamMappingCreated` `:385-394`; `DirectoryGroupMembershipChanged` `:395-402`; `DirectoryGroupRetired` `:403-408`; `SyncJobCompleted` `:409-414`; `SyncJobFailed` `:415-420`.
- Tenancy side, read only: `AddTeamMembership` `tenancy.yaml:280-309` returns `contribution_id`; `RemoveTeamMembership` `:310-328` denies while a mapping contribution still supports it; the fold defers exactly that record to this story: `crates/mandate-model/src/tenancy.rs:75-80`.
- Corpus: `directory-no-authority` `:5-18`, `mapping-contributes` `:20-33`, `mapping-remove` `:35-48`, `mapping-overlap` `:50-63`, `mapping-manual` `:65-78`, `mapping-cross-org` `:80-93` — all `story: story:directory-provenance`, each ending in `mandate.authorization.Check`. Five commands have no corpus case.

### Units — four, disjoint by file; the coordinator interface commit lands first

| Unit | Owns (source file) | Test file | Produces | Case ids |
|---|---|---|---|---|
| coordinator, first | `crates/mandate-provisioning/src/lib.rs` | — | the four `pub mod` lines; `Denied` carrying `DenialReason`; the `DirectoryRead` read port over the fold; the `SyncQueue` port trait (enqueue / claim / complete / fail, keyed by `CommandMeta.idempotency_key`, `eventlog-core/src/lib.rs:284-290`); four compiling stubs | — |
| `records` | `crates/mandate-provisioning/src/record.rs` | `tests/record.rs` | the five projections and `State` enums as plain `serde` structs on the `tenancy.rs` pattern; the `DirectoryEvent` enum over the declared events; the pure `apply` fold; the shared-organization invariant on every `references` relation | — |
| `commands` | `src/mapping.rs`, `src/sync.rs` | `tests/mapping.rs`, `tests/sync.rs` | `decide` for the eight commands: contributions keyed by (mapping, team membership) so a removal retracts only its own; cross-org denial (`:286`); manual and overlapping survival (`:264`, `:228`); `SyncDirectoryMembership` grants nothing without an explicit mapping (`:310`); composes `Tenancy::add_team_membership` `tenancy.rs:496`, `remove_team_membership` `:535`, `team_membership` `:700`, `is_member` `:728`, `admits` `:718`, `resolve_team` `:633` | the six cases' contribution half; the `Check` step is `mandate-authz`'s |
| `log` — the event-log host | `src/log.rs` | `tests/log.rs` | `Aggregate` (`eventlog-core/src/aggregate.rs:66-93`), `Projector` (`projection.rs:146-166`) and `Guard` (`:172-181`) impls binding `record.rs` to the kit; **one `AppendGroup` per command** (`atomic_group.rs:20-24`) through `AtomicEventStore::append_group_guarded` (`:99-114`) with `Expected::Exact` on every stream it touches (`lib.rs:173-180`); the `SyncQueue` implementation over the same store, `AppendResult.deduplicated` (`lib.rs:557-563`) as the dedup signal. **`decision-blocker:epoch-atomicity` evidence:** two concurrent removals racing on one membership's contributions — exactly one `EventLogError::Conflict` (`lib.rs:675`), every other contribution intact. **`decision-blocker:worker-orchestration` evidence:** a redelivered job does not double-apply a contribution; the worker holds no directory state | none in corpus |

Order: coordinator → `records` → `commands` ∥ `log`. `services/worker` has no unit row until S2 clears.

### Ports composed from wave 2

- `crates/mandate-model/src/tenancy.rs`: `Tenancy` `:284`, `TeamMembership` `:246-257`, and the six methods named above — cited; the only wave-2 fold this story must call.
- `crates/mandate-identity/src/port.rs:89` `IdentityRead`, `:114` `SecurityEpochWrite` — **not required**: no case and no acceptance clause reads a session or advances a generation.
- Kit, tag `0.2.1`: `EventStore::append` `crates/eventlog-core/src/lib.rs:678-684`, `append_guarded` `:819-826`, `recorded_command` `:706-711`, `Claim` `:236-240`; `Repository::new(Arc<dyn EventStore>)` `aggregate.rs:137`; `SqliteEventStore::open` `crates/eventlog-sqlite/src/lib.rs:65`, `in_memory` `:78`, `impl AtomicEventStore` `crates/eventlog-sqlite/src/atomic_group.rs:18` ("One BEGIN IMMEDIATE owns the complete group") — cited.

### Dependency ceiling and stop conditions — cited

- `mandate-provisioning`: `mandate-types`, `mandate-model`, `mandate-identity`, `eventlog-core`. `mandate-worker` is not a `libraries` key, so `xtask/src/main.rs:119` applies `external`: `clap`, `serde_json`, `sha2`, `eventlog-core`, `eventlog-sqlite`. The checker walks dev-dependencies too; `:104` pins 20 packages and 14 libraries.
- **S1 — `tokio` is admitted nowhere.** Every `SqliteEventStore` call runs `tokio::task::spawn_blocking` (`eventlog-sqlite/src/lib.rs:92-103`); no consumer here can construct a runtime or write `#[tokio::test]`. The coordinator must admit `tokio` (`rt`, `macros`) to `mandate-worker` and as a dev-dependency to `mandate-provisioning` before the `log` unit or any worker unit dispatches.
- **S2 — the worker cannot name `mandate-provisioning`.** `mandate-worker` falls to `external` and `:104` forbids a 15th `libraries` key, so the worker can neither implement the `SyncQueue` trait nor invoke a directory command. `task:runtime-wave-integration` must admit `mandate-*` crates to service packages first.
- **S3 — `eventlog-sqlite` is not in the provisioning ceiling**, so the `:memory:` race test cannot compile in `crates/mandate-provisioning/tests/`. The coordinator adds it as a dev-dependency there.
- **S4 — `mandate-graph` and `mandate-authz` are outside the ceiling.** Needed only if `Check` were executed in this crate; it is not.
- **S5 — the fold's inputs are not all declared.** The three removal events carry `context` only; no declared event creates a `DirectoryGroup` (`:2`), a `DirectoryGroupMembership` row with principals (`DirectoryGroupMembershipChanged` `:395-402` carries `group_id` and contribution ids), a `MembershipContribution`'s fields (`source`, `team_membership_id`, `mapping_id`, `created_by` are in no event), the mapping's own id (`DirectoryGroupTeamMappingCreated` `:385-394` omits `mapping_id`), or a `SyncJob` (`:3`). Under `docs/adr/0009-event-sourced-persistence.md:7` those are records the log does not hold; the `#[doc(hidden)]` seeding workaround was rejected by `review-result:wave2-session-epochs-adversary-2` F3.

### Coordinator ruling, 2026-09-18

This story leaves execution wave 3 and dispatches in execution wave 4, after `story:event-payloads-for-folds` has declared the directory fold inputs (S5) and regenerated `generated/`. Before that dispatch the coordinator admits `tokio` (S1), adds `eventlog-sqlite` as a dev-dependency of `mandate-provisioning` (S3), and records under `task:runtime-wave-integration` whether service packages may name workspace libraries (S2). The library half is the wave-4 unit; the worker half stays a directory entry with no unit until S2 clears.

### Excluded

`Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml`, `xtask/`, `tests/security/cases.json`, `generated/`, `systems/mandate/domains/*.yaml`. Also: `crates/mandate-model`, `crates/mandate-identity`, `crates/mandate-graph`, `crates/mandate-authz`; the record half of `AddTeamMembership` (`tenancy.rs:496`); a `serve` subcommand or any socket; SCIM HTTP transport; SAML; `#[ignore]`.

### Collisions

- `story:check-api` — `crates/mandate-authz/**` only: no shared file. Semantic overlap on the six cases' `Check` step (S4).
- `story:pkce-sessions` — no shared file. `Cargo.lock` is shared between its `sha2` admission and this story's S1/S3 widening; both are coordinator commits, serialized.
- `story:event-payloads-for-folds` — no shared file; ordering, not conflict (S5).
- Later waves, `services/worker`: `story:audit-worker-delivery` (`depends_on` this story) and `story:audit-recovery-conformance`.

### Gate per unit

`cargo fmt -p mandate-provisioning -- --check`; `cargo clippy -p mandate-provisioning --all-targets --locked -- -D warnings`; `cargo test -p mandate-provisioning --locked`, counts reported. `task check` once, by the coordinator, on the merged integration head.

### Not established

- `docs/architecture/runtime-decisions.md:96,145,336` cite `command-obligations.md:22-24` for the mapping cases; those rows are now delegation rows — stale pointers. The directory rows are `:27-34`.
- Whether `mandate-provisioning`'s existing `mandate-identity` edge is used by this story at all — no consumer found.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
