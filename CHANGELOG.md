# Changelog

All notable changes to Mandate are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are annotated git tags on the `main` merge commit of the pull request that delivered them, created and pushed by the organization bot. Pre-release tags mark the integration batches that led to the first release.

## [Unreleased]

## [0.2.0] - 2026-09-19

Wave E1 of the ESS-to-implementation drift-protection programme: the contract now declares its creators and wrong-state outcomes, the implementation carries generated contract shapes it must agree with, tenancy and resource commands emit their declared events and fold from them, and a harness validates emitted events against the closed contract. The specification changed (widened responses, one outcome per moving command), so this is a minor version under 0.x.

### Added

- `crates/mandate-contract`: structural Rust shapes for all 72 events, 59 command inputs, 24 responses, 11 errors and 36 entities, emitted by `cargo xtask generate` from the compiled model (`generated/ir/system.json`) and byte-compared by `cargo xtask contracts`; `deny_unknown_fields` records, `Presence<T>` for optionals (absent is an absent key, `null` refused), `serde_json::Number` for integers.
- `crates/mandate-testkit::contract`: `assert_event_conforms`, `assert_single_emission`, `assert_payload_sources` — schema validation with format assertions, one emission per accepted outcome and none per denied, and payload sources decided per `target_type` against the IR.
- `crates/mandate-model`: `TenancyEvent` (10) and `ResourceEvent` (2); every tenancy and resource command is `decide` + `apply` + `fold`, replay proofs fold each entity from its events alone.
- `crates/mandate-conformance` and the `mandate-conform` binary (skeleton; refuses until the conformance target lands), ESS 0.26.0 crates and `jsonschema` admitted, `cargo xtask adopt` for ESS output ownership in a fresh checkout, the `realizes!` registry.
- ESS repinned to 0.26.0.

### Changed

- `systems/mandate`: 16 creators declared (`creates:` + `instance:`), every creating event carries its record with truthful sources; 34 moving commands declare a `wrong-state` outcome; a consumed authorization code is that outcome; `AuthenticateFederation` creates the Session and its response carries `session_id`, `organization_id`, `principal_id`, `epochs`, `expires_at`; `RegisterResource`, the three issuance commands and `WriteRelationship` return their new identity. Synthesis 84 → 132 scenarios, refusals 106 → 59.
- `docs/architecture/command-obligations.md` and `federated-login.md` follow the contract.

### Conformance at this release

| Measure | Value |
|---|---|
| Scenarios the specification synthesizes | 132 |
| Scenarios executed against the implementation | 0 (no conformance target yet; `story:conformance-target`) |
| Refusals, named | 59: 57 `ESS-SYNTH-004` on 16 creator-less entities (`story:declared-writers`), 2 `ESS-SYNTH-011` on `Delegation` (invariant read by no view) |
| Entities the log cannot rebuild | 12 (was 14) |
| Events with a generated Rust shape | 72 of 72; agreement of the 11 hand-written event variants with those shapes is `story:federation-identity-alignment` |
| Accepted paths proven only against doubles | unchanged from 0.1.0 |
| Contract-versus-implementation drift surfaced, open | consumed authorization code returns 502 where the contract says 409; four idempotent-accept records where the contract says 409 (routed to `story:federation-identity-alignment`, `story:graph-policy-adapter`) |

### State at this release

777 tests across 127 targets, `task check` exit 0. Not in this release: everything the 0.1.0 entry lists as absent, plus the conformance run itself.

## [0.1.0] - 2026-09-19

The first tagged release: the state of `main` after wave 3 of the ten-wave forecast, plus this changelog. Contents are the sum of the four pre-releases below.

### Added

- `CHANGELOG.md`, with the integration batches since the repository's foundation backfilled as pre-release tags.

### State at this release

| What runs | Where |
|---|---|
| 611 tests across 109 targets, `task check` exit 0 | workspace |
| `mandate.authorization.Check` decided over the graph and policy ports | `crates/mandate-authz` |
| Federation registration, explicit linking, first-login provisioning, authentication, and the non-consuming `AuthorizePublicClient` validation | `crates/mandate-federation` |
| Session security generations, snapshots and refresh | `crates/mandate-identity` |
| Tenancy and resource topology folds | `crates/mandate-model` |
| Graph and policy ports over doubles, deny precedence | `crates/mandate-graph`, `crates/mandate-policy` |
| 72 events, 59 commands, 110 types, 36 entities, regenerated and byte-compared | `systems/mandate`, `generated/` |
| The gate reads its document deliverables (`cargo xtask documents`) | `xtask/` |

Not in this release: a served route (every binary refuses `serve`), a real signature or JWKS verifier (the port has a fixture double), a durable event-log adapter (the kit is wired, folds are in-memory), credential issuance and code redemption at STS, and the customer-facing login flow end to end. Fourteen entities still have no creation event and cannot be rebuilt from the log.

## [0.1.0-alpha.4] - 2026-09-19

Wave 3 of the forecast ([#7](https://github.com/beyond10x/mandate/pull/7)): `story:check-api`, `story:pkce-sessions`, `story:event-payloads-for-folds`, `story:gate-reads-document-deliverables`.

### Added

- `mandate-authz` decides `Check`: context binding (tenant, membership, audience, resource placement, space), one graph read and one policy read folded through deny precedence with the requested `AuthorityScope` and the applicable ceilings, decision assembly with challenges; `CouldNotAnswer` is never an allow; a context carrying an actor, delegation or execution other than the subject is refused closed until the agent stories land.
- `mandate-federation` validates `AuthorizePublicClient` without consuming: the S256 challenge form decided by decoding to 32 bytes, registered public client, exact redirect, target registered inside the tenant, session through `mandate-identity`, state and nonce compared in constant time, expiry; two concurrent callers each obtain a candidate.
- `mandate pkce-challenge`: the S256 challenge for a verifier read from stdin or a positional; RFC 7636 §4.1 form enforced; no message echoes the verifier.
- Seven seeding events no command emits, each published by its domain's component: `SessionOpened`, `EpochSnapshotRecorded`, `SecurityEpochRecorded`, `DirectoryGroupRecorded`, `SyncJobRecorded`, `DirectoryGroupMembershipRecorded`, `MembershipContributionRecorded`.
- Every move-event carries the moved record's identity; creation events carry every required field; `ResourceRegistered` and `RelationshipWritten` carry the exact `resource: ResourceRef` input.
- `cargo xtask documents` in `task check`: every architecture document exists and is non-empty, and every store-derived claim a document states equals `aep plan artifact blocked`.
- The event-log kit (`eventlog-core`, `eventlog-sqlite`, tag 0.2.1) wired for `mandate-provisioning` and `mandate-worker`.

### Changed

- `FederationAuthenticated`, `ExternalPrincipalProvisioned`, `SessionRefreshed` and `AuthorizationCodeIssued` carry explicit fields instead of a generated `VerifiedContext`.
- `generated/` regenerated: events 65 → 72; types, entities and commands unchanged.
- `docs/architecture/runtime-decisions.md`: eight store-derived row sets corrected; the blocker-group count is fourteen.
- `deny.toml` admits the event-log git source and the `Zlib` license (`foldhash`, transitive).

### Deferred

- `story:directory-provenance`: `tokio` admitted nowhere, the worker package cannot name `mandate-provisioning`, and its fold inputs were undeclared until this wave.

### Validation

`task check` on `333a1de`: exit 0; 109 targets; 611 passed; 0 failed. Eight adversary passes, 68 findings: 55 fixed, 9 no-op, 4 escalated and recorded on the stories.

## [0.1.0-alpha.3] - 2026-09-18

Wave 2 of the forecast ([#6](https://github.com/beyond10x/mandate/pull/6)): `story:session-epochs`, `story:tenancy-topology`, `story:federation-linking`, `story:graph-policy`.

### Added

- `mandate-identity`: principal, organization and federation generations as non-negative monotonic stand-ins for u64; epoch snapshots pinned to a session; `IncrementSecurityEpoch` as a compare-and-set that denies at the maximum; `RefreshSession` denying `StaleEpoch`; expiry compares RFC 3339 instants.
- `mandate-model`: organization, membership, team, space and resource folds; `cross_tenant_resource` holds and is mutation-measured; five tenant-scoped readers; a compile-time `PersistedValue` boundary over the projections.
- `mandate-federation`: `RegisterFederationConnection`, `LinkExternalPrincipal`, `AuthenticateFederation`, `ProvisionExternalPrincipal` behind ports; all eleven federation corpus ids execute; canonical key `(organization, connection issuer, subject)`; tenant resolution requires the selected connection's rule.
- `mandate-graph`, `mandate-policy`: sealed ports over doubles for the five graph commands and the two policy supersessions; the revision-bound read denies a revoked grant at every floor; deny precedence has one home and ranks the challenge by a total order.
- `AGENTS.md`: scripts serve quick tests and reviews only; persistent checks are Rust.

### Validation

`task check` on `5cf9fb9`: exit 0; 90 targets; 400 passed (81 at the wave-1 head). Eight adversary passes, 62 findings: 58 fixed, 4 escalated into named stories.

## [0.1.0-alpha.2] - 2026-09-18

Wave 1 of the forecast ([#5](https://github.com/beyond10x/mandate/pull/5)): `story:canonical-types`, `story:runtime-decision-dossier`.

### Added

- The 74 accepted ESS types realized across `mandate-types`, `mandate-model`, `mandate-token` and `mandate-proto`, with a machine-checked inventory binding them to `generated/schema/types`; `compile_fail` doctests enforce identifier non-interchangeability and the transient-credential boundary.
- `docs/architecture/runtime-decisions.md`: one section per open runtime decision blocker, each with a source-cited question, bounded alternatives, a proposed owner, affected stories read from the planning store, and the exact evidence required to clear it.

### Validation

`task check` on `ff31684`: exit 0; 72 tests across 45 targets and 14 doctest lanes (0 at the baseline).

## [0.1.0-alpha.1] - 2026-09-18

The planning batch ([#4](https://github.com/beyond10x/mandate/pull/4)), on top of the foundation chain published directly to `main` on 2026-09-17 (contracts, scaffold and public outlook; Atlas publication contracts; the foundation publication record and the canonical-type handoff).

### Added

- The ten-wave forecast over 22 stories with dependency and ownership boundaries.
- `docs/adr/0008-integration-batches.md`: story branches accumulate on an integration branch, one pull request per selected batch, releases selected separately from `main`.
- The canonical-types driver readiness record.

### Validation

`task check` passed, including AEP validation (72 artifacts), ESS validation and deterministic projections.

[Unreleased]: https://github.com/beyond10x/mandate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/beyond10x/mandate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.4...v0.1.0
[0.1.0-alpha.4]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/beyond10x/mandate/compare/v0.1.0-alpha.1...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/beyond10x/mandate/releases/tag/v0.1.0-alpha.1
