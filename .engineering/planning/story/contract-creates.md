---
format: aep.planning-md/1
id: story:contract-creates
kind: story
status: draft
title: Declare creators and wrong-state outcomes so the specification can synthesize its scenarios
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
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
revision: 3
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
