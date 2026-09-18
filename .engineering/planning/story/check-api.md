---
format: aep.planning-md/1
id: story:check-api
kind: story
status: implemented
title: Implement stable PEP check semantics
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:tenancy-topology
- depends_on: story:graph-policy
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-authz/src/context.rs
- confidence: inferred
  path: crates/mandate-authz/src/decision.rs
- confidence: inferred
  path: crates/mandate-authz/src/evaluate.rs
- confidence: cited
  path: crates/mandate-authz/src/lib.rs
- confidence: cited
  path: crates/mandate-authz/tests/adversary_check.rs
- confidence: cited
  path: crates/mandate-authz/tests/adversary_check_2.rs
- confidence: inferred
  path: crates/mandate-authz/tests/check_contract.rs
- confidence: inferred
  path: crates/mandate-authz/tests/context.rs
- confidence: inferred
  path: crates/mandate-authz/tests/decision.rs
- confidence: inferred
  path: crates/mandate-authz/tests/evaluate.rs
revision: 21
---
# Implement stable PEP check semantics

## Acceptance

Given a protected request missing a required approval, when the PEP asks the PDP, then it receives allowed=false with a structured scoped challenge and decision identifier.

## Required observations

Validated context required; enforce tenant/space/resource/audience, ceilings and denial precedence. approval-required is allowed=false. PEP outage test denies; return decision correlation/model/policy/revision; runtime contract cases and property tests pass.

## Home: `crates/mandate-authz` alone

`services/authorization` is removed from scope. Package `mandate-authorization` is absent from `dependency-boundaries.json` `libraries`, so `xtask/src/main.rs:119` applies `["clap","serde_json","sha2"]` to it and it cannot name `mandate-authz`; `xtask/src/main.rs:270-272` requires its binary to fail on `serve`. `ownership.md:13` gives `mandate.authorization` to `mandate-authz` as the Rust owner; `components.yaml:55-68` assigns `Check` to the `mandate-authorization` deployment component, not the package.

## Not transitively blocked

`crates/mandate-graph` and `crates/mandate-policy` are 4-line scaffolds and `story:graph-policy` is blocked on `decision-blocker:backend` and `decision-blocker:subject-relations`. This story proceeds anyway: every type `Check` consumes and produces exists — `VerifiedContext` (`crates/mandate-types/src/record.rs:63`), `Decision` and `DecisionChallenge` (`crates/mandate-model/src/lib.rs:117,93`), `DecisionReason` (`crates/mandate-types/src/enumeration.rs`). Only authority lookup is missing, and the dependency arrow already points `mandate-authz → mandate-graph, mandate-policy`, so the consumer declares the required interfaces as traits and the test double lives in this crate. An adapter satisfies them later.

## Units

The coordinator interface commit lands `src/lib.rs` — crate doc, every `mod` line, the `Check` entry-point signature, the two port traits — and the six module stubs; six units then run in parallel.

| Unit | Owns | Test file | Discharges |
|---|---|---|---|
| coordinator, first | `crates/mandate-authz/src/lib.rs` | `crates/mandate-authz/tests/check_contract.rs` | the end-to-end acceptance once the six land: approval missing → `allowed=false`, scoped challenge, `decision_id` |
| `port` | `crates/mandate-authz/src/port.rs` | `tests/port_double.rs` | the graph and policy required interfaces and the deterministic in-crate double |
| `context` | `src/context.rs` | `tests/context_binding.rs` | validated context required; tenant/space/resource/audience binding |
| `ceilings` | `src/ceilings.rs` | `tests/ceilings.rs` | platform and tenant ceiling intersection applied to the combinator's output — **deny precedence itself is `story:graph-policy`'s `precedence` unit and is consumed through the port, not re-implemented** |
| `challenge` | `src/challenge.rs` | `tests/approval_challenge.rs` | `ApprovalRequired` → `allowed=false` with a scoped `DecisionChallenge` |
| `availability` | `src/availability.rs` | `tests/outage.rs` | fail closed when graph, policy or credential authority is unavailable (`combined.md:55`); case `pdp-outage` |
| `dossier` | `src/dossier.rs` | `tests/dossier.rs` | `Decision` assembly: `decision_id`, correlation from context, `revision`, `policy_version`, `model_version` |

## Case ids

`pdp-outage` — the single case with `story: story:check-api`. The "property tests" in the Required observations are hand-rolled deterministic generators on the pattern of `crates/mandate-types/tests/adversary.rs`: no property-testing crate is in `Cargo.lock` and none may be added.

## Contract facts

`authorization.yaml` declares exactly one command, `mandate.authorization.Check` (`:4`), one event `DecisionRecorded` (`:28`), one error `Denied` (`:35`), zero entities. `Explain` is declared nowhere in `systems/`, `generated/` or `docs/` — unmapped, an ESS change for `story:domain-runtime` if wanted, not this story's. The addendum's `CheckRequest { subject, actor, action, resource, context: AuthorizationContext }` (`architecture-addendum.md:685-691`) differs from the contract's `Check(context: VerifiedContext, action, resource)` (`authorization.yaml:5-11`), where `VerifiedContext` already carries subject and actor; `AuthorizationContext` exists nowhere. The contract is what the gate enforces and what this story implements.

## Decisions that apply

`docs/adr/0009-event-sourced-persistence.md` — decisions are events (`DecisionRecorded`); the double's state is a fold. `decision-blocker:backend` constrains the adapter, not this story.

## Dependency ceiling

`mandate-types`, `mandate-model`, `mandate-graph`, `mandate-policy` — already in `crates/mandate-authz/Cargo.toml`; nothing is added, dev-dependencies included. No `serde_json`, no `proptest`. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

`services/authorization`. `Explain`. Any edit to `crates/mandate-graph`, `crates/mandate-policy`, `crates/mandate-model`, `crates/mandate-types`, `systems/mandate`. A concrete backend. `#[ignore]`.

## Scheduling hazard, recorded

`story:agent-authority-kernel` and `story:agent-security` scope `crates/mandate-authz` at directory level. Once this story is at file level, `waves` no longer reports the collision. Both are refined to files before either is scheduled near this story.

## Gate per unit

`cargo fmt -p mandate-authz -- --check`; `cargo clippy -p mandate-authz --all-targets --locked -- -D warnings`; `cargo test -p mandate-authz --locked`, count reported.

## Scope

Derived 2026-09-18 by `story-scoper` on `integration/wave-20260918-004` (tree equals `main` 46167f6). Every line is **cited** (read from the story or the tree) or **inferred** (a reading that could be wrong).

- **Primary surface:** `crates/mandate-authz` — cited; `docs/architecture/ownership.md:13` gives `mandate.authorization` to it; the crate is a 4-line doc stub (`crates/mandate-authz/src/lib.rs:1-4`).
- **Files (owned):**
  - `crates/mandate-authz/src/lib.rs` — cited; the crate's only source file today; coordinator.
  - `crates/mandate-authz/src/context.rs` — inferred; does not exist.
  - `crates/mandate-authz/src/evaluate.rs` — inferred; does not exist.
  - `crates/mandate-authz/src/decision.rs` — inferred; does not exist.
  - `crates/mandate-authz/tests/check_contract.rs` — inferred; does not exist.
  - `crates/mandate-authz/tests/context.rs` — inferred; `tests/<module>.rs` is the wave-2 convention (`crates/mandate-graph/tests/port.rs`, `crates/mandate-policy/tests/precedence.rs`).
  - `crates/mandate-authz/tests/evaluate.rs` — inferred; does not exist.
  - `crates/mandate-authz/tests/decision.rs` — inferred; does not exist.
- **Documents:** none — cited; every acceptance line is runtime behaviour in one crate.
- **Confidence:** high — the story names the crate, the contract names the command, and every consumed port and record exists in the tree at a `file:line` below; the file split within the crate is the only inferred part.
- **Would collide with:** any unit touching `crates/mandate-authz/` (`story:agent-authority-kernel` and `story:agent-security` still scope that directory whole); nothing else, provided the exclusions below hold.

### Ports consumed, not edited

Wave 2 delivered both ports and both doubles (`5cf9fb9`); the earlier body's "declare the required interfaces as traits and the test double lives in this crate" is stale. This story **calls** these and **edits none of them**:

| Crate | Symbol | Where | Role here |
|---|---|---|---|
| `mandate-graph` | `trait GraphRead`, `fn check(&self, &GraphQuery<'_>, &Self::Revision) -> Result<Observed, GraphError>` | `crates/mandate-graph/src/port.rs:166-183` (`fn check` at `:178`; doc at `:161` names `story:check-api` as the caller) | the one authority read per request — cited |
| `mandate-graph` | `GraphQuery { context, subject, resource, relation }` / `Observed { revision, through }` / `GraphError::{Denied, CouldNotAnswer}` / `GraphError::denial_reason()` | `port.rs:48-57` / `:69-74` / `:108-113` / `:121-126` | request/answer shapes; `CouldNotAnswer` → `DenialReason::Unavailable` — cited |
| `mandate-graph` | `trait Revision` sealed to `AuthzRevision` | `port.rs:30-33` | the `minimum` a PEP passes is an `AuthzRevision` — cited |
| `mandate-graph` | `trait ResourceLookup::placement` | `crates/mandate-graph/src/topology.rs:36-50` | resource-in-organization binding; `TenantMismatch` vs `ResourceUnresolved` — cited |
| `mandate-graph` | `GraphDouble::{new, admit_subject, record_grant}`, `impl GraphRead` | `crates/mandate-graph/src/double.rs:69, :83, :105, :465-497` | the graph side of every runtime test — cited |
| `mandate-policy` | `trait PolicyEvaluator::evaluate(&self, &PolicyRequest<'_>) -> Result<Evaluation, PolicyError>` | `crates/mandate-policy/src/port.rs:324-332` | the one policy read per request — cited |
| `mandate-policy` | `PolicyRequest` / `PolicyEffect` / `ChallengeRequirement::{Approval, Reauthentication}` / `Challenge { requirement, correlation }` / `Evaluation { effect, version: PolicyVersion, challenge }` / `PolicyError::denial_reason()` | `port.rs:168-179` / `:183-190` / `:202-207` / `:211-216` / `:224-232` / `:274-279` | request/answer shapes — cited |
| `mandate-policy` | `precedence::{Component, Component::of_effect, Combined, combine, Combined::allowed, Combined::denial_reason}` | `crates/mandate-policy/src/precedence.rs:23-37, :42-48, :53-78, :150-175, :94-96, :111-118` | deny precedence; `lib.rs:6-7` says `story:check-api` consumes it — cited |
| `mandate-policy` | `precedence::{strictest, strictness}` (Approval=0 above Reauthentication=1), `trait RoleCatalog`, `expand` | `precedence.rs:249-254, :235-240, :181-184, :213-224` | which challenge to issue; role-name expansion — cited |
| `mandate-policy` | `PolicyDouble::{new, record_policy, record_model, allow, deny, require_approval, record_role}`, `impl PolicyEvaluator`, `impl RoleCatalog` | `crates/mandate-policy/src/double.rs:49, :55, :60, :73, :91, :109, :128, :164, :315` | the policy side of every runtime test — cited |
| `mandate-model` | `Tenancy::{admits, is_member, resolve_space}` | `crates/mandate-model/src/tenancy.rs:718, :728, :657` | tenant/space binding of `VerifiedContext`; `tenancy.rs:68-70` says deciding authority is `mandate-authz`'s — cited |
| `mandate-model` | `Resource { organization_id, parent, space_id: Option<SpaceId>, .. }`, `Topology::resolve` | `crates/mandate-model/src/graph.rs:98-121, :207` | space binding source — cited |

### Contract and the types it must use

- `mandate.authorization.Check` — `systems/mandate/domains/authorization.yaml:4`; input `context: mandate.core.VerifiedContext`, `action: mandate.core.Action`, `resource: mandate.core.ResourceRef` (`:5-11`); `accepted` emits `DecisionRecorded` (`:12-20`); `denied` → error `Denied` (`:21-23`); response `decision: mandate.core.Decision` (`:24-26`); event `DecisionRecorded { context, decision }` (`:28-33`); error `Denied { reason: mandate.core.DenialReason }` (`:35-39`) — cited.
- `VerifiedContext { subject, actor, organization, audience, credential, delegation, execution, correlation }` — `crates/mandate-types/src/record.rs:63-95` — cited.
- `ResourceRef` — `record.rs:16-21`; `AuthorityScope { actions, resources, space }` — `record.rs:31-43` — cited.
- `Decision { allowed, reason: DecisionReason, decision_id: DecisionId, revision: Option<AuthzRevision>, challenge: Option<DecisionChallenge>, policy_version: Option<PolicyVersion>, model_version: Option<AuthorizationModelVersion> }` — `crates/mandate-model/src/lib.rs:131-166`; approval-required sample at `:180-188` — cited.
- `DecisionChallenge { action, resource, approver_policy: PolicyId, expires_at: Timestamp }` — `crates/mandate-model/src/lib.rs:107-116` — cited.
- `DecisionId` — `crates/mandate-types/src/identifier.rs:14` via `canonical_uuid_identifiers!` (`macros.rs:8`; ctor `new(Uuid)` `:25`, `parse` `:40`); `Uuid` has `from_bytes` and `parse` only (`crates/mandate-types/src/value.rs:55, :73`), no generator — cited.
- `DecisionReason { Allowed, Denied, ApprovalRequired, InvalidCredential, TenantMismatch, AudienceMismatch, Unavailable, StaleEpoch }` — `crates/mandate-types/src/enumeration.rs:9`; `DenialReason` (same minus `Allowed`) — `:11` — cited.
- `AuthzRevision`, `PolicyVersion`, `CorrelationId`, `AuthorizationModelVersion`, `Action`, `Audience` — `crates/mandate-types/src/text.rs:4-9`; `AuthoritySubject` — re-export `lib.rs:176`; `Timestamp` — `value.rs:249` — cited.

### Units

| Unit | Owns (source file) | Test file | Produces | Case ids (`tests/security/cases.json`) |
|---|---|---|---|---|
| `context` | `crates/mandate-authz/src/context.rs` | `crates/mandate-authz/tests/context.rs` | validated-context binding: organization admitted and subject a member (`Tenancy::admits`/`is_member`), audience equals the expected audience the caller supplies, resource placed in the verified organization (`ResourceLookup::placement`), space bound (`Resource.space_id` vs `AuthorityScope.space`); `TenantMismatch`, `AudienceMismatch`, `InvalidCredential` — inferred split | `reference-audience` `:223`, `cross-tenant-resource` `:589`, `mapping-cross-org` `:80` |
| `evaluate` | `crates/mandate-authz/src/evaluate.rs` | `crates/mandate-authz/tests/evaluate.rs` | one `GraphRead::check` and one `PolicyEvaluator::evaluate` per request, `expand` over `RoleCatalog`, folded through `precedence::combine`; platform/tenant ceiling intersection (`delegation.yaml:5`, fields `:106-111`) as further `Component`s; `CouldNotAnswer` from either port → `Unavailable`, never an allow — inferred split | `directory-no-authority` `:5`, `autonomous-ceiling` `:541`, `graph-revocation` `:614`, `pdp-outage` `:602` |
| `decision` | `crates/mandate-authz/src/decision.rs` | `crates/mandate-authz/tests/decision.rs` | `Decision` assembly: `decision_id` from a `DecisionIdAllocator` port declared here (precedent `crates/mandate-federation/src/lib.rs:218` `IdentityAllocator`), `revision` from `Observed.revision`, `policy_version` from `Evaluation.version`, `challenge` from `strictest` + `DecisionChallenge { action, resource, approver_policy, expires_at }` with `expires_at` from a clock port; `ApprovalRequired` → `allowed=false`; `model_version: None` (no port returns an `AuthorizationModelVersion`, see below) — inferred split | `approval-required` `:553` |
| coordinator | `crates/mandate-authz/src/lib.rs` | `crates/mandate-authz/tests/check_contract.rs` | crate doc, `mod` lines, the `check(...) -> Result<Decision, Denied>` entry point composing the three; the acceptance end to end (missing approval → `allowed=false`, scoped challenge, `decision_id`) — cited as the only existing file, inferred as the entry point's home | `approval-required` `:553` and `pdp-outage` `:602` end to end |

Every case whose `commands` include `mandate.authorization.Check` (cited, 16 of 50): `directory-no-authority` `:5`, `mapping-contributes` `:20`, `mapping-remove` `:35`, `mapping-overlap` `:50`, `mapping-manual` `:65`, `mapping-cross-org` `:80` (all `story:directory-provenance`); `reference-persistence` `:195`, `reference-revoked` `:209`, `reference-audience` `:223`, `reference-expired` `:237`, `profile-offline-bound` `:251` (all `story:credential-profiles`); `autonomous-ceiling` `:541`, `approval-required` `:553` (`story:agent-security`); `cross-tenant-resource` `:589` (`story:tenancy-topology`); `pdp-outage` `:602` (`story:check-api`, the only one); `graph-revocation` `:614` (`story:graph-policy`). The nine not in the table need `mandate.directory.*` / `mandate.credential.*` commands outside this crate's ceiling and are not dischargeable here — cited from their `commands` arrays.

### Excluded

Coordinator-owned, not edited by any unit: `Cargo.toml` (workspace root), `Cargo.lock`, `dependency-boundaries.json`, `deny.toml`, `xtask/`, `tests/security/cases.json`, `generated/`, `systems/mandate/domains/*.yaml`.

Story-declared, not edited — cited: `crates/mandate-graph`, `crates/mandate-policy`, `crates/mandate-model`, `crates/mandate-types`; `services/authorization` (its binary is also named `mandate-authz`, `services/authorization/Cargo.toml:13`, and `xtask/src/main.rs:314-328` requires it to refuse `serve` — a package, not this crate); `crates/mandate-testkit` (depends on `mandate-authz`, `crates/mandate-testkit/Cargo.toml:16`; a 4-line stub). `crates/mandate-authz/Cargo.toml` — cited; nothing is added, dev-dependencies included. Units read nothing under `generated/` — inferred rule, to stay disjoint from `story:event-payloads-for-folds`.

### Dependency ceiling

`dependency-boundaries.json:20-25` — `mandate-authz: [mandate-types, mandate-model, mandate-graph, mandate-policy]`. All three ports this story calls are already in the ceiling; `crates/mandate-authz/Cargo.toml:14-17` matches it. **No widening needed** — cited. `xtask/src/main.rs:117-128` checks every `cargo metadata` dependency entry with no kind filter, so a dev-dependency (`proptest`, `serde_json`) fails the gate too — cited. The story may not widen the ceiling.

### Collisions with this wave

| Story | Its files | Overlap |
|---|---|---|
| `story:pkce-sessions` | `crates/mandate-identity/src/{pkce,publicclient,candidate}.rs` + `tests/`, `bins/mandate/*`, `Cargo.lock` — cited from its scope before re-scoping | **none**; this story touches no lockfile line — cited |
| `story:directory-provenance` | `crates/mandate-provisioning`, `services/worker` — cited from its scope | **none** by file; `mandate-provisioning`'s ceiling (`dependency-boundaries.json:41-45`) cannot reach `mandate-authz`, so its six `Check`-invoking cases (`:16,:31,:46,:61,:76,:91`) are a semantic dependency on `GraphRead::check`'s membership refusal (`double.rs:483-487`), not a shared file — cited |
| `story:event-payloads-for-folds` | `systems/mandate/domains/*.yaml`, `generated/` — cited from its scope | **none** by file, both excluded here; `DecisionRecorded` (`authorization.yaml:28-33`) changes no entity (`generated/docs/domains/mandate-authorization.md:26`) so it is not a move-event — inferred that the folds story leaves `authorization.yaml` and `Decision` untouched |

### Gate

Per unit: `cargo fmt -p mandate-authz -- --check && cargo clippy -p mandate-authz --all-targets --locked -- -D warnings && cargo test -p mandate-authz --locked` (count reported). At integration, coordinator only: `task check` = `cargo xtask check` (`Taskfile.yml:3-6`), because `boundaries()` and the binary checks are workspace-level.

### Not established

- **Source of `Decision.model_version`:** `Evaluation` (`crates/mandate-policy/src/port.rs:224-232`) carries `version: PolicyVersion` only; no port method returns an `AuthorizationModelVersion`, and `AuthorizationModel.version` is itself typed `PolicyVersion` (`crates/mandate-policy/src/record.rs:129`). Coordinator ruling for this wave: the story records `model_version: None` and says so in the crate doc; widening the policy port is a later coordinator change.
- **What audience is bound against:** no audience registry is reachable from the ceiling (`mandate-token` owns resource servers, `ownership.md:15`, and is not in `dependency-boundaries.json:20-25`); `context` compares against a caller-supplied `Audience` — inferred.
- **Ceiling shape:** no ceiling type exists in any of the four crates (`AgentCapabilityCeilingId` only, `identifier.rs:18`) and no `ActionPattern` matcher exists anywhere in the ceiling; `evaluate` must declare an input shape and a matcher, and `story:agent-authority-kernel` owns the projection (`ownership.md:16`) — a semantic overlap the file scope cannot express.
- **`DecisionId` minting:** nothing in the ceiling generates a UUID (`value.rs:52-73`); the allocator port is inferred from the federation precedent, not from the story.
- **Stale citations in the story body:** `xtask/src/main.rs:270-272` for the `serve` refusal is now `:314-328`; `graph-policy`/`tenancy-topology` are `implemented`, not blocked.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Coordinator rulings for wave 3, 2026-09-19

- Correction round 1 (`review-result:wave3-check-api-adversary-1`): F1–F4 fixed, F5 no-op, F6 fixed (test claim amended, producible-reasons test added). The implementor extended the F2 ruling from `actor` to `delegation` and `execution`: a `VerifiedContext` carrying any of the three is refused closed (`DenialReason::Denied`) until `story:agent-authority-kernel` and `story:agent-security` deliver their intersections. Accepted: the same fail-closed direction one field over; the crate doc names both owners.

## Coordinator ruling after correction round 2, 2026-09-19

- Correction round 2 (`review-result:wave3-check-api-adversary-2`): G1, G2, G4 fixed; G3 escalated — `mandate.core.DecisionChallenge` carries no requirement, so a reauthentication challenge is unrepresentable and answered `Unavailable`; the follow-up (`DecisionChallenge.requirement`, a contract and `mandate-model` change) is recorded under Residue. The coordinator formatted `tests/adversary_check_2.rs` (one rustfmt hunk) so the package gate's fmt step passes. Unit committed as `e93395f`, merged `--no-ff` into `integration/wave-20260918-004`.

## Residue after wave 3

- `Decision.model_version` is always `None`: no port in the ceiling returns an `AuthorizationModelVersion` (`crates/mandate-policy/src/port.rs:224-232` carries `PolicyVersion` only). Widening the policy port is a coordinator change; no owning story yet.
- `mandate.core.DecisionChallenge` carries no requirement, so a `Reauthentication` selected by `precedence::strictest` is answered `Unavailable` (`crates/mandate-authz/src/decision.rs`, crate doc `lib.rs:51-64`). Closing it is a contract change (`DecisionChallenge.requirement`) plus `crates/mandate-model`; no owning story yet — filed for the coordinator's next planning pass.
- A `VerifiedContext` carrying an `actor`, `delegation` or `execution` other than the subject is refused closed (`context::direct`); the actor-ceiling intersection and the ceiling's `agent_id` binding are `story:agent-authority-kernel`'s and `story:agent-security`'s.
- `DenialReason::StaleEpoch` has no producer inside the ceiling; the producible reasons are asserted end to end in `tests/check_contract.rs` and the complement is pinned to `[StaleEpoch]`.
- `mandate.graph.Resource.space_id` has no writer (`story:declared-writers`), so a scope naming a space binds closed (`TenantMismatch`) today.
- `DecisionIdAllocator` and `ChallengeIssuer` are in-crate ports with `pub` doubles; their real sources (an id source; the policy that approves, with its expiry) arrive with the host adapter. The doubles move to `crates/mandate-testkit` under `story:testkit-doubles`.
- The audience is compared against a caller-supplied `Audience`; no registry is reachable from the ceiling (`mandate-token` owns resource servers).
- Scope resources are matched by `resource_id` alone, the graph's identity rule; a scope naming a parent does not cover a child request (closed direction, no contract states inheritance for `AuthorityScope.resources`).
