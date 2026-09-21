---
format: aep.planning-md/1
id: story:domain-runtime
kind: story
status: implemented
title: Settle remaining domain lifecycle contracts
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-types/src/inventory.rs
- confidence: cited
  path: crates/mandate-types/tests/inventory.rs
- confidence: cited
  path: docs/architecture/audit-routing.md
- confidence: cited
  path: docs/architecture/combined.md
- confidence: cited
  path: docs/architecture/command-obligations.md
- confidence: inferred
  path: docs/architecture/ownership.md
- confidence: inferred
  path: docs/architecture/runtime-decisions.md
- confidence: cited
  path: docs/architecture/unmapped.md
- confidence: cited
  path: generated
- confidence: cited
  path: systems/mandate/components.yaml
- confidence: cited
  path: systems/mandate/domains/audit.yaml
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
- confidence: cited
  path: tests/security/cases.json
revision: 15
---
# Settle remaining domain lifecycle contracts

## Acceptance

Given the unresolved lifecycle register, when the source-backed lifecycle decisions are accepted and projected through ESS, then every formerly unresolved mutation has one unambiguous declared transition or an explicit prohibition.

## Required observations

Resolve UNMAPPED-LIFECYCLE with source-backed lifecycle decisions, deletion/retention rules and typed transitions before runtime mutations; update ESS plus generated contracts and conformance cases.

## What this story now carries

Four contract changes the operator decided on 2026-09-18, all under `systems/mandate/domains/`, plus the regeneration and document revisions they force. Every change is read from the decisions recorded in `docs/architecture/federated-login.md` and as `approval` evidence on the blockers.

1. **Epoch generation in the contract.** An `Integer` field, constrained non-negative and monotonic, on `PrincipalSecurityEpoch` (`identity.yaml:165`), `OrganizationSecurityEpoch` (`:176`) and `FederationSecurityEpoch` (`:187`). ESS 0.25.0 has no unsigned primitive; `Integer` is the recorded stand-in for the addendum's `u64`, widened when ESS gains the type. At the maximum the increment denies (`command-obligations.md:36`). `EpochSnapshotRef` stays a handle.
2. **JIT provisioning.** A new command `mandate.federation.ProvisionExternalPrincipal(connection_id, proof)` → `external_principal_id`, one accepted outcome, one event, denial clause mirroring `AuthenticateFederation`'s plus "connection does not admit provisioning" and "composite key exists"; and a `Boolean` field `jit_provisioning` on `FederationConnection` (`federation.yaml:51-75`). The link it creates carries `ExternalLinkMethod::ConfiguredFederation`, already at `core.yaml:169-176`. No new type, no new entity: `crates/mandate-types/tests/inventory.rs:35,40,111` assert 110 type entries and 36 entities.
3. **Lifecycle under immutable-with-status.** Every entity whose lifecycle is `Recorded`-only gains the transitions its class needs, and nothing gains a destructive one. Retention is redaction. `combined.md:19`'s "`Recorded` represents an immutable observed record" is superseded by this decision and revised. There is no `UpdateFederationConnection`: a connection's issuer is immutable (`federation.yaml:2`), so a changed connection is `disable` plus `RegisterFederationConnection`; `audit-routing.md:12` records that answer.
4. **Regeneration.** Every ESS edit rewrites all 267 files under `generated/` because each carries the source digest. One `cargo xtask generate`, byte-compared, by the coordinator, after all units land.

## Units

| Unit | Owns | Produces |
|---|---|---|
| `epoch-field` | `systems/mandate/domains/identity.yaml`; `crates/mandate-types/tests/inventory.rs`; `crates/mandate-types/src/inventory.rs` | the three `Integer` fields; the tripwire at `tests/inventory.rs:133-153` ("gained a field; the exclusion must be revisited") revised to assert `{id, state, generation}`; the three exclusion reasons at `src/inventory.rs:466-480`, which read "no declared field", rewritten to state the exclusion that remains — arithmetic and realization, not the field |
| `jit-command` | `systems/mandate/domains/federation.yaml` | the command, its outcome, its event, the `Boolean` field |
| `lifecycle-a` | `systems/mandate/domains/credential.yaml`, `delegation.yaml`, `graph.yaml`, `policy.yaml` | transitions for `SigningKey`; `Agent`, `AgentCapabilityCeiling`, `Execution`, `Approval`; `Resource`; `Policy`, `AuthorizationModel` |
| `lifecycle-b` | `systems/mandate/domains/directory.yaml`, `tenancy.yaml`, `audit.yaml`, `workload.yaml` | transitions for `DirectoryGroup`, `SyncJob`; `Organization`, `Team`, `TeamMembership`, `Space` with the creation-command decision; `AuditEvent` with its retention answer; `WorkloadIdentity` |
| coordinator | `systems/mandate/components.yaml`; `docs/architecture/command-obligations.md`, `unmapped.md`, `combined.md`, `audit-routing.md`, `runtime-decisions.md`, `ownership.md`; `tests/security/cases.json`; `generated/**` | the JIT command and event wired into the control plane's `accepts`/`publishes` (`components.yaml:15-33,36-54`); one obligations row per new command, alphabetical, deny text verbatim; `unmapped.md:7`'s "never approximate them with Integer" rewritten to record the stand-in; `combined.md:19` revised; **`ownership.md:11-12`, `:14`, `:15` and `:16` revised for projections owned by the folding crate under ADR 0009** — graph/policy, federation, credential and delegation records respectively; `runtime-decisions.md` SC6, the "34 commands" count, and rows 5 and 7's affected story (`story:graph-policy-adapter`) refreshed; JIT cases added to the corpus after the command exists in the compiled index; regeneration |

All four units run at once; the coordinator's work is serial and follows. `core.yaml` and `system.yaml` are read by every unit and written by none. Every declared transition in the tree today is moved by exactly one command — 15 and 15; if ESS requires it, `lifecycle-a` and `lifecycle-b` each add commands and name them in their reports; the coordinator wires `components.yaml` and writes the obligations rows. No unit edits those two files.

This story runs alone in its wave: `story:federation-linking`, `story:graph-policy` and `story:tenancy-topology` all `depends_on` it, so nothing else is dependency-ready beside it.

## Case ids

None today: no case in `tests/security/cases.json` names `story:domain-runtime`. This story's evidence is `ess specify validate` and the byte-clean regeneration; the cases that exercise the new command belong to `story:federation-linking` and are added by the coordinator once the command compiles.

## Decisions that apply

`decision-blocker:lifecycle` (immutable-with-status; retention is redaction), `decision-blocker:epoch` (`Integer` stand-in, deny at maximum), `decision-blocker:jit-provisioning` (new command, `Boolean` field), `docs/adr/0009-event-sourced-persistence.md` (projections; the revision of `ownership.md:14`). `decision-blocker:worker-orchestration` (queue behind a port) constrains `SyncJob`'s transitions in `lifecycle-b` but adds no command here.

## Dependency ceiling

Not applicable to ESS files. `epoch-field` edits `crates/mandate-types` test and inventory source only; it adds no dependency and changes no `Cargo.toml`.

## Exclusions

No unit edits `components.yaml`, any file under `docs/architecture/`, `tests/security/cases.json`, `generated/`, `core.yaml`, `system.yaml`, `ess-inputs.yaml`, `xtask/`, or any crate other than the two `mandate-types` files named for `epoch-field`. No new type in `core.yaml`. No new entity. No destructive transition anywhere. No numeric arithmetic on the generation — the field is declared, not computed; `story:session-epochs` computes. No `#[ignore]`.

## Gate per unit

`ess specify validate --path systems/mandate`. Not `task check`: `xtask/src/main.rs:90-91` fails with "projection drift" until the coordinator regenerates, by design. `epoch-field` additionally runs `cargo test -p mandate-types --locked` **after** the coordinator's regeneration, because its tripwire reads `generated/schema` (`tests/inventory.rs:10`) and stays green in the unit worktree until then; the coordinator runs that test as part of the closing gate and reports its count.

## Scope

Confirmed by the implementor on 2026-09-18 against base `d47c0b5`; corrections visible rather than deleted.

- `systems/mandate/domains/identity.yaml` — cited; epoch fields landed at `:165`, `:176`, `:187` as inferred (exact).
- `systems/mandate/domains/federation.yaml` — cited; the JIT command, its event, `jit_provisioning` on the entity (`:51-75`, exact) and on `RegisterFederationConnection`'s input; `DisableOAuthClient` added beyond the unit table, `OAuthClient` being in this file and in no row.
- `systems/mandate/domains/credential.yaml`, `delegation.yaml`, `graph.yaml`, `policy.yaml`, `directory.yaml`, `tenancy.yaml`, `audit.yaml`, `workload.yaml` — cited; 25 commands and 25 events across them.
- `systems/mandate/components.yaml` — cited; coordinator; `:15-33` and `:36-54` grew to 44 and 65 entries.
- `crates/mandate-types/tests/inventory.rs` — cited; `:133-153` exact. `crates/mandate-types/src/inventory.rs` — **was inferred `:466-480`, is `:465-481`** inside `EXCLUDED_ENTITIES` at `:464-487`; off by one at both ends.
- `crates/mandate-types/tests/contract_adversary.rs` — not in any row; added by the adversary, nine cases, one a tripwire on ESS's invariant projection.
- `docs/architecture/command-obligations.md`, `unmapped.md`, `combined.md`, `audit-routing.md`, `runtime-decisions.md`, `ownership.md`, `federated-login.md` — coordinator; all seven written. `federated-login.md` was not in the original list; its FL2 counts and the `RegisterFederationConnection` signature went stale and were corrected.
- `xtask/src/main.rs` — not in the original list; coordinator; gained the commands-to-obligations check the implementor patched.
- `tests/security/cases.json` — cited; coordinator; three JIT scenarios added after the command existed in the compiled index.
- `generated` — cited; one directory entry on purpose; 267 files rewritten, 63 added.
- Not touched, as declared: `core.yaml`, `system.yaml`, `ess-inputs.yaml`.
- The one-agent execution: the four unit rows were done serially by a single implementor on the operator's "one per story"; the files stayed disjoint by construction.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Integration obligations

ESS changes in this story also regenerate and review generated/ through ESS; the typed scope includes that projection tree. This contract unit must freeze the canonical type/port surface before the concurrent federation and graph units begin, or replan the affected units. Changing runtime behavior is not implied by projection validation.

## Creation commands the tenancy story needs

`story:tenancy-topology`'s Required observations begin "Create org memberships, teams and spaces". `tenancy.yaml` declares exactly one command, `RemoveOrganizationMembership` (`:125`), and `tenancy.yaml:1` parks creation on `decision-blocker:lifecycle`. Under immutable-with-status, creation is a recorded transition and needs a command. The `lifecycle-b` unit, which owns `tenancy.yaml`, reads the preserved sources for the creation paths they support — administrative, invitation, SCIM (`original-design.md` §12.6, §38) — and either declares the commands with their single outcome and single event, or records in its report that creation of a given class is SCIM-only and belongs to `story:directory-provenance`. Whichever it decides, the coordinator wires `components.yaml` and writes the obligations rows. The same question applies to `Team`, `TeamMembership` and `Space`. `story:tenancy-topology` is re-scoped after this story merges.
