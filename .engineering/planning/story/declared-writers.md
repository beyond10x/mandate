---
format: aep.planning-md/1
id: story:declared-writers
kind: story
status: active
title: Every record has a declared writer
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:domain-runtime
- depends_on: story:contract-creates
scope:
- confidence: inferred
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/src/record.rs
- confidence: inferred
  path: crates/mandate-federation/src/register_client.rs
- confidence: inferred
  path: crates/mandate-federation/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-federation/tests/emitted_events.rs
- confidence: inferred
  path: crates/mandate-federation/tests/replay.rs
- confidence: inferred
  path: crates/mandate-identity/src/lib.rs
- confidence: inferred
  path: crates/mandate-identity/src/port.rs
- confidence: inferred
  path: crates/mandate-identity/tests/replay.rs
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
revision: 13
---
# Every record has a declared writer

## Acceptance

Given the compiled contract, when every entity's initial record is traced to the command whose accepted outcome creates it, then each of the 36 entities either names such a command or carries a declaration that its writer is an adapter or another system, and no field of a created record is left with no writer.

## Required observations

Read from the 59 command names in `systems/mandate/domains/*.yaml` on `integration/wave-20260918-003`, 2026-09-18. The contract declares a terminal move and no creation for: `mandate.credential.SigningKey` (retire, revoke; no registration or rotation), `mandate.delegation.Agent` (retire), `mandate.delegation.AgentCapabilityCeiling` (supersede; the first ceiling has no writer), `mandate.delegation.Execution` (complete; no start), `mandate.delegation.Approval` (consume; no grant), `mandate.directory.SyncJob` (complete, fail; no start), `mandate.federation.OAuthClient` (disable; found by the wave-2 `story:federation-linking` implementor — any log containing `OAuthClientDisabled` is unreadable to a fold that refuses orphan events), `mandate.graph.Grant` (revoke; found by the wave-2 `story:graph-policy` implementor — `record_grant` cannot refuse a padded role because no port admits one), `mandate.policy.Policy` and `mandate.policy.AuthorizationModel` (supersede; the first version has no writer), `mandate.workload.WorkloadIdentity` (revoke). Two fields have no writer at all: `mandate.graph.Resource.space_id` (`RegisterResource` takes no space; `review-result:wave2-tenancy-topology-adversary-1`) and the first `generation` of the three security-epoch entities (`IncrementSecurityEpoch` is an adapter obligation and the seeding record is undeclared; `review-result:wave2-session-epochs-adversary-1` F5). `mandate.identity.Principal` is created only by `ProvisionExternalPrincipal`; a non-federated principal has no writer. `mandate.identity.SecurityEpochSnapshot` is written by session issuance in another domain with no declared event.

Per entity the decision is one of two: a command in the contract with one accepted and one denied outcome and one event that is the creation record, carrying every required field of the record (`story:event-payloads-for-folds`); or a header declaration in the domain file naming the adapter or system that writes it and the event a fold consumes. A fold under `docs/adr/0009-event-sourced-persistence.md` refuses an event naming an instance no event created, so an undeclared writer is an unreadable log, not a gap in prose.

## Scope

Re-derived 2026-09-19 by `story-scoper` on `main` at `a76267b` (wave E1 and wave A merged), replacing the 2026-09-18 section. **Cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `systems/mandate/domains/` — cited; the story's own scope and its Exclusions ("contract-only"). Wave B lifts the exclusion for two fold arms whose owning stories are closed (see *Rulings — wave B opening*).
- **Confidence:** high for the two login-road entities; medium on the command and event names, which exist nowhere yet.
- **Would collide with:** any unit editing `systems/mandate/domains/*.yaml`, `systems/mandate/components.yaml`, `docs/architecture/command-obligations.md`, `docs/architecture/federated-login.md`, `generated/**`, or the count pins named under *Coordinator-owned*.

### What wave E1 changed under this story

- 19 `creates:` lines exist over 16 entities (`audit.yaml:142`; `credential.yaml:264,299,340,386,464`; `delegation.yaml:306`; `directory.yaml:304`; `federation.yaml:188,221,257,303`; `graph.yaml:180,210`; `tenancy.yaml:190,241,266,319,369`) — cited. 36 entities (`crates/mandate-types/tests/inventory.rs:111`) less 16 leaves 20 creator-less.
- `mandate.identity.Principal` is out of the unfoldable residue — cited: `crates/mandate-types/tests/adversary_fold_inputs.rs:399-412` and `adversary_fold_inputs_2.rs:324-337` pin 12 entities, Principal in neither. `mandate.federation.ExternalPrincipalProvisioned` carries every Principal field (`federation.yaml:459-464`).
- `mandate.federation.OAuthClient` is still residue at field `public` — cited, `adversary_fold_inputs.rs:405`.

### The login road, entity by entity

| Entity | Record | Seeding event today | Needs |
|---|---|---|---|
| `mandate.identity.Principal` (`identity.yaml:12-19`: `id`, `kind`, `display_name`) | 3 fields | `ExternalPrincipalProvisioned` carries `principal_id` (`federation.yaml:459-460`), `kind` (`:461-462`), `display_name` (`:463-464`) | a declaration only; no new event — cited |
| `mandate.federation.OAuthClient` (`federation.yaml:85-98`: `organization_id`, `public`, `redirect_uris`, `pkce_method`) | 4 fields | `OAuthClientDisabled` (`:495-500`) carries `context` and `id` only | a creating command and a creation event — cited |
| `mandate.credential.SigningKey` (`credential.yaml:77-107`: `key_reference`, `algorithm`, `not_before`, `expires_at`; `Recorded → Retired/Revoked`) | 4 fields | `SigningKeyRetired` (`:646`), `SigningKeyRevoked` (`:652`) move it; nothing creates it | a creating command and a creation event — cited |

### The contract gap, at its line

`federation.yaml:303` — cited. `ProvisionExternalPrincipal`'s accepted outcome spends its one `creates:` on `mandate.federation.ExternalPrincipal` (`instance: external_principal_id`, `:304`); under ESS 0.26.0 an outcome declares one of `creates`/`moves`/`updates`, so the Principal the same outcome produces (`:305`) cannot be declared there. Cross-domain `creates:` is not the obstacle (`AuthenticateFederation` at `:257` creates `mandate.identity.Session`). Closure taken: **P1**, a header declaration in `identity.yaml:1-10` in the form `:8` uses for `SessionOpened`, naming `ExternalPrincipalProvisioned` as the Principal's seeding event and the identity fold as its consumer; compiles to nothing, moves no pin. P2 (a `RegisterPrincipal` command) is not taken: it would amend the adapter's two-call sequence at `docs/architecture/federated-login.md:105,118`.

### Units

| Unit | Wave | Files | Adds | Gate |
|---|---|---|---|---|
| A1 `principal-writer` | B, contract round | `systems/mandate/domains/identity.yaml:1-10` | the Principal declaration (P1) | `ess specify validate --path systems/mandate` |
| A2 `oauth-client-writer` | B, contract round | `systems/mandate/domains/federation.yaml` (command before `DisableOAuthClient` at `:367`; event before `:495`); `systems/mandate/components.yaml:37,80`; `docs/architecture/command-obligations.md` | `mandate.federation.RegisterOAuthClient` → `OAuthClientRegistered` carrying `context`, `id`, `organization_id`, `public`, `redirect_uris`, `pkce_method`; `creates: mandate.federation.OAuthClient`, `instance: id`; a `denied` outcome | same |
| C1 `signing-key-writer` | B, contract round | `systems/mandate/domains/credential.yaml` (command before `RetireSigningKey` at `:475`; event before `:646`); `components.yaml`; `command-obligations.md` | `mandate.credential.RegisterSigningKey` → `SigningKeyRegistered` carrying `context`, `id`, `key_reference`, `algorithm`, `not_before`, `expires_at`; `creates: mandate.credential.SigningKey`, `instance: id`; a `denied` outcome | same |
| C0 `introspection-text` | B, contract round | `credential.yaml:417`; `command-obligations.md` row | the `IntrospectCredential` denial names a malformed or unresolvable presented proof, not "invalid/revoked/expired" (ruling on `story:credential-profiles`) | same |
| A3 `principal-fold` | B, realization round (after the coordinator's regeneration) | `crates/mandate-identity/src/port.rs` (the arm beside `session_of` at `:304-321`), `crates/mandate-identity/tests/replay.rs` | the Principal record folded from `mandate_contract::events::MandateFederationExternalPrincipalProvisioned` (`generated/rust/mandate-contract/src/events.rs:406`); `dependency-boundaries.json:44` already admits `mandate-contract` | `cargo test -p mandate-identity --locked` |
| A4 `oauth-client-fold` | B, realization round | `crates/mandate-federation/src/register_client.rs` (create), `src/record.rs` (the arm beside `:578-584`, replacing `FoldError::UnknownOAuthClient` at `:338-343`), `src/lib.rs:162-185` (`realizes!`), `tests/replay.rs`, `tests/emitted_events.rs`, `tests/contract_agreement.rs` | the `RegisterOAuthClient` handler and the creation arm | `cargo test -p mandate-federation --locked` |
| B `delegation-graph-writers`, C2 `policy-directory-workload` | later wave | `delegation.yaml:330,353,376,399`, `graph.yaml:153`, `policy.yaml:79,102`, `directory.yaml:376,399`, `workload.yaml:56`, `identity.yaml` | creators or declarations for the remaining creator-less entities; `RegisterResource` gains the space input | same |

No unit needs a new `mandate.core.*` type: `OAuthClientId` (`core.yaml:84`), `RedirectUri` (`:132`), `PrincipalKind` (`:147`), `PkceMethod` (`:188`), `VerifiedContext` (`:211`), `SigningKeyId`, `KeyReference`, `SigningAlgorithm` exist — cited; the 110-type and 74-authored pins (`inventory.rs:37,40`) do not move.

### Coordinator-owned

- `generated/**` — `cargo xtask generate` after the contract round merges, never hand-edited.
- Count pins moved by two new commands and two new events: `crates/mandate-types/tests/adversary_fold_inputs.rs:278-280` and `UNFOLDABLE` `:399-412`; `adversary_fold_inputs_2.rs:192-194,297-298` and `RECORDED_RESIDUE` `:324-337`; `crates/mandate-types/tests/contract_adversary.rs:172-176`; `xtask/tests/emit.rs:190-193`; `inventory.rs:111` (36 entities, unchanged).
- `docs/architecture/federated-login.md:29,49,105` name this story as the Principal's writer and are rewritten when A3 lands.
- `tests/security/cases.json` — no case is this story's; a case follows a command, coordinator's call.

### Which crate folds the record

Principal folds in `crates/mandate-identity` — the direction constraint decides it (`dependency-boundaries.json:49-61` lets `mandate-federation` see `mandate-identity`, never the reverse) and wave A's Session arm is the exact precedent (`crates/mandate-identity/src/port.rs:15`, `:304-321`). OAuthClient folds in `crates/mandate-federation`, whose projection exists (`src/record.rs:117-130`) and whose fold refuses at `:338-343` "because the contract declares no command that creates an `OAuthClient`". `mandate-model` is not touched. Crate sites naming this story: `crates/mandate-identity/src/lib.rs:214-216`, `crates/mandate-federation/src/disable.rs:180-192`, `src/publicclient.rs:14`, `tests/publicclient.rs:166`, `tests/replay.rs:444`, `crates/mandate-types/tests/adversary_fold_inputs.rs:395`.

### Collisions

- `story:credential-profiles` (same wave): no file collision — its scope is `crates/mandate-token/**`, `services/sts/**` and the coordinator's manifests; this story adds no entity and no `mandate.core.*` type, so `crates/mandate-types/tests/inventory.rs` does not move — cited.
- `story:product-listener`, `story:testkit-doubles` on `crates/mandate-federation/src/lib.rs` — neither is in wave B.

## Exclusions

`crates/**` realizations of the new commands are their owning stories', with one exception ruled at the wave B opening: the Principal fold arm (`crates/mandate-identity/src/port.rs`, `src/lib.rs`) and the `OAuthClient` creation handler and fold arm (`crates/mandate-federation/src/register_client.rs`, `src/record.rs`, `src/lib.rs`) are this story's, because the stories owning those crates are `implemented`. Everything else here is contract-only.

## Inherited from wave E1, 2026-09-19

- From `contract-creates` adversary pass 1 (A1-5): `mandate.identity.Principal` is created by `ProvisionExternalPrincipal`, whose accepted outcome already declares `creates: ExternalPrincipal`, and ESS refuses two subjects on one outcome. Declaring the Principal's creator therefore needs a second emitted event on a second outcome or a dedicated command, not a `creates:` on the existing outcome.
- The creator-less residue this story inherits is 20 entities: the 16 named in `story:contract-creates` plus `SecurityEpochSnapshot`, `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch`, `FederationSecurityEpoch` (no transitions, adapter-seeded).

## Inherited from wave E1 adversary pass 2, 2026-09-19

- From `contract-creates` adversary pass 2 (A2-3/A2-4): `ResourceRegistered` does not carry `space_id`; `Resource` stays in the unfoldable residue until this story adds the space input to `RegisterResource` and sources the event field from it.

## Rulings — wave B opening, 2026-09-19

Coordinator, after `review-result:wave-b-parallel-r1` and `review-result:wave-b-design-r1`.

1. **Two rounds.** Contract round first (A1, A2, C0, C1), one adversary pass, merge, then the coordinator's regeneration and re-pin commit; the realization round (A3, A4) and `story:credential-profiles` are cut from that head (parallel-safety 1 and 2).
2. **A2 shape.** `RegisterOAuthClient` takes `context`, `public`, `redirect_uris`, `pkce_method` — no `organization_id` input. The accepted outcome binds the client to `context.organization`; the response carries `id` and `organization_id`; `OAuthClientRegistered` sources `organization_id` from the response and carries `context`, `id`, `public`, `redirect_uris`, `pkce_method`. Denied: the caller lacks client-administration authority, the redirect set is empty or a URI is unadmitted, or a public client names a PKCE method other than S256 (design 5, and the critic's recommendation; `publicclient.rs:86,106-108` refuses the rest at authorization).
3. **C0 shape.** `IntrospectCredential`'s response gains `credential_id: Optional<mandate.core.CredentialId>`; `CredentialIntrospected` gains `active: Boolean` (`response: active`) and `credential_id` (`response: credential_id`); the denial text names a malformed or unresolvable presented proof in place of "invalid/revoked/expired" (design 6).
4. **C1 shape.** `RegisterSigningKey` takes `context`, `key_reference`, `algorithm`, `not_before`, `expires_at`; responds `id`; `SigningKeyRegistered` carries all six with `id` from the response; `creates: mandate.credential.SigningKey`, `instance: id`. Denied: the caller lacks signing-key administration authority, the algorithm is outside the deployment's allowlist, `not_before` is not before `expires_at`, or the key reference is unresolvable. Names no algorithm.
5. **A3 and the Session arm.** The identity fold does not refuse an opening whose principal has no record: the explicit-link path (`LinkExternalPrincipal`) names a principal no event creates until a `RegisterPrincipal` lands (C2, later wave). The fold answers `None` for such a principal; the test pins both paths (design 7). A3 also edits `crates/mandate-identity/src/lib.rs:208-216` (Principal leaves `ESS_UNREALIZED`).
6. **Exclusions amended** (design 8): A3 and A4 realize in `crates/mandate-identity` and `crates/mandate-federation` because the stories that own those crates are `implemented`; every other realization stays its owning story's.
7. **Every creator's event carries its record**, foreign keys from response fields the outcome decides — wave E1's rule, applied to A2 and C1.

## Inherited from the wave B contract round, 2026-09-19

- From the wave B contract-round adversaries (2026-09-19): ESS 0.26.0's synthesizer builds the same constant for every `Timestamp` input and never consults an entity invariant when building a creating command's input, so `mandate.credential.SigningKey`'s `not_before < expires_at` yields an accepted scenario no conforming handler passes (`RegisterSigningKey/outcome/accepted`); publishing a view adds an invariant scenario that is unsatisfiable for the same reason. Routed to the ESS wave as a synthesizer gap. ESS also does not type an invariant's comparison (a string newtype against a `Timestamp` validates), so chronological versus lexicographic is fixed nowhere; routed beside `story:invariant-boundary-validation`. Until both land, the `keys` unit's tests are the check, and the conform gate (`story:conform-gate`) expects that scenario `failed` with this note as its `blocked_on`.
