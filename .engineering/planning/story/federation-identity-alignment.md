---
format: aep.planning-md/1
id: story:federation-identity-alignment
kind: story
status: draft
title: Federation and identity agree with the contract field for field, emit and replay
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:contract-shapes
- depends_on: story:event-validation-harness
scope:
- confidence: inferred
  path: crates/mandate-federation/src/authorize.rs
- confidence: inferred
  path: crates/mandate-federation/src/disable.rs
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: inferred
  path: crates/mandate-federation/tests/adversary_pkce.rs
- confidence: inferred
  path: crates/mandate-federation/tests/authenticate.rs
- confidence: inferred
  path: crates/mandate-federation/tests/authorize.rs
- confidence: inferred
  path: crates/mandate-federation/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-federation/tests/emitted_events.rs
- confidence: inferred
  path: crates/mandate-federation/tests/link.rs
- confidence: inferred
  path: crates/mandate-federation/tests/replay.rs
- confidence: cited
  path: crates/mandate-identity/src/increment.rs
- confidence: cited
  path: crates/mandate-identity/src/lib.rs
- confidence: cited
  path: crates/mandate-identity/src/port.rs
- confidence: cited
  path: crates/mandate-identity/src/session.rs
- confidence: inferred
  path: crates/mandate-identity/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-identity/tests/emitted_events.rs
- confidence: inferred
  path: crates/mandate-identity/tests/replay.rs
revision: 11
---
## Acceptance

Given `mandate-federation` and `mandate-identity`, when every event, command input and entity record they hold is serialized, then it round-trips exactly into its generated contract shape; when a real handler emits an event, the emitted payload validates against the closed schema, its `input_field`/`response_field`/`literal` sources agree, and exactly one event is emitted per accepted outcome and none per denial; and when each durable entity's events are folded from an empty projection, the result equals the live projection.

## Why

Five event-shape drifts are live at `874a74f`: `IdentityEvent::SecurityEpochIncremented { target }` vs `{context, target}`; `IdentityEvent::SessionRevoked(SessionId)` vs `{context, id}`; `FederationEvent::FederationConnectionDisabled { context, connection_id }` vs `{context, id}`; `IdentityEvent::SessionOpened(Session)` and `EpochSnapshotRecorded(..)` carry entity records, not the declared payloads. Four commands whose events the folds consume have no deciding handler: `RevokeSession`, `DisableFederationConnection`, `UnlinkExternalPrincipal`, `DisableOAuthClient`.

## Scope

- `crates/mandate-federation/src/record.rs` — cited; `FederationEvent` variants become payload structs matching the contract, `Serialize` derived (`#[serde(untagged)]` on the enum, struct payloads), `fn ess_name(&self)`, `FederationConnectionDisabled.id`; handlers for `DisableFederationConnection`, `UnlinkExternalPrincipal`, `DisableOAuthClient` (inferred file `src/disable.rs`), fold arms.
- `crates/mandate-federation/src/lib.rs` — cited; `pub mod disable;`, `realizes!` registrations (from `story:coverage-map`'s macro if merged; else a `pub const ESS_REALIZATIONS`).
- `crates/mandate-federation/tests/contract_agreement.rs` — inferred; round trips for 6 events + 3 new, 5 command inputs, 3 entity records into `mandate_contract::*`.
- `crates/mandate-federation/tests/emitted_events.rs` — inferred; `register_federation_connection`, `link_external_principal`, `authenticate_federation`, `provision_external_principal`, the three new handlers, through `mandate_testkit::contract`.
- `crates/mandate-federation/tests/replay.rs` — inferred; FederationConnection (register → disable), ExternalPrincipal (link/provision → unlink), OAuthClient (fold only).
- `crates/mandate-identity/src/port.rs`, `src/session.rs`, `src/increment.rs`, `src/lib.rs` — cited; the five drifts corrected to declared payloads; `revoke_session(&mut IdentityLog, ctx, id) -> Result<SessionRevoked, Denial>` (inferred); `Serialize` derives; seeding constructors take the declared payloads.
- `crates/mandate-identity/tests/contract_agreement.rs`, `tests/emitted_events.rs`, `tests/replay.rs` — inferred; Session (open → refresh → revoke), SecurityEpochSnapshot, the three epochs (`SecurityEpochRecorded → Incremented`, +1 and the maximum denial); no `IdentityLog` seeding constructor and no `RequestContext` consulted by a fold.
- Existing tests under both `tests/` directories — cited; call sites follow the payload change (assertions unchanged).

### Units

| Unit | Owns | Test | Produces |
|---|---|---|---|
| `federation-shapes` | `src/record.rs`, `src/lib.rs` | `tests/contract_agreement.rs` | payload structs, serde, `id` rename, agreement |
| `federation-handlers` | `src/disable.rs` | `tests/emitted_events.rs`, `tests/replay.rs` | three handlers, emission and replay proofs |
| `identity-shapes` | `src/port.rs`, `src/session.rs`, `src/increment.rs`, `src/lib.rs` | `tests/contract_agreement.rs` | five drifts corrected, `revoke_session`, serde |
| `identity-proofs` | — | `tests/emitted_events.rs`, `tests/replay.rs` | emission and replay proofs |

One agent, serially; `Cargo.toml` dev-dependencies on `mandate-contract` and `mandate-testkit` are pre-landed by the coordinator.

### Excluded

`crates/mandate-federation/src/{pkce,publicclient,authorize,verifier}.rs`, `Cargo.*`, `dependency-boundaries.json`, `generated/`, `systems/`, `mandate-model`, `mandate-types`.

### Gate

`cargo fmt -p mandate-federation -p mandate-identity -- --check && cargo clippy -p mandate-federation -p mandate-identity --all-targets --locked -- -D warnings && cargo test -p mandate-federation -p mandate-identity --locked`; `cargo check --workspace --all-targets --locked`.

## Inherited from wave E1, 2026-09-19

- Surfaced by `contract-creates` adversary pass 2 (A2-9): `crates/mandate-federation/src/authorize.rs:293-295` returns `DenialReason::Denied` for a consumed authorization code and quotes the yaml text the contract no longer carries; the contract routes a consumed code to the `wrong-state` outcome (409). Align the handler and its two cases (`tests/authorize.rs:280`, `tests/adversary_pkce.rs:550`) to the wrong-state outcome.

## Coordinator rulings at wave opening, 2026-09-19

- This story owns `crates/mandate-federation/src/lib.rs` for the auth wave; the opening commit pre-lands `pub mod verifier_real;` over a stub, which the story keeps in place. `crates/mandate-federation/src/verifier.rs` and `verifier_real.rs` are `story:signing-and-verification`'s; the doubles in `verifier.rs` stay until every accepted path has a real-verifier case.
- Dev-dependencies on `mandate-contract` and `mandate-testkit` for both crates are pre-landed in the opening commit.
- The consumed-authorization-code alignment inherited from wave E1 (`authorize.rs:293-295` returns `Denied` where the contract says wrong-state) is in scope here: the handler's refusal reason distinguishes the wrong-state outcome, and the two cases follow.

## Coordinator rulings after critic round 1, 2026-09-19

- Opening a Session from the login (design D3): `mandate-identity` cannot see `FederationEvent` (direction `mandate-federation → mandate-identity`, never the reverse, per `story:pkce-sessions`'s ruling). The identity fold therefore consumes the generated contract payload `mandate_contract::events::MandateFederationFederationAuthenticated` — `mandate-contract` is admitted as a regular dependency of `mandate-identity` in the opening commit — and `IdentityLog` gains a fold arm that materializes the Session (`session_id`, `principal_id`, `organization_id`, `connection_id`, `epochs`, `expires_at`) from it; `SessionOpened` stays the seeding event for a non-federated open and a second open of a session already held is refused by the fold. This is the `identity-shapes` unit's (`src/port.rs`, `src/session.rs`) with its proof in `identity-proofs` (`tests/replay.rs`: login → refresh → revoke folds from the two events alone). The federation handler keeps returning `FederationAuthenticated`; appending it to the identity aggregate is the adapter's (control-plane), outside this crate.
- `crates/mandate-federation/src/authorize.rs`, `tests/authorize.rs`, `tests/adversary_pkce.rs` join this story's scope for the consumed-code alignment (design D4); `pkce.rs`, `publicclient.rs`, `verifier.rs` stay excluded.
- `tests/link.rs` and `tests/authenticate.rs` are this story's this wave (parallel PS1); the verifier unit does not write them.
