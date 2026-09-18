---
format: aep.planning-md/1
id: story:federation-linking
kind: story
status: active
title: Implement verified federation and explicit linking
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:canonical-types
- depends_on: story:runtime-decision-dossier
- informed_by: initiative:next-ten-waves
- depends_on: story:domain-runtime
scope:
- confidence: cited
  path: crates/mandate-federation/Cargo.toml
- confidence: inferred
  path: crates/mandate-federation/src/authenticate.rs
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/src/link.rs
- confidence: inferred
  path: crates/mandate-federation/src/record.rs
- confidence: inferred
  path: crates/mandate-federation/src/verifier.rs
- confidence: inferred
  path: crates/mandate-federation/tests/authenticate.rs
- confidence: inferred
  path: crates/mandate-federation/tests/link.rs
- confidence: inferred
  path: crates/mandate-federation/tests/record.rs
- confidence: inferred
  path: crates/mandate-federation/tests/verifier.rs
- confidence: inferred
  path: dependency-boundaries.json
revision: 9
---
# Implement verified federation and explicit linking

## Acceptance

Given a verified federation proof, when its exact organization/issuer/subject key is resolved, then exactly one configured tenant and explicitly linked principal form the resulting authenticated context.

## Required observations

Runtime cases issuer-isolation, email-isolation, explicit-link, link-conflict, tenant-valid, tenant-zero, tenant-ambiguous and tenant-unverified pass; verify configured issuer and client binding, JIT and linking authorization; no email auto-merge. Moved to `story:signing-and-verification`: signature verification, OIDC discovery/JWKS caching and key rollover.

## Deliverable this wave, and the follow-on

The acceptance's *given* is a verified proof. The `verifier-port` unit's `pub` double supplies one by construction, and the `linking` and `authenticate` units land the eight cases against it. On that evidence — eight cases executing under `cargo test -p mandate-federation`, count reported — the story moves to `implemented`. What it does not deliver is real signature verification, discovery, JWKS caching and rollover: `dependency-boundaries.json:35-40` admits no external crate and `Cargo.lock` holds no JOSE library, so those Required observations now belong to `story:signing-and-verification`, which `depends_on` this story and attaches at the `FederationVerifier` trait the coordinator's interface commit declares. The registered-client port that `story:pkce-sessions` later declares in `mandate-identity` is implemented over this story's `OAuthClient` projection by `story:product-listener`'s `port-adapters` unit, not here.

## Sequencing

`depends_on story:domain-runtime`: the `authenticate` unit realizes `ProvisionExternalPrincipal`, a command and event that story declares, and reads the `jit_provisioning` field it adds. This story dispatches only after that story's regeneration has landed.

## Units

A coordinator interface commit lands first; four units then own disjoint files. The split is forced by three facts: a `pub mod` line against a file that does not exist does not compile, so the coordinator seeds all four module files; the test double must be `pub` because `tests/*.rs` compile as separate crates, so `verifier-port` precedes `linking` and `authenticate`; no unit may add any dependency, because the crate's allowed list has none and the gate checks dev-dependencies.

| Unit | Owns | Test file | Produces |
|---|---|---|---|
| coordinator, first | `crates/mandate-federation/src/lib.rs`, `crates/mandate-federation/Cargo.toml` | — | the four `pub mod` lines; the four `src/*.rs` files as compiling `todo!()` stubs; the `Denied` error carrying `DenialReason`; the `FederationVerifier` port trait; the `SessionIssuer` port trait returning `SessionId` and `CredentialId`; the `ConnectionStore` and `LinkStore` read traits |
| `records` | `crates/mandate-federation/src/record.rs` | `crates/mandate-federation/tests/record.rs` | the `FederationConnection`, `ExternalPrincipal` and `OAuthClient` projection types; the composite-key conflict path returning the declared denial; `RegisterFederationConnection`; the `Enabled`/`Disabled` state read by authentication |
| `verifier-port` | `crates/mandate-federation/src/verifier.rs` | `crates/mandate-federation/tests/verifier.rs` | the `FederationVerifier` implementation surface and a `pub` test double that admits or refuses by construction and takes the algorithm allowlist as a constructor argument; no cryptography |
| `linking` | `crates/mandate-federation/src/link.rs` | `crates/mandate-federation/tests/link.rs` | `LinkExternalPrincipal`; cases `issuer-isolation`, `email-isolation`, `explicit-link`, `link-conflict` |
| `authenticate` | `crates/mandate-federation/src/authenticate.rs` | `crates/mandate-federation/tests/authenticate.rs` | `AuthenticateFederation` and `ProvisionExternalPrincipal`; cases `tenant-valid`, `tenant-zero`, `tenant-ambiguous`, `tenant-unverified`; the JIT path |

Order: coordinator → `records` ∥ `verifier-port` → `linking` ∥ `authenticate`. Five agents at most, four at once at most.

## Records ownership — a recorded departure

`docs/architecture/ownership.md:14` assigns `mandate.federation` connection/link/client *records* to `mandate-model`. That line predates `docs/adr/0009-event-sourced-persistence.md`. Under that record, a connection, a link and a client are projections materialized by this crate's own fold; they are not canonical value types. The 74 canonical types are `mandate.core.*` and `mandate_types::canonical_record!` hardcodes that prefix (`crates/mandate-types/src/macros.rs:404`); `mandate-model` holds exactly four of them and its conformance registry asserts that. `story:domain-runtime`'s coordinator row carries the revision of `ownership.md:14`.

## Case ids

From `tests/security/cases.json`, `story: story:federation-linking`: `issuer-isolation`, `email-isolation`, `explicit-link`, `link-conflict` (each names `LinkExternalPrincipal` and `AuthenticateFederation`); `tenant-valid`, `tenant-zero`, `tenant-ambiguous`, `tenant-unverified` (each names `AuthenticateFederation`). All eight must execute as tests under `cargo test -p mandate-federation`. The corpus file is coordinator-owned.

## Decisions that apply

- `decision-blocker:identity-uniqueness` — unique index on `(organization, connection.issuer, external subject)` on the projection, plus an explicit conflict path returning the declared denial (`command-obligations.md:28`). The issuer is populated from the validated connection. The concurrency case the dossier requires (`runtime-decisions.md:248`) is not expressible in this crate and belongs to the storage adapter; the `records` unit proves the single-writer conflict path and says so.
- `decision-blocker:jit-provisioning` — JIT through `ProvisionExternalPrincipal(connection_id, proof)`, gated by `FederationConnection.jit_provisioning: Boolean`, link method `ExternalLinkMethod::ConfiguredFederation`. Adapter sequence: `AuthenticateFederation`; on an absent-link denial with JIT admitted, `ProvisionExternalPrincipal`, then `AuthenticateFederation` again.
- `decision-blocker:algorithm-policy` — the shape is exercised through the double's constructor argument; no algorithm is named.
- `decision-blocker:epoch` — `Session.epochs` is an `EpochSnapshotRef`, an immutable handle. The `SessionIssuer` port returns the handle; nothing here compares generations.
- `docs/adr/0009-event-sourced-persistence.md` — the in-memory store implementations in tests are folds over a `Vec` of events.

## Dependency ceiling

`mandate-types`, `mandate-model`, `mandate-identity`, `mandate-token` — nothing else, in `[dependencies]` or `[dev-dependencies]`. No `serde_json` in tests. A unit may not edit `dependency-boundaries.json`, `Cargo.toml` or `Cargo.lock`.

## Exclusions

`UnlinkExternalPrincipal` — its invalidation runs through generation changes (`combined.md:33`), `decision-blocker:epoch`. `AuthorizePublicClient` — realized by `story:pkce-sessions` up to the STS port. Real cryptography, discovery, JWKS, rotation — `story:signing-and-verification`. HTTP, transport, async. Any edit to `crates/mandate-types`, `crates/mandate-model`, `crates/mandate-identity`, `xtask/`, `systems/mandate`, `generated/`, `tests/security/cases.json`. `#[ignore]`.

## Obligations the eight cases do not cover

Candidate adversary cases, not unit deliverables: four of five `ExternalLinkMethod` variants have no case; addendum `:307` requires every link to be auditable and only `explicit-link` mentions audit; resolution-order steps 4 and 5 have no negative case; a disabled connection has no case though `federation.yaml:210` declares the denial; issuer immutability (`unmapped.md:54`) has no case; `DenialReason` has no link-conflict variant, so `link-conflict` and a generic refusal both surface as `Denied` — a contract change for `story:domain-runtime` to weigh.

## Gate per unit

`cargo fmt -p mandate-federation -- --check`; `cargo clippy -p mandate-federation --all-targets --locked -- -D warnings`; `cargo test -p mandate-federation --locked`, count reported. The full `task check` runs once, by the coordinator, on the merged integration head.

## Scope

- `crates/mandate-federation/src/lib.rs` — cited; the crate's only source file today. `crates/mandate-federation/Cargo.toml` — cited.
- `crates/mandate-federation/src/record.rs`, `src/verifier.rs`, `src/link.rs`, `src/authenticate.rs` — inferred; do not exist.
- `crates/mandate-federation/tests/record.rs`, `tests/verifier.rs`, `tests/link.rs`, `tests/authenticate.rs` — inferred; do not exist.
- `dependency-boundaries.json` — inferred; coordinator-owned; reached only if a dependency were added, which is excluded.
- Would collide with: any unit touching `crates/mandate-federation`; `story:domain-runtime`, sequential by edge; `story:product-listener` and `story:signing-and-verification`, both `depends_on` this story.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
