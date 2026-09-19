---
format: aep.planning-md/1
id: story:oauth-integration
kind: story
status: draft
title: Integrate public-client endpoints with STS
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- depends_on: story:credential-profiles
- depends_on: story:protocol-adapters
- informed_by: initiative:next-ten-waves
- depends_on: story:product-listener
scope:
- confidence: cited
  path: services/sts/Cargo.toml
- confidence: inferred
  path: services/sts/src/audit.rs
- confidence: inferred
  path: services/sts/src/binding.rs
- confidence: inferred
  path: services/sts/src/code.rs
- confidence: inferred
  path: services/sts/src/lib.rs
- confidence: cited
  path: services/sts/src/main.rs
- confidence: inferred
  path: services/sts/src/redemption.rs
- confidence: inferred
  path: services/sts/src/store.rs
- confidence: inferred
  path: services/sts/tests/audit.rs
- confidence: inferred
  path: services/sts/tests/binding.rs
- confidence: inferred
  path: services/sts/tests/cli.rs
- confidence: inferred
  path: services/sts/tests/code.rs
- confidence: inferred
  path: services/sts/tests/redemption.rs
- confidence: inferred
  path: services/sts/tests/store.rs
- confidence: inferred
  path: services/sts/tests/surface.rs
revision: 11
---
# Integrate public-client endpoints with STS

## Acceptance

Given a fresh authorization code, when the public client redeems it through the actual OAuth endpoint, then exactly one correctly scoped credential is issued.

## Required observations

Run all PKCE corpus cases against actual federation/session/STS adapters, including two concurrent redeemers; verify form encoding, standard errors, registered redirects, state/nonce and credential profiles.

## Home: `services/sts` alone

`crates/mandate-server` is removed from this story's scope. `dependency-boundaries.json` caps it at `mandate-types` and `mandate-proto`, so `AuditRecord` (`mandate-model`) and `CredentialDescriptor` (`mandate-token`) are unreachable; `ownership.md:20` states the server adapter does not acquire token-issuance authority; `ownership.md:15` assigns issuance, verifier storage and code consumption to STS alone. Form encoding and standard OAuth errors are `story:protocol-adapters`'; the endpoint that serves them is `story:product-listener`'s, on which this story now depends for its acceptance's "actual OAuth endpoint".

## Cannot be completed under current policy

Two coordinator preconditions, both under `task:runtime-wave-integration`, before anything here compiles. `mandate-sts` is a binary package and takes the `external` allowlist `["clap","serde_json","sha2"]` (`xtask/src/main.rs:119`), so it cannot use `mandate-types` — where `AuthorizationCodeId`, `PkceChallenge`, `CredentialProof`, `VerifiedContext` and `AuthorityScope` live — until the coordinator admits the `mandate-*` crates to that allowlist (no count changes) or adds a `libraries` key (breaks `xtask/src/main.rs:104`'s 14 and needs an `xtask` edit). And `services/sts/Cargo.toml` needs a `[lib]` target before `tests/*.rs` can import anything; no service package has one. Beyond those: the "actual OAuth endpoint" in the Acceptance is blocked by the `serve` assertion at `xtask/src/main.rs:259-272`; HTTP, async and a database are absent from `Cargo.lock`; and "actual federation/session/STS adapters" do not exist. This story ends its first wave `active`.

## Deliverable now, behind ports

The transaction logic and all seven cases as deterministic tests against an in-memory fake store: the one-winner race as a single-process compare-and-set conflict on the fake's expected-version append — two candidates, one `Ok`, one version conflict, one credential; crash-boundary coverage as injected failure points around the append — no consumed-without-issued, no issued-without-audit; the denial path writing through `RecordAuditEvent` outside the transaction.

## Units

| Unit | Owns | Test file | ESS command | Cases |
|---|---|---|---|---|
| U1 `store` | `services/sts/src/store.rs` | `services/sts/tests/store.rs` | — the event-log port trait and its `pub` in-memory fake (CAS on expected version) | none directly; supplies U4's conflict injection |
| U2 `code` | `src/code.rs` | `tests/code.rs` | `IssueAuthorizationCode` (`credential.yaml:349`) | `pkce-plain`, `pkce-missing`, `pkce-wrong` |
| U3 `binding` | `src/binding.rs` | `tests/binding.rs` | the client/redirect/epoch/state-nonce re-reads inside redemption | `pkce-redirect`, `pkce-state-nonce` |
| U4 `redemption` | `src/redemption.rs` | `tests/redemption.rs` | `RedeemAuthorizationCode` (`credential.yaml:183`) | `pkce-valid`, `pkce-reuse` |
| U5 `audit` | `src/audit.rs` | `tests/audit.rs` | `RecordAuditEvent` (`audit.yaml:113`), rejection path only | every case's no-secret and denial-audit assertions |
| coordinator | `src/lib.rs`, `src/main.rs`, `services/sts/Cargo.toml` | `tests/surface.rs`, `tests/cli.rs` | — | `serve` still fails via `env!("CARGO_BIN_EXE_mandate-sts")` |

The fake store is a `pub` item in `src/store.rs`, not a `tests/common/mod.rs`, which would put one file in six rows. `AuthorizePublicClient` is named by all seven cases but is control-plane-owned (`ownership.md:26`); this story stands in for it with a fixture.

## Records

`AuthorizationCode` is a projection of this service's fold under `docs/adr/0009-event-sourced-persistence.md`, declared in `src/store.rs`. **`AccessCredential` and its `State` enum are declared once, in `crates/mandate-token/src/projection.rs` by `story:credential-profiles`**, which this story `depends_on`; `src/store.rs` consumes that type and declares no second copy. `ownership.md:15`'s assignment of these records to `mandate-model` predates the ADR and is revised by `story:domain-runtime`'s coordinator row.

## Case ids

`pkce-valid`, `pkce-wrong`, `pkce-missing`, `pkce-plain`, `pkce-reuse`, `pkce-redirect`, `pkce-state-nonce`. The corpus stays `contract-scenario` (`xtask/src/main.rs:172-174`); implementing them as tests does not change the file.

## Decisions that apply

`decision-blocker:epoch-atomicity` (one event-log transaction; the fake's CAS is its shape); `decision-blocker:guards` (denial through `RecordAuditEvent`, outside the refused transaction); `docs/adr/0009-event-sourced-persistence.md`. Open and blocking U5: the audit category for the redemption outbox record — `audit-routing.md:9-26` has no row for code redemption and the `AuditAction`/`AuditOutcome` vocabulary is unspecified (`:28`); that is `decision-blocker:audit-routing`.

## Dependency ceiling

Today `clap`, `serde_json`, `sha2`. After the coordinator's admission: additionally `mandate-types`, `mandate-model`, `mandate-token`. No HTTP framework, no async runtime, no database driver. A unit may not edit `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` or `xtask/`.

## Exclusions

`crates/mandate-server`. Any HTTP route. A `serve` subcommand. `AuthorizePublicClient`. Form encoding and standard OAuth error bodies. `tests/security/cases.json`. `#[ignore]`.

## Gate per unit

`cargo fmt -p mandate-sts -- --check`; `cargo clippy -p mandate-sts --all-targets --locked -- -D warnings`; `cargo test -p mandate-sts --locked`, count reported.

## Scope

- `services/sts/src/main.rs`, `services/sts/Cargo.toml` — cited; the package's two files today; coordinator.
- `services/sts/src/lib.rs`, `store.rs`, `code.rs`, `binding.rs`, `redemption.rs`, `audit.rs` — inferred; do not exist.
- `services/sts/tests/surface.rs`, `store.rs`, `code.rs`, `binding.rs`, `redemption.rs`, `audit.rs`, `cli.rs` — inferred; do not exist.
- Removed: `crates/mandate-server`.
- Not written, prerequisite: `dependency-boundaries.json`, `Cargo.toml`, `Cargo.lock`, `xtask/src/main.rs` — coordinator.
- Would collide with: `story:constrained-exchange` and `story:credential-profiles`, both holding `services/sts` as cited scope; the file split between them is settled when they are refined.

## Contract

`systems/mandate/ess-inputs.yaml`; `docs/architecture/combined.md`; `task check` and named runtime suites.

## Atomic redemption ownership

Consume the non-consuming validation candidate from pkce-sessions, then re-read/revalidate current code, session/epoch, client, redirect and target inside the authoritative STS transaction. Code consumption, credential creation and audit outbox must commit together or all roll back. Race two valid candidates: exactly one transaction may issue, and crash/retry at every commit boundary must not leave consumed-without-issued or issued-without-audit state. Source: docs/architecture/ownership.md:28; docs/architecture/unmapped.md:25.

## Inherited from wave A, 2026-09-19

- From wave A (2026-09-19): `mandate.credential.RedeemAuthorizationCode`'s `wrong-state` outcome (a consumed code) is this story's to realize with the redemption handler at STS; `AuthorizePublicClient` in `mandate-federation` refuses a consumed code with `denied`, as its contract declares.
