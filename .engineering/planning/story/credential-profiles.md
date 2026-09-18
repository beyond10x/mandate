---
format: aep.planning-md/1
id: story:credential-profiles
kind: story
status: draft
title: Implement audience registry and both credential families
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- depends_on: story:audit-client
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-token/src/algorithm.rs
- confidence: cited
  path: crates/mandate-token/src/lib.rs
- confidence: inferred
  path: crates/mandate-token/src/projection.rs
- confidence: inferred
  path: crates/mandate-token/src/signing.rs
- confidence: inferred
  path: crates/mandate-token/src/verifier.rs
- confidence: inferred
  path: crates/mandate-token/tests/algorithm.rs
- confidence: cited
  path: crates/mandate-token/tests/conformance.rs
- confidence: inferred
  path: crates/mandate-token/tests/projection.rs
- confidence: inferred
  path: crates/mandate-token/tests/signing.rs
- confidence: inferred
  path: crates/mandate-token/tests/verifier.rs
- confidence: inferred
  path: crates/mandate-types/src/inventory.rs
- confidence: inferred
  path: crates/mandate-types/tests/inventory.rs
- confidence: cited
  path: services/sts/Cargo.toml
- confidence: inferred
  path: services/sts/src/issue.rs
- confidence: inferred
  path: services/sts/src/lib.rs
- confidence: inferred
  path: services/sts/src/registry.rs
- confidence: inferred
  path: services/sts/src/resolve.rs
- confidence: inferred
  path: services/sts/tests/corpus.rs
- confidence: inferred
  path: services/sts/tests/issue.rs
- confidence: inferred
  path: services/sts/tests/registry.rs
- confidence: inferred
  path: services/sts/tests/resolve.rs
revision: 8
---
# Implement audience registry and both credential families

## Acceptance

Given a newly issued reference credential under ImmediateOnline, when it is revoked, then its next authorized introspection reports inactive even if an earlier resolution was cached.

## Required observations

Registered enabled organization-scoped targets and allowed sources required; signed/reference profiles meet declared TTL/cache guarantees; persistence contains verifier only. All credential corpus cases pass; introspection callers authorized. Moved to `story:signing-and-verification`: signing, asymmetric authentication, key rotation and expiry.

## Deliverable this wave, and the follow-on

The acceptance is the `resolve` unit's revoke-then-introspect against the `signing` unit's `pub` double, with the five corpus cases executing under `cargo test -p mandate-token -p mandate-sts`; on that evidence the story moves to `implemented`. Real signing, asymmetric authentication and rotation need a cryptographic library `Cargo.lock` lacks and `dependency-boundaries.json:34-38` forbids; those Required observations belong to `story:signing-and-verification`, which `depends_on` this story and attaches at the signing port. `services/sts` needs a `[lib]` target and the `mandate-*` crates admitted to its allowlist before any of its units compile; the coordinator's interface commit for this story's wave performs both, under the authority `task:runtime-wave-integration` records.

## Projections are forced into `mandate-token`

`ResourceServer.credential_profile` is `mandate.core.CredentialProfile` and `AccessCredential.descriptor` is `mandate.core.CredentialDescriptor`; both are declared in `crates/mandate-token/src/lib.rs:138,61`, and `mandate-model` may depend only on `mandate-types`, `serde`, `serde_json` (`dependency-boundaries.json:9-14`). `ownership.md:15`'s assignment of "registry/credential/code records" to `mandate-model` cannot compile; under `docs/adr/0009-event-sourced-persistence.md` the projections belong to the folding crate in any case. `SigningKey` follows by cohesion. **`AccessCredential` and its `State` enum are declared here and nowhere else**; `story:oauth-integration` consumes them from this crate. None enters `ACCEPTED` (`crates/mandate-types/tests/inventory.rs:50-65`) or `conformance::entries()` (`crates/mandate-token/tests/conformance.rs:71` asserts 2); entity projections get their own registry checked against `generated/schema/entities`.

## Units

Two coordinator interface commits — one per crate root — then the units. `crates/mandate-token/src/lib.rs` and `services/sts/src/lib.rs` are coordinator-owned; the latter is shared with `story:oauth-integration` and `story:constrained-exchange`, both `depends_on` this story, so the coordinator seeds their `mod code;` and `mod exchange;` lines when their waves come.

| Unit | Owns | Test file | Lands | ESS commands |
|---|---|---|---|---|
| coordinator, first | `crates/mandate-token/src/lib.rs`; `services/sts/src/lib.rs`; `services/sts/Cargo.toml` | `crates/mandate-token/tests/conformance.rs`; `services/sts/tests/corpus.rs` | `mod` lines and stubs; the `[lib]` target and dependency admission; the projection registry against `generated/schema/entities`; the five corpus cases end to end once the units land | — |
| `projection` | `crates/mandate-token/src/projection.rs` | `tests/projection.rs` | `ResourceServer`, `AccessCredential`, `SigningKey` and their `State` enums; the `(organization_id, audience)` conflict path returning the declared denial | — |
| `algorithm` | `crates/mandate-token/src/algorithm.rs` | `tests/algorithm.rs` | the allowlist shape: startup validation, reject unknown, empty, header-selected, `none`; takes the list as a constructor argument and names no algorithm | — |
| `signing` | `crates/mandate-token/src/signing.rs` | `tests/signing.rs` | the signing and verification port, `kid`, the rotation window, the `pub` double | — |
| `verifier` | `crates/mandate-token/src/verifier.rs` | `tests/verifier.rs` | the non-reversible reference verifier as a port with the digest supplied by the caller — `mandate-token` has no `sha2`; `services/sts` has — and constant-time comparison | — |
| `registry` | `services/sts/src/registry.rs` | `services/sts/tests/registry.rs` | audience registry administration | `RegisterResourceServer` (`credential.yaml:216`), `DisableResourceServer` (`:147`) |
| `issue` | `services/sts/src/issue.rs` | `services/sts/tests/issue.rs` | both credential families | `IssueReferenceCredential` (`:239`), `IssueSelfContainedCredential` (`:266`) |
| `resolve` | `services/sts/src/resolve.rs` | `services/sts/tests/resolve.rs` | introspection and revocation; the acceptance's revoke-then-introspect | `IntrospectCredential` (`:325`), `RevokeAccessCredential` (`:165`) |

## Case ids

`reference-persistence`, `reference-revoked`, `reference-audience`, `reference-expired`, `profile-offline-bound`; each names `IssueReferenceCredential`, `IntrospectCredential` and `mandate.authorization.Check`. The `Check` half is `story:check-api`'s port.

## Decisions that apply

`decision-blocker:algorithm-policy` — the shape, not the list; `runtime-decisions.md:276` still wants the approved list recorded by an authority. `decision-blocker:identity-uniqueness` — audiences unique within an organization; the `projection` unit proves the single-writer conflict path. `docs/adr/0009-event-sourced-persistence.md`.

## Dependency ceiling

`mandate-token`: `mandate-types`, `serde`, `serde_json`, nothing else — no `sha2`. `services/sts`: after the coordinator's admission `clap`, `serde_json`, `sha2`, `mandate-types`, `mandate-model`, `mandate-token`. A unit may not edit `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json` or `xtask/`.

## Exclusions

`services/sts/src/main.rs` — the stub stays a stub. `IssueAuthorizationCode`, `RedeemAuthorizationCode` (`story:oauth-integration`), `ExchangeCredential` (`story:constrained-exchange`). Real cryptography (`story:signing-and-verification`). Any edit to `crates/mandate-types` except through the coordinator: three `EXCLUDED_SEMANTICS` entries at `src/inventory.rs:493-495` describe what this story begins, and `tests/inventory.rs:159` asserts at least 6 of 7; the coordinator rewrites the three reasons rather than dropping them. `#[ignore]`.

## Gate per unit

`cargo fmt -p mandate-token -p mandate-sts -- --check`; `cargo clippy -p mandate-token -p mandate-sts --all-targets --locked -- -D warnings`; `cargo test -p mandate-token -p mandate-sts --locked`, counts reported; the two wave-1 `mandate-token` suites still execute unchanged.

## Scope

- `crates/mandate-token/src/lib.rs`, `crates/mandate-token/tests/conformance.rs` — cited; coordinator.
- `crates/mandate-token/src/projection.rs`, `algorithm.rs`, `signing.rs`, `verifier.rs`; `tests/projection.rs`, `algorithm.rs`, `signing.rs`, `verifier.rs` — inferred; do not exist.
- `services/sts/Cargo.toml` — cited; coordinator.
- `services/sts/src/lib.rs`, `registry.rs`, `issue.rs`, `resolve.rs`; `tests/corpus.rs`, `registry.rs`, `issue.rs`, `resolve.rs` — inferred; do not exist.
- `crates/mandate-types/src/inventory.rs`, `crates/mandate-types/tests/inventory.rs` — inferred; coordinator; the exclusion reasons; sequential with `story:domain-runtime` by a four-edge chain.
- Would collide with: any unit touching either crate root; `story:domain-runtime` on the two inventory files; `story:oauth-integration` and `story:constrained-exchange` on `services/sts/src/lib.rs`, all sequential by edge.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
