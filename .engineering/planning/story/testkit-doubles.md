---
format: aep.planning-md/1
id: story:testkit-doubles
kind: story
status: draft
title: Test doubles live in mandate-testkit, not in library crates
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:session-epochs
- depends_on: story:graph-policy
revision: 1
---
# Test doubles live in mandate-testkit, not in library crates

## Acceptance

Given the workspace after wave 2, when `cargo doc` is read for `mandate-federation`, `mandate-identity`, `mandate-graph` and `mandate-policy`, then no type that admits every proof, seeds a fold around its guards, or records instead of issuing is exported by a library crate; each lives in `crates/mandate-testkit` and reaches the library crates' integration tests through a dev-dependency.

## Required observations

Filed from the wave-2 adversary passes, 2026-09-18. Integration tests are separate crates, so every double a story needed was made `pub` in the library: `mandate-federation` exports `ConstructedVerifier::admitting` (admits every proof, no cryptography), `SequentialAllocator`, `RecordingSessionIssuer`, `RecordedPrincipals` (`review-result:wave2-federation-linking-adversary-2` J3); `mandate-identity` exports `IdentityLog` with its seeding constructors behind `#[doc(hidden)]`, which removes them from rustdoc and not from the API (`review-result:wave2-session-epochs-adversary-2` F3); `mandate-graph` and `mandate-policy` export `GraphDouble` and `PolicyDouble` by the story's own design. Nothing in the gate distinguishes them from shippable code: `cargo xtask boundaries` checks dependencies, not exports. The coordinator ruled in both waves that the doubles stay `pub` until a home exists; this story is that home.

`crates/mandate-testkit` exists in the workspace (`Cargo.toml` members) and has no consumers. Adding it as a dev-dependency of the four crates touches `dependency-boundaries.json` (`xtask/src/main.rs:117-127` enforces the ceiling on dev-dependencies too), so the boundary edit is this story's and no other's.

## Scope

- `crates/mandate-testkit/src/**` — the doubles, moved.
- `crates/mandate-federation/src/{verifier,lib}.rs`, `crates/mandate-identity/src/port.rs`, `crates/mandate-graph/src/double.rs`, `crates/mandate-policy/src/double.rs` — exports removed; inferred from the adversary reports.
- `crates/{mandate-federation,mandate-identity,mandate-graph,mandate-policy}/Cargo.toml` — `[dev-dependencies] mandate-testkit`.
- `dependency-boundaries.json` — the four dev edges.
- `crates/*/tests/**` of the four crates — imports.

## Exclusions

No behaviour change in any double. No new double. `mandate-model`'s `Tenancy`/`Topology` are folds, not doubles, and stay.
