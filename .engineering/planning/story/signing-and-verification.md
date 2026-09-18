---
format: aep.planning-md/1
id: story:signing-and-verification
kind: story
status: draft
title: Real signature verification and signing behind the port seams
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:credential-profiles
- informed_by: feature-design:federated-login
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: inferred
  path: crates/mandate-federation/tests/verifier_real.rs
- confidence: cited
  path: crates/mandate-token/src/lib.rs
- confidence: inferred
  path: crates/mandate-token/src/signing_real.rs
- confidence: inferred
  path: crates/mandate-token/tests/signing_real.rs
- confidence: cited
  path: deny.toml
- confidence: cited
  path: dependency-boundaries.json
revision: 6
---
# Real signature verification and signing

## Acceptance

Given a customer IdP token signed under an admitted algorithm and a published JWKS, when `mandate-federation` verifies it through the real verifier behind the `verifier-port` seam, then the eight federation cases pass with no test double in the chain.

## Required observations

Moved here from `story:federation-linking`, exactly as its moved-to sentence names them: signature verification, OIDC discovery/JWKS caching and key rollover. Moved here from `story:credential-profiles`, exactly as its moved-to sentence names them: signing, asymmetric authentication, key rotation and expiry. Additionally, from `runtime-decisions.md:276-282`: a token whose header names a non-admitted algorithm is refused regardless of signature validity, and `none` is refused; `kid` overlap across a rotation window; an exercised emergency revocation path. Issuer and client-binding verification stay with `story:federation-linking`.

## Why a separate story

`dependency-boundaries.json:35-40` admits no external crate to `mandate-federation`, `:34-38` none to `mandate-token`, and `Cargo.lock` holds no JOSE library or asymmetric primitive. Admitting one is the dependency decision recorded as pending in `task:runtime-wave-integration`; until it lands, the two parent stories deliver their acceptances behind `pub` test doubles and this story is blocked.

## Units

The coordinator adds one `pub mod` line to each crate root — `crates/mandate-federation/src/lib.rs`, `crates/mandate-token/src/lib.rs` — and performs the dependency admission in `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml`. `story:product-listener` `depends_on` this story, so its later `mod adapters;` line on the federation root and its own root-config edits are ordered after these.

| Unit | Owns | Test file | Lands |
|---|---|---|---|
| coordinator, first | `crates/mandate-federation/src/lib.rs`; `crates/mandate-token/src/lib.rs`; `Cargo.toml`; `Cargo.lock`; `dependency-boundaries.json`; `deny.toml` | — | the two `pub mod` lines; the admitted crate |
| `federation-verifier` | `crates/mandate-federation/src/verifier_real.rs` | `crates/mandate-federation/tests/verifier_real.rs` | the `FederationVerifier` implementation over the admitted crate; discovery; JWKS cache; rollover; header-algorithm and `none` refusal |
| `token-signer` | `crates/mandate-token/src/signing_real.rs` | `crates/mandate-token/tests/signing_real.rs` | the signing port implementation; `kid`; rotation window; emergency revocation |

## Scope

- `crates/mandate-federation/src/verifier_real.rs`, `tests/verifier_real.rs` — inferred; do not exist.
- `crates/mandate-token/src/signing_real.rs`, `tests/signing_real.rs` — inferred; do not exist.
- `Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml` — coordinator, under `task:runtime-wave-integration`.

## Validation and contract

`cargo test -p mandate-federation -p mandate-token --locked`, counts reported; the parents' suites unchanged. Blocked on `decision-blocker:algorithm-policy` for the list and on the dependency decision for the crate.
