---
format: aep.planning-md/1
id: story:product-listener
kind: story
status: draft
title: Serve the product routes and replace the serve refusal
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:protocol-adapters
- depends_on: story:pkce-sessions
- depends_on: story:federation-linking
- depends_on: story:signing-and-verification
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: inferred
  path: crates/mandate-federation/src/adapters.rs
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-federation/tests/adapters.rs
- confidence: cited
  path: deny.toml
- confidence: cited
  path: dependency-boundaries.json
- confidence: cited
  path: services/sts/src/lib.rs
- confidence: cited
  path: services/sts/src/main.rs
- confidence: inferred
  path: services/sts/src/serve.rs
- confidence: inferred
  path: services/sts/tests/serve.rs
- confidence: cited
  path: xtask/src/main.rs
revision: 6
---
# Serve the product routes

## Acceptance

Given the route table `story:protocol-adapters` declares, when a client requests any generated `/<domain>/commands/<Command>` path against a running `mandate-sts`, then it is refused and the served metadata document lists only product routes.

## Required observations

Moved here from `story:protocol-adapters`: a listener behind the route table; the served RFC 8414 metadata document; JWKS key material. The `serve` refusal at `xtask/src/main.rs:259-273` replaced with per-binary milestone checks that keep refusal coverage for still-unimplemented commands — coordinator work under `task:runtime-wave-integration`. An HTTP framework and an async runtime admitted to the service packages. The registered-client port `story:pkce-sessions` declares in `mandate-identity` implemented over `story:federation-linking`'s `OAuthClient` projection.

## Why a separate story

Every item above is blocked by fact 1 (the `serve` assertion) or by a dependency the policy forbids. `story:protocol-adapters` and `story:oauth-integration` deliver their logic as libraries under test; this story binds them to transport.

## Units

Credential issuance over HTTP is `story:oauth-integration`'s acceptance, which `depends_on` this story; this story proves the listener and the surface, not the transaction. The coordinator adds `pub mod adapters;` to `crates/mandate-federation/src/lib.rs` and `mod serve;` to `services/sts/src/lib.rs`, and performs the transport admission; both are ordered after `story:signing-and-verification` and `story:credential-profiles` by edge.

| Unit | Owns | Test file | Lands |
|---|---|---|---|
| coordinator, first | `crates/mandate-federation/src/lib.rs`; `services/sts/src/lib.rs`; `services/sts/src/main.rs`; `xtask/src/main.rs`; `Cargo.toml`; `Cargo.lock`; `dependency-boundaries.json`; `deny.toml` | — | the two `mod` lines; the `serve` milestone checks; the transport dependency |
| `listener` | `services/sts/src/serve.rs` | `services/sts/tests/serve.rs` | the listener over the route table; the metadata document served; the generated paths refused |
| `port-adapters` | `crates/mandate-federation/src/adapters.rs` | `crates/mandate-federation/tests/adapters.rs` | `impl` of the identity-declared registered-client port over the federation records |

## Scope

- `services/sts/src/serve.rs`, `tests/serve.rs`; `crates/mandate-federation/src/adapters.rs`, `tests/adapters.rs` — inferred; do not exist.
- `services/sts/src/main.rs`, `xtask/src/main.rs` — cited; coordinator.

## Validation and contract

`task check` on the merged head with the replaced `serve` checks; the seven `pkce-*` cases executed over HTTP, counts reported. Blocked on `decision-blocker:guards`.
