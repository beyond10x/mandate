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
revision: 8
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

## Coordinator rulings at wave opening, 2026-09-19

- Dependency decision (operator, 2026-09-18, recorded here as the pending decision `task:runtime-wave-integration` named): `jsonwebtoken` (major 10, `default-features = false`, feature `rust_crypto`, so the primitives are the pure-Rust `rsa`/`p256`/`sha2`/`hmac` crates under MIT/Apache rather than `ring`), `ureq` (major 3, TLS backend chosen by `cargo deny` against the allowlist as it stands; if no backend fits, the coordinator decides on the one license it would add). Dev-dependencies for test keys generated at test time: `rand`; no private key of any kind is committed (runtime-decisions §9 evidence row). Boundaries: `mandate-federation` += `jsonwebtoken`, `ureq`, `serde_json`; `mandate-token` += `jsonwebtoken`.
- Allowlist (operator, 2026-09-18, `approval` evidence on `decision-blocker:algorithm-policy`): RS256 and ES256, deployment-configured and validated at startup; an unknown name, an empty list, a header-selected algorithm and `none` are refused. The blocker clears at this wave's close on the runtime cases §9 lists: refusal at issuance and at validation, header algorithm refused regardless of signature, every verification item of the original design's list (not signature alone), `kid` overlap across a rotation window, an exercised emergency revocation, no private key in source or config.
- Network stays behind a port: `verifier_real.rs` defines a `JwksSource` (discovery document and JWKS by issuer) with an in-memory implementation the tests drive and a `ureq` implementation exercised only against a local listener the test owns; no test reaches the network.
- Files: `crates/mandate-federation/src/verifier_real.rs` and `crates/mandate-token/src/signing_real.rs` are pre-landed as stub modules with their `pub mod` lines in the opening commit, so neither unit touches a crate root; `crates/mandate-federation/src/lib.rs` belongs to `story:federation-identity-alignment` in this wave (its `pub mod disable;` and `realizes!` registrations); `crates/mandate-token/src/lib.rs` is touched by nobody after the opening commit. The `FederationVerifier` trait at `lib.rs:242` is the seam the real verifier implements; if the seam's signature cannot carry what verification needs, the unit reports rather than editing the root.

## Coordinator rulings after critic round 1, 2026-09-19

- Shared test files (parallel PS1): `crates/mandate-federation/tests/link.rs` and `tests/authenticate.rs` are `story:federation-identity-alignment`'s this wave. The verifier unit delivers the acceptance in `tests/verifier_real.rs`: the eight federation cases (issuer-isolation, email-isolation, explicit-link, link-conflict, tenant-valid, tenant-zero, tenant-ambiguous, tenant-unverified) re-expressed over the real verifier with test-time keys, no double in the chain. Replacing the double in the two existing files is a follow-on after both units merge (a coordinator alignment commit if mechanical, else the next wave), recorded here.
- The signing port (parallel PS2, design D1): `token-signer` declares `pub trait CredentialSigner` inside `signing_real.rs` — sign a claims set under an admitted algorithm with a selected `kid`, expose the active and overlapping keys of a rotation window, and revoke a key on the emergency path — and implements it there over `jsonwebtoken`; the crate root stays untouched, `pub mod signing_real;` exposes it. `story:credential-profiles`' `signing` row is superseded: it consumes this port (recorded on that story).
- Issuance-side refusal (design D5): the signer refuses an unconfigured algorithm at construction and at `sign`, so the "refusal at issuance" case of `decision-blocker:algorithm-policy` is this unit's, without STS; the validation-side refusals are the verifier unit's. Both land in this wave; the blocker clears at its close.
- Seam (parallel item 3): `FederationVerifier::verify(&self, &FederationConnection, &CredentialProof) -> Result<VerifiedProof, Denied>` is the seam; the real verifier is constructed with its `JwksSource`, allowlist and clock, so `verify` needs nothing more. If the unit finds otherwise it reports; merge order is alignment first, then the verifier, then the signer, then model-agreement, and a coordinator commit lands any seam change between the first two.
- `ureq` TLS backend and `jsonwebtoken` features (parallel item 4) are decided in the opening commit by measurement against `deny.toml`; the values are recorded on the wave page when the pre-lands land.
