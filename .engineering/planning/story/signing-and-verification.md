---
format: aep.planning-md/1
id: story:signing-and-verification
kind: story
status: implemented
title: Real signature verification and signing behind the port seams
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federation-linking
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
revision: 16
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

## Coordinator rulings after signer adversary pass 1, 2026-09-19

- Claims envelope (signer A1-1, A1-2): the standard claims are the signer's alone. The caller's value is serialized to a JSON map first; a key among `iss sub aud exp nbf iat jti` (exact, and any case variant) is refused with a named error; the envelope is written as one map with no duplicate key, and a case decodes every emitted token with `jsonwebtoken` against the published key. `serde_json` becomes a regular dependency of `mandate-token` (the boundaries already admit it; the unit makes that one manifest edit and the coordinator accepts it at merge).
- Revocation is permanent (signer A1-3): `revoke` records a tombstone by `kid` and by the public key's fingerprint; `new` and `rotate` refuse a tombstoned `kid` or material with a named error for the signer's lifetime. Persisting tombstones across restarts is `story:credential-profiles`' with the `SigningKey` record.
- Window invariant (signer A1-4): a key stays published until every credential it signed has expired, so `RealSigner::new` refuses `overlap_seconds < ttl_seconds` with a named error; the invariant is the signer's, not the deployment's.
- PEM and DER strictness (A1-5, A1-6, J3): a non-map caller value is refused as documented; DER with trailing bytes is refused; the PEM label must match the family and a file with more than one block is refused.

## Coordinator rulings after verifier adversary pass 1, 2026-09-19

- HTTPS (verifier A1-1): `UreqJwks::new()` selects the native TLS provider explicitly (`ureq`'s `native-tls-no-default` compiles it without making it the default and without a bundled root set; the host store supplies roots); an https issuer never panics. If the feature cannot select the provider, the coordinator changes the feature against `cargo deny`, not the unit.
- Absence is not verification (A1-2): for a claim whose companion OIDC defines (`email_verified` for `email`, `phone_number_verified` for `phone_number`), an absent or non-`true` companion means the claim is not verified; other claims are issuer-asserted as signed. The `tenant-unverified` contract case holds on absence; the `tenant_valid` fixture supplies `email_verified: true`. Trust assumption recorded: the companion is IdP-controlled, so a lax IdP can promote a claim; that is the customer's IdP policy, not this verifier's.
- JWKS destination is bounded (A1-3): the `jwks_uri` is parsed, not prefix-matched; userinfo, a non-https scheme (loopback http only through the test constructor), a literal IP or `localhost` host are refused; the host must equal the issuer's host or be one the deployment lists for that connection (`RealVerifier::configure_connection` carries the allowed JWKS hosts beside the algorithm; some IdPs publish keys off a second host); the path is unconstrained on an allowed host.
- Cache (A1-4, A1-5, A1-9): an unknown `kid` refetches at most once per issuer per refetch interval (negative cache); the mutex is released across the source call; `RealVerifier::forget(&self, issuer)` drops an issuer's cached set at once for the emergency path, beside the max age.
- Audience (A1-6): a list `aud` naming a party other than this client is refused unless `azp` names this client (OIDC Core 3.1.3.7). `crit` present is refused (A1-7). `sub` is bounded at 255 bytes (A1-8, the OIDC limit). The shipped `UreqJwks::new()` configuration is exercised by a case (A1-10). `typ: at+jwt` stays refused (A1-11): the proof is an ID token.

## Coordinator rulings after signer adversary pass 2, 2026-09-19

- Window boundary (signer A2-1, A2-2): a windowed key stays published and its `kid` reserved through the instant of `exp` of the last credential it could have signed: `drops_at = rotated_at + overlap + 1` with `retain(drops_at > now)`, so at `now == exp` the key is still published and the `kid` not free; the unit's own boundary assertion follows the rule.
- Material identity (A2-3, A2-4): `rotate` refuses material the signer already holds (thumbprint comparison beside the `kid` check); `revoke` drops every holding whose thumbprint matches the tombstone, not only the matching `kid`; a repeated revoke answers `RevokedKey` (A2-5).
- Caller map bound (A2-7): the caller's claims map is bounded (256 keys, 64 KiB serialized) with a named refusal; documented.
- Correction of the wave-opening ruling text (A2-6): the dependency landed as `jsonwebtoken` over `aws_lc_rs` (RS256 and ES256, constant-time; the pure-Rust `rsa` path carries RUSTSEC-2023-0071), with `ISC` and `BSD-3-Clause` admitted — the `rust_crypto` sentence in the opening ruling is superseded by the opening commit and the wave page's deviation 1.

## Coordinator rulings after verifier correction round 1, 2026-09-19

- TLS provider (verifier correction 1): `ureq`'s `native-tls-no-default` compiles the provider without letting an agent select it (`TlsProvider::NativeTls` is `cfg!(feature = "native-tls")`), so the manifest takes `native-tls`, which carries `webpki-root-certs 1.0.9` (CDLA-Permissive-2.0, a data license for the Mozilla root store; compiled and unused, the platform verifier is selected). `deny.toml` admits `CDLA-Permissive-2.0`; the unit made both edits and the coordinator accepts them at merge; the lock gains one crate (225 resolved).
- Two divergences from the pass-1 ruling, accepted as implemented: plaintext is admitted only for a loopback *host* (in both constructors), because the shipped `UreqJwks::new()` must be exercised against a loopback listener; the allowed JWKS hosts sit beside the algorithm in the per-connection record through `RealVerifier::allowing_jwks_hosts` (the `configure_connection` shape unchanged); `JwksSource::jwks_from(issuer, allowed_hosts)` is a defaulted port method. Also added: `with_max_proof_lifetime` (24 h ahead bound on `exp`).

## Coordinator rulings after verifier adversary pass 2, 2026-09-19

- Negative cache is a rate bound (verifier A2-1): the unknown-`kid` refetch is one per issuer per interval whatever the rate — a per-issuer in-flight marker under the lock, and a re-check of `missed_at` after the read before folding the result.
- Destination rule edges (A2-2, A2-3, A2-4): both arms compare (host, port) with the scheme's default port normalized; a listed host admits only the listed port (default if none listed); the loopback guard refuses by name class (`localhost` with any trailing dot, any `*.localdomain`, every address literal). `azp` present and not a string is refused; the untrusted-audience test is membership, not count (A2-5, A2-6).
- No environment proxy (J1): the shipped configuration sets `proxy(None)`; the JWKS fetch goes where `allowing_jwks_hosts` says and nowhere else. An explicit egress proxy is a later deployment option, documented as absent.
- Replay of a captured ID token (J2) is the login flow's defence (the relying party's `nonce`/`state` and one-time redemption), which the verify seam cannot carry; recorded on `feature-design:federated-login` for the served-route story.
