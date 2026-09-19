# Wave A (auth flow, 1 of n): real verification and signing, federation and identity aligned with the contract

Integration branch `integration/wave-20260919-002`, cut from `c04dba5` (the closing store commit of wave E1; tree equal to `main` `79cb71a`). Coordinator: this session; every sub-agent runs on Opus.

## Why this wave

The customer use case is a federated login: a principal authenticated on the customer's platform is logged in on ours. Waves E2–E4 of the drift-protection programme are deferred behind it (operator, 2026-09-19). The path to it, in order: a real verifier and signer behind the port seams (`story:signing-and-verification`), federation and identity handlers that agree with the contract and open a Session from `FederationAuthenticated` (`story:federation-identity-alignment`), then credential profiles at STS, the served route, and the OAuth integration.

## Selection

| Story | Units | Crates | Agents |
|---|---|---|---|
| `story:signing-and-verification` | `federation-verifier`, `token-signer` | `mandate-federation` (`verifier_real.rs`), `mandate-token` (`signing_real.rs`) | 2 |
| `story:federation-identity-alignment` | four, serially | `mandate-federation` (`record.rs`, `disable.rs`, `lib.rs`, tests), `mandate-identity` | 1 |
| `story:model-agreement` | `model`, `types` | `mandate-model` tests + `lib.rs`, `mandate-types/tests/conformance.rs` | 1 |

Collision resolved before dispatch: `crates/mandate-federation/src/lib.rs` is `federation-identity-alignment`'s; the opening commit pre-lands `pub mod verifier_real;` and `pub mod signing_real;` over stubs so the verifier and signer units touch no crate root.

## Coordinator pre-lands (opening commit)

- `jsonwebtoken` 10 (`rust_crypto`), `ureq` 3, dev `rand`; `deny.toml`; `dependency-boundaries.json`; stub modules with their `pub mod` lines; dev-dependencies `mandate-contract` and `mandate-testkit` on `mandate-federation`, `mandate-identity`, `mandate-model`, `mandate-types`.
- Rulings recorded on the three stories; critic panel over the set before dispatch.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`: this opening commit; one commit per unit; one `--no-ff` merge per unit; coordinator alignment commits if regeneration or a ruling moves a pinned value; the closing store commit; publication; the PR to `main` and its App merge. No tag.

## Preflight

| Check | Reading |
|---|---|
| `df -h /` | 80 GB free at opening |
| base | `c04dba5`, tree equal to `main` |

## Stage log

- Opening: tree cut; rulings on the three stories; pre-land implementor dispatched.
- Critic panel round 1: parallel-safety `needs-revision` (2: shared federation test files; no signing port), design `needs-revision` (5: the signing port, two owners of the signing surface, the Session-from-login seam across the crate direction, `authorize.rs` excluded yet needed, issuance-side refusal not carried). Rulings on the four stories: alignment owns `tests/link.rs`/`tests/authenticate.rs` and the verifier proves the eight cases in `tests/verifier_real.rs`; `token-signer` declares `CredentialSigner` in `signing_real.rs` (credential-profiles consumes it); the identity fold opens the Session from `mandate_contract`'s generated `FederationAuthenticated` payload (`mandate-contract` admitted for `mandate-identity`), keeping the crate direction; `authorize.rs` and its two tests join alignment's scope; `mandate-types` inventory files join model-agreement's. Outcomes recorded `fixed`; no second round — each fix is a ruling, a scope line or a pre-land.

## Declared deviations

1. `deny.toml` allowlist widened by two tokens, `BSD-3-Clause` and `ISC`, for `jsonwebtoken 10.4.0` over `aws_lc_rs`: `aws-lc-rs 1.18.1` (ISC AND (Apache-2.0 OR ISC)), `aws-lc-sys 0.45.0` (a conjunction over ISC, Apache-2.0, MIT, BSD-3-Clause), `untrusted 0.7.1` (ISC). The pure-Rust path was measured and refused: `rsa 0.9.10` carries RUSTSEC-2023-0071 (Marvin timing attack, no fix) and selecting `p256`/`sha2`/`rand` without the `rust_crypto` umbrella installs no crypto provider at all (panics at the first verify). `aws-lc-sys` builds with a C compiler alone here (cmake declared, not invoked; pre-generated bindings); `ubuntu-latest` carries the toolchain, a claim about the runner image until CI runs. RS256 and ES256 both verify, measured.
2. `ureq 3.4.2` with `native-tls-no-default`: the only TLS feature inside the allowlist (`rustls*` pull ISC via `rustls-webpki`/`ring`; the bundled root sets are CDLA-Permissive-2.0). Consequence: HTTPS links system OpenSSL through `openssl-sys` and trusts the host store, not a bundled root set. Recorded here; the JWKS fetch is behind the `JwksSource` port and no test reaches the network.
3. The license gate did not see dev-dependencies: cargo-deny 0.20.2 in this repository leaves 12 dev-only crates out of its graph (`rand` is the first dev-only external crate; `[graph] exclude-dev = false` changes nothing). A lock-wide license fold reading `deny.toml`'s allowlist becomes an xtask step in `check`, so nothing in `Cargo.lock` escapes the allowlist again.
4. `rand` pinned at `=0.8.8` (the line `jsonwebtoken 10.4.0`, `rsa 0.9`, `p256 0.13` key generation drives), not the newest.
- Pre-lands round 1 (Opus): `ureq`, `rand`, `serde_json`, stubs with their `pub mod` lines, dev-dependencies, `mandate-contract` regular for `mandate-identity`, three link tests (777 → 785 cases, `task check` exit 0); `jsonwebtoken` stopped on `subtle` BSD-3-Clause (deviation 1) — ruled and sent back with the lock-wide license step (deviation 3).
- Pre-lands rounds 2 and 3 (Opus): `jsonwebtoken =10.4.0` over `aws_lc_rs` (RS256 and ES256 live; the ES256-only pin was found to install no crypto provider), `ISC` admitted, the lock-wide `cargo xtask licenses` step (224 resolved crates, reads the allowlist from `deny.toml`, 8 cases incl. a doctored dev-only BSD-2-Clause crate refused by name). Coordinator adds `aws-lc-rs =1.18.1` as a dev-dependency of `mandate-federation` and `mandate-token` for test-time key generation. `task check` exit 0, 801 tests, 131 targets; 47 new crates in the lock.
