---
format: aep.planning-md/1
id: story:pkce-sessions
kind: story
status: draft
title: Implement public-client authentication and sessions
relations:
- decomposes: epic:authentication
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:session-epochs
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: Cargo.lock
- confidence: inferred
  path: bins/mandate/Cargo.toml
- confidence: inferred
  path: bins/mandate/src/main.rs
- confidence: inferred
  path: bins/mandate/tests/cli.rs
- confidence: inferred
  path: crates/mandate-identity/src/candidate.rs
- confidence: inferred
  path: crates/mandate-identity/src/pkce.rs
- confidence: inferred
  path: crates/mandate-identity/src/publicclient.rs
- confidence: inferred
  path: crates/mandate-identity/tests/candidate.rs
- confidence: inferred
  path: crates/mandate-identity/tests/pkce.rs
- confidence: inferred
  path: crates/mandate-identity/tests/publicclient.rs
revision: 11
---
# Implement public-client authentication and sessions

## Acceptance

Given a registered public client and an unconsumed, unexpired S256-bound code record, when the matching verifier and exact registered redirect are validated under the bound client and authenticated session, then the core returns a non-consuming validation candidate.

## Required observations

Implement non-consuming validation behind typed ports: S256, exact registered redirect, expiry, state/nonce, client binding, active organization and authenticated session state. Cases cover missing, wrong and plain verifiers, expired or already-consumed records, redirect/client mismatch and secret-free CLI primitives. Validation neither consumes a code nor creates a credential or committed redemption result. Two concurrent valid callers may both obtain validation candidates; neither has authority to redeem. story:oauth-integration owns revalidation inside the STS transaction, atomic one-use consumption, credential creation and durable outbox commit, including the one-winner concurrency assertion. No identity-owned code store or separate consume-then-issue transaction is authorized.

## Units

`crates/mandate-identity/src/lib.rs` is coordinator-owned: this story appends three `pub mod` lines through the coordinator's integration edit and does not declare the file. Units A, B and D are independent; C composes A and B by signature.

| Unit | Owns | Test file | Lands |
|---|---|---|---|
| A `pkce` | `crates/mandate-identity/src/pkce.rs` | `crates/mandate-identity/tests/pkce.rs` | the S256 digest **port** — this crate cannot link `sha2` — and the challenge/verifier predicate; missing and wrong verifier; `plain` is unrepresentable because `PkceMethod` has exactly one variant (`crates/mandate-types/src/enumeration.rs:10`) |
| B `publicclient` | `src/publicclient.rs` | `tests/publicclient.rs` | the registered-client port **declared here with a `pub` test double**: `public`, exact match against `redirect_uris` (`federation.yaml:91-92`), `pkce_method`, organization binding. The real implementation over `story:federation-linking`'s `OAuthClient` projection is `story:product-listener`'s `port-adapters` unit — that story runs after both and may touch `mandate-federation`; this one may not |
| C `candidate` | `src/candidate.rs` | `tests/candidate.rs` | **`mandate.federation.AuthorizePublicClient` (`federation.yaml:215-248`) up to the STS `IssueAuthorizationCode` port call**: the session/epoch read port consumer; the read-only code-record input (`credential.yaml:95-127`); expiry, state/nonce, active organization, authenticated session state; the `ValidationCandidate` and refusal types; two concurrent callers each obtain a candidate |
| D `cli` | `bins/mandate/src/main.rs` | `bins/mandate/tests/cli.rs` | a clap-derive subcommand of pure local computation: derive the S256 challenge from a caller-supplied verifier and print the challenge only; `--help` and `--version` still exit zero, `serve` still exits non-zero (`xtask/src/main.rs:259-271`) |

## Coordinator decisions for this story

- **The CLI prints the challenge, never the verifier.** "Secret-free" is RFC 8252's sense — no client secret, PKCE in its place. A freshly generated verifier is credential material and `AGENTS.md` forbids raw credentials in logs and fixtures; the narrow form satisfies both readings.
- **`bins/mandate` links no workspace crate.** `xtask/src/main.rs:119` applies the `external` allowlist `["clap","serde_json","sha2"]` to it, and `:104` forbids a 15th library. Its S256 derivation is an independent implementation over `sha2`. `sha2` joins `bins/mandate/Cargo.toml` and `Cargo.lock` through the coordinator's integration edit.
- **Dependency inversion, not a new dependency.** `mandate-federation → mandate-identity`, never the reverse; every federation-supplied fact is a trait declared here.
- **The session port takes a `SessionId`, never the proof.** Resolving `session_proof` to a session is trusted-adapter work under `decision-blocker:guards`; `AuthenticateFederation` already returns the id (`federation.yaml:213`).

## Case ids

None owned. The seven `pkce-*` cases carry `story: story:oauth-integration` and `xtask/src/main.rs:164-171` validates that field, so this story cannot re-own one. What its candidate underwrites: `pkce-wrong`, `pkce-missing`, `pkce-plain`, `pkce-redirect`, `pkce-state-nonce` in full as predicates; `pkce-valid` as the candidate half; `pkce-reuse` as the "previously redeemed" refusal only — the concurrent second redemption and "at most one issuance" are STS's and this story never claims them.

## What this story needs from its prerequisites

From `story:session-epochs`, read-only and `&self`: the `Session` shape (`identity.yaml:30-56`), `resolve(&SessionId)`, `current(&SecurityEpochTarget)`, and the `Eligibility` verdict. From `story:federation-linking`: the registered-client lookup `OAuthClientId → { organization_id, public, redirect_uris, pkce_method }` (`federation.yaml:82-94`) and an already-resolved `SessionId`. The code record is an input through a port, not a store (`ownership.md:28`; `credential.yaml:4`).

## Dependency ceiling

`mandate-identity`: `mandate-types`, `mandate-model`, nothing else, dev-dependencies included. `bins/mandate`: `clap`, `serde_json`, `sha2`, nothing else. A unit may not edit `Cargo.toml`, `Cargo.lock` or `dependency-boundaries.json`.

## Exclusions

Any code store. Any consumption. Any credential creation. `services/sts`, `crates/mandate-server`, `crates/mandate-model`. `crates/mandate-identity/src/lib.rs`. `tests/security/cases.json`. A `serve` subcommand or any socket. `#[ignore]`.

## Scheduling hazard, recorded

`story:product-cli` scopes `bins/mandate` at directory level. Once this story's scope is at file level, `aep plan artifact waves` no longer reports the two as colliding on `bins/mandate/src/main.rs`, though both edit it. `story:product-cli` is refined to files before it is scheduled, or this note is carried.

## Gate per unit

`cargo fmt -p mandate-identity -p mandate -- --check`; `cargo clippy -p mandate-identity -p mandate --all-targets --locked -- -D warnings`; `cargo test -p mandate-identity -p mandate --locked`, counts reported.

## Scope

- `crates/mandate-identity/src/pkce.rs`, `src/publicclient.rs`, `src/candidate.rs` — inferred; do not exist; names chosen for disjointness from `story:session-epochs`.
- `crates/mandate-identity/tests/pkce.rs`, `tests/publicclient.rs`, `tests/candidate.rs` — inferred.
- `bins/mandate/src/main.rs` — inferred that this story edits it; cited as the package's only source.
- `bins/mandate/tests/cli.rs` — inferred; `env!("CARGO_BIN_EXE_mandate")`, no dev-dependency.
- `bins/mandate/Cargo.toml`, `Cargo.lock` — inferred; coordinator; `sha2`.
- Not declared on purpose: `crates/mandate-identity/src/lib.rs` — coordinator-owned; `story:session-epochs` holds the cited entry.
- Would collide with: any unit adding modules to `crates/mandate-identity`; any unit editing `bins/mandate/src/main.rs` or `Cargo.lock`.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Ten-wave refinement

The first review identified that returning a consumed redemption result would split the STS transaction. This story is now explicitly non-consuming. STS owns code storage; story:oauth-integration performs the complete consume/issue/outbox transaction under decision-blocker:epoch-atomicity. The former direct atomicity blocker added during preparation is removed from this validation-only story; its existing session-epoch prerequisite remains unchanged. Source: docs/architecture/ownership.md:28 and docs/architecture/unmapped.md:25.

## Validation outcomes and final review correction

| Input | Required result |
|---|---|
| Matching S256 verifier, exact registered redirect and bound client, unexpired/unconsumed record, valid bound session/state/nonce | Validation candidate; no code consumption, credential issuance or committed redemption |
| Missing or wrong verifier; plain method | Refusal; no candidate |
| Expired or already consumed record | Refusal; no candidate |
| Client/redirect mismatch or invalid bound session/state/nonce | Refusal; no candidate |
| Two concurrent callers each meeting every positive condition | Each may validate; only the later atomic STS transaction decides the redemption winner |

This explicit matrix answers review-result:ten-waves-acceptance-r2 after the second and final critic round. The coordinator checked it against the existing Required observations and the STS transaction boundary; the wording correction has not received a third independent review. No runtime evidence is claimed.

## ESS command realized

`mandate.federation.AuthorizePublicClient` (`federation.yaml:215-248`) is realized by this story's `candidate` unit: every validation its denial clause names — session proof, registered public client, exact redirect, state and applicable nonce, S256 challenge, registered target inside the tenant — up to the point where the accepted outcome invokes STS `IssueAuthorizationCode`. That invocation and the code record are `story:oauth-integration`'s (`ownership.md:26-28`); its tests stand in for this command with a fixture and do not re-implement it. The command is control-plane-owned (`components.yaml`); the deployment that hosts it is `story:product-listener`'s. `epic:authentication`'s "public authorization-code/S256 PKCE" is claimed here.
