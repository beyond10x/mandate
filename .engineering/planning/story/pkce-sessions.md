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
- confidence: cited
  path: bins/mandate/src/main.rs
- confidence: inferred
  path: bins/mandate/tests/cli.rs
- confidence: inferred
  path: crates/mandate-federation/src/authorize.rs
- confidence: inferred
  path: crates/mandate-federation/src/pkce.rs
- confidence: inferred
  path: crates/mandate-federation/src/publicclient.rs
- confidence: inferred
  path: crates/mandate-federation/tests/authorize.rs
- confidence: inferred
  path: crates/mandate-federation/tests/pkce.rs
- confidence: inferred
  path: crates/mandate-federation/tests/publicclient.rs
revision: 15
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

Derived 2026-09-18 by `story-scoper` on `integration/wave-20260918-004` (`20f354d`). Every line is **cited** (read from the story or the tree) or **inferred** (a reading that could be wrong). File granularity; no directory entries.

- **Primary surface:** `crates/mandate-federation` — cited. The contract declares `mandate.federation.AuthorizePublicClient` (`systems/mandate/domains/federation.yaml:269-302`), `components.yaml:2-9,35` hosts it in `mandate-control-plane`, and `crates/mandate-federation/src/authenticate.rs:268-269` defers "step 5, nonce/state/PKCE" to this story from inside that crate.
- **Crate decision (was `mandate-identity`):** the record the command validates against — `OAuthClient { id, organization_id, public, redirect_uris, pkce_method, state }` — already exists as a fold in `crates/mandate-federation/src/record.rs:113-129` with `Projection::clients()` at `:530-534`; placing the units in `mandate-identity` would force a duplicate of that shape behind a trait in a crate that cannot see the fold. The dependency direction is already declared, `mandate-federation → mandate-identity` (`crates/mandate-federation/Cargo.toml:16`; `dependency-boundaries.json:36-41`), so the session check consumes `mandate_identity::IdentityRead` directly and no inverted trait is needed — cited.
- **Reused in `mandate-federation`:** `OAuthClient` and `OAuthClientState` (`record.rs:113-129`, `:64-66`), `Projection::clients()` (`record.rs:530-534`) — cited; `ConnectionStore` (`src/lib.rs:229-240`) and its double `RecordedPrincipals` (`:371-378`) as the pattern for the sibling registered-client port and its `pub` double — cited; `Denied`/`DenialClause` (`lib.rs:56-60`, `:86-135`) and `RequestContext.at` (`lib.rs:160`) for refusals and the expiry instant — cited. `SessionIssuer` (`lib.rs:198-211`) is **not** reused: the candidate reads a session, it does not mint one; it takes the `session_id` `AuthenticateFederation` responded with (`Authenticated.session_id`, `authenticate.rs:47-49`) and resolves it through `mandate_identity::IdentityRead::resolve(&SessionId)` (`crates/mandate-identity/src/port.rs:89-91`), `current` (`:96`), `snapshot` (`:99`), `as_of` (`:106`), `Session` (`session.rs:27-36`) and `Eligibility` (`snapshot.rs:43-48`) — cited; `crates/mandate-federation/` imports nothing from `mandate_identity` yet, so this is the edge's first use — cited.
- **Files:** `bins/mandate/src/main.rs:1-10` — cited; the package's only source, a clap-derive stub with an empty `Args`.
- **Files:** `crates/mandate-federation/src/pkce.rs`, `src/publicclient.rs`, `src/authorize.rs` — inferred; do not exist; `authorize.rs` follows the crate's command-named files (`authenticate.rs`, `link.rs`) and is disjoint from every existing source.
- **Files:** `crates/mandate-federation/tests/pkce.rs`, `tests/publicclient.rs`, `tests/authorize.rs`, `bins/mandate/tests/cli.rs` — inferred; do not exist.
- **Symbols:** `PkceMethod { S256 }` (`crates/mandate-types/src/enumeration.rs:10`), `PkceChallenge`, `RedirectUri`, `CredentialVerifier` (`text.rs:7-8`), `OAuthClientId` (`identifier.rs:16`), `AuthorityScope` (`record.rs:31`), `CredentialSecret`/`CredentialProof` (`credential.rs:8`) — cited. The read-only code-record input is `mandate.credential.AuthorizationCode` (`credential.yaml:109-127`); the port the candidate stops at is `IssueAuthorizationCode` (`credential.yaml:363-381`) — cited.
- **Also likely:** none — the S256 digest stays a port because neither `mandate-federation` (`dependency-boundaries.json:36-41`) nor `mandate-token` can link `sha2` — cited.
- **Documents:** none.
- **Dependency ceiling:** `mandate-federation` = `mandate-types`, `mandate-model`, `mandate-identity`, `mandate-token` (`dependency-boundaries.json:36-41`), dev-dependencies included (`xtask/src/main.rs:116-128` walks every `dependencies` entry without filtering by kind); `mandate` bin = the `external` list (`dependency-boundaries.json`, applied by `xtask/src/main.rs:119`), which holds `sha2`. This story may not widen either — cited.
- **Gate, per unit:** `cargo fmt -p mandate-federation -- --check && cargo clippy -p mandate-federation --all-targets --locked -- -D warnings && cargo test -p mandate-federation --locked` for A–C; the same with `-p mandate` for D. Not `task check` — cited from the ceiling above.
- **Case ids:** none owned; all seven `pkce-*` cases carry `story: story:oauth-integration` (`tests/security/cases.json:335-419`) and `xtask/src/main.rs:218-224` validates that field — cited. Underwritten per unit in the table.
- **Confidence:** high on the crate and on every exclusion — contract, deferral comment, fold and declared dependency edge were all read; the six new file names are inferred and marked so.
- **Would collide with:** any unit adding modules to `crates/mandate-federation` or editing `crates/mandate-federation/src/lib.rs` or `src/record.rs`; any unit editing `bins/mandate/src/main.rs`; any `Cargo.lock` edit between the coordinator's `sha2` pre-land and the wave's `--locked` gates.
- **Wave siblings, file overlap:** `story:check-api` (`crates/mandate-authz/**`) — none; `story:directory-provenance` (`crates/mandate-provisioning`, `services/worker`; provisioning does not depend on federation, `dependency-boundaries.json:42-46`) — none; `story:event-payloads-for-folds` (`systems/mandate/domains/*.yaml`, `generated/`) — none on file; this story reads `federation.yaml:269-302` and `credential.yaml:109-127,363-381` and writes neither — cited. Semantic hazard, inferred: if that story reshapes the link events the fold in `record.rs` must follow at integration; `record.rs` is in neither scope.

### Units

| Unit | Owns (source file) | Test file | Produces | Case ids |
|---|---|---|---|---|
| A `pkce` | `crates/mandate-federation/src/pkce.rs` | `crates/mandate-federation/tests/pkce.rs` | the S256 digest port with a `pub` double (the crate cannot link `sha2`); challenge well-formedness; `plain` unrepresentable because `PkceMethod` has one variant (`enumeration.rs:10`); the challenge/verifier predicate over a read-only `AuthorizationCode` (`credential.yaml:109-127`); missing and wrong verifier refused | underwrites `pkce-plain` (`cases.json:377`), `pkce-wrong` (`:349`), `pkce-missing` (`:363`); owns none |
| B `publicclient` | `crates/mandate-federation/src/publicclient.rs` | `crates/mandate-federation/tests/publicclient.rs` | the registered-client read port in the shape of `ConnectionStore` (`lib.rs:229-240`), implemented for `Projection` over `clients()` (`record.rs:530-534`) plus a `pub` double; `public`, `state == Recorded` (`record.rs:64-66`), exact `redirect_uris` match (`federation.yaml:94-95`), `pkce_method`, `organization_id` binding | underwrites `pkce-redirect` (`:405`); owns none |
| C `authorize` | `crates/mandate-federation/src/authorize.rs` | `crates/mandate-federation/tests/authorize.rs` | `AuthorizePublicClient` (`federation.yaml:269-302`) up to the `IssueAuthorizationCode` input (`credential.yaml:363-381`); session via `IdentityRead::resolve` (`port.rs:91`) and `Eligibility` (`snapshot.rs:43`); state/nonce; expiry against `RequestContext.at` (`lib.rs:160`); active organization; `ValidationCandidate` and its refusal type; two concurrent callers each obtain a candidate; no consumption, no credential | underwrites `pkce-valid` candidate half (`:335`), `pkce-state-nonce` (`:419`), `pkce-reuse` previously-redeemed refusal only (`:391`); owns none |
| D `cli` | `bins/mandate/src/main.rs` | `bins/mandate/tests/cli.rs` | a clap-derive subcommand: verifier in, S256 challenge out, printed alone, over `sha2` directly (the bin links no workspace crate); `--help`/`--version` exit zero, `serve` non-zero (`xtask/src/main.rs:322-327`); test via `env!("CARGO_BIN_EXE_mandate")`, no dev-dependency | none |

Coordinator ruling for wave 3: one agent runs A–D serially (one agent per story). That agent may add the three `pub mod` lines and any `DenialClause` variants to `crates/mandate-federation/src/lib.rs`, because no other story touches the crate this wave; the exclusion of `lib.rs` below binds every other story, not this one.

### Excluded

- `Cargo.toml` — workspace manifest; `sha2 = "0.10"` is already declared; coordinator.
- `Cargo.lock` — changes when the `mandate` package gains `sha2`; pre-landed by the coordinator so every `--locked` gate passes.
- `bins/mandate/Cargo.toml` — the one-line `sha2.workspace = true` lands with the lock; coordinator.
- `dependency-boundaries.json` — the ceiling; read, not widened.
- `deny.toml`, `xtask/` — coordinator; the boundary check (`xtask/src/main.rs:96-131`) and the `serve` refusal (`:322-327`) stay as they are.
- `tests/security/cases.json` — a contract corpus whose seven `pkce-*` rows already name `story:oauth-integration`; no re-ownership.
- `generated/`, `systems/mandate/domains/*.yaml` — `story:event-payloads-for-folds` owns them this wave; this story reads `federation.yaml` and `credential.yaml`, never writes.
- `crates/mandate-federation/src/record.rs` — the fold; read, not edited.
- `crates/mandate-identity/**` — no longer touched; the session read is consumed through the existing crate edge.
- `services/sts`, `crates/mandate-server`, `crates/mandate-model` — unchanged from the earlier exclusions.

### Not established

- No contract event creates an `OAuthClient` (`crates/mandate-federation/tests/record.rs:184-189`; `federation.yaml` declares only `DisableOAuthClient` `:303` and `OAuthClientDisabled` `:382`), so `Projection::clients()` is empty from any real log — unit B's port has a double but no real source until `story:declared-writers` (execution wave 4) declares the creating command.
- `AuthorizationCode`'s lifecycle (the consumed state) past `credential.yaml:127` was not read; `pkce-reuse`'s "previously redeemed" refusal is cited to the record shape only.
- `services/sts` cannot link any workspace library today (`external` allowlist via `xtask/src/main.rs:119`), so `story:oauth-integration`'s reuse of the `pkce.rs` predicate needs a boundary widening that is not this story's.
- Earlier body citations `federation.yaml:215-248`, `:213`, `:82-94`, `:91-92` and `xtask/src/main.rs:164-171`, `:259-271` are stale on this tree (now `:269-302`, `:212`, `:85-97`, `:94-95`, `xtask:208-224`, `:322-327`).

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
