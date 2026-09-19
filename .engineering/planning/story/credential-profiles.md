---
format: aep.planning-md/1
id: story:credential-profiles
kind: story
status: implemented
title: Implement audience registry and both credential families
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:pkce-sessions
- informed_by: initiative:next-ten-waves
- informed_by: story:audit-client
- depends_on: story:signing-and-verification
- depends_on: story:declared-writers
scope:
- confidence: cited
  path: crates/mandate-token/src/lib.rs
- confidence: inferred
  path: crates/mandate-token/src/projection.rs
- confidence: inferred
  path: crates/mandate-token/src/verifier.rs
- confidence: cited
  path: crates/mandate-token/tests/conformance.rs
- confidence: inferred
  path: crates/mandate-token/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-token/tests/projection.rs
- confidence: inferred
  path: crates/mandate-token/tests/verifier.rs
- confidence: cited
  path: services/sts/Cargo.toml
- confidence: inferred
  path: services/sts/src/issue.rs
- confidence: inferred
  path: services/sts/src/keys.rs
- confidence: inferred
  path: services/sts/src/lib.rs
- confidence: inferred
  path: services/sts/src/registry.rs
- confidence: inferred
  path: services/sts/src/resolve.rs
- confidence: inferred
  path: services/sts/tests/contract_agreement.rs
- confidence: inferred
  path: services/sts/tests/corpus.rs
- confidence: inferred
  path: services/sts/tests/emitted_events.rs
- confidence: inferred
  path: services/sts/tests/issue.rs
- confidence: inferred
  path: services/sts/tests/keys.rs
- confidence: inferred
  path: services/sts/tests/registry.rs
- confidence: inferred
  path: services/sts/tests/replay.rs
- confidence: inferred
  path: services/sts/tests/resolve.rs
revision: 20
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

Re-derived 2026-09-19 by `story-scoper` on `main` at `a76267b` (wave A merged), replacing the section written before wave A. **Cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `services/sts` — cited; the acceptance's revoke-then-introspect and three of the five unit rows land there. Co-primary `crates/mandate-token` — cited; the projections and the reference verifier.
- **Confidence:** high for the two crates and the coordinator set; medium for the per-unit file split (the files do not exist).
- **Superseded by wave A, dropped from scope:** `crates/mandate-token/src/algorithm.rs`, `src/signing.rs`, `tests/algorithm.rs`, `tests/signing.rs` — cited. `AllowedAlgorithms` (`crates/mandate-token/src/signing_real.rs:156`), `CredentialSigner` (`:662`, `sign<T: Serialize>` at `:669`), `RealSigner<C>` (`:741`), `RevokedKey` (`:706`), `SigningKeyMaterial` (`:413`), `Clock` (`:642`), `StandardClaims` (`:550`), `SignedCredential` (`:563`) exist there. `story:signing-and-verification` owns that file and its four test files; this story consumes the port and edits none of them. `decision-blocker:algorithm-policy` is cleared.

### Units — one implementor this wave; the rows are the order inside it

| Unit | Crate | Files (all to create) | Symbols | ESS commands / events | Test file |
|---|---|---|---|---|---|
| `projection` | `crates/mandate-token` | `src/projection.rs`, `tests/projection.rs`, `tests/contract_agreement.rs` | `ResourceServer`, `AccessCredential`, `SigningKey` records and their `State` enums agreeing with `generated/rust/mandate-contract/src/entities.rs`; `CredentialEvent` as the declared payload structs with `ess_name()`; folds; the `(organization_id, audience)` conflict path returning the declared denial (`decision-blocker:identity-uniqueness` evidence) | entities `credential.yaml:10`, `:46`, `:77` — cited | `tests/projection.rs` |
| `verifier` | `crates/mandate-token` | `src/verifier.rs`, `tests/verifier.rs` | non-reversible reference verifier as a port, digest supplied by the caller (`mandate-token` has no `sha2`: `dependency-boundaries.json:33-40`) — cited; constant-time comparison | — | `tests/verifier.rs` |
| `registry` | `services/sts` | `src/registry.rs`, `tests/registry.rs` | satisfies `mandate_federation::authorize::TargetRegistry` (`crates/mandate-federation/src/authorize.rs:65-81`) — cited | `RegisterResourceServer` (`credential.yaml:242`), `DisableResourceServer` (`:161`); `ResourceServerRegistered` (`:542`), `ResourceServerDisabled` (`:522`) — cited | `tests/registry.rs` |
| `issue` | `services/sts` | `src/issue.rs`, `tests/issue.rs` | consumes `CredentialSigner`, `StandardClaims`, `SignedCredential` — cited | `IssueReferenceCredential` (`:272`), `IssueSelfContainedCredential` (`:313`); `CredentialReferenceIssued` (`:554`), `CredentialSelfContainedIssued` (`:572`) — cited | `tests/issue.rs` |
| `resolve` | `services/sts` | `src/resolve.rs`, `tests/resolve.rs` | the acceptance's revoke-then-introspect over the `AccessCredential` projection | `IntrospectCredential` (`:400`), `RevokeAccessCredential` (`:183`); `CredentialIntrospected` (`:608`), `AccessCredentialRevoked` (`:528`) — cited | `tests/resolve.rs` |
| crate roots — this story's implementor, shared with no other unit this wave | both | `crates/mandate-token/src/lib.rs` (`pub mod projection; pub mod verifier;` beside `:182`); `services/sts/src/lib.rs`; `services/sts/tests/corpus.rs`, `tests/emitted_events.rs`, `tests/replay.rs` | `realizes!` registry over `mandate.credential`; `ESS_REALIZATIONS` / `ESS_UNREALIZED` | — | `crates/mandate-token/tests/conformance.rs:71` (2 entries, unchanged) — cited |

- **Gate:** `cargo fmt -p mandate-token -p mandate-sts -- --check`; `cargo clippy -p mandate-token -p mandate-sts --all-targets --locked -- -D warnings`; `cargo test -p mandate-token -p mandate-sts --locked`, counts reported.
- **Minimum set for the acceptance and the five corpus cases:** all five units — cited: `tests/security/cases.json:195, :209, :223, :237, :251` each name `IssueReferenceCredential` and `IntrospectCredential`; `reference-persistence` (`:199`) needs `verifier`; `reference-audience` needs `registry`. `IssueSelfContainedCredential` is named by no case's `commands` list — inferred; its half of `issue` is carried by the Required observations.

### Coordinator-owned — pre-landed in the wave's opening commit; no unit edits them

- `services/sts/Cargo.toml` (`:12-17` today: `[[bin]]` and `clap` alone) — cited; gains a `[lib]` target, `serde`, `serde_json`, `mandate-types`, `mandate-model`, `mandate-token`, and dev `mandate-contract`, `mandate-testkit`.
- `crates/mandate-token/Cargo.toml:19-21` — inferred; gains dev `mandate-contract`, `mandate-testkit` (pre-landed for four crates in wave A, not this one: `docs/plans/2026-09-19-wave-a-execution.md:21`).
- `dependency-boundaries.json` — cited; `mandate-sts` has no `libraries` key (`:111-117`, falls through to `external`) and gets its own; `mandate-token` (`:33-40`) gains the two dev crates.
- `xtask/src/main.rs:190` `LIBRARIES = 16` → 17 and the doc comment at `:188-189` — cited.
- `Cargo.lock` — inferred; path edges only.
- `services/sts/src/main.rs:1-10` stays the stub — cited; `xtask/src/main.rs:457-473` keeps asserting `serve` fails.
- `crates/mandate-types/src/inventory.rs`, `tests/inventory.rs` — not touched: the seven `EXCLUDED_SEMANTICS` entries at `src/inventory.rs:577-584` are `mandate-types`' own value types — inferred.

### Contract facts this story's implementor builds against — settled at the wave B opening

1. `IntrospectCredential` (`credential.yaml:400-423`): the accepted response carries `active: Boolean`; `CredentialIntrospected` (`:608-613`) carries `context` and `descriptor` only. A well-formed credential that is revoked or expired is `accepted` with `active: false` and no descriptor — the reading the corpus states (`reference-revoked`, `reference-expired`: "inactive"). The `denied` clause is corrected by `story:declared-writers` this wave to name a malformed or unresolvable presented proof instead of "invalid/revoked/expired".
2. `mandate.credential.SigningKey` (`:77`) has no creating command or event — cited. `story:declared-writers` adds `RegisterSigningKey` / `SigningKeyRegistered` this wave; the `projection` unit folds `SigningKey` from the regenerated shape in its correction round, or names the residue.
3. `profile-offline-bound` (`tests/security/cases.json:251-262`) is a "signed credential" case naming `IssueReferenceCredential` — cited; corrected to `IssueSelfContainedCredential` in the opening commit (coordinator-owned corpus).
4. `depends_on story:audit-client` carried no reason and nothing here can depend on `crates/mandate-audit` (`dependency-boundaries.json:69-71`; not in `external` at `:111-117`) — cited. Downgraded to `informed_by`; audit on the denial path is a port stand-in, as `story:protocol-adapters`' `denial` unit takes.

### Would collide with

- `story:oauth-integration` (`services/sts/src/main.rs`, `services/sts/Cargo.toml`) and `story:constrained-exchange` on `services/sts` — cited; both `depends_on` this story, sequential by edge.
- Any unit touching `dependency-boundaries.json`, `Cargo.lock`, `xtask/src/main.rs` — coordinator-only.
- Not `crates/mandate-token/src/signing_real.rs` or its four test files — `story:signing-and-verification`'s.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Inherited from wave A, 2026-09-19

- Superseded by wave A (design D2): the `signing` unit row no longer lands the signing port, `kid` or the rotation window in `crates/mandate-token/src/signing.rs`; `story:signing-and-verification`'s `token-signer` declares and implements `CredentialSigner` in `signing_real.rs` first, and this story's issuance consumes that port.

## Rulings — wave B opening, 2026-09-19

Coordinator, after `review-result:wave-b-parallel-r1` and `review-result:wave-b-design-r1`.

1. **Order.** This story's tree is cut only after `story:declared-writers`' contract round has merged and the coordinator has regenerated `generated/**`; `depends_on story:declared-writers` records it. The wave page's "disjoint and parallel" reads as: disjoint by file, sequential by the IR (parallel-safety 1 and 2, design 2).
2. **Edge direction.** `depends_on story:signing-and-verification` recorded here; that story's `depends_on story:credential-profiles` removed — wave A landed the signer first and the `issue` unit consumes `CredentialSigner` (design 1).
3. **Crate roots.** `crates/mandate-token/src/lib.rs` and `services/sts/src/lib.rs` are this story's implementor's this wave. The "two coordinator interface commits" paragraph under Units, and the `algorithm` and `signing` rows of that table, are superseded by wave A and by the re-derived Scope (parallel-safety 3).
4. **One registry.** The `mandate.credential` realization registry lives in `services/sts/src/lib.rs` with its exhaustive test in `services/sts/tests/contract_agreement.rs`; entities and events realized by `mandate-token` types are accounted there by path. `crates/mandate-token` carries no domain registry.
5. **No federation edge.** The `registry` unit does not implement `mandate_federation::authorize::TargetRegistry`. It exposes the `ResourceServer` fold's read API — the organization a registered target belongs to, and whether it is enabled — and the `TargetRegistry` adapter over it is the composition's (`story:product-listener`, `port-adapters`). `mandate-sts` gains no `mandate-federation` dependency (design 3).
6. **Sixth unit, `keys`.** `services/sts/src/keys.rs`, `tests/keys.rs`: `RegisterSigningKey`, `RetireSigningKey`, `RevokeSigningKey` deciding over the `SigningKey` projection and emitting `SigningKeyRegistered`, `SigningKeyRetired`, `SigningKeyRevoked`. Rehydrating `RealSigner::new_with_revocations` from the fold is the composition's, named as residue (design 4).
7. **Introspection.** A well-formed credential that is revoked or expired answers `accepted` with `active: false`, no descriptor; the event carries `active` and `credential_id` after `declared-writers` C0 (design 6). `reference-audience` stays a denial.
8. **The cached-resolution clause.** The `resolve` acceptance test owns a caching resolver double and shows it is not consulted after `AccessCredentialRevoked`.
9. **Stale prose.** "`mandate-model` may depend only on `mandate-types`" under *Projections are forced into `mandate-token`* is stale since wave A (`dependency-boundaries.json:12-19` lists five entries); the projections still land in `mandate-token` because `CredentialProfile` and `CredentialDescriptor` are declared there.

## Inherited from wave B, 2026-09-19

- From the wave B implementor and adversary 1 (2026-09-19): `credential.yaml:410,428` source `reference_verifier` as `generated: true` on both issuance events while `AccessCredential.reference_verifier` is `Optional`; the testkit's source check requires a generated field to be present, so the self-contained family records the digest of the returned token as its verifier. A contract touch that makes the field's sourcing match its optionality is `story:declared-writers`' (contract-only), not this story's; until then the digest is always present and the crate doc says why.

- From the wave B adversary 1 and correction 1 (2026-09-19): `mandate.credential.AccessCredential` (`credential.yaml:46-76`) declares no issuing registration while both issuance events carry `target`, so a credential's revocation guarantee is not recoverable from the declared record alone. The projection keeps `target` and `issuing_profile` outside the wire form (`#[serde(skip)]`) and decides the guarantee from them; the contract touch that declares the issuing registration on the record is `story:declared-writers`' (contract-only), routed there.

- Routed from `story:coverage-map` (2026-09-19): `mandate-token` realizes `mandate.core.CredentialDescriptor` and `CredentialProfile` (and its projection records) with no `ESS_REALIZATIONS` registry, so the coverage manifest carries them `declared`; a `realizes!` registry and the manifest-equality case in `crates/mandate-token/src/lib.rs` and `tests/contract_agreement.rs` close it — a small follow-up unit of this story or the E4 close.

- Correction (2026-09-19): the routing above is withdrawn — this story is `implemented`; the `mandate-token` registry lands in `story:coverage-map`'s correction 1 (scope extended).
