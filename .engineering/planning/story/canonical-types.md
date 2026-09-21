---
format: aep.planning-md/1
id: story:canonical-types
kind: story
status: implemented
title: Realize accepted canonical Rust types
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:foundation-contracts
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: crates/mandate-model
- confidence: cited
  path: crates/mandate-proto
- confidence: cited
  path: crates/mandate-token
- confidence: cited
  path: crates/mandate-types
- confidence: cited
  path: dependency-boundaries.json
revision: 13
---
# Realize accepted canonical Rust types

## Acceptance

Given the accepted ESS type set, when the canonical Rust conformance suite serializes and decodes each admitted type, then the canonical type conformance suite exits zero.

## Required observations

Realize the explicitly accepted ESS identifier, enum, record and wire types with deterministic serialization; prove PrincipalId cannot substitute OrganizationId and transient CredentialSecret/Proof cannot enter persisted records. Use ESS type realization support where admitted; account for every accepted type and exclusion. No numeric epochs, invented lifecycle, crypto, PDP or HTTP implementation. task check and compile-fail/round-trip tests pass.

## Scope

Derived 2026-09-18 by `story-scoper` against `dc76aa3`. Every line is **cited** (read from the story
or the tree) or **inferred** (a reading that could be wrong). The revision-10 scope of seven paths is
verified correct and complete; nothing is added to it.

- **Primary surface:** `crates/mandate-types` — cited; identifiers, enums, unions and shared value
  records. The only crate with an empty `[dependencies]`.
- **Primary surface:** `crates/mandate-model` — cited; accepted domain records and the
  credential-containment conformance suite.
- **Additional surface:** `crates/mandate-token` — cited; accepted credential-format types only.
- **Additional surface:** `crates/mandate-proto` — cited; accepted wire contracts and explicit
  conversions.
- **Files:** `crates/{mandate-types,mandate-model,mandate-token,mandate-proto}/src/lib.rs` — cited;
  each is a 4-line `//!` doc scaffold with no items, no `tests/` directory and no dev-dependencies,
  so every line of this story is an addition, not an edit.
- **Files:** the four crates' `Cargo.toml` — cited; each gains the serialization dependency.
  `cargo xtask check` asserts `version`/`edition`/`rust-version`/`license`/`publish` on all 20
  members, so these stay `*.workspace = true`.
- **Shared file:** `dependency-boundaries.json` — cited; `xtask/src/main.rs:119` reads
  `libraries.get(name).unwrap_or(&policy["external"])`, and all four crates are keys in `libraries`,
  so the `external` allowlist does **not** apply to them. Every added dependency goes into that
  crate's own array. `mandate-types` is `[]` today; the other three are `["mandate-types"]`.
- **Shared file:** `Cargo.toml` — cited; `[workspace.dependencies]` holds only `clap`, `serde_json`,
  `sha2`. A serialization dependency needs an entry here before any crate can say
  `serde.workspace = true`.
- **Shared file:** `Cargo.lock` — cited; the gate runs clippy, test, build, `cargo metadata` and
  `cargo deny` with `--locked`. `serde`, `serde_core` and `serde_derive` are already resolved
  transitively through `serde_json`, so the lock delta is the members' dependency lists — unless a
  `uuid` or time crate is admitted, which is new resolution.
- **Symbols:** `PrincipalId`, `OrganizationId`, `CredentialSecret`, `CredentialProof`,
  `AuthoritySubject`, `EpochSnapshotRef` — cited; all six in `systems/mandate/domains/core.yaml`.
  `AuthoritySubject` is `kind: union, tag: kind` over `{principal: PrincipalId, team: TeamId}`.
  `EpochSnapshotRef` is `newtype of Uuid`.
- **Excluded, and not types:** `PrincipalSecurityEpoch`, `OrganizationSecurityEpoch`,
  `FederationSecurityEpoch`, `SecurityEpochSnapshot` — cited from
  `systems/mandate/domains/identity.yaml:128,161,172,183`. All four are **entities**, not `types:`
  entries. The first three are the only entities among 36 with `fields: []`.
- **Not required:** `xtask/` — cited; `xtask/src/main.rs:104` asserts 20 packages and 14 libraries
  and this story changes neither. `cargo metadata --no-deps` reports workspace members only; adding
  entries to an existing `libraries` array cannot move the key count. No new crate, no new
  `libraries` key.
- **Documents:** none in the repository. The mandatory accepted-type and exclusion inventory is a
  wave-page artefact, not a repository write — inferred from `docs/handoff.md` naming it a dispatch
  precondition rather than a deliverable.
- **Confidence:** high — the four crates, the three shared files and the boundary mechanism were each
  read directly.
- **Would collide with:** any unit touching the four crate directories, and — because `Cargo.toml`,
  `Cargo.lock` and `dependency-boundaries.json` are workspace-wide — any unit anywhere in the
  repository that adds, removes or repins a dependency on any crate. That second clause is the wide
  one and is not limited to these four crates.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Final review disposition

Round-two acceptance found two independent results in the acceptance sentence. The final wording names one suite outcome; the required round-trip and compile-fail observations remain below it. This editorial correction was made after the final critic round and has not been re-reviewed; no third round is claimed.

## Scope and acceptance clarification after the technical review

The scope includes dependency-boundaries.json, Cargo.toml and Cargo.lock so required serialization dependencies can be admitted and pinned with the consuming crates. No external dependency is silently permitted by the existing gate.

The accepted realization set must explicitly exclude the empty principal/organization/federation generation ownership placeholders and the incomplete numerical SecurityEpochSnapshot representation until UNMAPPED-EPOCH is cleared. AuthoritySubject is an admitted tagged value type; its conditional storage foreign keys remain blocked under UNMAPPED-SUBJECT-RELATIONS. Realizing a value type does not implement those storage or policy semantics. The scope/exclusion inventory is required before dispatch; the first Wave remains a proposal and Drive still requires its reviewed verifier and operator spending limits.

These corrections follow review-result:design-review-1 and review-result:contracts-review-1. They do not rewrite those verdicts or claim another completed critic round.
