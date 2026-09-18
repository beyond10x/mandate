# Wave 1 execution page

Skill: `aep-drive:wave` **0.9.2** — the version in `.claude-plugin/plugin.json` of the installed
plugin at `~/.claude/plugins/cache/beyond10x/aep-drive/0.9.2`, resolved through
`installed_plugins.json`. The ten-wave proposal quotes 0.8.1 from a stale cache directory; the two
`wave/SKILL.md` bodies differ only in the version banner, two example crate paths and
`aep drive eval run` → `metaharness aep drive eval run`.

Integration branch: `integration/wave-20260918-002`, forked from `dc76aa3`.

## Why a new integration branch

`integration/wave-20260918-001` was merged to `main` as `dc76aa3` (PR #4, 2026-09-18 01:47Z).
`git merge-base --is-ancestor integration/wave-20260918-001 main` exits 0, so that batch is closed.
`docs/adr/0008-integration-batches.md` requires the integration branch to be created from current
verified `main`. This wave accumulates on `integration/wave-20260918-002`.

## Selection

Re-run in this checkout against AEP `protocol 0.55.0`:

| Command | waves | collisions | unassessed |
|---|---:|---:|---:|
| `aep plan artifact waves --kind story --status proposed --format json` | 1 | 0 | 0 |
| `aep plan artifact waves --kind story --status draft --format json` | 10 | 16 | 0 |

Proposed wave 1: `story:canonical-types`. Draft wave 1: `story:runtime-decision-dossier`.
Neither appears in `aep plan artifact blocked`. The thirteen `decision-blocker:*` are all `open`;
the eleven runtime blockers name other stories, and `drive-verifier` / `drive-map-authority` name
`task:canonical-types-drive`, not the story.

The two units' write surfaces are disjoint: seven code/dependency paths against one architecture
directory.

## Units

| Unit | Story | Branch | Worktree | Build directory | Scratch |
|---|---|---|---|---|---|
| w1-canonical-types | `story:canonical-types` | `impl/canonical-types` | `…/trees/b10x/mandate/mandate-w1-canonical-types` | `~/.cache/b10x-target/mandate/w1-canonical-types` | `~/.cache/b10x-wave/mandate-w1/canonical-types` |
| w1-runtime-decision-dossier | `story:runtime-decision-dossier` | `impl/runtime-decision-dossier` | `…/trees/b10x/mandate/mandate-w1-runtime-decision-dossier` | `~/.cache/b10x-target/mandate/w1-runtime-decision-dossier` | `~/.cache/b10x-wave/mandate-w1/runtime-decision-dossier` |

Coordinator checkout: managed id `mandate-w1-coordinator`, path
`…/trees/b10x/mandate/mandate-w1-coordinator`, branch `integration/wave-20260918-002`, owner `agent`,
session lease `wave1-coordinator`, live-leases 1.

## Commits this approval authorises

One commit per unit, the two `--no-ff` merges into `integration/wave-20260918-002`, the opening and
closing planning-store commits, and one push of the integration branch for recovery proof.
Nothing else — not a merge to `main`, not a PR, not a tag, not a release, not a Drive launch.

`AGENTS.md` and ADR 0008 override the skill's automatic merge to `main`: this wave stops at the
gated integration branch.

## Declared deviations

1. Skill version quoted by the committed proposal (0.8.1) is stale; this wave runs 0.9.2.
2. Build directories are `~/.cache/b10x-target/mandate/<unit>` — one root per repository, one
   subdirectory per unit. The skill forbids two trees sharing one build directory; the operator's
   standing rule keeps targets out of worktrees. This satisfies both. The coordinator sets
   `CARGO_TARGET_DIR` in each brief; implementors never set it.
3. `RUSTC_WRAPPER` is unset in the ambient environment. Each brief wires `/usr/bin/sccache`
   explicitly.

## Preflight

| Check | Result |
|---|---|
| primary checkout clean, on `main` | `dc76aa3`, `git status --porcelain` empty |
| `git worktree list` before create | only the primary — no leftover trees |
| `aep --version` | `protocol 0.55.0` |
| `ess --version` | `ess 0.25.0` |
| `aep plan artifact validate` | `valid`, 72 artifacts, 9 pre-existing no-findings-block diagnostics |
| `ess specify validate --path systems/mandate` | `mandate v1 — 14 file(s), valid` |
| free disk | recorded per reading below; floor 10 GiB |

### Disk readings

| Time | Free |
|---|---|
| 03:41 | 38 G |
| 03:50 | 24 G |
| 03:56 | 14 G |

Another session holds `cargo test --workspace --exclude ess-xtask --locked` (PID 1210663) and
`…/trees/b10x/ess` is 16 G. Not this wave's to remove. Re-read on every unit return.

### Opening cheap gate on the integration branch

Run in the coordinator checkout at `dc76aa3`, before any unit tree was created, with
`CARGO_TARGET_DIR=~/.cache/b10x-target/mandate/w1-coordinator`, `RUSTC_WRAPPER=/usr/bin/sccache`,
`CARGO_BUILD_JOBS=2`.

| Step | Exit | Output |
|---|---:|---|
| `cargo xtask boundaries` | 0 | `20 packages satisfy metadata and dependency boundaries` |
| `cargo xtask corpus` | 0 | `47 contract scenarios traced; source hashes match; no runtime enforcement claimed` |
| `cargo xtask contracts` | 0 | `ESS projections match deterministically` |

xtask compiled in 7.50s. The compiler and test suite were not run at this stage.

## Stage log

| Time | Unit | Stage | Note |
|---|---|---|---|
| 03:58 | — | coordinator tree created | `mandate-w1-coordinator`, lease `wave1-coordinator` |
| 03:59 | — | opening cheap gate | boundaries/corpus/contracts all exit 0 |
| 04:00 | both | unit trees created | `impl/canonical-types`, `impl/runtime-decision-dossier`, both at `dc76aa3`, leases held |
| 04:01 | dossier | scoped | `aep-drive:story-scoper`; `## Scope` written, revision 6; `docs/architecture/unmapped.md` added inferred, revision 7 |
| 04:02 | dossier | dispatched | `aep-drive:implementor`, brief at `~/.cache/b10x-wave/mandate-w1/runtime-decision-dossier/brief.md` |

Sub-agent types dispatched, in full: `aep-drive:story-scoper`, `aep-drive:implementor`,
`aep-drive:adversary`. No built-in substitution.

Re-derivation after the dossier scope write: `waves --kind story --status draft` still returns
wave 1 = `story:runtime-decision-dossier` alone, 16 collisions, 0 unassessed — the added inferred
leaf created no new collision.

## Accepted type and exclusion inventory

`story:canonical-types` makes this inventory mandatory before dispatch and names no destination file.
It lives here. Read from `systems/mandate/domains/core.yaml` and `identity.yaml` at `dc76aa3`.

**Two denominators, and they are different.** Stating one makes the story's phrase "every accepted
type and exclusion" read as self-contradictory, because no excluded item is a type.

### Types — 74 accepted, 0 excluded

`core.yaml` declares all 74 named types in the model. Every other domain file declares zero.

| Kind | Count | Notes |
|---|---:|---|
| `newtype of Uuid` | 34 | 31 `*Id`, plus `EpochSnapshotRef`, `AccessCredentialId`, `AgentCapabilityCeilingId` |
| `newtype of String` | 19 | `Action`, `ResourceType`, `Audience`, `Issuer`, `ExternalSubject`, `ClientId`, `AuthzRevision`, `PolicyVersion`, `CorrelationId`, `CredentialVerifier`, `KeyReference`, `PkceChallenge`, `RedirectUri`, `TrustDomain`, `ActionPattern`, `AuthorizationModelVersion`, `SigningAlgorithm`, `AuditAction`, `AuditOutcome` |
| `newtype of Bytes` | 2 | `CredentialSecret`, `CredentialProof` — the transient pair |
| `enum` | 8 | `PrincipalKind`, `CredentialKind`, `RevocationGuarantee`, `MembershipSource`, `ExternalLinkMethod`, `DecisionReason`, `PkceMethod`, `DenialReason` |
| `struct` | 9 | `ResourceRef`, `AuthorityScope`, `VerifiedContext`, `CredentialDescriptor`, `CredentialProfile`, `TenantResolutionRule`, `DecisionChallenge`, `Decision`, `AuditRecord` |
| `union` (tag `kind`) | 2 | `AuthoritySubject`, `SecurityEpochTarget` |
| **Total** | **74** | |

### Entities — 4 excluded, 0 accepted

| Excluded entity | Source | Why |
|---|---|---|
| `PrincipalSecurityEpoch` | `identity.yaml:161` | `fields: []` ownership placeholder |
| `OrganizationSecurityEpoch` | `identity.yaml:172` | `fields: []` ownership placeholder |
| `FederationSecurityEpoch` | `identity.yaml:183` | `fields: []` ownership placeholder |
| `SecurityEpochSnapshot` | `identity.yaml:128` | carries no per-dimension numeric values, pending UNMAPPED-EPOCH |

Those first three are the only entities among all 36 with empty `fields`.

## Coordinator decisions taken before dispatch

The scoper surfaced two items the story leaves undecided and three traps. Decided here so the
implementor does not guess.

1. **`mandate.core.SecurityEpochTarget` is ACCEPTED.** It is a tagged union over `PrincipalId`,
   `OrganizationId` and `FederationConnectionId`. It carries no numeric content, so realizing it
   does not touch UNMAPPED-EPOCH. It is named by neither the story's accepted nor its excluded list;
   this resolves that.
2. **The 36 derived `<Entity>.State` enums are EXCLUDED.** The compiled IR reports 110 type entries:
   74 authored plus one derived state enum per entity. `ess generate types --all-types` selects all
   110 and would pull in the four excluded epoch entities' states. Select by explicit
   `--root mandate.core.<T>`, never `--all-types`. This is the most likely way the unit silently
   overruns its stated exclusions.
3. **Compile-fail cases use `compile_fail` doctests, not `trybuild`.** A `trybuild` dev-dependency
   would widen admission across all three shared files for no acceptance benefit. Doctests run under
   the existing `cargo test --workspace --locked` with zero new dependencies.
4. **No Rust output under `generated/`.** `xtask` `contracts()` regenerates from exactly four kinds
   and byte-compares the whole tree; anything else placed there reads as projection drift. Generate
   to `crates/mandate-*`.
5. **`cargo xtask type-properties` is out of this unit's scope.** It does not exist, it is Drive-only
   tooling, and it is blocked by `decision-blocker:drive-verifier`. This story's acceptance resolves
   through `task check` → `cargo test --workspace --locked`, which crate-local tests satisfy.
6. **`deny.toml` is not in scope.** The licence allowlist is `Apache-2.0`, `MIT`, `Unicode-3.0`.
   If a required dependency falls outside it, the unit stops and reports rather than widening the
   file.
7. **Dev-dependencies need boundary entries too.** `xtask/src/main.rs:113` iterates
   `cargo metadata`'s per-package `dependencies` without filtering on `kind`, so a dev-only crate is
   admitted the same way. Unverified — no package in the workspace currently has one — so treat it
   as true and admit any dev-dependency in the same array.

Open and left to the implementor, with its scope confirmation table as the answer: how the 74 types
allocate across the four crates. The story gives the rule (identifiers/enums/shared value records →
`mandate-types`; domain records → `mandate-model`; credential formats → `mandate-token`; wire
contracts and conversions → `mandate-proto`); nothing in the tree declares a per-crate partition.
