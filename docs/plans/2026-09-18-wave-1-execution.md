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

## Constraint found during the run — the closing gate cannot use a custom build directory

`xtask/src/main.rs:266` builds the path `format!("target/debug/{b}")` for the five executables it
checks. It is a literal relative path, so a `CARGO_TARGET_DIR` pointing outside the worktree makes
the executable scaffold checks fail spuriously — the binaries are built, but not where the gate
looks.

Consequence, and it splits the two kinds of check:

- **Unit-level and cheap gate steps** — `cargo xtask boundaries`, `corpus`, `contracts`,
  `cargo test -p …`, `cargo fmt`, `cargo clippy` — run fine under
  `CARGO_TARGET_DIR=~/.cache/b10x-target/mandate/<unit>`. None of them reads `target/debug/<bin>`.
- **The closing full `task check` on the integration branch** must run with `CARGO_TARGET_DIR`
  **unset**, so the build lands at `<coordinator worktree>/target/`. That target directory is
  deleted by exact path at teardown.

This is a third deviation from the operator's build-directory decision, forced by the repository's
own gate rather than chosen. Recorded rather than worked around; nothing in `xtask/` was edited,
and `xtask/` is in no unit's scope.

## Unit result — story:runtime-decision-dossier

Implementor verdict green. One new file, `docs/architecture/runtime-decisions.md`, 344 lines, no
tracked file modified. Eleven rows, all five fields each, 198 citation line references resolved,
both Drive blockers recorded as excluded rather than as rows.

Lane counts, read off each runner's own summary: `cargo xtask corpus` 47 scenarios exit 0;
`contracts` deterministic exit 0; `boundaries` 20 packages exit 0; `cargo fmt --all -- --check`
exit 0; `aep plan artifact validate` 72 artifacts `valid` exit 0. The unit's own checker went
0 → 1 case, red → green.

Two reds were produced before green: the file-absent case, then a forced trap variant with the
affected-stories column rebuilt from the register, which failed four rows. A second red came after
the first green, when the checker was extended to require every cited line to carry text: 10
citations landed on blank lines or bare code fences, and reading every distinct citation found 16
more that resolved to a non-blank but wrong line. 26 citation sites corrected.

**Correction to the coordinator's brief.** The brief claimed five stale register rows. Four are
stale (`lifecycle`, `identity-uniqueness`, `audit-routing`, `worker-orchestration`). The fifth,
`guards`, is not: the register does carry `story:audit-client`, at `unmapped.md:44` in the
UNMAPPED-DENIAL-AUDIT section rather than on the `AEP:` line at `:21`. The register is complete for
guards, split across two sections. The implementor checked the claim instead of taking it.

### Finding carried out of this unit

`docs/architecture/unmapped.md` carries four `AEP:` lines that under-state affected stories against
the store. Origin **pre-existing** — it predates `story:audit-worker-delivery` and
`story:agent-authority-kernel`. The implementor did not edit it: that file is another story's
collision surface and outside this unit's scope. It is recorded in the dossier's own divergence
table and is filed as a story after the adversary pass, per the wave skill's routing rule that a
pre-existing finding does not block the unit.

## Adversary pass 1 — story:runtime-decision-dossier

Verdict NEEDS-CHANGE. Recorded verbatim as `review-result:wave1-dossier-adversary-1`. 96 assertions,
5 red. Two mutants applied to a scratch copy both passed the unit's own checker with exit 0 and
failed the adversary's.

The adversary disclosed four of its own first-run failures as its bug — a length threshold on a
field that is legitimately 21 characters when a row has one story. It fixed its checker, not the
document. That disclosure is why the remaining five count.

| # | Finding | Verdict | Origin | Routed to |
|---|---|---|---|---|
| 1 | `:147` cites the Read-after-write class for a claim about the class used after revocation | CONFIRMED | introduced | same implementor |
| 2 | `:31` claims every owner comes from the ownership map; rows 6 and 9 do not | NEEDS-CHANGE | introduced | same implementor |
| 3 | `:257` claims no concrete algorithm is named; `:269` names `none` | CONFIRMED | introduced | same implementor |
| 4 | `:161` row 5's policy-engine alternatives are open and unstated | INFEASIBLE | introduced | coordinator, `no-op` |
| 5 | `task check` reads no path under `docs/architecture` | CONFIRMED | pre-existing | coordinator, `escalated` |
| 6 | the unit's checker resolves 198 of 210 citations; continuation refs invisible | CONFIRMED | introduced | same implementor |
| 7 | the unit's checker never validates the index table against the store | CONFIRMED | introduced | same implementor |
| 8 | the coordinator's brief said five stale register rows; it is four | CONFIRMED | pre-existing | coordinator, no artifact change |

First attack, no case failed twice, so the five introduced findings go back to the **same**
implementor rather than a fresh one.

### Coordinator decisions on the three not routed

**Finding 4, accepted as written.** Row 5's policy-engine half declares its alternative set open and
unstated. No permitted source enumerates policy-engine candidates, and inventing three would breach
the story's own prohibition. The story says a decision may remain unanswered and the dossier still
be complete. Naming the gap is the honest answer; recorded `no-op`.

**Finding 5, escalated.** Filed as `story:gate-reads-document-deliverables`. The fix lands in
`xtask/`, which is a coordinator-owned integration surface no story's scope may claim, so it cannot
be folded into this unit. It is pre-existing — it reproduces at `dc76aa3` — so under the wave
skill's routing rule it does not block the unit. Recorded `escalated`.

**Finding 8, no artifact change.** The error was the coordinator's brief, not the store and not the
deliverable. The implementor checked the claim instead of taking it and was right. Corrected in this
page and in the routing message; the brief file itself is scratch and not part of the wave's record.

### Judgement upheld

The adversary was asked to rule on the implementor citing `docs/sources/architecture-addendum.md`,
which the brief's explicit source list omitted. Ruled legitimate: `combined.md:3` makes the addendum
a normative input snapshot of equal standing to `original-design.md`, both are pinned by the same
`SHA256SUMS`, and the prohibition grants the directory rather than one file in it. Three claims have
no equivalent in the brief's named list, so dropping it would have meant inventing or omitting.

## Unit result — story:canonical-types

Implementor verdict green. 11 tracked files changed, 863 insertions; 16 untracked files, 2345 lines.
All 27 paths lie inside the assigned seven-path surface.

**The count that matters.** The workspace went from 34 test targets executing **0** tests to 43
targets executing **54**. That is the first runtime evidence this repository has produced; every
prior gate run was a scaffold measurement.

| Lane | Executed | Exit |
|---|---:|---:|
| `mandate_types tests/conformance.rs` | 0 → 11 | 0 |
| `mandate_types tests/inventory.rs` | 0 → 10 | 0 |
| `mandate_model tests/conformance.rs` | 0 → 6 | 0 |
| `mandate_proto tests/conformance.rs` | 0 → 5 | 0 |
| `mandate_token tests/conformance.rs` | 0 → 4 | 0 |
| Doc-tests, four crates | 0 → 18 | 0 |
| `cargo test --workspace --locked` | 0 → 54 | 0 |

No lane's count fell.

### The brief's open question, answered

Neither `uuid` nor any time crate is needed. The ESS projection maps `Uuid` to a string with a
`pattern`, and `Timestamp`/`Duration` to strings with a `format` and no pattern. `Cargo.lock` gained
**no registry entries** — only the four member dependency lists, plus `serde_derive` under `serde`'s
`derive` feature, serde 1.0.229 having already been locked transitively.

### Two coordinator claims the implementor measured rather than took

**Decision 7 was unverified and is now confirmed.** Appending an unadmitted `[dev-dependencies]
sha2` to `mandate-types` made `cargo xtask boundaries` exit 1 with
`forbidden dependency mandate-types -> sha2`; restoring returned it to exit 0. Dev-dependencies are
gated exactly like regular ones. `Cargo.lock` was verified byte-identical after restore.

**The brief cited the wrong line.** It said the dependency loop is `xtask/src/main.rs:113`. It is
`:117`; `:113` is the `publish` metadata check. Verified in the coordinator tree. `:119` and `:104`
in the brief were correct. This is the second brief error an implementor caught by checking rather
than taking — the first was the five-versus-four stale register rows.

### The `task check` constraint, measured from both sides

Under the mandated `CARGO_TARGET_DIR` the full gate exits **201** at
`No such file or directory (os error 2)`; every step before the final binary probe passes. Symlinking
`target/debug` to the cache directory for one run gave **exit 0 with 54 tests executed**, and the
symlink was removed. This is the same `xtask/src/main.rs:266` literal-path constraint recorded above,
now measured rather than read. It is environmental and pre-existing, not a defect in this diff.

### Judgement left to the coordinator

The implementor allocated 68 of the 74 types to `mandate-types`, 4 to `mandate-model`, 2 to
`mandate-token` and **0 to `mandate-proto`**. Its reasoning: no authored type is a wire-only
contract, and admitting model or token into proto's boundary array would reverse the declared
dependency direction. `mandate-proto` instead carries `WireContract` over the 68 types it can reach,
and `tests/conformance.rs` asserts that set equals the `Owner::Types` share.

The story says proto holds "accepted wire contracts and explicit conversions". Whether a proto crate
holding none of the accepted types satisfies that is the open call. The implementor recorded its
reasoning in `crates/mandate-types/src/inventory.rs` and made `tests/inventory.rs` assert the
68/4/2/0 partition explicitly, so reversing the decision is a one-line change with a failing test to
point at. Put to the adversary before the coordinator decides.

### Not done, and each for a stated reason

No `ess generate types --target rust`: its output names types `MandateCorePrincipalId`, emits
`EssShape<hash>` helpers into the public API, is one flat file that cannot be split across four
crates, and its manifest pins `serde_json` with `arbitrary_precision`, which would unify that feature
onto xtask's `serde_json`. The 74 types are hand-declared through macros and conformance is decided
against `generated/schema/types`, the projection `cargo xtask contracts` byte-compares, so a hand
declaration cannot drift from the contract silently. The generator was run once into scratch to read
what the Rust target needs; that is how the `uuid` question was settled.

No trybuild, no `deny.toml` change, no `xtask/` change, no Rust under `generated/`, no
`cargo xtask type-properties` — decisions 3, 6, 4 and 5 held, and `type-properties` was confirmed
absent from the `Action` enum.

## Adversary pass 2 — story:runtime-decision-dossier — the unit leaves the wave

Verdict NEEDS-CHANGE. Recorded verbatim as `review-result:wave1-dossier-adversary-2`. 109 assertions,
7 red, 9 findings, all `introduced`. Origin was established rather than guessed:
`git show dc76aa3:docs/architecture/runtime-decisions.md` reports the file exists on disk but not in
`dc76aa3`, so the deliverable has no base version and nothing in it can be pre-existing.

The budget is two passes. This unit is red after both, so under the wave skill it stops here and goes
to a person. **It does not merge.** Its worktree, branch and build directory are retained until the
operator says otherwise.

### Findings ledger — `aep plan artifact findings story:runtime-decision-dossier`

| | count |
|---|---:|
| carried | 0 |
| new | 9 |
| resolved | 8 |

**Nothing survived both passes.** Every pass-1 finding was resolved, and the correction was verified
by the adversary line by line rather than taken. That is the trend, and it is a good one. What stops
the unit is that pass 2 found a new set the same size as the first.

### The three that hold the unit

| `file:line` | What |
|---|---|
| `runtime-decisions.md:161` | The document tells a reviewer no permitted source enumerates policy-engine candidates. `docs/sources/original-design.md:3364` is a section headed `## Policy engine` listing `simple internal condition language?`, `Cedar?`, `another engine?`. Cedar and Open Policy Agent are also at `:740` and `:742`. |
| `runtime-decisions.md:261` and `:31` | Both cite `combined.md:67` as listing the key provider among decisions needing a reviewed **owner**. That line says those items "need reviewed **decisions** before their implementation" and contains the word `owner` zero times. The conclusion is still true; the cited support does not establish it. |
| `runtime-decisions.md:234` | Row 8 names "the storage adapter owner" citing `ownership.md:14`, `:15`, `:16`, none of which mentions storage or an adapter, and declares no gap. A third counterexample to the narrowed universal at `:31`. |

All three are one-sentence corrections. They are held together because they are the same defect class
the unit was already sent back for once, and two of them falsify the closure claim that was offered as
the reason the class was shut.

Three more findings are about the unit's own checker, which never ships: it tests that *some*
`ownership.md` line is cited rather than a relevant one (which is why `:234` survived to this pass),
matches 16 algorithm shortnames case-sensitively so `es256` and `ecdsa` pass, and validates only that
a citation resolves to a non-blank line. They bound what the unit's green run is worth. Two are
judgement notes, and one records that pass 1's own suite now emits two dead reds.

### Correction to a coordinator decision

**The `no-op` recorded against pass 1 finding 4 was wrong, and I made it.** I accepted row 5's
policy-engine alternatives being "open and unstated" on the stated ground that no permitted source
enumerates candidates. Pass 2 measured that ground and it is false —
`docs/sources/original-design.md:3364-3368` enumerates three. The row can be bounded from a permitted
source, so the acceptance gap is closable rather than infeasible. That is the same defect as
`:161`, and it is now finding 1 of pass 2 rather than an accepted exception.

### What a person has to decide

The corrections are small and the implementor has fixed everything routed to it so far. The rule that
stops this is the two-pass budget, not a judgement that the work is bad. The options are to authorise
a third correction round, to accept the unit as-is with the three findings filed against a follow-up
story, or to take the document over.

## Adversary pass 1 — story:canonical-types

Verdict NEEDS-CHANGE. Recorded verbatim as `review-result:wave1-canonical-types-adversary-1`.
62 executed, 58 passed, 4 red. Seven findings, all `introduced` — at `dc76aa3` all four crates are
4-line scaffolds with no items and no `tests/` directory, so nothing reproduces against the base.

The adversary modified no tracked file and added four test files,
`crates/mandate-{types,model,token,proto}/tests/adversary.rs`, 311 lines. Four control cases are
green: each `compile_fail` body compiles once exactly one token changes. That is what makes the
corresponding cases proofs rather than accidents, and it is how finding 5 was caught.

### The blocker

`crates/mandate-proto/src/lib.rs:42` and `:20` promise that decoding "never coerces one identifier
into another" and that a wire form decoded into the wrong identifier "is a refusal, not a coercion".
`OrganizationId::from_wire` of a `PrincipalId` wire form returns `Ok`. The unit's own
`proto/tests/conformance.rs:58` asserts the two wire forms are **equal**, which makes refusal
impossible. Two halves of one commit contradict each other, and the contradicted half is this story's
headline claim.

### The case that proved nothing

`crates/mandate-proto/src/lib.rs:23` offered
`let organization: OrganizationId = principal.to_wire().unwrap();` as proof that the identifier types
do not convert. `to_wire` returns `Result<String, _>`, so the annotation is compared against `String`
and the case passes identically whichever identifier is named. `cargo test --doc` reports it green,
so the suite was recording a proof it never performed. The other seven `compile_fail` cases are sound.

### Coordinator decision on finding 2 — the allocation is overturned

The implementor allocated 0 of the 74 types to `mandate-proto`, on the stated ground that admitting
`mandate-model` and `mandate-token` "would reverse the declared dependency direction". The adversary
read `dependency-boundaries.json`: only `mandate-client` and `mandate-server` depend on
`mandate-proto`. Neither model nor token does, so `proto -> model` and `proto -> token` is a **new**
edge, not a reversal, and it moves neither of xtask's 20/14 counts.

Decided: extend `mandate-proto`'s array and give the six wire-named types their `WireContract`. The
story says proto holds "accepted wire contracts and explicit conversions", and a proto crate carrying
none of the accepted types does not satisfy that. The declared direction that does exist —
`types -> model -> graph/policy -> authz` and `token -> types` — is preserved.

This reverses the judgement recorded in the unit result above, on evidence the implementor did not
have. The implementor flagged it as a coordinator call rather than asserting it, and made
`tests/inventory.rs` assert the partition explicitly so reversing it is a one-line change with a
failing test to point at. That is why it was cheap to overturn.

### Remaining five, all routed to the same implementor

| `file:line` | What |
|---|---|
| `crates/mandate-types/src/record.rs:37` | an optional field decodes explicit JSON null, which the projection does not declare, and the result is not a fixed point. Systemic: the same attribute pair is on 28 fields across five records. |
| `crates/mandate-types/src/marker.rs:18` | `PersistedValue` is unsealed, so a local wrapper over `CredentialSecret` with its own impl is admitted by `canonical_record!`. INFEASIBLE — the state was built, nothing in the tree reaches it. Fix is a doc line, not a seal. |
| `crates/mandate-types/tests/inventory.rs:172` | the pattern scan reads only the top-level `$defs` node while the test's name claims more. True today, latent. |
| `crates/mandate-model/Cargo.toml:16`, `crates/mandate-token/Cargo.toml:16` | `serde_json` is a regular dependency of both and used by no library source in either, so the boundary policy permits it at runtime where it is not needed. |

First attack, no case failed twice, so all of them go back to the **same** implementor.

### What the adversary could not break

The inventory account re-derived independently from `generated/schema`: 110 type entries, 74
`mandate.core.*`, 36 `.State` all non-core and none accepted. The `x-ess-kind` breakdown is
set-identical to the three declaration macros. All 9 structs and 76 properties match the projection
exactly on field names, `required` versus `Option<T>`, and every `$ref`. Both unions' tags and all 38
enum variants match.

The "set equals the `Owner` share" assertions are **not** tautologies: the chain runs
`generated/schema` file names → `ACCEPTED` → per-crate macro declaration lists → `wire_contracts!`,
three independently authored lists each pinned to the next.

`canonical_record!`'s field-omission guard holds — a field not named is `E0027`, and the full set of
`PersistedValue` impls is closed and enumerable. Round-trip is honest: serialize, re-serialize for
determinism, decode, compare, re-serialize for fixed point, refuse every `REJECTED_WIRE` form, for
all 74 rather than a sample. base64 and UUID codecs survived padding, empty input, embedded `=`,
trailing-bit and case probes.

## Correction round 1 — story:canonical-types

Six of seven findings corrected. The seventh is argued unsatisfiable, with a runnable demonstration
rather than an opinion. 66 executed, 65 passed, 1 red. 43 → 47 test targets.

No lane's count fell. The +4 are the implementor's: one container-laundering case in types, two
wire-coverage cases in proto, one added doctest twin in proto.

### The one still red, and why it stays red

`mandate-proto/tests/adversary.rs::a_wire_form_decoded_into_the_wrong_identifier_is_refused`. The
implementor took the offered resolution — the doc was wrong, separation is type-level — and left the
adversary's case standing, unmodified and red, rather than weakening it. That is the correct move.

**Coordinator verification of the unsatisfiability claim, done independently.** The `$defs` nodes of
`mandate.core.PrincipalId` and `mandate.core.OrganizationId` are identical after dropping `title` and
`x-ess-name`: both are
`{"type":"string","format":"uuid","pattern":"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$","x-ess-kind":"newtype"}`.
Read from the projection in the unit's own worktree, not taken from the report.

It follows that `from_wire`, being a function of the string alone, cannot both accept
`OrganizationId::parse(x).to_wire()` and reject the byte-identical `PrincipalId::parse(x).to_wire()`.
The adversary's own file pins `to_wire()` to the bare JSON string, so no type tag can ride along.

The story requires proof that `PrincipalId` cannot substitute `OrganizationId`. Type-level separation
proves that in Rust, which is the only level this story's scope reaches — changing the wire form means
changing ESS meaning, which the story forbids. Put to adversary pass 2 before it is settled.

### The six, and one that went further than asked

| # | Correction |
|---|---|
| 2 | `mandate-proto`'s boundary array gained `mandate-model` and `mandate-token`; `wire_contracts!` covers all **74**, with `WIRE_CONTRACTS.len() == 74` and equality with `ACCEPTED` asserted so the gap cannot reopen. `libraries` still 14, packages still 20. The false rationale at `inventory.rs` was replaced and the doc records that an earlier revision gave the wrong reason. |
| 3 | Class fixed, not the field: **30** optional fields, not the 28 the coordinator's routing message counted. `conformance::check` gained `reject_null_for_every_declared_field`, which walks every encoded sample's keys, so a record cannot gain a null-tolerant field without a case appearing for it. |
| 4 | The proto `compile_fail` body is now `fn tenant(_: OrganizationId){}` / `tenant(PrincipalId::parse(..).unwrap())` with a positive twin differing only in the identifier. |
| 5 | The `inventory.rs` pattern scan recurses objects and arrays at any depth. Still exactly two patterns; a third anywhere now fails. |
| 6 | Claim narrowed in `marker.rs` and `canonical_record!`'s doc. **It also closed the hole at runtime**, which was more than the routing asked for: `CredentialSecret`/`CredentialProof` now serialize as `REDACTED`, not valid base64 so it cannot decode back, and the declared base64 form moved to a named `Canonical::encode` that nothing derives. A doc line alone would have left the adversary's wrapper case red. |
| 7 | `serde_json` moved to `[dev-dependencies]` in model and token, boundary entries kept. It stays regular in types (the conformance harness calls it) and proto (`WireContract` defaults). |

### One of the adversary's files was reformatted, and the implementor proved it was only that

`cargo fmt --all` took `crates/mandate-proto/tests/adversary.rs` from 107 to 110 lines by wrapping one
`assert!` across four. The implementor reconstructed the pre-format text, ran `rustfmt --edition 2024`
on it and `cmp`'d: condition and message byte-identical, the shipped file is exactly
`rustfmt(original)`. The other three adversary files are untouched. Leaving it unformatted was the
alternative and it fails the repository's own `cargo fmt --all -- --check`.

Correction round 1 counts as the unit's one correction. Pass 2 is the last it gets.

## Adversary pass 2 — story:canonical-types — the unit leaves the wave

Verdict NEEDS-CHANGE. Recorded as `review-result:wave1-canonical-types-adversary-2`. 69 executed,
66 passed, 3 red. Six findings, all `introduced`.

The budget is two passes. This unit is red after both, so it stops here and goes to a person with the
dossier. **Neither unit merged.**

### The unsatisfiability ruling — three parties, one answer

Pass 2 was asked to attack the implementor's claim and ruled it correct, having verified the two
`$defs` nodes itself rather than through the unit's test. It also ruled out all three alternatives the
coordinator proposed:

| Alternative | Ruling |
|---|---|
| tagged envelope at the contract boundary | Out. `mandate-types/tests/conformance.rs:143` validates the encoded form against `$defs[ess_name]`, which is `{"type":"string"}`; an object panics at "encodes as a JSON string". Trades one red for three, two of them the projection. |
| `from_wire` taking a context | Out on merit, not feasibility. Implementable and changes no ESS meaning, but the discriminating information comes from the caller's own argument, so the refusal is a tautology about the caller. It renames the type-level separation the unit already has, more weakly — runtime instead of compile time. |
| `parse`/`from_wire` split | Out trivially. Both are functions of the string alone. |

It also corrected the implementor's argument on one point: the gate an envelope would break is the
projection conformance suite, **not** `cargo xtask contracts` — that gate only byte-compares
`generated/` against a regeneration, and no Rust change can move it.

The acceptance requirement "prove `PrincipalId` cannot substitute `OrganizationId`" is discharged by
the compile_fail pair, verified to fail with exactly `E0308` and nothing else.

### What holds the unit

| `file:line` | What | Severity |
|---|---|---|
| `mandate-proto/tests/adversary.rs:28` | `task check` exits 1 because pass 1's case is red, so the acceptance statement is not met by the tree | blocker |
| `mandate-proto/tests/adversary.rs:25` | that case is INFEASIBLE. Only the coordinator may retire it — the implementor doing so would read as weakening an adversary case | blocker-to-clear |
| `adversary_second_pass.rs:132` | `serde` renders `"<redacted>"` for both transient types, which the declared base64 pattern refuses. 12 files under `generated/schema/{commands,responses}` `$ref` them. Nothing reaches it today; it is a wall the next unit hits on day one, invisible because the suite is green about it | warning |
| `mandate-types/src/macros.rs:164` | the doc claims the base64 form is reachable only through `Canonical::encode`; `WireContract::to_wire` returns the material to a caller that never names it | warning |

Two notes: the recursive pattern scan is correct but unobservable against this corpus, and the
conformance harness ships in the library rather than behind a feature, so `Canonical::encode` links
into every downstream crate.

Pass 2's merge call: do not merge as it stands, but the only blocker is bookkeeping rather than code.
Retire the unsatisfiable case with the reason recorded and the gate goes green.

### All six corrections verified, and two coordinator claims corrected

74 wire contracts, no duplicates, set-equal to `ACCEPTED`; `libraries` 14, packages 20; `proto -> model`
and `proto -> token` are new edges with no cycle. 30 optional fields with 30 `deserialize_with`, one
to one — **the implementor's count was right and pass 1's was two short.** Every `compile_fail` body
compiled standalone: single-error, correct. `serde_json` shows as `('serde_json','dev')` inside
`cargo metadata`'s `dependencies`, which verifies brief decision 7 a second way.

## Close — the wave merged nothing

Both units reached their two-pass budget red. Under the wave skill that ends the loop for both: after
two attacks, hand over, do not open a third.

`integration/wave-20260918-002` carries the wave's record and no unit work. Each unit is committed on
its own branch so nothing is lost:

| Branch | Commit | Contents |
|---|---|---|
| `impl/canonical-types` | `0a8c32e` | 32 paths, all inside the declared seven-path surface |
| `impl/runtime-decision-dossier` | `a6e18e6` | one file, 344 lines |

Three managed trees are retained with their build directories: `mandate-w1-coordinator`,
`mandate-w1-canonical-types`, `mandate-w1-runtime-decision-dossier`. A unit that left the wave keeps
its tree until the operator says otherwise. No tree was finished, no `gc` was applied, no branch was
deleted, nothing merged to `main`, no tag.

### What the wave produced

| | |
|---|---|
| Test targets | 34 → 47 |
| Tests executed | 0 → 69 (66 passing) |
| Review-results recorded | 4, verbatim |
| Findings raised | 30 |
| Findings resolved | 8 |
| Stories filed from findings | 1 — `story:gate-reads-document-deliverables` |
| Coordinator decisions overturned by evidence | 2 |

The two overturned decisions are worth keeping. The `no-op` on the dossier's policy-engine
alternatives rested on a claim that a later pass measured and found false. The acceptance of
`proto = 0 types` rested on a dependency-direction reason that a later pass read out of
`dependency-boundaries.json` and found unsupported. Both were made by the coordinator on an
implementor's report and corrected by an adversary reading the tree.

### Cost

Nine sub-agent runs: 2 scopers, 2 implementors with 2 correction rounds, 4 adversary passes.
Approximately 1.60 million sub-agent tokens, 437 tool uses.

---

# Reopened on operator instruction — both units merged

The operator authorised merging both units after reading the hand-over above. The two-pass budget
hold is lifted by that instruction; everything below follows it.

## The unsatisfiable case, retired by the coordinator

`mandate-proto/tests/adversary.rs::a_wire_form_decoded_into_the_wrong_identifier_is_refused` is
retired and rewritten to assert what was decided, which is the wave skill's third option for a
correct case the unit will not satisfy. Retiring it is the coordinator's act: the implementor doing
so would read as weakening an adversary case, and the adversary is forbidden from touching it.

It is now `the_two_identifiers_share_one_declared_wire_form_no_decoder_can_discriminate`, and it is
not vacuous — it reads both schema files, asserts the declared nodes are equal after dropping
`title` and `x-ess-name`, asserts both identifiers encode to the same string, and asserts a decoder
accepts it. It fails if the projection stops declaring them identically, which is the state that
would make the original requirement meaningful.

## Correction round 2 — story:runtime-decision-dossier

Green. All three findings corrected and verified by the coordinator against the sources rather than
taken from the report.

`original-design.md:3364` is a section headed `## Policy engine` listing three candidates — read
directly in the unit's own tree. Row 5 now enumerates all six candidates across both halves and
selects none. The "open and unstated" claim is gone.

The implementor went past what was routed in two useful ways. It carried across the fourth question
that section asks and the dossier did not answer — how resource attributes are trusted and
distributed — because an engine chosen without that answer is chosen against unknown inputs. And it
checked the neighbouring `no source states a decision-latency target` claim for the same shape
before it had to, finding it true but weakly grounded, and gave it its own basis.

**The meta-correction is the valuable part.** "34 universals enumerated, exactly two false, class
closed" was itself a hand-made universal and it was wrong. The document now carries a table of the
seven claims it makes about itself, each bound to the check that enforces it, verified
bidirectionally — a claim whose wording drifts, or a check that is dropped, fails the gate. Two
judgements are recorded as deliberately outside the table.

Citations 213 → 233. All eight mutants red; two of them passed before this round.

## Correction round 2 — story:canonical-types

Green. 72 executed, 0 red, verified by the coordinator running the suite independently: real exit 0,
72 passed, 0 failed.

`Serialize` is unchanged and the redaction stays, so a container that says nothing still redacts.
Two `serialize_with` helpers let a container that must carry credential material name the helper at
the field. The optional variant exists because
`systems/mandate/domains/credential.yaml:298` declares `Optional<mandate.core.CredentialProof>` — a
shape the contract asks for rather than one invented.

`WireContract::to_wire` keeps rendering the declared base64 on the two transient types, and the
decision is recorded rather than assumed: gating it would have taken `WIRE_CONTRACTS` from 74 to 72
and turned the wire-coverage case red, buying a true doc with a broken contract. So the docs moved.
**Four** sites claimed the base64 form was reachable only through `Canonical::encode`, not the two
the routing named; all four now list the three named routes, and `macros.rs` records that an earlier
revision claimed otherwise and was wrong.

### The adversary's case was changed, and the change was disclosed

`projection_violations` gained a `render` parameter. The two controls pass `serde_rendering`, which
is the old behaviour verbatim; the two subjects pass `declared_field_rendering`, which builds the
envelope a realized command would. The pattern lookup, the per-sample loop, the deciders and the
`assert!(failures.is_empty(), …)` at `:170` are intact — coordinator-verified in the file, not taken
from the report. That is re-pinning to what was decided, which the wave skill permits, and the reason
is written into the case's own doc comment where the next reader will find it.

One inaccuracy in the implementor's report: it said the failure message lost the word "serde". It did
not — `:172` still reads "admitted types whose serde serialization is not the declared form", which
is now slightly misleading, since two of the four subjects are no longer rendered through serde. Too
small to spend a round on; recorded here instead.

## Merges

| Merge | Branch | Contents |
|---|---|---|
| `0efb797` | `impl/canonical-types` | 74 accepted types across four crates |
| `cd47045` | `impl/runtime-decision-dossier` | eleven-row dossier, 369 lines |

Serial, `--no-ff`, message from a file, no conflicts.

## Closing gate — the whole thing, once, on the merged head

`task check` on `cd47045`, with `CARGO_TARGET_DIR` unset so `xtask/src/main.rs:266` finds
`target/debug/<bin>`. **Real exit 0**, read per step.

| Step | Result |
|---|---|
| `rustc` pin, `aep --version` | pass |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | pass |
| `cargo test --workspace --locked` | 45 targets + 14 doctest lanes, **72 executed, 0 failed, 0 ignored** |
| `cargo build --workspace --locked` | pass |
| `cargo xtask boundaries` | `20 packages satisfy metadata and dependency boundaries` |
| `cargo xtask corpus` | `47 contract scenarios traced; source hashes match` |
| `cargo xtask contracts` | `ESS projections match deterministically` |
| `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok` |
| `aep plan artifact validate` | `77 artifact(s) … valid` |
| executable scaffold refusals | pass |

The 9 no-findings-block diagnostics predate this wave. All four review-results it recorded carry
explicit findings blocks.

Baseline before this wave: 34 test targets executing **0** tests.

## Stories moved terminal

Both `active -> implemented`, each against a `test_result` recorded from the gate on `cd47045`.
The store refused the first attempt — `implemented is on the ladder and not yet earned: reaching
implemented needs at least 1 test_result record(s)` — which is the ladder doing its job.

**A bad record exists and is not being hidden.** Working out the evidence verb's arguments, the
coordinator recorded one `test_result` against `story:canonical-types` with the source string
`probe`. Evidence is append-only, so it cannot be removed; the real record sits beside it and the
journal holds both. `story:canonical-types` therefore shows `test_result=2` where one is meaningless.

## Publication — blocked, and not worked around

`b10x-gates` pre-push refuses: `outgoing commit must have the exact bot author and committer`. Every
commit this wave made carries author and committer `b10x-bot[bot]`, verified. The rejected commit is
`dc76aa3`, the PR #4 merge made by another actor at 03:47, whose committer is
`GitHub <noreply@github.com>`. The newest signed receipt `76187c49` binds commits up to `9a0304da`
and does not list `dc76aa3`, so the merge is re-presented as unverified outgoing.

Minting a fresh receipt with `b10x-gates check --repo <tree> --head HEAD --receipt <path>` fails with
`protected file unavailable`, real exit 1 — a condition on a file under `~/.config/b10x/gates`.

The workspace `AGENTS.md` says a GitHub-created pull-request merge may legitimately record a
`web-flow` committer. Advancing the trusted receipt past it is publication authority and was not
taken. `as-bot.sh` refuses `--no-verify` on pushes and `AGENTS.md` forbids bypassing hooks; neither
was attempted. **The integration branch is committed locally and unpublished.**
