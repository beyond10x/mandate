# Waves I, J and K — execution

Opened 2026-09-23 on `integration/wave-20260923-001`, cut from `main` at `92fc026` (`v0.4.0`).
Coordinator: an interactive session running `aep-drive:wave` 0.9.3. The operator asked for the
next three waves, clean worktrees and at most three concurrent agents.

The three waves accumulate on one integration branch (`AGENTS.md` § Integration batches). Each wave
forks its units from the integration branch as the previous wave left it, so a collision *across*
waves is sequencing, not a conflict.

## Selection

`aep plan artifact waves --kind story --status draft --format json` exited 0. Before this session it
reported 17 stories unassessed. All 17 were scoped by `aep-drive:story-scoper` (three agents, one
batch of five or six stories each, because of the operator's three-agent cap) and their typed scope
entries and `## Scope` sections written. After that the verb reports **unassessed: none**.

The verb reads typed scope and not blockers. Every story it groups that carries an open
`decision-blocker` was excluded on that ground before any pair was judged — `agent-authority-kernel`,
`audit-client`, `directory-provenance`, `domain-folds-over-the-kit`, `audit-worker-delivery`,
`constrained-exchange`, `agent-security`, `graph-policy-adapter`, `protocol-adapters`,
`advanced-delegation`, `oauth-integration`.

Collisions the verb reports that shaped this selection (verbatim ids; 70 collisions in total):

| a | b | path | confidence |
|---|---|---|---|
| `story:cross-crate-clauses` | `story:federation-rule-disjointness` | `contracts/obligations/federation.json` | cited |
| `story:cross-crate-clauses` | `story:identity-tenant-containment` | `contracts/obligations/identity.json` | inferred |
| `story:sts-lifetime-bounds` | `story:sts-refusal-draws-nothing` | `services/sts/src/issue.rs` | inferred |
| `story:sts-lifetime-bounds` | `story:sts-refusal-draws-nothing` | `services/sts/src/redemption.rs` | inferred |
| `story:control-plane-loopback-fold` | `story:federation-admission-port` | `services/control-plane/src/adapters.rs` | inferred |
| `story:control-plane-loopback-fold` | `story:linked-event-method-unenforced` | `services/control-plane/src/adapters.rs` | inferred |
| `story:enabled-for-issuer-filters-in-the-implementor` | `story:federation-rule-disjointness` | `crates/mandate-federation/src/record.rs` | inferred |
| `story:epoch-snapshot-generations` | `story:identity-tenant-containment` | `crates/mandate-identity/src/port.rs` | inferred |

`story:jit-principal-record` is `active`, so the verb (run over `draft`) does not see it. Its typed
scope — `services/control-plane/src/adapters.rs`, `crates/mandate-identity/src/port.rs`,
`services/control-plane/Cargo.toml`, `dependency-boundaries.json`,
`services/control-plane/tests/adapters.rs` — was compared by hand. It shares `adapters.rs` with
`control-plane-loopback-fold` and `port.rs` with `identity-tenant-containment`, so both go in wave J.

### The three waves

| wave | unit | story | serves | scope |
|---|---|---|---|---|
| I | I1 | `story:jit-principal-record` | `vision:mandate` | cited + inferred |
| I | I2 | `story:folded-is-not-an-address-fold` | `vision:mandate` | cited, one inferred test file |
| I | I3 | `story:sts-lifetime-bounds` | `vision:mandate` | cited for `registry.rs`, inferred for the issuance sites |
| J | J1 | `story:control-plane-loopback-fold` | `vision:mandate` | cited |
| J | J2 | `story:identity-tenant-containment` | `vision:mandate` | cited |
| J | J3 | `story:federation-rule-disjointness` | `vision:mandate` | cited |
| K | K1 | `story:cross-crate-clauses` | `vision:mandate` | cited for xtask, inferred for contract files |
| K | K2 | `story:sts-refusal-draws-nothing` | `vision:mandate` | cited |
| K | K3 | `story:road-lane-child-prints-address` | `vision:mandate` | cited |

`story:eventlog-repin-0-3-0` lands before wave I as a coordinator alignment commit: it writes
`Cargo.toml` and `Cargo.lock`, which a unit adding a dependency would also touch.

### Left out, and why

| story | reason |
|---|---|
| `linked-event-method-unenforced` | premise contradicted by `services/control-plane/src/adapters.rs:962-970`; needs a decision on a seeded link's method. Recorded in its `## Scope` |
| `federation-admission-port` | the seed path at `adapters.rs:923` has no caller to admit; undecided. Recorded in its `## Scope` |
| `enabled-for-issuer-filters-in-the-implementor` | collides with J3 and K1's neighbours; next candidate |
| `epoch-snapshot-generations` | largest candidate; the refresh-proof → session port is named nowhere |
| `refusal-discriminators` | the amended acceptance's counts (7 / 1 / 5) do not reconcile |
| `conformance-denial-reasons` | where reason and clause are recorded is undecided (`run.json` is ESS-owned) |
| `unpublished-refusals` | collides with K1 on the registry step; large |
| `ess-evidence-suite-version` | option 1 needs an AEP change; the body leaves the option open |
| `ess-synthesizer-prerequisites` | needs an ESS release that does not exist |

## Commits these waves authorise

Per unit: one commit, plus each adversary pass's test file. The merges into
`integration/wave-20260923-001`. The coordinator's opening, alignment and closing store commits.
The publication of the integration branch for recovery proof. Nothing else — no PR, no merge into
`main`, no tag, no release.

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `92fc026`, clean but for untracked `.agents/`, which no unit touches |
| leftover worktrees | `mandate-w1-canonical-types`, `mandate-w1-runtime-decision-dossier` — retained on `no-remote-recovery-proof` (see `docs/handoff.md`); no branch this wave uses |
| leftover wave scratch | wave H's scratch root is gone |
| free disk | 100G, `/` at 88% |
| compiler cache | `sccache` present |
| model budget | none stated; the operator's cap of three concurrent agents applies |
| Gates baseline | `92fc026` since `gates-policy` `dc5d16d`; branches cut from `main` publish |

## Units

Unit worktrees live under the worktree manager's tree root; each builds into its own `target/`.
Scratch roots are under `~/.cache/claude-tmp/wijk/`.

| unit | branch | managed id | build dir | scratch | stage |
|---|---|---|---|---|---|
| coordinator | `integration/wave-20260923-001` | `mandate-wijk-coordinator` | its own `target/` | `~/.cache/claude-tmp/wijk/` | open |
| I1 | `impl/jit-principal-record` | `mandate-wi-jit-principal` | its own `target/` | `~/.cache/claude-tmp/wijk/i1/` | planned |
| I2 | `impl/folded-is-not-an-address-fold` | `mandate-wi-folded` | its own `target/` | `~/.cache/claude-tmp/wijk/i2/` | planned |
| I3 | `impl/sts-lifetime-bounds` | `mandate-wi-sts-lifetime` | its own `target/` | `~/.cache/claude-tmp/wijk/i3/` | planned |
| J1 | `impl/control-plane-loopback-fold` | `mandate-wj-loopback` | its own `target/` | `~/.cache/claude-tmp/wijk/j1/` | planned |
| J2 | `impl/identity-tenant-containment` | `mandate-wj-tenant` | its own `target/` | `~/.cache/claude-tmp/wijk/j2/` | planned |
| J3 | `impl/federation-rule-disjointness` | `mandate-wj-disjoint` | its own `target/` | `~/.cache/claude-tmp/wijk/j3/` | planned |
| K1 | `impl/cross-crate-clauses` | `mandate-wk-cross-crate` | its own `target/` | `~/.cache/claude-tmp/wijk/k1/` | planned |
| K2 | `impl/sts-refusal-draws-nothing` | `mandate-wk-draws` | its own `target/` | `~/.cache/claude-tmp/wijk/k2/` | planned |
| K3 | `impl/road-lane-child-prints-address` | `mandate-wk-road-lane` | its own `target/` | `~/.cache/claude-tmp/wijk/k3/` | planned |

## Stage log
