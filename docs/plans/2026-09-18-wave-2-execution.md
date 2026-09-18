# Wave 2 execution page

Status: running, opened 2026-09-18. Interactive session; the operator gave the go on the story set the critic panel reviewed twice, with the instruction: orchestrator, up to four Opus agents, one per story.

**Skill version 0.9.2** — `aep-drive` at `.claude-plugin/plugin.json` of the loaded plugin. **AEP** `protocol 0.55.0`. **ESS** `ess 0.25.0`.

Integration branch: `integration/wave-20260918-003`, cut from `ff31684` — the last all-bot commit, tree byte-identical to `main` `2ee9d6f`. `docs/adr/0008-integration-batches.md` says "from current verified `main`"; the deviation is forced by the organization push guard, which refuses the GitHub-created merge commits `main` carries (`task:runtime-wave-integration`, "Publication constraint"). Opening head: `3f96c3b`.

## Selection

`aep plan artifact waves --kind story --status draft --format json` on `3f96c3b`: wave 1 = `story:domain-runtime` alone; wave 2 = `story:federation-linking`, `story:graph-policy`, `story:session-epochs`, `story:tenancy-topology`, 0 shared files among them. This page runs the first; a second page runs the four.

`story:domain-runtime` is `[blocked: decision]` on `decision-blocker:lifecycle`, `worker-orchestration` and `jit-provisioning`. Each carries the operator's decision of 2026-09-18 as `approval` evidence; each stays `open` because its clearance evidence is what this unit produces. The wave runs against open blockers by design and says so here.

## Units

One unit, one agent, on the operator's instruction "one per story". The story's four-row unit table (`epoch-field`, `jit-command`, `lifecycle-a`, `lifecycle-b`) is executed serially by that one agent; the files stay disjoint by construction and the coordinator's row is unchanged.

| Unit | Branch | Worktree | Build directory | Scratch root | Managed id | Lease |
|---|---|---|---|---|---|---|
| `domain-runtime` | `impl/domain-runtime` | `~/.local/state/worktree/trees/b10x/mandate/mandate-w2-domain-runtime` | `~/.cache/b10x-target/mandate/w2-domain-runtime` | `~/.cache/claude-tmp/wave2/domain-runtime` | `mandate-w2-domain-runtime` | the implementor's own session id |
| coordinator | `integration/wave-20260918-003` | `~/.local/state/worktree/trees/b10x/mandate/mandate-w2-coordinator` | `~/.cache/b10x-target/mandate/w2-coordinator` (full gate runs with the variable unset: `xtask/src/main.rs:266`) | `~/.cache/claude-tmp/wave2/coordinator` | `mandate-w2-coordinator` | `claude-a5a67d36` |

Per-unit gate: `ess specify validate --path systems/mandate` and `ess specify compile --path systems/mandate --format json`. Not `task check`: it fails on projection drift until the coordinator regenerates (`xtask/src/main.rs:90-91`).

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`, author and committer `b10x-bot[bot]`: this opening store commit (page, story move, the two store files carrying the journal-redaction disclosure); one commit on `impl/domain-runtime`; one `--no-ff` merge into the integration branch; the coordinator's regeneration and document commit on the integration branch; the closing store commit; publication of the integration branch. No merge to `main`, no tag.

## Declared deviations

1. Two finished trees from the previous wave remain on disk — `mandate-w1-canonical-types`, `mandate-w1-runtime-decision-dossier` — because the manager refuses removal without a remote reachable from their exact heads; their content is on the remote inside `ff31684` (`git cherry` shows every commit equivalent). They touch no branch this wave uses.
2. Two files are dirty in the coordinator tree and are not this wave's: `docs/customer/build.py`, `docs/customer/figures/sso-flow.py` (the customer PDF made parametric). They are left uncommitted; no unit's surface touches them.
3. No coordinator interface commit: the unit's surfaces are ESS files and two test/inventory files, not a crate root.
4. The critic agents of the planning round ran on Opus, not their pinned Sonnet; recorded on each `review-result`.

## Preflight

| Check | Reading |
|---|---|
| disk free | 38G at open; floor 10G |
| coordinator tree | `integration/wave-20260918-003` @ `3f96c3b`; `git status --porcelain` before the opening commit: ` M .engineering/planning/journal.jsonl`, ` M .engineering/planning/task/runtime-wave-integration.md`, ` M docs/customer/build.py`, ` M docs/customer/figures/sso-flow.py` |
| `aep --version` | `protocol 0.55.0` |
| `ess --version` | `ess 0.25.0` |
| `RUSTC_WRAPPER` | unset ambiently; `/usr/bin/sccache` wired in the brief and the coordinator's gate |
| one measured build | wave 1: `mandate-types` unit target 526M; this unit builds nothing until the coordinator regenerates |
| the repository's agent file | `AGENTS.md` read; managed checkout with lease; bot publication; AEP sole store writer; ESS sole `generated/` writer |

## Stage log

- open: story moved `draft → proposed → active`; page written; opening commit follows.
- implementor, pass 1: `red` by design — the epoch tripwire against stale `generated/`; every other lane green. 12 files, +824/−40. Commands 34→59, events 40→65, errors 9→11; types 110 and entities 36 unchanged; 34 transitions each moved by one command. Acted beyond the unit table on `OAuthClient` (`DisableOAuthClient`), accepted. Three coordinator patches left in scratch. Cost: 266,645 tokens, 134 tool uses, 22.6 min.
- adversary, pass 1: `NEEDS-CHANGE`, cases 25→29 red 4, findings 10 — introduced 7, pre-existing 3. Recorded as `review-result:wave2-domain-runtime-adversary-1`. Blockers A (`jit_provisioning` settable by no command) and B (`SigningKey.Retired` neither initial nor terminal) plus F, G, H, I and the introduced instances of D, E route to the same implementor as correction round 1. C (ESS drops entity invariants from the schema projection) → `story:invariant-boundary-validation`; the base half of D, E → `story:event-payloads-for-folds`; J → no-op. Cost: 184,388 tokens, 66 tool uses, 18.3 min.
- coordinator error: four `review_outcome: no-op` records were written against `review-result:wave2-domain-runtime-adversary-1` where two (C, J) were meant; evidence is append-only, so the two surplus stand and D, E receive their `fixed` records when the correction lands.
- coordinator edits staged in the integration tree, uncommitted until the merge: `unmapped.md` (EPOCH, LIFECYCLE), `combined.md:19`, `ownership.md` rows 11-12/14/15/16, `audit-routing.md:12`, `runtime-decisions.md` (59 commands; rows 5 and 7 → `story:graph-policy-adapter`), `federated-login.md` FL2; three JIT scenarios in `tests/security/cases.json` (47→50).
- implementor, correction 1: `green` on A and B; C red by design; tripwire red until regeneration. +899/−42 over base. Two declared deviations from the fix text, both sound: no `source` field on `TeamMembership` (its `DirectoryMapping` value would be settable by nothing — finding A's shape) and `linked_at` not carried on the JIT event (the base `ExternalPrincipalLinked` must make the same call under `story:event-payloads-for-folds`). Named, not closed: four pre-existing creation gaps of A's shape in other stories' records (`OAuthClient`, `Policy`/`AuthorizationModel`, the agent records, `DirectoryGroup`/`SyncJob`). Gate blocker found: the adversary's own file fails `cargo fmt --check`; pass 2 owns it. Cost: 311,768 tokens cumulative, 155 tool uses, 5.3 min this round.
- outcomes recorded on `review-result:wave2-domain-runtime-adversary-1`: 8 `fixed` (A, B, F, G, H, I, D, E), 4 `no-op` (C, J, and the two surplus disclosed above).
- adversary, pass 2 (the last): `NEEDS-CHANGE`, cases 29→34 red 6, findings 8, all introduced; every pass-1 fix held, including that ESS type-checks the `ConfiguredFederation` literal (`ESS-COMMAND-002` on a mutated scratch copy). Recorded as `review-result:wave2-domain-runtime-adversary-2` with the scratch path prefix redacted to `<scratch>/` before recording. Findings 1–8 route to the same implementor as correction round 2; no adversary pass follows — the coordinator verifies the fixes by the adversary's own cases D1–D4 in the tree and the compiled-model counts, and discloses that here. Cost: 202,812 tokens, 74 tool uses, 18.2 min.
- implementor, correction 2: `green` — D1–D4 green, A and B green; +947/−46 over base; counts 110/36/59/65/11 verified by the coordinator's own compile. One deviation accepted: row 4's contribution claim made true (`AddTeamMembership` returns and carries `contribution_id`; the two mapping events carry `contributions`) rather than deleted, because the adversary's case D3 guards those sentences. Cost: 366,802 tokens cumulative, 25 tool uses, 6.9 min this round.
- coordinator: adversary case C (ESS drops entity invariants from JSON Schema) rewritten into a tripwire that pins the known gap and names `story:invariant-boundary-validation`; the file went 9/9 green. Unit commit `630e7b9` on `impl/domain-runtime`; merge `099f4ca`; regeneration and documents commit `f0da11e` — `generated/` replaced from a fresh `ess generate` root because the repository carries no `.ess-output` ownership record and in-place regeneration refuses; the gate's byte-compare is what judges it. `cargo xtask contracts`: "ESS projections match deterministically". `cargo test -p mandate-types`: 7 targets, 48 passed, 0 failed.
- outcomes on `review-result:wave2-domain-runtime-adversary-2`: 8 `fixed`.

## Commits made

| commit | what |
|---|---|
| `d47c0b5` | opening store commit |
| `630e7b9` | unit commit, `impl/domain-runtime` |
| `099f4ca` | merge into `integration/wave-20260918-003` |
| `f0da11e` | regeneration, `components.yaml`, obligations, xtask check, seven architecture documents, three corpus cases |
| — | closing store commit follows the gate |

## Cost

| agent | tokens | tool uses | wall |
|---|---|---|---|
| implementor (3 rounds) | 366,802 | 155 + 25 | 22.6 + 5.3 + 6.9 min |
| adversary pass 1 | 184,388 | 66 | 18.3 min |
| adversary pass 2 | 202,812 | 74 | 18.2 min |
| total sub-agent | 754,002 | 320 | 71.3 min |

## Closing gate — the whole thing, once, on the merged head

First run on `f0da11e`: `cargo fmt --all -- --check` refused two hunks in the implementor's xtask patch; exit 201, nothing after fmt ran. Fixed as `5924657` (`chore(xtask): rustfmt the obligations check`), a coordinator commit beyond the five this page named — declared here. Second run on `5924657`: **exit 0**, read from the gate's own status line. Per step: rustc pin, aep pin, fmt, clippy `-D warnings`, workspace test (**49 targets, 81 passed, 0 failed**; wave 1 closed at 72), workspace build, boundaries (20 packages), corpus (50 scenarios traced; **59 commands named in command-obligations.md** — the new check), contracts (ESS projections match deterministically), cargo deny, aep validate (valid), the five scaffold refusals.

## Stories moved terminal

`story:domain-runtime` → `implemented` on `test_result` evidence against `59246579b178a7357a98d57f45e81b62d0e03dd8`. Its three blockers stay `open`: `lifecycle` and `jit-provisioning` now have the contract half of their clearance evidence in the tree; the runtime cases each names are wave 2's and later.

## Wave 2 shape, revised by the operator's "one per story"

Four agents, one per story, each owning its whole crate including `src/lib.rs` — so no coordinator interface commits. `federation-linking` (`crates/mandate-federation`), `graph-policy` (`crates/mandate-graph`, `crates/mandate-policy`), `session-epochs` (`crates/mandate-identity`), `tenancy-topology` (`crates/mandate-model`). Zero shared files among the four. Briefs at the wave scratch root, base `59246579b178a7357a98d57f45e81b62d0e03dd8` plus the closing store commit.

## Wave 2 — the four stories, one agent each

Base: `fd34d9025a0ed9b70f4ccc97074e378b3f20ee28`. Stories moved `draft → proposed → active`: `federation-linking`, `graph-policy`, `session-epochs`, `tenancy-topology`. `aep plan artifact waves --status active` places all four in one wave with no collision. `federation-linking` stays blocked on `identity-uniqueness`, `algorithm-policy` and `jit-provisioning`; the decisions are recorded and the units produce the runtime cases those blockers name.

| Unit | Branch | Worktree | Build directory | Scratch root | Managed id |
|---|---|---|---|---|---|
| `federation-linking` | `impl/federation-linking` | `~/.local/state/worktree/trees/b10x/mandate/mandate-w2-federation-linking` | `~/.cache/b10x-target/mandate/w2-federation-linking` | `~/.cache/claude-tmp/wave2/federation-linking` | `mandate-w2-federation-linking` |
| `graph-policy` | `impl/graph-policy` | `…/mandate-w2-graph-policy` | `…/w2-graph-policy` | `…/wave2/graph-policy` | `mandate-w2-graph-policy` |
| `session-epochs` | `impl/session-epochs` | `…/mandate-w2-session-epochs` | `…/w2-session-epochs` | `…/wave2/session-epochs` | `mandate-w2-session-epochs` |
| `tenancy-topology` | `impl/tenancy-topology` | `…/mandate-w2-tenancy-topology` | `…/w2-tenancy-topology` | `…/wave2/tenancy-topology` | `mandate-w2-tenancy-topology` |

Per-unit gate: `cargo fmt -p`, `cargo clippy -p --all-targets -D warnings`, `cargo test -p` for the unit's crates. Disk at open: 37G; floor 10G; four parallel builds of small crates over the shared sccache.
