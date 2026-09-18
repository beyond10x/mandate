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
