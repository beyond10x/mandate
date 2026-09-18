# Wave 3 execution page

Status: opening, 2026-09-18. Interactive session; the operator approved the road plan of 2026-09-18 (forecast order; real verifier dependencies admitted; RS256 + ES256 allowlist; customer-doc scripts preserved outside the repository) and keeps the standing instruction: orchestrator, up to four Opus agents, one per story.

**Skill version 0.9.2** — `aep-drive` at `.claude-plugin/plugin.json` of the loaded plugin. **AEP** `protocol 0.55.0`. **ESS** `ess 0.25.0`.

Integration branch: `integration/wave-20260918-004`, cut from `20f354d` — the last all-bot commit, tree byte-identical to `main` `46167f6` (`git diff --stat 20f354d 46167f6` empty). `docs/adr/0008-integration-batches.md` says "from current verified `main`"; the deviation is the one `task:runtime-wave-integration` records: the push guard refuses the GitHub-created merge commits `9fca656` and `46167f6`.

## Selection

Forecast row 4 (`docs/plans/2026-09-18-next-ten-waves.md:25`) is `story:check-api`, `story:directory-provenance`, `story:pkce-sessions`. This wave runs `check-api` and `pkce-sessions` from that row, plus two stories the wave-2 close created and the forecast predates: `story:event-payloads-for-folds` (contract-only; the fold inputs every event-log host needs) and `story:gate-reads-document-deliverables` (one `xtask` step; coordinator-owned file, no other story touches `xtask/` this wave).

`story:directory-provenance` leaves this wave. Its scoper found five stop conditions, recorded in its Scope: `tokio` admitted nowhere though every `eventlog-sqlite` call needs a runtime (S1); the worker package cannot name `mandate-provisioning` under `xtask/src/main.rs:104,119` (S2); `eventlog-sqlite` absent from the provisioning ceiling (S3); and the directory fold's inputs undeclared in the contract (S5) — three removal events carry `context` only, and no event creates a `DirectoryGroup`, a `SyncJob`, or a `MembershipContribution`'s fields. S5 is what `story:event-payloads-for-folds` fixes this wave (ruling in that story's body); S1 and S3 are coordinator admissions before the next dispatch.

`aep plan artifact waves --kind story --status draft` after re-scoping: no collision among the four; `story:declared-writers` collides with `story:event-payloads-for-folds` on six yaml files and `generated/` and is therefore the next wave's; `story:testkit-doubles` scoping in progress at opening.

## Units

One unit, one agent, on the operator's instruction "one per story". Each story's unit table is executed serially by that one agent; files stay disjoint by construction.

| Story | Branch | Worktree | Build directory | Scratch root | Managed id |
|---|---|---|---|---|---|
| `check-api` | `impl/check-api` | `~/.local/state/worktree/trees/b10x/mandate/mandate-w3-check-api` | `~/.cache/b10x-target/mandate/w3-check-api` | `~/.cache/claude-tmp/wave3/check-api` | `mandate-w3-check-api` |
| `pkce-sessions` | `impl/pkce-sessions` | `…/mandate-w3-pkce-sessions` | `…/w3-pkce-sessions` | `…/wave3/pkce-sessions` | `mandate-w3-pkce-sessions` |
| `event-payloads-for-folds` | `impl/event-payloads-for-folds` | `…/mandate-w3-event-payloads-for-folds` | `…/w3-event-payloads-for-folds` | `…/wave3/event-payloads-for-folds` | `mandate-w3-event-payloads-for-folds` |
| `gate-reads-document-deliverables` | `impl/gate-reads-document-deliverables` | `…/mandate-w3-gate-reads-document-deliverables` | `…/w3-gate-reads-document-deliverables` | `…/wave3/gate-reads-document-deliverables` | `mandate-w3-gate-reads-document-deliverables` |
| coordinator | `integration/wave-20260918-004` | `…/mandate-w3-coordinator` | in-tree `target` for the full gate (`env -u CARGO_TARGET_DIR`), `~/.cache/b10x-target/mandate/w3-coordinator` otherwise | `~/.cache/claude-tmp/wave3/coordinator` | `mandate-w3-coordinator` |

Per-unit gates, from each story's Scope: `cargo test -p mandate-authz --locked`; `cargo test -p mandate-federation --locked` and `-p mandate`; `ess specify validate --path systems/mandate`; `cargo xtask documents` (verb inferred) and `cargo xtask check`. Not `task check` in a unit tree: it fails on projection drift until the coordinator regenerates (`xtask/src/main.rs:90-91`).

## Coordinator pre-lands (this opening commit)

- Event-log kit: `eventlog-core` and `eventlog-sqlite` at tag `0.2.1` in the workspace manifest; `crates/mandate-provisioning` → `eventlog-core`; `services/worker` → both; `deny.toml` admits the git source and the `Zlib` license (`foldhash 0.1.5`, transitive of `eventlog-sqlite`); `dependency-boundaries.json` widened for both packages. `cargo deny --locked check` ok on all four sections; `cargo xtask boundaries` prints 20 packages; `task check` exit 0, 90 targets, 400 passed, 0 failed.
- `bins/mandate` → `sha2` (pre-landed so `story:pkce-sessions` unit D runs under `--locked`).
- Store: `approval` evidence on `decision-blocker:algorithm-policy` (RS256, ES256; operator as authority); dependency admissions and the `audit-routing` gap on `task:runtime-wave-integration`; file-level Scope sections on `check-api`, `pkce-sessions`, `event-payloads-for-folds`, `declared-writers`, `directory-provenance`, `gate-reads-document-deliverables`, `invariant-boundary-validation`; coordinator rulings on `event-payloads-for-folds` and `directory-provenance`.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`, author and committer `b10x-bot[bot]`: this opening coordinator commit (page, store, manifests); one commit per unit on its `impl/*` branch; one `--no-ff` merge per unit into the integration branch; the coordinator's regeneration and pin-raising commit after `event-payloads-for-folds` merges; the closing store commit; publication through `b10x-gates publish`; the PR to `main` and its App merge under the standing authorization. No tag, no release.

## Declared deviations

1. `story:directory-provenance` deferred from forecast row 4 to the next wave (stop conditions above). `story:event-payloads-for-folds` and `story:gate-reads-document-deliverables` fill the slots; neither is in the forecast table.
2. `Zlib` added to `deny.toml`'s license allowlist for `foldhash`, a transitive dependency of the event-log kit. Not in the approved plan; recorded here and in the commit.
3. Two finished trees from wave 1 remain on disk (`mandate-w1-canonical-types`, `mandate-w1-runtime-decision-dossier`): their heads `010688f` and `781517b` have zero-line diffs to `8a60eee` and `5c99f43` on `main`, but the manager refuses removal without a remote reachable from the exact heads.
4. The two customer-doc scripts modified in the wave-2 coordinator tree were copied to `~/.cache/mandate-customer-docs/2026-09-18/` (byte-compared) and the tree reverted on the operator's answer; three scripts remain committed under `docs/customer/` (`build.py`, `build.sh`, `figures/sso-flow.py`) against `AGENTS.md`'s scripting rule — not this wave's surface.
5. The critic agents of the planning round run on their pinned models; recorded on each `review-result`.

## Preflight

| Check | Reading |
|---|---|
| `df -h /` at opening | 20 GB free (98 % used); floor 10 GB; re-read before each dispatch |
| `cargo deny --locked check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo xtask boundaries` | 20 packages satisfy metadata and dependency boundaries |
| `task check` on the wired tree | exit 0; 90 targets; 400 passed; 0 failed |
| `aep plan artifact validate` | valid |
| `generated/schema/types/`, `entities/` | 110, 36 (unchanged; asserted by `crates/mandate-types/tests/inventory.rs`) |

## Stage log

- Opening: store writes and pre-lands as above; critic panel (parallel-safety, design) on the four-story set — results below.
- Critic panel, round 1: parallel-safety `approve`, 0 findings (`review-result:wave3-parallel-r1`); design `needs-revision`, 1 medium finding D1 — no owner for the Rust fold of the reshaped `ExternalPrincipalLinked` (`review-result:wave3-design-r1`). Ruling written on `story:event-payloads-for-folds`: the coordinator carries the four fields into `crates/mandate-federation/src/record.rs` in the regeneration commit and un-hides the three identity seeding constructors; outcome recorded `fixed`. No second round: the finding was an unassigned duty, and the assignment is now on the record.
- Selection stands: the four stories move `draft → proposed → active` at dispatch.
