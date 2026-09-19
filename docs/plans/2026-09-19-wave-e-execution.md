# Wave E execution page — ESS-to-implementation drift protection

Status: opening, 2026-09-19. Interactive session; the operator approved the drift-protection plan (audit, enforcement design, remediation, release implications) with the standing instruction: orchestrator, up to four Opus agents, one per story; every sub-agent on Opus. This programme runs before any further forecast wave; `story:signing-and-verification` follows it.

**Skill version 0.9.2** — `aep-drive` at `.claude-plugin/plugin.json` of the loaded plugin. **AEP** `protocol 0.55.0`. **ESS** `ess 0.26.0` (repinned this wave from 0.25.0: newest tagged release; `generated/` regenerates byte-identically under it — 0 diff lines; `0.27.0` is in the ESS changelog but not yet cut).

Integration branch: `integration/wave-20260919-001`, cut from `8bc9a88` — the last all-bot commit, tree byte-identical to `main` `874a74f` (`git diff --stat 8bc9a88 874a74f` empty); the push guard refuses the GitHub-created merge commits (`task/runtime-wave-integration.md:33-35`).

## Selection

Twelve stories under `epic:foundations`, created this wave from the approved plan, all scoped to files; three Mandate waves plus one parallel ESS wave:

| Wave | Stories |
|---|---|
| E1 | `contract-creates`, `contract-shapes`, `tenancy-graph-events`, `event-validation-harness` |
| E2 | `federation-identity-alignment`, `model-agreement`, `coverage-map`, `authored-denial-scenarios` |
| E3 | `conformance-target`, `obligation-registry`, `mutation-controls`, `conform-gate` |
| ESS (parallel, ESS repository) | `realizer-element-roots`, `coverage-selection-scope`, `refusal-audits`; the `0.27.0` release |

`aep plan artifact waves --kind story --status draft` after scoping: the E1 set has no internal collision; every listed collision is with a story of a later wave (`declared-writers`, `testkit-doubles`, `graph-policy-adapter`, `signing-and-verification`, `product-listener`).

## Coordinator rule for xtask

Each story owns its own `xtask/src/<step>.rs`; the coordinator adds the `mod`, `Action` and `Check` lines in `xtask/src/main.rs` at integration, so no two units touch `main.rs`.

## Units — E1

| Story | Branch | Worktree | Build directory | Scratch root |
|---|---|---|---|---|
| `contract-creates` | `impl/contract-creates` | `~/.local/state/worktree/trees/b10x/mandate/mandate-we-contract-creates` | `~/.cache/b10x-target/mandate/we-contract-creates` | `~/.cache/claude-tmp/wavee/contract-creates` |
| `contract-shapes` | `impl/contract-shapes` | `…/mandate-we-contract-shapes` | `…/we-contract-shapes` | `…/wavee/contract-shapes` |
| `tenancy-graph-events` | `impl/tenancy-graph-events` | `…/mandate-we-tenancy-graph-events` | `…/we-tenancy-graph-events` | `…/wavee/tenancy-graph-events` |
| `event-validation-harness` | `impl/event-validation-harness` | `…/mandate-we-event-validation-harness` | `…/we-event-validation-harness` | `…/wavee/event-validation-harness` |
| coordinator | `integration/wave-20260919-001` | `…/mandate-we-coordinator` | in-tree `target` for the full gate; `~/.cache/b10x-target/mandate/we-coordinator` otherwise | `…/wavee/coordinator` |

Unit trees get a real `target` directory, not a symlink: `ess generate` refuses a symlinked output path, and `cargo xtask contracts` must be runnable in `contract-shapes`' tree.

## Coordinator pre-lands (opening commit)

- ESS repin to `0.26.0` (`xtask/src/main.rs:74`, `.github/workflows/ci.yml`, `README.md`, `AGENTS.md`); `cargo xtask contracts` green.
- Workspace: `ess-conformance`, `ess-primitives`, `ess-domain` as git dependencies at tag `0.26.0`; `jsonschema =0.52.1` without default features; `deny.toml` admits the ESS git source; `dependency-boundaries.json` gains `mandate-contract`, `mandate-conformance`, the testkit entries; xtask pins 22 packages / 16 libraries; `mandate-conform` joins the serve-refusal list.
- Skeleton crates `crates/mandate-contract` (empty, to be filled by `contract-shapes`) and `crates/mandate-conformance` (stub target, `mandate-conform` CLI refusing until `story:conformance-target`).
- Store: the twelve stories with bodies and file scope; critic panel round 1 on the E1 set.

## Commits this wave makes

Through `atlas/scripts/as-bot.sh`, author and committer `b10x-bot[bot]`: this opening commit; one commit per unit on its `impl/*` branch; one `--no-ff` merge per unit; the coordinator's regeneration commit after `contract-creates` merges (and the xtask wiring commits at each wave's integration); the closing store commit per wave; publication through `b10x-gates publish`; the PR to `main` and its App merge under the standing authorization. No tag, no release.

## Declared deviations

1. The plan said "repin to the newest tagged release at the wave's opening"; that is `0.26.0`, taken now; `0.27.0` will be cut in the ESS wave.
2. Tags for ESS crates: `ess-conformance` and siblings are pulled as git dependencies at the same tag as the binary; the boundaries checker treats them as external names.
3. `deny.toml` allowlist widened by one token, `MIT-0`: `jsonschema =0.52.1` pulls `referencing → fluent-uri → borrow-or-share 0.2.4` (MIT-0), non-optional at that version with default features off. MIT-0 is MIT without the attribution clause.
4. `xtask/src/main.rs` is in `story:contract-shapes`' scope for E1 only (`mod emit;` plus the Rust kind in `generate()`/`contracts()`): no other E1 unit touches the file, and the story's gate is not runnable without the wiring. Recorded on the story.
5. ESS 0.26.0 output ownership: `cargo xtask generate` refuses in a fresh checkout (`unowned output destination …; adopt exact generated reference bytes explicitly`) because the ledger `generated/.ess-output/` is gitignored. A coordinator-owned `cargo xtask adopt` step runs `contracts()` and then `ess generate output adopt --ownership-root generated --from target/xtask-contract-regeneration --owner projection:<kind>` for the four kinds; once per tree, not part of `check`.
6. `story:conformance-target`'s first body cited a file by an absolute path under the operator's home directory; the body was redacted (revision 6) but `journal.jsonl` keeps two body snapshots (revisions 1 and 4) with the path, and AEP 0.55.0 has no verb that rewrites the journal. The commit hook's `personal-paths` rule refused both lines, so the path string inside the two snapshots was replaced by hand with `<ess-repository>/…` (a string replace, no structural change; `validate` valid afterwards). This is the one hand edit of the store this wave; AEP needs a redaction verb so the next one is a command.

## Preflight

| Check | Reading |
|---|---|
| `df -h /` at opening | 14 GB free after E0 wiring (99% used, 848 GB device); floor 10 GB; unit builds share `~/.cache/b10x-target/mandate` |
| `ess --version` | `ess 0.26.0`; `cargo xtask contracts` → "ESS projections match deterministically" |
| `aep plan artifact validate` | valid |
| E1 collisions | none |

## Stage log

- Opening: branch cut; repin; twelve stories created and scoped; E0 wiring delegated to an Opus implementor; critic panel (parallel-safety, design) dispatched over the E1 set.
- Critic panel round 1: parallel-safety `needs-revision`, 3 findings (`review-result:wave-e-parallel-r1`); design `needs-revision`, 7 findings (`review-result:wave-e-design-r1`). Every finding is an ordering or ownership gap, none against the specification changes. Rulings recorded on the seven affected stories: the coordinator pre-lands `generated/ir/system.json`, the `realizes!` macro and the `obligations()` selection fix in the opening commit; E1 merge order fixed (`contract-shapes` → `contract-creates` → regeneration); `tenancy-graph-events` emits one `ResourceRegistered` payload with `resource_id`; `conformance-target` produces the first conformance corpus, `conform-gate` owns `expected-outcomes.json`; `declared-writers` gains `depends_on story:contract-creates`. Outcomes recorded `fixed`; no second critic round — every fix is an edge, a pre-land or a sentence, verified by `waves` and by the opening gate.
- E0 wiring (Opus implementor, 2 rounds, 369k tokens): ESS crates `ess-conformance`/`ess-primitives`/`ess-domain` at tag `0.26.0` (`a5f1bea`); `jsonschema =0.52.1` admitted under deviation 3; boundaries 22 packages / 16 libraries with interpolated constants; `mandate-contract` and `mandate-conformance` skeletons, `mandate-conform` refusing until `story:conformance-target`; fifth generate kind `generated/ir/system.json` (437,047 bytes; 12 domains, 110 types, 36 entities, 59 commands, 72 events, 11 errors) byte-compared by `contracts()`; `realizes!` + `ESS_REALIZATIONS` with a cross-crate test; `obligations()` selects the `external` outcome (59 unchanged). Four reds shown before their change. `task check` exit 0, 615 cases (was 611). Lock 99 → 177 packages. Agent disclosed and removed one stray `/tmp/.x` write.
- Open at E0 close: `mandate-testkit` declares `jsonschema` and nothing links it yet (`src/contract.rs` is `story:event-validation-harness`); an unused dependency trips no lane today.
