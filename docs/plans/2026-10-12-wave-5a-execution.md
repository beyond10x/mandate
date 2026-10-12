# Wave 5a (agent authority): execution

Opened 2026-10-12 on `integration/wave-20261012-001`, cut from `main` at `e725a36`.
Coordinator: an interactive session running `aep:implementing` 0.22.4 in wave mode, approved by the
operator on 2026-10-12. Initiative: `initiative:next-ten-waves`, wave 5, reduced to its agent
authority half.

Purpose: the shared agent authority evaluator that constrained exchange and agent security build on,
on the newest ESS release.

## Units

| unit | story | branch | managed id | scratch | stage |
|---|---|---|---|---|---|
| U0 | `story:ess-repin-0-59` | `impl/ess-repin-0-59` | `mandate-w5a-ess-repin` | `~/.cache/mandate-w5a/u0/` | not started |
| U1 | `story:agent-authority-kernel` | `impl/agent-authority-kernel` | `mandate-w5a-authority` | `~/.cache/mandate-w5a/u1/` | not started |

U1 depends on U0: `domains/delegation.yaml`, which U1 models in, is refused by ESS 0.59.0 until U0
lands. They run in sequence, and each tree builds into its own `target/`.

## Decisions this wave rests on

- `decision-blocker:identity-uniqueness-ceiling` (cleared 2026-10-12): the ceiling key is
  `(agent_id, organization_id)` with absent meaning platform; the current ceiling is the latest
  recorded per key; two current ceilings on one key are a declared denial. It replaces
  `decision-blocker:identity-uniqueness` on `story:agent-authority-kernel`. The rest of that record
  stays open for `story:agent-security`.
- Not decided, and outside this wave: `decision-blocker:async-runtime`, and the audit-routing and
  guards decisions `story:audit-client` needs.

## Commits this wave authorises

The opening store commit; one commit per unit, plus each adversary pass's test file; the merges into
the integration branch; the closing store commit; one PR from the integration branch to `main`, and
its bot merge on green CI. No release without a separate decision.

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `e725a36`, clean but for an untracked `.agents/` that is not this wave's |
| free disk | 12G at 16:02Z (`df -BG /`) |
| build floor | no cargo build below 28G free; one build at a time; du limit 5G per package gate, 10G for U0's regenerate and `task check` |
| load | 35.28 (`/proc/loadavg`), over 30: builds use `CARGO_BUILD_JOBS=8` |
| ESS | `ess 0.59.0` refuses `systems/mandate` with 3 errors, listed in `story:ess-repin-0-59` |

## Stage log

- 16:02Z opening store commit: U0 story created; epics `foundations` and `agents-workloads` and both
  stories moved to active; ceiling decision recorded and cleared.
