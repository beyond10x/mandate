# Wave 6 (unknown-instance refusals, AEP repin): execution

Opened 2026-10-13 on `integration/wave-20261013-001`, cut from `main` at `4b1ed8a` (0.7.0).
Coordinator: a session running `aep:implementing` in wave mode, approved by the operator on
2026-10-13 before it was proposed. Epic: `epic:foundations`.

Purpose: the 15 synthesized `wrong-state` scenarios for commands acting on a record that does not
exist expect the refusal Mandate already gives, and the planning tooling moves to the newest AEP.

## Units

| unit | story | branch | managed id | scratch | stage |
|---|---|---|---|---|---|
| U1 | `story:aep-repin-0-71` | `impl/aep-repin-0-71` | `mandate-w6-aep-repin` | `~/.cache/mandate-w6/u1/` | opened |
| U2 | `story:unknown-instance-refusals` | `impl/unknown-instance-refusals` | `mandate-w6-unknown-instance` | `~/.cache/mandate-w6/u2/` | opened |

U1 and U2 share one line, `AGENTS.md:13`, which names both the AEP pin and the ESS format. U1 lands
first; U2 is cut from the integration branch after U1's merge and owns the format words on that line.
Builds run one at a time, each in its own tree's `target/`.

## Decisions this wave rests on

- `decision-blocker:identity-uniqueness` (cleared 2026-10-13): the external-principal, audience and
  exchange-source keys are decided on the shipped command-path refusals and fold conflict views;
  ceiling data enters only through `SupersedeAgentCapabilityCeiling`. Atomic storage enforcement
  moved to `decision-blocker:identity-uniqueness-storage`, which blocks
  `story:domain-folds-over-the-kit`. This frees `story:agent-security` for the next wave; it is not
  in this wave.
- `story:unknown-instance-refusals` raises `systems/mandate` past `ess/4`. The raise must name every
  synthesized scenario it removes; a probe to `ess/22` removed 20 (180 to 160).

## Commits this wave authorises

The opening store commit with this page; one commit per unit, plus adversary test files and unit
fix-ups; the merges into the integration branch; the closing store commit; one PR from the
integration branch to `main` and its bot merge on green CI; the release through this repository's
process (`AGENTS.md`, standing cadence).

## Pre-flight

| check | reading |
|---|---|
| primary checkout | `main` at `4b1ed8a`, clean but for an untracked `.agents/` that is not this wave's |
| Gates baseline | `4b1ed8a` (`gates-policy/policy.json`, read 2026-10-13) |
| free disk | 62G at 05:20Z (`df -BG /`) |
| build budget | at most 10G du per build target; pause under 15G free, resume over 17G |
| load | 7.70 (`/proc/loadavg`) |
| tools | `aep 0.71.2`, `ess 0.59.0` (newest ESS release, `gh release list -R beyond10x/ess`) |

## Stage log

- 05:20Z opening store commit: `story:aep-repin-0-71` created; both stories moved to active;
  `decision-blocker:identity-uniqueness` cleared; `decision-blocker:identity-uniqueness-storage`
  created.
