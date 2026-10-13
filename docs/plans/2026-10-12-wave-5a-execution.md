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
| U0 | `story:ess-repin-0-59` | `impl/ess-repin-0-59` | `mandate-w5a-ess-repin` | `~/.cache/mandate-w5a/u0/` | merged `3cc4643` (unit head `b3696b6`) |
| U1 | `story:agent-authority-kernel` | `impl/agent-authority-kernel` | `mandate-w5a-authority` | `~/.cache/mandate-w5a/u1/` | merged `ac9dac2` (unit head `88b1e75`) |

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
its bot merge on green CI. No release without a separate decision. Amended 2026-10-13: the
operator granted the release of this wave through the repository's own process; it is a minor
release, because the `SigningKeyWindow` move is a Rust API break. The unit fix-ups after each
adversary pass are unit commits too.

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
- U0 spec phase, commit `69cf8e8` on `impl/ess-repin-0-59`: `SigningKey`'s instants move into
  `mandate.core.SigningKeyWindow`; `RegisterSigningKey` and `SigningKeyRegistered` carry `window`;
  `CreateDelegation` sets `transitive: false`. `ess specify validate --path systems/mandate` exits
  0 under 0.59.0, with 2 `implied_relation` warnings on `domains/audit.yaml:8`, outside this story.
  Completeness: unscenarioed 52 (49 before; the 3 new ones are `SigningKey` invariant scenarios that no
  view publishing `window` covers).
- Coordinator decision: the `window` reshape is accepted. It is a Rust API change with no HTTP route
  (`services/sts/src/lib.rs:99`), and no event is stored durably (`services/sts/src/store.rs:41-49`:
  in-memory doubles). It goes in the changelog as **Breaking**. A format raise to `ess/22`, which
  would keep the flat fields, was rejected: in a probe it dropped 20 synthesized wrong-state
  scenarios (180 to 160).
- Phase 2, waiting for disk (11G free; the floor is 28G): repin `Cargo.toml:24-26` and `Cargo.lock`;
  `cargo xtask adopt` then `generate`; move the hand-written consumers listed by the spec phase
  (`crates/mandate-token/src/projection.rs`, `services/sts/src/keys.rs`,
  `crates/mandate-conformance/src/commands/credential.rs` and their tests) to `window`; update the
  ESS version text in `AGENTS.md` and `xtask/src/main.rs`; package gates; `task check`.
- 2026-10-13, phase 2 under a 10G build slot: `18ab3aa` (pins, regenerate, `window` consumers),
  `254fb52` (re-anchored mutants). ESS 0.59.0 writes a new conformance suite: 166 scenarios at
  `ess-conformance/9` became 200 at `ess-conformance/35`. Every gap is attributed: 19 new
  `unsupported` rows restate the target's owner; the 4 `ResourceServer` scenarios whose synthesized
  input names an unarranged resource server go to `story:ess-synthesizer-prerequisites` (an ESS
  defect, planned fix in an ESS release); 15 `wrong-state` scenarios on an unknown identity go to
  the new draft `story:unknown-instance-refusals` (`626f694`; ESS's rule, repaired on this side by
  declaring `unknown_instance:`, which needs a format raise and so waits for a later wave). The 3
  authored federation scenarios: production returns the stated reason (`authenticate.rs:267-272`,
  `record.rs:1002-1005`, `link.rs:96-101`); only the target pre-empted it, fixed there.
- `867ed5e`: `deny.toml` ignores RUSTSEC-2024-0449 (unsafe-libyaml, unmaintained, reached only
  through `serde_yaml` in the ESS crates; `main` at `e725a36` fails the same way) until ESS drops
  `serde_yaml`.
- Adversary pass `c043221` (5 cases, 4 red): one blocker (the 15 rows' owner) and three label
  defects in the target; fixed in `b3696b6`. `task check` on `b3696b6`: exit 0, 2125 passed and
  0 failed over 287 result lines, every mutant killed; process groups `1879143` (on `867ed5e`) and
  `3045585` (on `b3696b6`); peak `target/` 7.2G.
- Merged into the integration branch as `3cc4643`.
- U1, `story:agent-authority-kernel`, from `c9854f1`: `516dad2` (the evaluator, its spec clause
  and scenario `exchange-ceiling-conflict`), `d5dc6b3` and `c0384de` (gate findings). 20
  required-observation tests red against a stub (0 of 20), then green; two hand-rolled properties
  (exhaustive, 65,536 cases; 20,000 seeded samples). `task check` on `c0384de`: exit 0.
- Adversary pass `39855ee` (18 cases, 1 red; the unit's suite missed 10 of 17 mutations, which
  this file kills): a policy refusal lost its declared reason. Fixed in `59dc790`, for every
  `DenialReason`. `91b9195` and `88b1e75` move the delegation commands, events, conformance rows
  and obligation clauses this story does not realize to `story:agent-security` (deferred on
  `decision-blocker:identity-uniqueness`); `5c05abf` is rustfmt on the adversary file. `task
  check` on `88b1e75`: exit 0, 2165 tests listed, process group `2415528`, peak `target/` 6.0G.
- Merged into the integration branch as `ac9dac2`. Closing store commit: both stories move to
  `implemented` on their `task check` results; `story:agent-security` records what it inherits
  and the two gaps the adversary noted for it (execution records are not read; a subject that is
  an agent is not bounded by its own ceilings).
