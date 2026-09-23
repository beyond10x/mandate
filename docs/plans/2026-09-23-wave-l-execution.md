# Wave L — execution

Opened 2026-09-23 on `integration/wave-20260923-002`, cut from `main` at `52de770` (`v0.5.0`).
Coordinator: an interactive session running `aep-drive:wave` 0.9.3, approved by the operator's goal
"all up until Wave L completed". At most three concurrent agents. At close the standing cadence in
`AGENTS.md` applies: PR, bot merge, baseline advance, release, cleanup.

## Selection

`aep plan artifact waves --kind story --status draft --format json` exited 0 with **unassessed:
none**. Collisions that shaped the selection (verbatim):

| a | b | path |
|---|---|---|
| `story:bracketed-literal-trailing-dot` | `story:federation-guard-trailing-dots` | `crates/mandate-federation/src/verifier_real.rs` |
| `story:control-plane-multi-fold-writes` | `story:control-plane-readable-instant` | `services/control-plane/src/adapters.rs` |
| `story:control-plane-multi-fold-writes` | `story:provisioning-replay-principal` | `services/control-plane/src/adapters.rs` |

The two trailing-dot stories share one file and one class, so they are one unit.

| unit | stories | serves | branch | managed id | scratch |
|---|---|---|---|---|---|
| L1 | `story:federation-guard-trailing-dots`, `story:bracketed-literal-trailing-dot` | `vision:mandate` | `impl/federation-trailing-dots` | `mandate-wl-trailing-dots` | `~/.cache/claude-tmp/wl/l1/` |
| L2 | `story:control-plane-multi-fold-writes` | `vision:mandate` | `impl/control-plane-multi-fold-writes` | `mandate-wl-multi-fold` | `~/.cache/claude-tmp/wl/l2/` |
| L3 | `story:enabled-for-issuer-filters-in-the-implementor` | `vision:mandate` | `impl/enabled-for-issuer` | `mandate-wl-enabled-for-issuer` | `~/.cache/claude-tmp/wl/l3/` |

Each tree builds into its own `target/`.

**Coordinator decision for L1:** `story:bracketed-literal-trailing-dot` leaves open whether the guard
refuses `[::1.]` or the fetcher reaches `::1`. The guard refuses: a bracket holds an address and
nothing else, which the comment at `verifier_real.rs:470` already states, and refusing fails closed.

Left for wave M: `story:control-plane-readable-instant` and `story:provisioning-replay-principal`
(both on `adapters.rs` with L2).

## Commits this wave authorises

One commit per unit plus each adversary pass's test file; the merges into the integration branch;
the coordinator's opening, alignment and closing store commits; then the standing cadence — the PR
merge, the Gates baseline advance, the release commit, tag and Release, and branch deletion.

## Stage log

