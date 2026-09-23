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

- Opening commit `bde627b`; `cargo fmt --all --check` 0, `cargo xtask documents` 0. Three unit trees at `bde627b`; three `aep-drive:implementor` dispatches. Free disk 81G.
- L2 green: executed 165→167, red 1; one site fixed (copy-then-swap), two documented unreachable. Committed `a8bb09b`. Adversary pass 1 dispatched.
- L3 green: federation 328→329 in its report; the implementor found the same defect in `register_federation_connection` (`record.rs:975`) and wrote a patch; the coordinator applied it (no other L unit touches `record.rs`): federation 330 passed, clippy and fmt 0. Committed `10e9036`. Adversary pass 1 dispatched.
- L1 green: federation 328→330; the planned fix left 3 cases red, and an added `..` refusal in `origin` closed them; sweep 0 refused→admitted, 418 admitted→refused. Committed `4f268d7`. Adversary pass 1 dispatched.
- L2 adversary 1: red, 1 finding (undecided: `ConnectionSeeding::admit` at `adapters.rs:1031` keeps the connection when its link is refused; `main.rs` aborts on that refusal), recorded `review-result:wl-l2-multi-fold-adversary-1`; case `c271959`. Coordinator decision: same class, same file, fixed here. Back to the same implementor.
- L2 correction 1 green (168); `ConnectionSeeding::admit` and `ClientSeeding::admit` copy-then-swap. Committed `af7d4e6`, outcome `fixed`. Adversary pass 2 dispatched.
- L3 adversary 1: red, 2 findings (pre-existing: a redelivered `FederationConnectionCreated` after a disable leaves an `Enabled` copy, `record.rs:494`; introduced: `enabled_on_issuer` trusts the enumerated state, `lib.rs:638`; both deny only), recorded `review-result:wl-l3-enabled-for-issuer-adversary-1`; cases `d63201f`. Coordinator decision: fix both here (idempotent creation arm; state read through `connection(id)`).
- L2 adversary 2: red, 1 finding outside the story (two connection documents may state one `external_principal_id`; the second link is dropped), recorded `review-result:wl-l2-multi-fold-adversary-2`; cases `cb3dccd`. Filed `story:seeding-repeated-external-principal-id`; final correction re-pins the red case to today's state naming it.
- L1 adversary 1: red, 3 findings, all pre-existing (dotted IPv4 literal admitted and unresolvable; empty labels in `.localdomain` names; the two guards' `.localdomain` divergence), recorded `review-result:wl-l1-trailing-dots-adversary-1`; cases `cd9be4e`. Decisions: F1 and F2 fixed in L1 (same class, same file); F3's case re-pinned to the divergence decided in wave J; the control-plane doc claim at `adapters.rs:620` is the coordinator's.
- L3 correction 1 green (334; 3 red → 0), committed; outcomes `fixed` ×2. Adversary pass 2 dispatched.
- L2 final: case re-pinned (2 asserts added, 1 removed; exact values), control-plane 170 passed. Outcome `no-op` (filed). **L2 merged.**
- Coordinator commit `d58750d` on the integration branch: `is_loopback`'s doc states the one decided divergence (`.localdomain`) instead of claiming the guards cannot disagree.
- L3 adversary 2: red, 2 notes (introduced: a listed id the store cannot answer by id is dropped and the decision widens; the `apply` doc overstates), recorded `review-result:wl-l3-enabled-for-issuer-adversary-2`; cases `ae5722a`. Findings trend 2 → 2, carried 0. Decision: fail closed on an unanswerable id; doc corrected. Final correction to the same implementor.
- L1 correction 1: one case red because the control-plane guard still admitted `127.0.0.1.`. Coordinator decision: apply the implementor's control-plane patch (names-only fold); federation 335, control-plane 165, clippy and fmt 0. Committed; outcomes `fixed` ×3. Adversary pass 2 dispatched. Sweep since `bde627b`: 685 decisions moved, all admitted → refused.
- L3 final correction: coordinator verified — `src/` only, no test file changed; federation 339, conformance 41, clippy and fmt 0. Outcomes `fixed` ×2. **L3 merged.**
