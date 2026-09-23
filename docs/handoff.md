# Execution handoff

Rewritten 2026-09-22 at the close of wave H; its state sections refreshed 2026-09-23 at the 0.5.0
release, after waves I, J and K.

## Read these first

| | |
|---|---|
| where the plan lives | `.engineering/planning/`, written only through `aep plan artifact` |
| how work is run | [ADR 0008](adr/0008-integration-batches.md) — units on their own branches, one integration branch per batch; under the standing cadence in `AGENTS.md` every closed batch is merged, released and cleaned up without a further ask |
| what is undecided | [`architecture/unmapped.md`](architecture/unmapped.md) and the bounded alternatives in [`architecture/runtime-decisions.md`](architecture/runtime-decisions.md) |
| what is not true yet | `contracts/use-cases/federated-login.json`, the `not_yet_true` list |

## Where it stands

`v0.5.1` is the latest release. Twelve waves have run — 1 to 3, then A to L. The federated-login road runs end
to end against the shipped binary: `mandate-control-plane serve` serves `/v1/federation/login`,
`/oauth/authorize`, `/oauth/token`, `/oauth/introspect`, `/oauth/jwks` and
`/.well-known/oauth-authorization-server`, a first login provisions a user just in time where the
connection admits it, and a revoked link is not provisioned around.

Measured at `0.5.1`: `task check` exit 0, 274 suites, 2,016 tests, 0 failed; 11 named mutants each
killed; 292 contract elements with 201 implemented; 166 conformance scenarios with 44 passed and 0
error; 191 denial clauses with 85 decided on the real path.

Waves I–K moved the clause count for the first time since wave D (83 of 190 → 85 of 191; one
clause was split). The account is `docs/plans/2026-09-23-waves-i-j-k-execution.md`.

## In flight right now

Nothing. `main` holds 0.5.1; no integration branch is open. Wave L closed with its account in
`docs/plans/2026-09-23-wave-l-execution.md`. The next batch is wave M, not yet proposed. Candidates
with no blocker and typed scope: `control-plane-readable-instant`, `provisioning-replay-principal`
(both `adapters.rs`, so sequenced), `seeding-repeated-external-principal-id` (also `adapters.rs`) and
`numeric-shorthand-trailing-dot` (`verifier_real.rs`).

Left out of waves I–K and still undecided: `linked-event-method-unenforced` (its premise is
contradicted by the connection seeding at `services/control-plane/src/adapters.rs:962-970`) and
`federation-admission-port` (the seed path has no caller to admit).

## What is actually blocking

Two decisions, each with a written dossier, hold more of the remaining work than any amount of
implementation does. Neither needs further analysis.

**`decision-blocker:guards`** — open since 2026-09-18. 35 clause entries across five contract files
name it in `blocked_on`. It blocks `story:protocol-adapters`, `story:audit-client` and
`story:product-listener`, which between them are the customer-facing registration route and every
audited denial. The question, three bounded alternatives for the denial-record half, and what is out
of bounds are in `architecture/runtime-decisions.md` § 3.

**`decision-blocker:async-runtime`** — filed 2026-09-22. ADR 0009 decided event-sourced persistence
through the organization `eventlog` kit and **nothing implements it**: the kit is pinned and named by
two manifests, no Rust file references it, and every fold is in memory. The kit's surface is async
and this workspace admits no runtime; that was recorded as wave 3's stop condition S1 and deferred
four waves ago. Three options are stated in the blocker.

Between them they close three of the six gaps the use case lists. A fourth — **no transport
security** — has no story and no owner, and is the reason the use case says no customer may be put
on the road.

## Traps this repository has already paid for

- **The Gates adoption baseline.** `gates-policy/policy.json` holds
  `repositories."beyond10x/mandate".baseline`, and the push guard reads its outgoing range from that
  commit. Any branch cut from a `main` that has gained a `GitHub`-committed merge since the baseline
  is refused — *"outgoing commit must have the exact bot author and committer"* — **even for commits
  already on `main`**. On 2026-09-22 this refused the release branch until it was rebased onto the
  baseline itself. Wave G recorded advancing the baseline as a reset rather than a fix, five resets
  ago; this was the sixth occasion. Until the baseline moves, cut publishable branches from it.
- **A store write cannot be based on a pre-wave commit.** `.engineering/planning/journal.jsonl` is
  append-only and nothing merges it: a branch whose base lacks the current tail produces a document
  whose revision no event supports, which the store's own validator reports as forgery. Planning
  writes go on a branch cut from the current store, which is why the transport-security story is not
  filed yet.
- **`cargo fmt --all --check` is the gate's first step.** A whole gate run was spent on one
  unformatted import line whose failure hid every later step.
- **Read a gate's own exit status.** A run piped into anything reports the pipe's status. One gate
  here exited 201 and the harness reported 0.
- **Adversary findings blocks are YAML.** A `message:` containing a colon followed by a space is
  refused by the store; single-quote the scalar.
- **Concurrency above four copies of a control-plane test lane measures the host**, not the code:
  an 8-way probe put ~40,000 sockets in TIME_WAIT against a 28,231-port ephemeral range.

## Worktrees and branches

`main` is clean. Two managed worktrees are retained and cannot be cleared: `mandate-w1-canonical-types`
and `mandate-w1-runtime-decision-dossier`, whose commits `010688f` and `781517b` are advertised by no
remote ref. Their trees are **byte-identical** to `8a60eee` and `5c99f43` on `main` — `git diff`
between each pair is empty — so nothing is unintegrated. Publishing them to satisfy the recovery
check is refused, because they predate the adoption baseline. They stay until somebody retires them
out of band.

## Drive — still not launched

`.engineering/tasks/canonical-types.yaml` and `.engineering/drivers/canonical-types.yaml` are
unchanged and unlaunched. `decision-blocker:drive-verifier` and `decision-blocker:drive-map-authority`
both remain open; a launch needs a reviewed task and an operator-supplied `--budget-usd` and
`--assume-usd-per-run`, neither of which is inferred. Wave and Drive never own one story at once.

## What the next session should do first

1. Take `decision-blocker:guards` and `decision-blocker:async-runtime` from their dossiers
   (`architecture/runtime-decisions.md`); the operator has asked the orchestrator to decide within the
   approved design and to ask only for a disruptive or critical architecture change. They are what
   moves the clause count and the persistence gap.
2. Propose wave L from the candidates above, run it, and follow the standing cadence in `AGENTS.md`
   at its close.
3. Two more traps from waves I–K: a change to `services/sts` can move a named mutant's anchor
   (`tests/mutants/*.json`), which only the last step of `cargo xtask check` notices; and fast-forwarding
   the `gates-policy` checkout rewrites `policy.json` as mode 644, which `b10x-gates api` refuses
   (*"protected file ownership or permissions invalid"*) until it is `chmod 600` again.
