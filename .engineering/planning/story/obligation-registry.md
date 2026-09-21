---
format: aep.planning-md/1
id: story:obligation-registry
kind: story
status: implemented
title: Every external denial clause of an implemented command is bound to a real-path test
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:coverage-map
- informed_by: initiative:drift-enforcement
scope:
- confidence: cited
  path: contracts/conformance/obligations-report.json
- confidence: cited
  path: contracts/obligations/README.md
- confidence: cited
  path: xtask/src/coverage.rs
- confidence: cited
  path: xtask/src/obligations_registry.rs
- confidence: cited
  path: xtask/tests/obligations_registry.rs
revision: 22
---
## Acceptance

Given `contracts/obligations.json`, when `cargo xtask obligations-registry` runs, then every IR command has an entry and no entry names a non-compiled command; every `implemented` command has at least one `denial` test per external clause with `path: real` and one `no-state-change` test, or the gate fails; `double`-backed tests are counted in their own column and never as conforming; every `tests/security/cases.json` id is bound to a test or deferred to its story; every addendum requirement (resolution order 1–9, §5.x) is bound; and `generated/conformance/obligations-report.json` is byte-identical to the run.

## Scope

- `contracts/obligations.json` — inferred; format `mandate-obligations/1`; per command `{status, tests: [{id, kind: denial|accepted|no-state-change|precedence|denial-audit, clause, path: real|double, double?, blocked_on?}]}`, `addendum` and `cases` sections.
- `xtask/src/obligations_registry.rs` — inferred; the step (IR ↔ registry both directions; test-id existence via `cargo test -- --list`; rules above; report writer).
- `xtask/tests/obligations_registry.rs` — inferred; red/green over a scratch copy.
- `generated/conformance/obligations-report.json` — cited (generated).
- New real-path denial tests, one file per crate so no other unit's file is touched: `crates/mandate-federation/tests/obligations.rs`, `crates/mandate-identity/tests/obligations.rs`, `crates/mandate-authz/tests/obligations.rs`, `crates/mandate-model/tests/obligations.rs` — inferred; every external clause of the 21 implemented commands driven through the real validation path with a malformed or mismatched input, plus a `no-state-change` assertion per command and precedence tests where two denials compete. Clauses only a double can reach today (proof verification) are registered `path: double`, `blocked_on: story:signing-and-verification`.
- `denial-audit` entries are `deferred` for every command until ESS carries `audits:` (the ESS story).

### Units

| Unit | Owns | Test |
|---|---|---|
| `registry+step` | `contracts/obligations.json`, `xtask/src/obligations_registry.rs` | `xtask/tests/obligations_registry.rs` |
| `tests` | the four `tests/obligations.rs` files | themselves |

One agent, serially. The coordinator wires the `mod`, `Action`, `Check` line.

### Excluded

`xtask/src/main.rs`, `docs/architecture/command-obligations.md` (text unchanged), `Cargo.*`, every `src/`.

### Gate

`cargo test -p xtask -p mandate-federation -p mandate-identity -p mandate-authz -p mandate-model --locked`; `cargo xtask obligations-registry` on the tree.

## Scope — re-derived 2026-09-19 (wave D second half)

By `story-scoper` on `6d812e0`. The story as written is stale: `contracts/coverage.json` reports **41** implemented commands across **seven** crates (sts 11, model 10, federation 9, graph 5, identity 3, policy 2, authz 1), not 21 across four; `story:signing-and-verification` is `implemented`, so the proof clauses are real-path, not double-backed. Splitting each command's `condition.cause` on comma/`or` gives ~203 clauses (sts 61, federation 49, model 49, graph 19, identity 12, policy 8, authz 5) against a hand-built precedent of ~67 rows for the 11 STS commands in `services/sts/tests/declared_denials.rs:108`; the seven packages already run 911 tests, ~441 denial-named, so the work is mostly binding existing tests to clauses, with new tests where a crate has no clause vocabulary (`mandate-model`, and the `Denied`/`GraphError`/`RefusedOutcome`/`PolicyError` crates).

- **This story (the registry and its step, S–M):** `contracts/obligations.json` (`mandate-obligations/1`, keyed on `(command, clause)`, one entry per IR command both directions, never duplicating `coverage.json`'s element-level `impl`/`crate`/`story`), `xtask/src/obligations_registry.rs` (reuses `coverage::Compiled` — one `cargo test --no-run` pass per process — and the same-crate rule; the clause matcher is `str` + `serde_json`, `xtask`'s ceiling admits no regex), `xtask/tests/obligations_registry.rs` (scratch-root fixtures as `xtask/tests/coverage.rs:38-45`), `contracts/conformance/obligations-report.json` (`{implemented, real_covered, double_only, deferred}`, compared by its own step — ruling 1 on `story:conform-gate`). The existing `obligations()` (markdown ↔ IR text) stays; the new action is `obligations-registry`. A `denial-audit` row is excluded from numerator and denominator while `decision-blocker:audit-routing` is open. The step lands green: every clause of an implemented command either bound or carrying `blocked_on` its crate's binding story.
- **Coordinator wiring (excluded):** `xtask/src/main.rs` `mod`/`Action::ObligationsRegistry { root }`/`Check` line; `generate()` untouched (the report is the step's own).
- **Not this story's:** the per-crate binding files — split into seven stories below, one file each, parallel-safe (no two share a package): `services/sts/tests/obligations.rs`, `crates/mandate-{model,federation,graph,identity,policy,authz}/tests/obligations.rs`. `docs/adr/0010-drift-enforcement.md` is `story:conform-gate`'s.
- **Collisions:** `xtask/src/main.rs` wiring (coordinator-serialised with `conform-gate`, `mutation-controls`); nothing under `generated/`.

## Rulings — wave D second half, 2026-09-19

1. Split as scoped: this story is the registry and its step; seven binding stories (`story:obligations-sts`, `-model`, `-federation`, `-graph`, `-identity`, `-policy`, `-authz`) each `depends_on` this one and owns one test file; the registry's `blocked_on` for an unbound clause names that crate's binding story until it lands.
2. The clause list is authored in `contracts/obligations.json` by this story from the IR causes, with the STS precedent table as the granularity check; a clause the IR does not carry verbatim is refused.
3. The report lives at `contracts/conformance/obligations-report.json` (ruling 1 on `story:conform-gate`), not under `generated/`.

## Corrections after `review-result:wave-d-second-half-design-r1` (2026-09-19)

- **One owner per surface.** The Units table above and the former `scope:` rows for the per-crate `tests/obligations.rs` files are superseded: those files belong to `story:obligations-{sts,model,federation,graph,identity,policy,authz}` alone and are removed from this story's scope.
- **The registry is one file per crate.** `contracts/obligations/<crate>.json` (`mandate-obligations/1`, keyed on `(command, clause)`), seven files plus `contracts/obligations/README.md` stating the format. This story authors all seven with the clause list from the IR and every test row `blocked_on` the crate's binding story; from then on each file is its binding story's, which is what makes the seven parallel-safe. The step reads the directory.
- **Acceptance at this story's close** (amending the Acceptance above): every external clause of every implemented command is either bound to a `path: real` denial test of its own crate that `cargo test -- --list` runs, or carries `blocked_on` naming its crate's binding story, which is live; a clause with neither fails the step. "Or the gate fails" for an unbound clause applies once its binding story is `implemented`, and the step enforces that transition by reading the store's frontmatter (the reader `xtask/src/coverage.rs` has). The `no-state-change` and `precedence` rows follow the same rule.
- The report `contracts/conformance/obligations-report.json` carries per crate `{clauses, real_covered, double_only, deferred}`.

## Acceptance — amended 2026-09-19 (replaces the Acceptance above where they differ)

`cargo xtask obligations-registry` exits 0 on a tree where the seven `contracts/obligations/<crate>.json` files name exactly the IR's 61 commands, every clause is a verbatim substring of its command's cause, every named test is compiled and runs and belongs to the entry's crate, every clause of an implemented command is bound to a real-path denial test or `blocked_on` a live binding story, every `cases` id is in `tests/security/cases.json` and back, and `contracts/conformance/obligations-report.json` is byte-identical to the computed report with per crate `{clauses, real_covered, double_only, deferred}`. It exits non-zero, naming the row, on any of those failing.

- Implementor result (2026-09-19): green in its tree — `contracts/obligations/{README,authz,federation,graph,identity,model,policy,sts}` (172 clauses at the `declared_denials` granularity: sts 50, federation 40, model 40, graph 17, identity 12, policy 8, authz 5 — the scoper's 203 counted a comma inside a list as a boundary; every clause is a verbatim substring of its IR cause, checked on every run), `xtask/src/obligations_registry.rs` (910 lines, reuses `coverage::Compiled`, one `--no-run` pass per process), `xtask/tests/obligations_registry.rs` (18 cases, red first), `contracts/conformance/obligations-report.json`. Table: 69 real-path / 7 double-only (`PolicyDouble` 6, `GraphDouble` 1) / 96 deferred; no-state-change 32 of 41 bound; cases 29 of 50 bound; addendum 11 of 11. 131 xtask cases green; boundaries 22. The production entry refuses on the unit tree with 133 "story the store does not hold" rows because the seven binding stories live in the coordinator's uncommitted store — correct behaviour, resolved on the integration tree. Residue: `coverage::terminal_rung` is private, so the registry carries a duplicate frontmatter reader (a one-word `pub` patch is in scratch); the `cases` rows are exempt from the same-crate rule by design (a case filed at the wire is decided by `mandate-proto`/`mandate-server`). Adversary 1 dispatched.

## Acceptance — amended 2026-09-21 (the same-crate rule)

Every clause row and no-state-change row and every `addendum` row names a test of the entry's crate; a `cases` row names a test of the entry's crate or of `mandate-proto` or `mandate-server` (the two packages that decide a security case at the wire), and no other package. A clause carries rows of one path only: `real` rows, or `double` rows with `blocked_on` the story that owns the real path.

- Correction 1 result (2026-09-21): 138 xtask cases green after the coordinator amended adversary case c to the 2026-09-21 rule (a `cases` row may name `mandate-proto` or `mandate-server`) and applied the implementor's one-line clippy patch to the adversary file; 176 clauses (69 real / 8 double / 99 deferred) — four clauses split into seven by decider (`RegisterResource`, `IssueAuthorizationCode`, `RedeemAuthorizationCode`, and `WriteRelationship`, found by enumerating the 29 conjunctive clauses); `obligation()` refuses a clause carrying both paths; `owners` replaces `same_crate` (addendum exemption gone; `cases` bounded to the two wire packages); `coverage::terminal_rung` is `pub` and the duplicate deleted. Residue stated: `LinkExternalPrincipal` "Caller/method lacks linking authority" is real-covered on the method half; the caller half is `mandate-authz`'s and no verbatim split exists. Adversary 2 dispatched.

- Correction 2 result (2026-09-21): 145 xtask cases green, all eight adversary cases; 176 clauses: 68 real / 8 double / 100 deferred; the tiling has a reader (`tiles()` walks each cause positionally, refusing a dropped, nested, overlapping or out-of-order clause and quoting the unaccounted text); a double row never defers to its own binding story (the eight double-only clauses defer to `story:graph-policy-adapter`); `RedeemAuthorizationCode`'s two undriven halves deferred to `story:obligations-sts`. Unit committed `787cded`, merged `89280c7`; wiring (`cargo xtask obligations-registry [--write]`, `check` after `coverage`) in the alignment commit that follows; the step passes on the integration head, where the seven binding stories are present in the store.
