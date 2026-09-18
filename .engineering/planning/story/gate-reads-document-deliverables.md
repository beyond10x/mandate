---
format: aep.planning-md/1
id: story:gate-reads-document-deliverables
kind: story
status: implemented
title: task check cannot see a document deliverable, so it cannot fail one
relations:
- serves: vision:mandate
scope:
- confidence: inferred
  path: xtask/src/documents.rs
- confidence: cited
  path: xtask/src/main.rs
- confidence: cited
  path: xtask/tests/adversary_documents.rs
- confidence: cited
  path: xtask/tests/adversary_documents_2.rs
- confidence: inferred
  path: xtask/tests/documents.rs
revision: 9
---
## Acceptance

Given a repository checkout whose `docs/architecture/runtime-decisions.md` has been emptied, when
`task check` runs, then it exits non-zero naming that file.

## Why

`task check` is the gate this repository's stories name as their validation. It reads exactly two
paths under `docs/`: `docs/sources` and `docs/sources/SHA256SUMS`, both at `xtask/src/main.rs:202-212`.
Nothing in `cargo xtask check` opens `docs/architecture/`. So a documentation deliverable under that
directory can be emptied or deleted and the gate stays green.

This was measured, not inferred. An adversary pass on `story:runtime-decision-dossier` ran the
mutation: the dossier's entire contents are invisible to every step of the gate that declared the
unit green. It reproduces at `dc76aa3`, so it predates that story — `git show dc76aa3:xtask/src/main.rs`
carries the same two `docs/` reads.

The consequence is not that the dossier is wrong. It is that the gate cannot tell. Any future story
whose deliverable is a document under `docs/architecture/` inherits the same hole.

## Scope and boundary

The fix lands in `xtask/`, which is a coordinator-owned integration surface that no story's scope
may claim on its own. It needs a structural check, not a content check: the gate should not try to
judge whether a dossier is correct, only that a declared document exists, is non-empty, and — where
a document declares a row set derived from the store — that the row set still matches
`aep plan artifact blocked`.

Do not widen this into a prose linter. Do not make the gate re-derive planning state on every run
if that makes `task check` depend on a network or a lock.

## Sources

`xtask/src/main.rs:202-212` (the only `docs/` reads); `xtask/src/main.rs:233-273` (the full check
sequence); `review-result:wave1-dossier-adversary-1` finding 5, which holds the mutation result and
its verdict.

## Scope

Derived 2026-09-18 by `story-scoper` against `20f354d` (`integration/wave-20260918-004`, tree equal to `main`). Every line is **cited** (read from the story or the tree) or **inferred** (a reading that could be wrong).

- **What the gate reads under `docs/` today:** `xtask/src/main.rs` opens exactly three document paths — `docs/architecture/command-obligations.md` in `obligations` (`:137-186`, the read at `:152`, rows compared to the ESS command index `:164-180`, called from `corpus` at `:267`); `docs/sources/SHA256SUMS` and each `docs/sources/<name>` in the digest loop (`:256-266`); and `tests/security/cases.json` in `corpus` (`:187-273`, read at `:200`, owner check against `.engineering/planning/story/<id>.md` at `:223`). `Check` (`:287-329`) runs `boundaries` `:309`, `corpus` `:310`, `contracts` `:311`, `aep plan artifact validate` `:313`, and the `serve` refusal `:314-328`. — cited
- **Documents nothing enforces:** no reader of `docs/architecture/runtime-decisions.md` or `docs/architecture/federated-login.md` exists anywhere in the tree; every hit is a doc-comment citing the document as a source. The two scratch checkers the wave-1 adversary names are not in `git ls-files`. So **SC1–SC7** (`docs/architecture/runtime-decisions.md:357-363`) and **FL1–FL4** (`docs/architecture/federated-login.md:159-162`) all name an "enforced by" check that does not exist. — cited
- **Primary surface:** `xtask/src/main.rs` — cited; `AGENTS.md:17` requires a persistent check to be a Rust `xtask` step, test or workspace binary; `AGENTS.md:23` gives shared integration files to the coordinator alone.
- **Files the step would own:** a new `Action` variant at `xtask/src/main.rs:16-23` and one call in `Check` beside `corpus()` at `:310` — cited location, inferred name (`Documents`); the function body either in `xtask/src/main.rs` or a new `xtask/src/documents.rs` behind `mod documents;` — inferred. `xtask/Cargo.toml` and `dependency-boundaries.json` untouched on the premise that `serde_json` (already a dependency, `xtask/Cargo.toml:14`) parses `aep plan artifact blocked --format json` — inferred.
- **Documents it reads (never writes):** `docs/architecture/runtime-decisions.md` — index table `:37-47` (11 rows), exclusions table `:340-349`, claim table `:355-363`; `docs/architecture/federated-login.md` — claim table `:157-162`. Which files count as "declared documents" is not stated by the story; either a constant in the step or all seven `docs/architecture/*.md` — inferred.
- **What it asserts, in the acceptance:** file exists and is non-empty, else exit non-zero naming the path. — cited
- **What it asserts, in the story's boundary:** where a document declares a row set derived from the store, that the row set still matches `aep plan artifact blocked`: SC2 (`:358`), SC6 (`:362`), SC7 (`:363`) and FL4 (`federated-login.md:162`). `aep plan artifact blocked` is a local store read, the same class of call as `aep plan artifact validate` already at `:313`. — cited
- **What the tables promise and the story does not deliver:** SC1 (`:357`), SC3 (`:359`), SC4 (`:360`, algorithm denylist), SC5 (`:361`), FL1 (`:159`), FL2 (`:160`), FL3 (`:161`). The story forbids widening into a prose linter, so these seven stay unenforced after it merges. — cited
- **Gate:** `cargo xtask check` via `task check` (`Taskfile.yml:6`); the acceptance is reproduced by emptying `docs/architecture/runtime-decisions.md` in a scratch checkout and running the gate. — cited
- **Confidence:** high — the story names the file and the ownership rule; the only inferred lines are the verb name, the module split, the document list, and the test placement, all inside `xtask/`.
- **Would collide with:** any unit writing `xtask/src/main.rs` (today: `story:product-listener`'s coordinator row replacing the `serve` refusal at `:314-327`); any unit changing the shape of `docs/architecture/runtime-decisions.md:37-47`, `:355-363` or `docs/architecture/federated-login.md:157-162`.

### Units

| Unit | Owns | Test | Produces |
|---|---|---|---|
| coordinator, sole | `xtask/src/main.rs` (+ `xtask/src/documents.rs` if split) | `xtask/tests/documents.rs` — a temp root with an emptied `runtime-decisions.md` and an index row that disagrees with a stubbed `blocked` list; xtask has no test today | `cargo xtask documents` (verb inferred), wired into `cargo xtask check` so `task check` exits non-zero naming the file |

### Excluded

- `docs/architecture/*.md` bodies and both claim tables — read, not written.
- `docs/runbooks/**` (`story:recovery-runbooks`), `docs/sources/**` and `SHA256SUMS` (already covered at `:256-266`), `docs/customer/**`.
- `tests/security/cases.json`, `systems/mandate/**`, `generated/**`, every `crates/**` and `services/**`, `.engineering/planning/**`, `Taskfile.yml`, `AGENTS.md`.
- `xtask/Cargo.toml`, `Cargo.lock`, `dependency-boundaries.json`, `deny.toml` — on the no-new-dependency premise above.

### Wave placement

Run as the coordinator's own unit, on the integration branch, before any `story:product-listener` xtask edit; concurrent with anything that does not write `xtask/src/main.rs`.

### Not established

- Whether the step's document list is a constant or a directory walk: the story does not say.
- `docs/architecture/federated-login.md:143` cites `xtask/src/main.rs:259-273` for the `serve` refusal; stale since `f0da11e`, now `:314-327`. Not in this story's acceptance.
- Three scripts are committed under `docs/customer/` (`build.py`, `build.sh`, `figures/sso-flow.py`) despite `AGENTS.md:17`; not this story's surface.

## Residue after wave 3

- Correction round 2 (`review-result:wave3-gate-reads-document-deliverables-adversary-2`): D-1 to D-10 fixed; the silent-table report had two identical sites and was collapsed into one so a mutant has one place to hide, not two.
- The step is red on the live integration tree by design until the coordinator's `docs/architecture/runtime-decisions.md` row-set correction lands (applied in the coordinator tree; verified green with the unit's binary: 9 documents, 24 row sets).
- Reader residue, none asked for by a ruling: a deleted `docs/architecture/*.md` is invisible to a directory walk (only `README.md`/`AGENTS.md` deletion is caught); `cells()` honours the GFM `\|` escape but not a raw `|` inside a code span; a `Blocker` cell naming several blockers in a table with a store column attributes the row set to each; documents outside `docs/architecture` plus the two root files are not declared; prose count claims are not checked.
- `ess generate` refuses a symlinked `--out` path, so `cargo xtask contracts` cannot run in a unit tree provisioned with a `target` symlink; recorded for `task:runtime-wave-integration` (provisioning), not this story's.
- The self-claims SC1, SC3, SC4, SC5, FL1, FL2, FL3 remain unenforced by design (the story forbids a prose linter); their "enforced by" column still names checks that do not exist.
