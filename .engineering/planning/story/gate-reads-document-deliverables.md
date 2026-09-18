---
format: aep.planning-md/1
id: story:gate-reads-document-deliverables
kind: story
status: draft
title: task check cannot see a document deliverable, so it cannot fail one
relations:
- serves: vision:mandate
revision: 1
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
