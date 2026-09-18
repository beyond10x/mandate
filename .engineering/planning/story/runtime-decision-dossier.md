---
format: aep.planning-md/1
id: story:runtime-decision-dossier
kind: story
status: active
title: Prepare the runtime decision dossier without clearing blockers
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:foundation-contracts
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: docs/architecture
- confidence: inferred
  path: docs/architecture/runtime-decisions.md
- confidence: inferred
  path: docs/architecture/unmapped.md
revision: 9
---
# Prepare the runtime decision dossier without clearing blockers

## Acceptance

Given the eleven open runtime decision blockers, when an independent reviewer follows the dossier, then every blocker has a source-cited decision question, bounded alternatives, proposed owner, affected stories and exact evidence required to clear it.

## Required observations

Cover epoch representation and arithmetic, lifecycle/retention, guards and denial audit, transaction boundaries, graph/policy backend, deferred global trust, conditional subject references, uniqueness, algorithm policy, audit routing/vocabulary and worker orchestration. Global trust stays deferred. The separate Drive verifier is recorded as excluded execution tooling. Mark recommendations as proposals. Do not clear a blocker, select an unapproved algorithm/backend, claim runtime tests, or change ESS meaning. A decision can remain unanswered and this dossier can still be complete; downstream runtime cannot start until its own decisions are recorded and cleared by an authorized owner.

## Contract and provenance

Existing entities and relations in systems/mandate/domains/*.yaml are referenced only. This story creates a decision document, no domain noun or persisted envelope.

Sources: docs/architecture/unmapped.md:5; docs/sources/original-design.md:3327; docs/architecture/command-obligations.md:1. Placement in wave 1 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper` against `dc76aa3`. Every line is **cited** (read from the story
or the tree) or **inferred** (a reading that could be wrong).

- **Primary surface:** `docs/architecture` — cited; the story's Sources name
  `docs/architecture/unmapped.md:5` and `docs/architecture/command-obligations.md:1`, and `xtask`
  imposes no check on this directory.
- **Files:** `docs/architecture/runtime-decisions.md` — inferred; the file does not exist,
  `git ls-files docs/architecture` returns five files and none is this one. The name carries over
  from revision 5 and nothing in the tree fixes it.
- **Symbols:** none — cited; acceptance requires a decision document and forbids clearing a blocker,
  selecting an algorithm or backend, and claiming runtime tests.
- **Also likely:** `docs/architecture/unmapped.md` — inferred; a back-link from the register to the
  dossier follows the convention at :66 and :72, but the acceptance does not require it.
- **Documents:** document-only. Eleven rows, one per open runtime decision blocker, each with a
  source-cited question, bounded alternatives, proposed owner, affected stories and clearance
  evidence.
- **Read-only, never written:** `docs/sources/` — cited; `xtask/src/main.rs:202-212` re-hashes every
  file named in `docs/sources/SHA256SUMS` and fails with `source changed: {name}`. Citing into
  `original-design.md:3327` is safe; editing it breaks `task check`.
- **Excluded surface:** `docs/adr/` — cited; all eight existing ADRs carry `Status: accepted`, and
  this story must mark recommendations as proposals.
- **Confidence:** high for the directory and the document-only shape — the store yields exactly
  eleven runtime blockers. Medium for the leaf filename, which nothing in the tree fixes.
- **Would collide with:** any unit writing under `docs/architecture`. `story:domain-runtime` holds
  `docs/architecture` as cited scope, so the collision is real. It is **not live in this wave**:
  that story sits in wave 2, depends on this one, and carries two open blockers. Wave 1's other
  unit scopes only `Cargo.lock`, `Cargo.toml`, `crates/mandate-{model,proto,token,types}` and
  `dependency-boundaries.json`, which is disjoint.

**The affected-stories column must come from `aep plan artifact blocked`, not from this file's
`AEP:` lines.** The register is stale against the store on five of eleven rows — it predates
`story:audit-worker-delivery` and `story:agent-authority-kernel`. Rows affected: lifecycle (adds
`audit-worker-delivery`), guards (adds `audit-client`), identity-uniqueness (adds
`agent-authority-kernel`), audit-routing (adds `audit-worker-delivery`), worker-orchestration (adds
`audit-worker-delivery`). Building the column from the file yields five wrong rows, and this story's
own Validation step checks the matrix against `aep plan artifact blocked`.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Only nonterminal prerequisites and blockers applicable to this dispatched story prevent dispatch; the downstream runtime decisions are its subject, not prerequisites to writing it. Verify an eleven-row blocker matrix against `aep plan artifact blocked`; independently follow each source citation and check every row includes question, alternatives, proposed owner, affected stories and clearance evidence.
