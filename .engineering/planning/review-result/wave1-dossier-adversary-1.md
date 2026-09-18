---
format: aep.planning-md/1
id: review-result:wave1-dossier-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — runtime decision dossier, wave 1
relations:
- reviews: story:runtime-decision-dossier
revision: 1
---
```
unit: story:runtime-decision-dossier — docs/architecture/runtime-decisions.md (untracked, md5 d328bb5f8836290f87a168e2a494229c) in worktree impl/runtime-decision-dossier, base dc76aa3
verdict: NEEDS-CHANGE
cases: executed 47→47 (repo suite unchanged; my checker is in scratch, 96 assertions outside it), red 5
origin: introduced 6 / pre-existing 2 / undecided 0
wrote-outside-worktree: 30 files in my assigned scratch + 1 pre-existing shared build dir
needs-coordinator: whether finding 5 (no gate step reads the deliverable) becomes its own story — fixing it means touching xtask, which this story's own Scope names as a coordinator-owned integration surface
```

## 1. Diff

`git --no-pager diff --stat` empty. `git status --short` shows only `?? docs/architecture/runtime-decisions.md`. The adversary changed no file in the worktree; the deliverable's md5 is byte-identical to the implementor's own record. `docs/sources` re-verified: `original-design.md: OK`, `architecture-addendum.md: OK`.

## 2. The case, and its red output

`adv_check_dossier.py` in assigned scratch — 96 assertions driving the dossier against the store, against every line it cites, and against the universal claims it makes about itself.

First run came back 8 red. Four were the adversary's own bug: a `>40 chars` threshold on the affected-stories field, legitimately 21 chars when a row has one story. The checker was fixed, not the document, and it is disclosed because a case that fails for a reason not claimed is not a finding. Corrected run, exit 1:

```
FAIL C2-unit-checker-resolves-every-citation-this-document-makes: unit's checker resolves 198 of 210 line refs; 10 continuation refs (`:NN`) are invisible to it
FAIL D1-every-proposed-owner-cites-the-ownership-map: ['decision-blocker:global-trust (owner paragraph cites no ownership.md line)']
FAIL E1-no-concrete-algorithm-named-as-claimed: claim at :257; algorithm identifiers found at [(269, 'none')]
FAIL F1-after-revocation-claim-cites-a-section-about-revocation: runtime-decisions.md:147 cites original-design.md:[1625, 1633]; sections containing 'revocation': [] (the class 'Used after revocation' is :1629)
FAIL J1-a-gate-step-reads-the-dossier: xtask reads only ['docs/sources', 'docs/sources/SHA256SUMS']; nothing in `cargo xtask check` opens docs/architecture/runtime-decisions.md

96 checks executed, 5 red
EXIT=1
```

Mutation probe, two mutants applied to a copy in scratch, never the worktree:

| mutant | unit's `check_dossier.py` | adversary checker |
|---|---|---|
| index table line 41 claims `story:domain-runtime` for `decision-blocker:backend` | green, exit 0 | FAIL, exit 1 |
| continuation citation at line 87 pushed to `:9999` | green, exit 0 | FAIL, out of range |

## 3. The suite

`cargo xtask corpus` 47 scenarios exit 0. `cargo xtask contracts` 246 artifacts, deterministic, exit 0. Both are green regardless of the dossier's contents, which is finding 5. 47 is both the before and the after count.

## 4. Findings

1. `docs/architecture/runtime-decisions.md:147` — the clearance bullet asks for the consistency class used after revocation but cites `original-design.md:1625`, which is the Read-after-write class and contains no "revocation". The class "Used after revocation" is `:1629`, which row 5 cites correctly at `:172`. The dossier contradicts itself between rows 4 and 5. CONFIRMED / introduced.
2. `docs/architecture/runtime-decisions.md:31` — the preamble claims every proposed owner is a role or boundary taken from the ownership map. Row 6's owner paragraph at `:191` cites no `ownership.md` line and names a story id whose owner the store does not record. Row 9's key-management half at `:261` cites `original-design.md:2499`, a requirements heading that assigns no owner. NEEDS-CHANGE / introduced.
3. `docs/architecture/runtime-decisions.md:257` — claims no concrete algorithm is named anywhere in the document, then names `none` at `:269`, a JOSE `alg` identifier. Naming an algorithm to reject it is not selecting one, so this is not a prohibition breach; the defect is the false universal. CONFIRMED / introduced.
4. `docs/architecture/runtime-decisions.md:161` — acceptance demands bounded alternatives per blocker; row 5's policy-engine half states its alternative set is open and unstated. No permitted source enumerates policy-engine candidates and inventing three would breach the story's prohibition. INFEASIBLE / introduced.
5. `xtask/src/main.rs:202` — the only `docs/` path any gate step opens is `docs/sources/SHA256SUMS`. `task check` never reads `docs/architecture/`. Emptying or deleting the deliverable leaves the gate green. Reproduces at `dc76aa3`. CONFIRMED / pre-existing.
6. `check_dossier.py:24` — the unit's citation checker anchors on a full `path.md:NN` token, so 10 continuation citations covering 12 line refs are never resolved: 198 of 210. A mutated copy with an out-of-range continuation citation passes it. Latent, not live: all 12 currently resolve correctly. CONFIRMED / introduced.
7. `check_dossier.py:71` — the unit's checker reads affected stories only from each row's declaration line, never from the index table at `:35-47`, which is the first thing a reviewer reads. A mutated copy naming the wrong story there passes it. Latent, not live: all 11 index rows verified correct by hand. CONFIRMED / introduced.
8. `brief.md` — the coordinator's brief claims the register is stale on five of eleven rows including guards. `unmapped.md:44` does carry `story:audit-client` for `decision-blocker:guards`; only the `AEP:` line at `:21` omits it. The register is stale on four, and the implementor's split-section reading is correct. CONFIRMED / pre-existing.

Judgement on `docs/sources/architecture-addendum.md`: legitimate. `combined.md:3` makes the addendum a normative input snapshot of equal standing to `original-design.md`, both are pinned by the same `SHA256SUMS`, and the prohibition grants the directory rather than one file in it. Three claims have no equivalent in the brief's named list; dropping them would have meant inventing or omitting.

## 5. Attacked and could not break

Row set: `aep plan artifact blocked --format json` returns 13 groups, 11 runtime plus 2 Drive, all open. Numbering 1-11 and both exclusions match exactly.

Affected stories: all 11 per-row declarations and all 11 index rows match the store exactly, including the four store-only additions the register lacks. No shortcut through `unmapped.md` anywhere.

Citations: 210 line references resolved; none blank, none a bare fence, none out of range, none a missing file. About 45 targets read by hand across all 11 rows. All support their claims except `:147`.

Asserted counts: "34 commands in `command-obligations.md:7-40`" is exactly 34 rows. "18 categories at `audit-routing.md:9-26`" is exactly 18.

ESS naming: the dossier uses the real ESS names; `combined.md:47` and the yaml comments use the shorthand. No ESS meaning changed.

Prohibitions: no blocker cleared, no store write, no backend or algorithm selected (row 5 refuses explicitly at `:159`), no runtime test claimed at `:344`, global trust deferred as a row not a resolution at `:181`. No alternative phrased as settled.

`docs/sources/`: `sha256sum -c` OK on both files, `git status` clean.

Two over-reads judged too weak to raise: `command-obligations.md:24` at `:327` is the right command but its deny clause is about authority-without-mapping rather than double-application; and the addendum constraint claim at `:222` covers 2 of the row's 4 keys, though `:232` flags the ceiling-key gap correctly.

```findings
- file: docs/architecture/runtime-decisions.md
  line: 147
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the clearance bullet asks for the consistency class used after revocation but cites original-design.md:1625, the Read-after-write class, where the class used after revocation is :1629 and row 5 cites it correctly.
- file: docs/architecture/runtime-decisions.md
  line: 31
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the preamble claims every proposed owner is a role or boundary taken from ownership.md, but row 6 cites no ownership.md line and names a story whose owner the store does not record, and row 9's key-management half cites a requirements heading that assigns no owner.
- file: docs/architecture/runtime-decisions.md
  line: 257
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the document claims no concrete algorithm is named anywhere in it and then names `none` at :269, which is a rejection requirement rather than a prohibited selection, so the defect is the false universal and not a prohibition breach.
- file: docs/architecture/runtime-decisions.md
  line: 161
  category: acceptance
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: acceptance requires bounded alternatives for every blocker and row 5's policy-engine half declares its alternative set open and unstated, which cannot be fixed here because no permitted source enumerates policy-engine candidates and inventing them would breach the story's prohibition.
- file: xtask/src/main.rs
  line: 202
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: no step of `task check` reads docs/architecture, so the gate that declared this unit green is insensitive to the deliverable's entire contents and would stay green if the file were emptied or deleted.
- file: check_dossier.py
  line: 24
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the unit's own citation checker resolves 198 of 210 line references because its regex cannot match the continuation form `:NN`, and a mutated copy with an out-of-range continuation citation passes it with exit 0.
- file: check_dossier.py
  line: 71
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the unit's own checker never validates the index table at runtime-decisions.md:35-47 against the store, and a mutated copy naming the wrong story in that table passes it with exit 0.
- file: brief.md
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: the brief's trap claims the register is stale on five of eleven rows including guards, but unmapped.md:44 does carry story:audit-client for decision-blocker:guards and only the AEP line at :21 omits it, so the register is stale on four and the implementor's split-section reading is correct.
```
