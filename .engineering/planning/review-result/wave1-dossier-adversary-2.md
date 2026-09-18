---
format: aep.planning-md/1
id: review-result:wave1-dossier-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — runtime decision dossier, wave 1
relations:
- reviews: story:runtime-decision-dossier
revision: 1
---
```
unit: story:runtime-decision-dossier — docs/architecture/runtime-decisions.md (untracked, 344 lines, md5 cf6daa728b38394ec92bbc55a7a854f5), branch impl/runtime-decision-dossier, base dc76aa3
verdict: NEEDS-CHANGE
cases: executed 96→109, red 7
origin: introduced 9 / pre-existing 0 / undecided 0
needs-coordinator: whether finding 1 reopens the "policy-engine alternatives open and unstated" item the coordinator accepted — not re-raised, but the reason the document gives for it is false
```

Origin is `introduced` for all nine without guessing: `git show dc76aa3:docs/architecture/runtime-decisions.md` reports the file exists on disk but not in `dc76aa3`. The deliverable has no base version, so nothing in it can be pre-existing.

## The five corrections, verified individually

| Correction | Result |
|---|---|
| `:147` moved `:1625` → `:1629` | **Good.** `original-design.md:1629` is `### Strong/security-sensitive`, body at `:1631` "Used after revocation…". Rows 4 and 5 now both cite `[1629, 1633]`. Pass 1's F1 flipped to PASS. |
| `:31` narrowed to two exceptions | **Still false, in a third place.** Exactly two paragraphs declare the gap, but row 8 names an owner from outside the map without declaring one. |
| `:191` / `:261` declare no ownership-map owner | `:191` honest. `:261` conclusion sound, support misquoted. |
| `:257` rewritten | **Good, nothing weakened.** `:269` unchanged in substance across drafts; `:257` discloses `none` instead of deleting the requirement. |
| "34 universals enumerated, exactly two false, class closed" | **False.** Two more exist. |

## Findings

1. `runtime-decisions.md:161` — CONFIRMED / introduced / warning. The claim that no permitted source enumerates policy-engine candidates is false. `docs/sources/original-design.md:3364` is a section headed `## Policy engine` listing `simple internal condition language?`, `Cedar?`, `another engine?`; Cedar and Open Policy Agent are also named at `:740` and `:742`. What reaches it: the independent reviewer named in the acceptance statement is told to stop looking for candidates the source has. The graph half of the same row is bounded from `:2367-2374`, and `## Authorization backend` sits seven lines above the `## Policy engine` section the row missed, under the same parent heading.
2. `runtime-decisions.md:261`, same words at `:31` — NEEDS-CHANGE / introduced / warning. Both cite `combined.md:67` as listing the key provider among decisions needing a reviewed **owner**. That line reads "Graph backend, policy implementation, key provider, sender-constraint profile, retention and cache bounds need reviewed **decisions** before their implementation" and contains the word `owner` zero times. The conclusion is still true — `ownership.md` has no key-provider row — but the cited source does not establish it.
3. `runtime-decisions.md:234` — CONFIRMED / introduced / warning. Row 8's owner paragraph opens "The storage adapter owner" and cites `ownership.md:14`, `:15`, `:16`; none contains "storage" or "adapter", and no gap is declared. Third counterexample to the narrowed universal at `:31`. A weaker sibling at `:209` cites `:11`, which at least says "concrete storage remains an adapter".
4. `check_dossier.py:105` — CONFIRMED / introduced / warning. The owner check is `any(basename(p)=="ownership.md")`: presence, never relevance. Mutant E repointed row 5's graph/policy owner at `ownership.md:18` (`mandate.audit`, worker deployment) and the checker printed "every proposed owner traced to ownership.md", exit 0. This is what let finding 3 through.
5. `check_dossier.py:180` — CONFIRMED / introduced / warning. `ALGORITHMS` is 16 JWS shortnames matched case-sensitively with no `re.I`. Mutant F proposed `es256`, `RSASSA-PKCS1-v1_5` and `ecdsa` over `P-256` as the initial admitted set: exit 0, "no concrete algorithm proposed". This is the one prohibition the checker claims to enforce mechanically.
6. `check_dossier.py:168` — CONFIRMED / introduced / note. Citations are checked only for resolving to a non-blank non-fence line. Mutant G repointed the row 9 owner-gap citation from `combined.md:67` to `combined.md:41` and passed with exit 0. The bound the implementor already declared open, recorded because finding 2 is a live instance of it in the shipped document.
7. `runtime-decisions.md:226` — CONFIRMED / introduced / note. Alternative 1 offers `architecture-addendum.md:859-862` as "the exact composite keys". That range holds `UNIQUE (organization_id, issuer, external_subject)`, `(organization_id, audience)`, `(directory_group_id, team_id)` and a credential verifier index — 2 of row 8's 4 named keys, no ceiling key at all, plus 2 keys the row never names. A reviewer picking alternative 1 gets no constraint for the ceiling key.
8. `runtime-decisions.md:3` — CONFIRMED / introduced / note. The promise that a reviewer can take one row "without reading the rest of this file" is contradicted by seven cross-row dependencies; `:310` ("composes with alternative 1 of row 10") cannot be evaluated from its own row. Judgement only, raised because it is a self-referential universal the closure claim covered.
9. `adversary/adv_check_dossier.py:166` — CONFIRMED / introduced / note. Pass 1's `C2` hardcodes the superseded citation regex instead of invoking the checker and now reports a false red (201/213 when the checker resolves 213/213); `D1` asserts the pre-narrowing `:31`; `E1` passes vacuously since `:257` was reworded. Two of that suite's three reds are dead. Not edited, per hard rule 2.

## Attacked, could not break

`:173` "no decision-latency target exists in any source" — true. Index table, per-row declarations and `aep plan artifact blocked` agree on all 11 rows including the five store-only additions. Both Drive blockers excluded, never rows, neither argued nor recommended. "34 commands in `command-obligations.md:7-40`" is exactly 34. "18 categories at `audit-routing.md:9-26`" is exactly 18, and `audit-routing.md:5` says 18 itself. All 213 line references resolve to non-blank non-fence lines; about 45 load-bearing ones read by hand, and every one but findings 2 and 7 says what the dossier says it says. No blocker cleared — 13 groups, 13 open. Planning store and `docs/sources` clean in git, SHA256SUMS match. Global trust still a deferral at `:181`. No backend selected: `SpiceDB` and `OpenFGA` appear only at `:155-156` inside the enumerated list, with `:159` selecting none.

## Merge call

Nothing here blocks on its own. Findings 1, 2 and 3 are one-sentence document corrections and the unit should be held for them together, because all three are the same defect class the last round was sent back for and two of them falsify the closure claim offered as the reason the class was shut. Findings 4-6 are about the unit's own checker, which never ships — they bound what its green run is worth, and finding 4 is why finding 3 survived to this pass. Finding 1 goes in front of a person first: it is the only one where the document tells a reviewer to stop looking for something the source has.

```findings
- file: docs/architecture/runtime-decisions.md
  line: 161
  category: acceptance
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the claim that no permitted source enumerates policy-engine candidates is false — original-design.md:3364-3368 is a section headed "Policy engine" listing "simple internal condition language?", "Cedar?" and "another engine?", with Cedar and Open Policy Agent also named at :740 and :742.
- file: docs/architecture/runtime-decisions.md
  line: 261
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: combined.md:67 is cited here and at :31 as listing the key provider among decisions needing a reviewed owner, but it says those items need reviewed decisions before their implementation and contains the word owner zero times.
- file: docs/architecture/runtime-decisions.md
  line: 234
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: row 8 names "the storage adapter owner" while citing ownership.md:14, :15 and :16, none of which mentions storage or an adapter, and declares no gap — a third counterexample to the narrowed universal at :31, so the class-is-closed claim is false.
- file: check_dossier.py
  line: 105
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the owner check tests only that some ownership.md line is cited, so mutant E repointing row 5's graph/policy owner at ownership.md:18 passes with exit 0.
- file: check_dossier.py
  line: 180
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the prohibited-algorithm list is 16 JWS shortnames matched case-sensitively, so a proposed allowlist of es256, RSASSA-PKCS1-v1_5 and ecdsa over P-256 passes with exit 0.
- file: check_dossier.py
  line: 168
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: citations are checked only for resolving to a non-blank non-fence line, so mutant G repointing the row 9 owner-gap citation from combined.md:67 to combined.md:41 passes with exit 0, with a live instance at runtime-decisions.md:261.
- file: docs/architecture/runtime-decisions.md
  line: 226
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: alternative 1 offers architecture-addendum.md:859-862 as the exact composite keys for a row whose question names a ceiling key per agent and organization-or-platform, and that range contains no such constraint while containing two keys the row never names.
- file: docs/architecture/runtime-decisions.md
  line: 3
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the promise that a reviewer can take one row without reading the rest of the file is contradicted by seven cross-row dependencies, of which :310 cannot be evaluated from its own row.
- file: adv_check_dossier.py
  line: 166
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: pass 1's C2 hardcodes the superseded citation regex instead of invoking the checker and now reports a false red, D1 asserts the pre-narrowing :31, and E1 passes vacuously since :257 was reworded.
```
