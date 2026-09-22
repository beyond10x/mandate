---
format: aep.planning-md/1
id: review-result:wave-h-host-spelling-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — host-spelling-folded
relations:
- reviews: story:host-spelling-folded
revision: 1
---
# Adversary pass 2 — `story:host-spelling-folded`

Against `af2982c`, the correction that answered pass 1. Returned 2026-09-22.

```
unit: story:host-spelling-folded
verdict: red
cases: executed 307→311, red 4
origin: introduced 6, pre-existing 1, undecided 0
wrote-outside-worktree: two suite logs under ~/.cache/claude-tmp/waveh/h2-host-spelling/adv2/
needs-coordinator: yes
```

Two scalars of the findings block below are single-quoted so the store can parse it; the adversary
wrote it unquoted and its embedded `"Out of scope: Widening"` made the YAML a mapping. No character
of the message changed.

One untracked test file added, `crates/mandate-federation/tests/adversary_host_spelling_2.rs`. No
implementation file was mutated: the base and mutant variants were reimplemented inside probe test
files, which were deleted.

## The ledger against pass 1

Pass 1: 7 findings. Pass 2: 7 findings. **Carried: 0. New: 7. Resolved: 7.** The count is flat and
nothing came back — pass 1's findings were about the guard reaching two of three comparisons; pass
2's are about what the correction's own test asserts. Computed by hand, on `file:line` + verdict +
origin, because the two passes share no signature.

## What it attacked and could not break

- **The monotonicity claim, which is the one that decides whether this unit widened an SSRF guard.**
  12,168 base→head decisions (39 × 39 spellings × 2 schemes × 4 host lists): 269 move refused →
  admitted and **every one leaves through the issuer's own-origin comparison, zero through the
  containment branch**; 777 move admitted → refused and every one is an address literal spelled with
  a trailing dot. No host becomes reachable through containment that was not reachable before. It
  survived.
- **The IPv6 mutant re-run.** With `!literal_address(host) && !loopback(host)` deleted, **all 23**
  rows of `a_listed_host_that_spells_the_loopback_interface_is_refused` flip to admitted, the eight
  IPv6 rows included. The `{bare}:443` entry is what makes them non-vacuous, as the correction
  claimed.
- Both spelling tables, all 35 rows, match the implementation — the two new residue rows included.
- Nothing was lost between `06c6747` and `af2982c`: `adversary_verifier_2.rs` untouched, and the
  rewritten property's crossed block is a strict superset of `d6b1876`'s.

## The four red cases

```
panicked at adversary_host_spelling_2.rs:113:5:
the containment comparison is satisfied by two refusals for 14 of 16 rows, so it asserts nothing
about the branch it names

panicked at adversary_host_spelling_2.rs:167:5:
every comparison the (http, idp.example) row makes is a refusal against a refusal: [false, false,
false, false, false, false]

panicked at adversary_host_spelling_2.rs:217:13:
issuer http://[::1]:8443: [::1] and [0:0:0:0:0:0:0:1] are one address and the guard gave them two
answers: alike=true, otherwise=false

panicked at adversary_host_spelling_2.rs:249:9:
https://../jwks folds to the empty host `origin` refuses, and was admitted as the issuer's own origin
```

## Findings

```findings
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2434
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the reworked property's containment-branch comparison is two refusals for 14 of its 16 rows, so deleting the containment guard leaves it green, contradicting the case's own claim at :2367 that every host is asked at sites 2 and 3.
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2395
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the ("http", "idp.example") row the correction added to reach the plaintext arm makes six comparisons and every one is a refusal against a refusal, so the row asserts nothing at all.
- file: crates/mandate-federation/src/verifier_real.rs
  line: 344
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: folded is not total, so ::1, 0:0:0:0:0:0:0:1 and 0:0::0:1 are one host to literal_address/loopback and three strangers to the own-origin equality, giving one host two answers at the site this correction folded; it fails closed and no caller was found that reaches it.
- file: crates/mandate-federation/src/verifier_real.rs
  line: 519
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: trim_end_matches('.') strips every trailing dot, so ".", ".." and "..." all fold to the empty host origin refuses at :455 and become one origin, and the same over-fold is why the unit's document counts 127.0.0.1.. as a spelling of 127.0.0.1.
- file: .engineering/planning/story/host-spelling-folded.md
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the story''s "Out of scope: Widening or narrowing what admits allows" is contradicted by the shipped change, which widens 269 decisions and narrows 777 and documents both itself; the change is right and the story text must be amended by the coordinator.'
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 69
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the safety measurement backing the fold is scoped to the empty host list, the one configuration in which the narrowed containment branch cannot fire, so "none goes admitted-before to refused-after" is asserted from a measurement that could not have observed the 777 pairs that do.
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2295
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: '"Every row of the module''s own table is here" is false — [::FFFF:7F00:1] and [::127.0.0.1] are table rows at :47-48 and are absent from the 23-row enumeration, though both behave as the table states.'
```

## How the coordinator routed each

This is the second pass, so the attacking budget is spent. The correction answering it is verified by
the coordinator rather than by a third pass.

| finding | row taken |
|---|---|
| `tests/verifier_real.rs:2434` and `:2395` — comparisons satisfied by two refusals | back to the implementor. The guard itself is covered — `a_listed_host_that_spells_the_loopback_interface_is_refused` kills the mutant on all 23 rows — so what is wrong is a case describing itself falsely, which is the defect this unit was written to stop |
| `tests/verifier_real.rs:69` — the safety measurement is scoped to the dead configuration | back to the implementor: state the 12,168-decision figure, both directions, and what the 777 narrowed decisions are |
| `tests/verifier_real.rs:2295` — the enumeration is 23 rows against a 25-row table | back to the implementor |
| `src/verifier_real.rs:344` and `:519` — `folded` is not total, and over-folds an all-dots host | documented, not fixed. Both are `INFEASIBLE`, both fail closed, and `:344` reproduces identically at the wave base. Making `folded` total means the guard resolving rather than parsing, which is a different story |
| the story's `## Out of scope` | the coordinator's own document, amended at the close |
