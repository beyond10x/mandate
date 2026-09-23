---
format: aep.planning-md/1
id: review-result:wijk-k2-draws-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on K2 (sts-refusal-draws-nothing)
relations:
- reviews: story:sts-refusal-draws-nothing
revision: 1
---
unit: story:sts-refusal-draws-nothing, working tree at 5f28245 plus one untracked test file
verdict: red (3 red cases, all INFEASIBLE: no caller in the tree builds any of their states)
cases: executed 221→225, red 3
origin: introduced 3, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k2/scratch/adv2-suite.log
needs-coordinator: no

Cases in services/sts/tests/adversary_draws_nothing_2.rs:
- a_release_after_an_overtaking_draw_leaves_the_allocator_where_it_was red: reserve, draw, release, draw gives ordinals (2, 3) where (1, 2) was expected
- a_draw_that_skips_the_last_ordinal_does_not_overflow red: 254 drawn, 255 reserved, next draw panics at services/sts/src/lib.rs:293:13: attempt to add with overflow
- a_signer_that_unwinds_leaves_no_reservation_behind red: after a caught signer panic the next issuance panics at lib.rs:303:9: a credential identity is already reserved
- a_second_issuance_after_a_refusal_and_an_acceptance_signs_distinct_identities green

Suite: cargo test -p mandate-sts --locked --no-fail-fast exit 101, 222 passed, 3 failed. clippy Finished.

F1 lib.rs:323 INFEASIBLE introduced: release does not undo the skip at :292-293; the trait docs at :204-205, :218-219 promise the allocator is back where it was. Reaches: nothing — issue.rs:429-445 holds &mut from reserve to release.
F2 lib.rs:293 INFEASIBLE introduced: the second increment overflows u8 at 254 drawn plus 255 held. Reaches: nothing (needs F1's overtaking draw).
F3 issue.rs:429 INFEASIBLE introduced: no panic guard; a panicking sign_credential leaves the reservation held. Reaches: nothing — catch_unwind only in tests; control-plane does not wire self-contained issuance and its SystemAllocator is stateless.

Could not break: no ? or early return between reserve and commit/release; &mut exclusive; commit after an overtaking draw keeps ids unique; SystemAllocator ids fresh; StatedResourceServerIdentity reserve never reached; reference and code issuance draw only after every refusal.

```findings
- file: services/sts/src/lib.rs
  line: 323
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: release after a draw overtook the reservation does not undo the skip, so the released identity is never handed out and the allocator is not where it was
- file: services/sts/src/lib.rs
  line: 293
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the skip past a held ordinal overflows u8 when 254 are drawn and 255 is held
- file: services/sts/src/issue.rs
  line: 429
  category: concurrency
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a signer that unwinds leaves the SequentialAllocator reservation held, and the next issuance through it panics in reserve_credential_id
```
