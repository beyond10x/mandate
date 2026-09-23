---
format: aep.planning-md/1
id: review-result:wl-l2-multi-fold-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on L2 (control-plane-multi-fold-writes)
relations:
- reviews: story:control-plane-multi-fold-writes
revision: 1
---
unit: story:control-plane-multi-fold-writes, working tree a8bb09b plus one untracked test file
verdict: red
cases: executed 167→168, red 1
origin: introduced 0, pre-existing 0, undecided 1
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l2/scratch/adv1-suite.log
needs-coordinator: no

The commit's three sites held up; one red case at a site the story does not list.

Case: services/control-plane/tests/adversary_multi_fold_1.rs, a_refused_connection_document_seeds_no_connection — red. ConnectionSeeding::admit gets a document with a stated connection_id and link subject " subject-1"; the link is refused (Unseedable, SubjectNotTrimmed) but the connection stays in the seeding's fold; the corrected document with the same id is refused as a repeat naming no earlier file.
panicked at services/control-plane/tests/adversary_multi_fold_1.rs:57:5: a refused document left its connection in the seeding's fold: Err(RepeatedConnectionId { path: "corrected.json", incumbent: "", connection_id: ... })

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast exit 101, 167 passed, 1 failed. clippy and fmt clean.

F1 adapters.rs:1031-1037 INFEASIBLE undecided note: the loop writes the connection event then the link event into self.projection; a refused second write leaves the first. Reaches: nothing — main.rs:252-255 stops the process on the first seeding refusal. Fix: copy-then-swap as Deployment::provisioned does.

Could not break: authenticate_once's ignored federation.apply (connection found in the same fold, record.rs:808, same &mut call; no event removes a connection); redeem's ignored credentials.apply (decide checks the target against the same fold first, binding.rs:314); copy-then-swap in OpeningSessionIssuer::issue (no lost write, no double apply); ClientSeeding::admit and TargetSeeding::admit have no refusal after an earlier write.

```findings
- file: services/control-plane/src/adapters.rs
  line: 1031
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: undecided
  message: 'ConnectionSeeding::admit applies the connection event before its link, so a refused link leaves the connection in the seeding fold; main.rs aborts on the refusal, so nothing reaches it'
```
