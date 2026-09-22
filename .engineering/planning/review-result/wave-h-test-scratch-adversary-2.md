---
format: aep.planning-md/1
id: review-result:wave-h-test-scratch-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — per-run-test-scratch
relations:
- reviews: story:per-run-test-scratch
revision: 1
---
# Adversary pass 2 — `story:per-run-test-scratch`

Against `d08e7f4`, the correction that answered pass 1. Returned 2026-09-22.

```
unit: story:per-run-test-scratch
verdict: red
cases: executed 147→150, red 3
origin: introduced 6, pre-existing 0, undecided 0
wrote-outside-worktree: 16 paths under ~/.cache/claude-tmp/waveh/h4-test-scratch/adv2/
needs-coordinator: yes — no session lease was held on the tree for this pass, and the routing of the three constructed-state rows is the coordinator's
```

One file touched, `services/control-plane/tests/end_to_end.rs`, 169 insertions, 0 deletions.

## The ledger against pass 1

Pass 1: 5 findings. Pass 2: 6. **Carried 0, new 6, resolved 5.** Pass 1 attacked whether the scratch
root was per run; pass 2 attacks whether the correction's own cases prove what they say.

## What it attacked and could not break

- **the three mutation results reproduce.** A standalone probe against the verbatim helper: deleting
  the `sweep_finished_runs` call is caught by the finished-run assertion, deleting `&& finished(pid)`
  by the running-run assertion, deleting the run's own `remove_dir_all` by the cleared-root
  assertion. Each is caught by the one assertion the commit names, and by no other
- **the helper is byte-identical across the four lanes**, character for character with doc comments
  stripped
- `two_copies_of_this_lane_run_at_once_and_both_pass` is green at 4 copies × 10 rounds
- **the sweep cannot take a live run's root on a host with a populated `/proc`**: a pid is allocated
  at fork, before its root exists, so there is no window; `pid_max` here is 4,194,304
- a zombie and a foreign pid both read as *not finished* — the safe direction
- every document in the four lanes is written under the run root; the two `adversary_listener` lanes,
  `adversary_jit_login`, `adapters` and `authority` contain no `std::fs`, no `Command::new`, no `Path`

## Findings

```findings
- file: services/control-plane/tests/end_to_end.rs
  line: 2439
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the acceptance case says each copy runs the lane as the unit left it at eighteen cases, but the correction added a nineteenth without adding it to the skip list, so all forty copies run it and each spawns a further child
- file: services/control-plane/tests/end_to_end.rs
  line: 2483
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the per-copy check of exit status plus a summary containing '0 failed' accepts a copy that executed no case at all, which the sibling second-copy case guards against explicitly and this one does not
- file: services/control-plane/tests/end_to_end.rs
  line: 337
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: finished() guards on the /proc directory existing rather than on procfs answering, so where /proc is an unmounted mount point every live run reads as finished and the sweep deletes a running run's root, the opposite of what the doc comment above it promises
- file: services/control-plane/tests/end_to_end.rs
  line: 2446
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the case is named and documented as two copies of the lane at once while COPIES is 4, which mis-states the number the story asks to have reported
- file: services/control-plane/tests/end_to_end.rs
  line: 2193
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the doc says two copies of the binary run at once, but .output() blocks the first copy until the second has exited, so what the case proves is that the two paths differ and not that concurrent writes do not collide
- file: services/control-plane/tests/end_to_end.rs
  line: 377
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a failure of the run's own clear is discarded and create_dir_all then succeeds on the surviving directory, so the run is silently handed a root still holding the previous id-holder's documents
```

## How the coordinator routed each

The attacking budget is spent; the correction answering this pass is verified by the coordinator.

All six go back to the implementor. Every one is in a file the unit owns, every one is cheap, and
five of the six are the unit's own text saying something the code does not do — which is the class
this unit was written to close, turned on the unit itself. The two `INFEASIBLE` rows are routed rather
than filed because their fixes are one line each and both strictly narrow: guard `finished()` on
`/proc/self` answering rather than on the directory existing, and stop discarding the failure of the
run's own clear.

The lease note is the coordinator's process, not the unit's: this pass ran without a session lease on
the tree, which is a gap in how the pass was dispatched and not a finding about the code.
