---
format: aep.planning-md/1
id: review-result:wijk-k3-road-lane-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on K3 (road-lane-child-prints-address)
relations:
- reviews: story:road-lane-child-prints-address
revision: 1
---
unit: story:road-lane-child-prints-address, commit 5699e09 (base 9646f68), working tree clean
verdict: green
cases: executed 165→165, red 0
origin: introduced 1, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k3/scratch/{adv2-probe-concurrent.log, adv2-probe-second.log, adv2-suite.log}
needs-coordinator: no

No failing case; one note. No case file written: the only case would glob target/debug/deps for the sibling binary. Probed from the shell instead.

Suite: cargo test -p mandate-control-plane --locked EXIT=0, 165 passed; adversary_login_road ok. 10 passed. clippy and fmt 0.

1 adversary_login_road.rs:1375 INFEASIBLE introduced note: with MANDATE_SECOND_COPY=1 exported the full binary prints test result: ok. 10 passed ... finished in 0.04s, EXIT=0; the acceptance case returns before starting any copy. The || SECOND_COPY clause is new in this unit and dead on every existing path (the second copy is always started with --exact a_second_copy...). Reaches: nothing — the name is shared with serve.rs:3344 and adversary_login_pass2.rs:693, each setting it only on a copy of its own binary; no Taskfile or CI sets it. Fix: drop the clause or fail loudly.
With MANDATE_ADVERSARY_CONCURRENT_COPY=1 exported the two spawning cases panic at :1328 with the guard's message, FAILED. 8 passed; 2 failed, EXIT=101 — loud, not vacuous.

Could not break: the only current_exe call is :1333 and all three spawns go through it; skip-list names checked against --list, no substring over-skip; the prefix match cannot confuse 7 and 17 passed; the guard trips a missing skip; pass-1 note 2 fixed; no pipe deadlock.

```findings
- file: services/control-plane/tests/adversary_login_road.rs
  line: 1375
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'with MANDATE_SECOND_COPY exported the acceptance case returns before starting any copy and the whole lane reports ok. 10 passed; the clause is dead on every path that exists, and nothing sets the variable outside the lane itself'
```
