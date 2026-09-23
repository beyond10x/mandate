---
format: aep.planning-md/1
id: review-result:wijk-k3-road-lane-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on K3 (road-lane-child-prints-address)
relations:
- reviews: story:road-lane-child-prints-address
revision: 1
---
unit: story:road-lane-child-prints-address, commit b40b4f4 (base 9646f68), working tree clean
verdict: green
cases: executed 155→155, red 0
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k3/scratch/adv1-suite.log
needs-coordinator: no

No defect turned into a failing test; two judgement notes. No case added: Served and bound_address are private to the adversary_login_road binary.

Suite: cargo test -p mandate-control-plane --locked EXIT=0, 155 passed; adversary_login_road: test result: ok. 10 passed; acceptance case alone ok in 1.82s.

1 adversary_login_road.rs:1341 CONFIRMED introduced note: at the commit's own red-before rate of 1 in 192, one 192-copy run against the base comes out green about 37% of the time ((191/192)^192); arithmetic on the implementor's number, base not re-measured.
2 adversary_login_road.rs:1351 CONFIRMED introduced note: each copy skips only the acceptance case and still runs a_second_copy_of_this_binary_does_not_write_this_runs_documents and the_run_root_clears_what_is_finished_and_keeps_what_is_running, each of which starts another copy; end_to_end.rs:2546 CASES_A_COPY_SKIPS treats exactly this as a defect.

Held: silent / stderr-only / early-dying child bounded by recv_timeout, exited(), Disconnected arm and a 30 s deadline; println! flushes per line; drain thread joins after kill; Drop kills and reaps on unwind; no spoofable listening line (main.rs:369 after bind); acceptance not vacuous (count from --list, 0 passed refused, no prefix match); no other lane drops a probe listener (adversary_login_pass2.rs:254, end_to_end.rs:1366 hold theirs).

```findings
- file: services/control-plane/tests/adversary_login_road.rs
  line: 1341
  category: property
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'at the commit''s own red-before rate of 1 in 192, one 12x16 run against the base comes out green about 37% of the time, so the acceptance case does not reliably separate the old design from the new'
- file: services/control-plane/tests/adversary_login_road.rs
  line: 1351
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'copies skip only the acceptance case and still run the two cases that start copies of the binary, which end_to_end.rs CASES_A_COPY_SKIPS treats as a defect'
```
