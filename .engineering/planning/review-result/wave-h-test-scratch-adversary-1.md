---
format: aep.planning-md/1
id: review-result:wave-h-test-scratch-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — per-run-test-scratch
relations:
- reviews: story:per-run-test-scratch
revision: 1
---
# Adversary pass 1 — `story:per-run-test-scratch`

Against `08f68a5` in `mandate-wh-test-scratch`, base `06c6747`. Returned 2026-09-22.

```
unit: story:per-run-test-scratch
verdict: NEEDS-CHANGE
cases: executed 141→144, red 2
origin: introduced 3, pre-existing 2, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/waveh/h4-test-scratch/ (859 probe logs and sources)
needs-coordinator: yes
```

No implementation file touched; 199 insertions, 0 deletions, both in test files. No existing case was
deleted, skipped, weakened or rewritten.

## What it attacked and could not break

- **the acceptance itself**: 576 concurrent copies of `end_to_end` over three 32-way attempts,
  10,368 cases, 0 failures; plus 80 copies at 4-way
- **all five scratch write sites moved**: `CARGO_TARGET_TMPDIR` now appears only inside the four
  `run_root`s, and no `fs::write`, `File::create`, `create_dir_all`, `PathBuf::from` or `Path::new`
  scratch construction in the four lanes bypasses `document` / `seed_file`
- `serve` at 6-way: 3,780 cases, 0 failures. `adversary_login_pass2` at 6-way: 240 cases, 0 failures
  — its `serve_refusing` **holds** the listener, which is the correct pattern
- all 33 `seed_file` names are distinct, so the flat seed directory has no intra-process collision
- no patch under `tests/mutants/` touches these four files

## The two red cases

```
panicked at services/control-plane/tests/end_to_end.rs:2261:5:
4 of 4 runs that have exited left their scratch root standing: [".../run-2755958", ".../run-2755960",
".../run-2755962", ".../run-2755964"]. The story delivers a root created at start and removed at end;
this one is cleared at start and only ever its own, so the parent gains one directory for every
process id that has ever run this binary
```

```
panicked at services/control-plane/tests/adversary_login_road.rs:1086:5:
12 of 192 copies of this lane refused while other copies of it ran:
round 3, copy 15: ... 'a_connection_document_can_list_the_host_the_issuer_publishes_its_keys_on' panicked
round 5, copy 13: ... 'a_connection_with_no_link_and_no_provisioning_is_refused_at_step_seven' panicked
round 5, copy 15: ... 'a_discovery_document_naming_another_issuer_refuses_the_login' panicked
[9 more]
```

Underlying messages: `400 access_denied` on logins that must return 200, `404` on routes only the
copy's own child seeded, `ConnectionReset`, and `Address already in use (os error 98)`.

Concurrency rates for the road lane, TIME-WAIT held below 20% of the 28,231-port ephemeral range:
sequential 0/40 · 2-way 0/40 · 4-way 1/40 · 8-way 1/80 · 16-way 12/192 and 4/192.

## Findings

```findings
- file: services/control-plane/tests/adversary_login_road.rs
  line: 546
  category: concurrency
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: stand_up binds an ephemeral port, drops the probe and then hands the port to the child while PORT excludes only this process's threads, so four or more concurrent copies of this lane hand two children one port and a case talks to another copy's server - measured 12 of 192 at 16-way and 1 of 40 at 4-way against 0 of 40 sequential and 0 of 40 at the two-copy bar the unit measured; the failing path is byte-identical at 06c6747 and I had no base worktree to run, so the origin rests on that identity rather than on a base run.
- file: services/control-plane/tests/end_to_end.rs
  line: 340
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the story delivers a root "created at start and removed at end" and the doc comment claims clearing at start "keeps the parent from growing without bound", but a run that has exited leaves its root standing (4 of 4 measured) and target/tmp in this worktree went from 37 MB to 644 MB across one adversary pass.
- file: services/control-plane/tests/serve.rs
  line: 1414
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the comment says clearing the run root is what makes every_refusal_of_a_flag_document_exits_two_and_names_the_file's absent document absent, but none of the 33 seed_file call sites names no-such-document.json, so that case is absent whether or not the root is ever cleared.
- file: services/control-plane/tests/adversary_login_road.rs
  line: 526
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: this comment justifies PORT "for the reason tests/end_to_end.rs's own PORT does", and end_to_end.rs:845 records that that PORT was deleted precisely because a lock in one process "narrowed that window and never closed it".
- file: services/control-plane/tests/end_to_end.rs
  line: 348
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the remove_dir_all that the commit rests its pid-reuse claim on is decided by no case in any of the four lanes and by no mutant under tests/mutants, so deleting that line leaves the suite green.
```

## How the coordinator routed each

| finding | row taken |
|---|---|
| `adversary_login_road.rs:546` — the port race at four or more copies | filed as `story:road-lane-child-prints-address`, with the adversary's 16-way case in the story body. Pre-existing, byte-identical at `06c6747`, and the fix already exists one lane over: wave G's `27a103b` moved `end_to_end.rs` to a child that prints the address it bound |
| `end_to_end.rs:340` — a root removed at start, never at end | back to the implementor. The story's own delivery statement says removed at end, and one adversary pass took `target/tmp` from 37 MB to 644 MB |
| `serve.rs:1414` — the comment's justification does not hold | back to the implementor |
| `adversary_login_road.rs:526` — `PORT` justified by a design that was deleted | back to the implementor: it is one comment in a file the unit is already rewriting, and leaving it would leave the next reader the retired design as the current reason |
| `end_to_end.rs:348` — the `remove_dir_all` is decided by nothing | back to the implementor, with the one above: whatever the sweep becomes, a case has to fail when it is deleted |
