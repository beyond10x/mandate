---
format: aep.planning-md/1
id: story:road-lane-child-prints-address
kind: story
status: draft
title: The login-road lane still picks its child's port by dropping a listener
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/tests/adversary_login_road.rs
revision: 3
---
# The login-road lane still picks its child's port by dropping a listener

## Why

`services/control-plane/tests/adversary_login_road.rs`'s `stand_up` (`:546`) chooses the address its
child binds by binding `127.0.0.1:0` itself, reading `local_addr`, **dropping the probe**, and then
handing that port to the child. `PORT` (`:529`) is a process-local `Mutex`, so it serializes that
window against the other threads of this process and against nothing else. Two concurrent copies of
this binary hand their children one port; a case then finds `Address already in use (os error 98)`,
or — worse — talks to the other copy's child and is answered `404` for a route only its own child
seeded, or `400 access_denied` on a login that must return 200.

Wave G already fixed this class once, in the sibling lane: `27a103b`, *"Let the child print the
address it bound"*, `services/control-plane/tests/end_to_end.rs:530-560`. The road lane was not moved
with it, and `story:per-run-test-scratch` put the port handling out of scope on the stated ground
that `Served::spawn` takes no address and the child prints the one it bound — which is true of
`end_to_end.rs` and not of this file.

Measured 2026-09-22 by the adversary of `story:per-run-test-scratch`, with TIME-WAIT held below 20%
of the 28,231-port ephemeral range, so this is not exhaustion:

| copies at once | failures |
|---|---|
| sequential | 0 of 40 |
| 2 | 0 of 40 |
| 4 | 1 of 40 |
| 8 | 1 of 80 |
| 16 | 12 of 192, and 4 of 192 |

The two-copy bar `story:per-run-test-scratch` was measured against is honest: its "after: 0" is a
true statement about two copies. This defect starts at about four.

**What reaches it:** the flake hunt, the bisect, the mutation run and the name-sharded CI matrix that
`story:per-run-test-scratch` names in its own *Why it matters*, and `cargo nextest`, which runs test
binaries concurrently by default. Not `cargo test`, which runs one copy of a lane.

## What this story delivers

`adversary_login_road.rs` takes the design its sibling already has: the child binds an ephemeral port
and prints the address, the parent reads it, and no probe listener is bound and dropped. `PORT` goes
with it, and so does the comment at `:526` justifying `PORT` "for the reason `tests/end_to_end.rs`'s
own `PORT` does" — `end_to_end.rs:845` records that that `PORT` was **deleted**, because a lock in one
process "narrowed that window and never closed it".

## Acceptance

`cargo test -p mandate-control-plane --locked` exits 0, and the case below — 16 copies of the lane at
once over 12 rounds — passes, red before the change and green after.

## Out of scope

`serve.rs` at high concurrency: the adversary measured it failing at 24 copies at once, and that is
ephemeral-port exhaustion it caused, on a state nothing was shown to reach.

## The case the adversary wrote, kept here because nothing else keeps it

Red against `08f68a5`. It was not committed — one red case takes a suite's exit status for
everything — and its worktree does not outlive the wave, so the diff lives here.

```diff
diff --git a/services/control-plane/tests/adversary_login_road.rs b/services/control-plane/tests/adversary_login_road.rs
index 478b385..9f81985 100644
--- a/services/control-plane/tests/adversary_login_road.rs
+++ b/services/control-plane/tests/adversary_login_road.rs
@@ -1016,3 +1016,78 @@ fn a_second_copy_of_this_binary_does_not_write_this_runs_documents() {
         stated(&mine)
     );
 }
+
+// ---------------------------------------- adversary pass 1, `story:per-run-test-scratch`
+
+/// What tells a copy of this binary that it is one of the concurrent copies below.
+const CONCURRENT_COPY: &str = "MANDATE_ADVERSARY_CONCURRENT_COPY";
+
+/// Copies of this lane, run at once, all pass.
+///
+/// The unit reports this lane as "29 of 140" failing concurrently before its change and
+/// "0" after, and the story puts the port handling out of scope as already "fixed:
+/// `Served::spawn` takes no address and the child prints the one it bound". Neither holds
+/// here. This file's [`Served::spawn`] **takes an address**, and [`stand_up`] chooses it by
+/// binding an ephemeral port, reading `local_addr` and **dropping the listener** before the
+/// child binds it. [`PORT`] serializes that window against the other threads of *this*
+/// process and against nothing else, so two copies of this binary hand their children the
+/// same port — and a case then either finds `Address already in use` or, worse, talks to
+/// the other copy's child and is answered `404` for a route only its own child seeded.
+///
+/// That is the same failure the story is about — one copy reading another copy's state —
+/// reached through the port rather than through the scratch directory, and the scratch fix
+/// does not touch it.
+///
+/// Each copy skips this case, so what runs in a copy is the lane exactly as the unit left
+/// it: eight cases, and the copy reports `0 failed`.
+#[test]
+fn copies_of_this_lane_run_at_once_and_all_pass() {
+    if std::env::var_os(CONCURRENT_COPY).is_some() {
+        return;
+    }
+    const ROUNDS: usize = 12;
+    const COPIES: usize = 16;
+
+    let mut refused: Vec<String> = Vec::new();
+    for round in 0..ROUNDS {
+        let running: Vec<Child> = (0..COPIES)
+            .map(|_| {
+                Command::new(std::env::current_exe().expect("this test binary's own path"))
+                    .args(["--skip", "copies_of_this_lane_run_at_once_and_all_pass"])
+                    .env(CONCURRENT_COPY, "1")
+                    .stdout(Stdio::piped())
+                    .stderr(Stdio::piped())
+                    .spawn()
+                    .expect("a copy of this lane runs")
+            })
+            .collect();
+
+        for (copy, child) in running.into_iter().enumerate() {
+            let finished = child
+                .wait_with_output()
+                .expect("a copy of this lane is waited on");
+            let printed = String::from_utf8_lossy(&finished.stdout);
+            if finished.status.success() {
+                continue;
+            }
+            let why = printed
+                .lines()
+                .find(|line| line.contains("panicked at"))
+                .or_else(|| {
+                    printed
+                        .lines()
+                        .find(|line| line.starts_with("test result:"))
+                })
+                .unwrap_or("<nothing was printed>");
+            refused.push(format!("round {round}, copy {copy}: {why}"));
+        }
+    }
+
+    assert!(
+        refused.is_empty(),
+        "{} of {} copies of this lane refused while other copies of it ran:\n{}",
+        refused.len(),
+        ROUNDS * COPIES,
+        refused.join("\n")
+    );
+}
```

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `services/control-plane` tests — cited
- **Files:** `services/control-plane/tests/adversary_login_road.rs` (`Served::spawn` `:435`, `listening` `:504`, `PORT` `:640`, `stand_up` `:643`; the body's line numbers have drifted) — cited
- **Model, read not edited:** `services/control-plane/tests/end_to_end.rs` (`EPHEMERAL` `:949`, `LISTENING` `:1138`); the child already prints `listening on <addr>` at `services/control-plane/src/main.rs:369` — cited
- **Confidence:** high
- **Would collide with:** any unit touching `adversary_login_road.rs`
