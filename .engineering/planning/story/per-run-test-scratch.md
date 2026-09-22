---
format: aep.planning-md/1
id: story:per-run-test-scratch
kind: story
status: active
title: Two copies of one test binary do not share a scratch directory
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: services/control-plane/tests/adversary_login_pass2.rs
- confidence: cited
  path: services/control-plane/tests/adversary_login_road.rs
- confidence: cited
  path: services/control-plane/tests/end_to_end.rs
- confidence: cited
  path: services/control-plane/tests/serve.rs
revision: 8
---
# Two copies of one test binary do not share a scratch directory

## Why

`services/control-plane/tests/end_to_end.rs` writes its flag documents —
connection, key, client, resource server — under `env!("CARGO_TARGET_TMPDIR")`.
That macro is resolved **at compile time**, so every execution of the same test
binary writes the same paths.

Under `cargo test` that is harmless: cargo runs one copy of a lane. Two copies
of the same binary at once clobber each other's documents, and the failure does
not look like a collision. Measured 2026-09-22 while proving the port race
closed: a concurrency harness running the lane binary many times produced **422
failures, every one `IssuerMismatch` or `SignatureInvalid`** — a child reading
another run's connection document and refusing a proof that was correct for its
own.

The unit that found it discarded that harness rather than let the numbers stand
as evidence, and fixed the race it was actually chasing by a different route.
The scratch collision was never fixed.

## Why it matters even though cargo does not do it

The evidence this road rests on is the end-to-end lane. Anything that runs it
twice at once — a bisect script, a flake hunt, a mutation run over two mutants,
a CI matrix that shards by test name rather than by binary — gets failures that
read as verification defects and are not. The last person to meet this spent
part of a session on it.

## What this story delivers

A scratch root per execution, not per compilation: a directory named from
something unique to the run, created at start and removed at end, with every
document written under it. `CARGO_TARGET_TMPDIR` stays the parent.

Then the same treatment for any sibling lane that writes documents the same way
— check `tests/serve.rs` and the two `adversary_listener` lanes before assuming
this one is alone.

## Acceptance

Two copies of `end_to_end` run concurrently and both pass, repeated enough times
to mean something, with the count reported. The existing lane keeps its current
exit status and case count under ordinary `cargo test`.

## Out of scope

The port handling, which is fixed: `Served::spawn` takes no address and the
child prints the one it bound.

## Scope

Derived 2026-09-22 by `story-scoper`. Every line is **cited** (read from the story or the tree) or
**inferred** (a reading that could be wrong).

- **Primary surface:** `services/control-plane/tests` — cited; all four lanes that write flag
  documents are here and nothing outside this directory changes
- **Files:** `services/control-plane/tests/end_to_end.rs:337-345` (`document`, 12 call sites) — cited
- **Files:** `services/control-plane/tests/serve.rs:1406-1412` (`seed_file`, 33 call sites) and
  `services/control-plane/tests/serve.rs:1801-1803` (the "absent" path, built inline from the same
  root) — cited
- **Files:** `services/control-plane/tests/adversary_login_road.rs:217-225` (`document`, 7 call sites)
  — cited
- **Files:** `services/control-plane/tests/adversary_login_pass2.rs:87-95` (`document`, 11 call sites)
  — cited
- **Symbols:** `CARGO_TARGET_TMPDIR`, `document`, `seed_file`, `stated`, `seed_path`, `stand_up` —
  cited; these five sites are the only `CARGO_TARGET_TMPDIR` uses in the workspace
- **Not affected, checked:** `adversary_listener_1.rs`, `adversary_listener_2.rs`,
  `adversary_jit_login.rs`, `adapters.rs`, `authority.rs` — cited; no `std::fs`, no `Command::new`,
  no `Path` use
- **Also likely:** the doc comments above three of the helpers claim the per-case directory makes a
  collision impossible (`end_to_end.rs:328-336`, `adversary_login_pass2.rs:85-86`,
  `serve.rs:1404-1405`) — inferred, they state the property this story falsifies and are rewritten
  with the code
- **No new dependency:** the workspace carries no `tempfile` and none is added; the run identity comes
  from what is already admitted, so `services/control-plane/Cargo.toml`, the root `Cargo.toml`,
  `Cargo.lock` and `dependency-boundaries.json` are **not** touched
- **Same defect class, not this story:** `xtask/tests/adversary_conform_1.rs:30`,
  `xtask/tests/adversary_conform_2.rs:33`, `xtask/tests/adversary_coverage_2.rs:200`,
  `crates/mandate-conformance/tests/target.rs:59`,
  `crates/mandate-conformance/tests/adversary_conformance_1.rs:37` — cited; each builds a fixed root
  under `target/`, per repository rather than per run
- **Documents:** none — cited; `AGENTS.md` bars committing a shell or Python harness, so the measured
  count is reported into the story record and no repository document changes
- **Confidence:** high — the story names the file, the macro and the sibling lanes to check, and the
  grep for that macro returns exactly five sites, all inside one directory
- **Would collide with:** any unit touching `services/control-plane/tests` — the `end_to_end`,
  `serve`, `adversary_login_road` and `adversary_login_pass2` lanes. No production source.
