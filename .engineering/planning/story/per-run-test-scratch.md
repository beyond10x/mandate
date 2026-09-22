---
format: aep.planning-md/1
id: story:per-run-test-scratch
kind: story
status: draft
title: Two copies of one test binary do not share a scratch directory
relations:
- decomposes: epic:foundations
- serves: vision:mandate
revision: 1
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
