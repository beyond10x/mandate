---
format: aep.planning-md/1
id: story:domain-folds-over-the-kit
kind: story
status: draft
title: The domain folds over the kit's log, not over a hand-written substitute
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: cited
  path: dependency-boundaries.json
revision: 4
---
# The domain folds over the kit's log, not over a hand-written substitute

## Why

`docs/adr/0009-event-sourced-persistence.md` was accepted on 2026-09-18 and says every durable state
in this repository is implemented with the organization's `eventlog` kit: a command produces events,
the events are the record, every read is a fold, state tables are projections. It gives one reason for
believing a test proves anything about a deployment, and that reason is the kit's own in-memory
backend:

> The kit's SQLite backend is `:memory:`-capable, which is why a property proved in a test is proved
> for the deployment.

`SqliteEventStore::in_memory` exists — `eventlog-sqlite/src/lib.rs:118` at tag `0.3.0`. The domain does
not use it. Every fold here is hand-written and synchronous: `Projection` in `mandate-federation`,
`InMemoryCodeLog` in `mandate-sts`, the tenancy and resource folds in `mandate-model`. No `.rs` file in
this repository references the kit at all.

Each substitution was admitted with a reason of its own, and the reasons are the same reason.
`docs/plans/2026-09-19-wave-c-execution.md:24`, verbatim: *"`eventlog-core` is not admitted (the
in-memory fake is a test double with the kit's shape, ADR 0009: no second mechanism)."* A double with
the kit's shape is a second mechanism; what makes it not one is the kit.

What that costs, stated plainly rather than guessed: the properties the folds prove are properties of
the hand-written folds. Ordering, idempotency on retry, the tenant-scoped append identity, the
compare-and-set on expected stream version that `decision-blocker:epoch-atomicity` was resolved
against, redaction that rewrites a projection and records the rewrite — none of them is exercised by
anything this repository runs.

## What this story delivers

The domain's durable state is read and written through the kit, with `SqliteEventStore::in_memory` as
the store every test builds. The hand-written folds become projections the kit rebuilds, or they are
deleted.

The scope of the first unit is one aggregate, not all of them: federation, because its fold is the one
two waves have already attacked and its properties are written down.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with the federation projection built by the kit's
in-memory store, and with the ordering and replay cases that exist today passing against it unchanged
— they are the same assertions, over the kit's log rather than over a `Vec`. `cargo xtask boundaries`
and `cargo deny --locked check` exit 0 with the new admission.

## Blocked on

`decision-blocker:async-runtime`. The kit's surface is async and this workspace admits no runtime;
that was recorded as stop condition S1 on 2026-09-18 and is still open. This story does not dispatch
before it is decided, and a version bump does not decide it: `EventStore` is async at `0.3.0` exactly
as at `0.2.1`.

## Out of scope

Which backend a deployment runs — ADR 0009 leaves that to a deployment that exists. The graph and
policy backends under `decision-blocker:backend`. Any change to what the domain decides; this is where
its decisions are recorded, not what they are.
