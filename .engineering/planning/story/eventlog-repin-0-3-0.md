---
format: aep.planning-md/1
id: story:eventlog-repin-0-3-0
kind: story
status: implemented
title: Repin the event log from 0.2.1 to 0.3.0
relations:
- decomposes: epic:foundations
- serves: vision:mandate
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: deny.toml
revision: 7
---
# Repin the event log from 0.2.1 to 0.3.0

## Why

`Cargo.toml:22-23` pins `eventlog-core` and `eventlog-sqlite` at git tag `0.2.1`, released
2026-09-10. `0.3.0` was tagged on 2026-09-22 (`ac6b173`, merge of `chore/release-0.3.0`).
`docs/adr/0009-event-sourced-persistence.md` says what to do about that: *"It is repinned to the next
release when that release lands … so a repin is expected to be a version bump."*

The release is additive. Its changelog carries `Added`, `Changed`, `Fixed` and `Known`, and **no
`Removed`**.

What is in it that this repository has a use for:

- **`InspectHistory`**, with `FileHistoryInspector` and `SqliteHistoryInspector`: one tenant's complete
  decoded history from a store nobody opened for writing, granting no writer or recovery authority and
  creating no root, lock or table. `InspectionLimits` states explicit caps where zero is a real limit.
  A redacted or malformed envelope refuses rather than being returned.
- **`InlineProjectionAdmin`**: attach an existing inline projector without writing durable state and
  atomically rebuild its complete tenant row sets from committed history and active blobs, preserving
  unrelated tenants. That is ADR 0009's *"projections: derived, droppable, rebuildable"* as an API.
- **Existing-only open paths** for File and SQLite: refuse an absent or incomplete store without
  creating one.
- Fixed: SQLite selects the exact bundled `rusqlite` 0.40.2 line, so a composed consumer carries one
  native SQLite dependency against its existing 3.51.3 admission floor.

## What this story delivers

The two pins move to `0.3.0`, `Cargo.lock` follows, and `cargo deny --locked check` is re-run against
the new transitive tree — the `Zlib` allowance for `foldhash` was admitted for `eventlog-sqlite` at
`0.2.1` and the new tree has to be checked rather than assumed.

## Acceptance

`task check` exits 0 with both pins at `0.3.0`. `cargo deny --locked check` exits 0 on all four
sections, or the licenses it refuses are reported and this story stops. `cargo xtask boundaries`
prints its package count unchanged.

## What it does not buy, stated so nobody expects it

A repin does not make the kit usable here. `EventStore` is async at `0.3.0`
(`eventlog-core/src/lib.rs:59,698`) exactly as at `0.2.1`, and `SqliteEventStore::in_memory` is still
`pub async fn` (`eventlog-sqlite/src/lib.rs:118`). The admission that would let a crate consume any of
this is `decision-blocker:async-runtime`. This story is hygiene on a dependency nothing calls.

## Read before relying on a name

`0.3.0`'s own `### Known`: `FileEventStore` carries two public methods named
`append_group_with_blobs` — the inherent one and `AtomicBlobEventStore`'s — and Rust resolves the
inherent one. *"Naming is to be settled before either is relied on by name."* This repository calls
neither.

## Out of scope

Consuming the kit, which is `story:domain-folds-over-the-kit`. Any provider selection, which ADR 0009
leaves to a deployment that exists.
