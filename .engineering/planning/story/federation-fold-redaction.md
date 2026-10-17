---
format: aep.planning-md/3
id: story:federation-fold-redaction
kind: story
status: draft
title: The federation fold reads redacted events
relations:
- serves: vision:mandate
- decomposes: epic:foundations
revision: 1
---
# The federation fold reads redacted events

## Why

The wave 11 security review found that `recorded()` in `crates/mandate-federation/src/record.rs` decodes every payload without checking for a redaction tombstone, so one redacted event would make the whole federation fold fail as `Unreadable`. No path redacts today (the store is private and in memory), and privacy obligations are met by redaction (`docs/adr/0009-event-sourced-persistence.md`).

## Acceptance

Given a federation stream holding a redacted event, when the fold runs, then it completes and the redacted fact is absent from the folded state; a case redacts one event of a registered connection.
