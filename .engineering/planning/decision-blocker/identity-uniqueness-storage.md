---
format: aep.planning-md/3
id: decision-blocker:identity-uniqueness-storage
kind: decision-blocker
status: open
title: Composite keys enforced atomically in storage
relations:
- blocks: story:domain-folds-over-the-kit
revision: 1
---
# Composite keys enforced atomically in storage

## What is undecided

`docs/architecture/unmapped.md` (UNMAPPED-UNIQUENESS) asks that storage enforce the composite keys atomically: external principal (organization, connection issuer, external subject), resource-server audience per organization, and one current capability ceiling per (agent, organization or platform). Today each is a read-then-write refusal on the command path plus a conflict view in the fold (`decision-blocker:identity-uniqueness`, cleared 2026-10-13). Two writers racing past the read can both append; the fold records the conflict and the decision path denies, but nothing refuses the second append.

How the event log admits a unique key (a guarded append, a key stream, or a projection index checked in the same transaction) depends on the persistence surface, which waits on `decision-blocker:async-runtime`.

## Clearing needs

A chosen mechanism per key, a test where two concurrent appends on one key leave exactly one accepted, and the conflict views kept as the read-side check.
