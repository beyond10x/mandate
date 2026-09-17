---
format: aep.planning-md/1
id: task:canonical-types-drive
kind: task
status: draft
title: Prepare governed canonical-type execution
relations:
- derived_from: story:canonical-types
revision: 2
---
Reviewed task proposal: `.engineering/tasks/canonical-types.yaml`; Mandate verifier map: `.engineering/drivers/canonical-types.yaml`. See `docs/handoff.md`. No launch authorization or spending limits have been supplied. Wave and Drive must not share lifecycle ownership.

Technical review response: the selected story, map and handoff include dependency-boundaries.json, Cargo.toml and Cargo.lock for reviewed serialization dependencies. The accepted inventory explicitly excludes incomplete epoch ownership/snapshot records and all blocked semantics. This updated proposal still requires review and the missing property verifier before launch; no new approval is claimed.
