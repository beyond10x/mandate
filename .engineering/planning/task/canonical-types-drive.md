---
format: aep.planning-md/1
id: task:canonical-types-drive
kind: task
status: draft
title: Prepare governed canonical-type execution
relations:
- derived_from: story:canonical-types
revision: 3
---
Reviewed task proposal: `.engineering/tasks/canonical-types.yaml`; Mandate verifier map: `.engineering/drivers/canonical-types.yaml`. See `docs/handoff.md`. No launch authorization or spending limits have been supplied. Wave and Drive must not share lifecycle ownership.

Technical review response: the selected story, map and handoff include dependency-boundaries.json, Cargo.toml and Cargo.lock for reviewed serialization dependencies. The accepted inventory explicitly excludes incomplete epoch ownership/snapshot records and all blocked semantics. This updated proposal still requires review and the missing property verifier before launch; no new approval is claimed.

## Current readiness inspection

verification-report:canonical-driver-readiness records successful configuration loading and no recorded runs. Both decision-blocker:drive-verifier and decision-blocker:drive-map-authority remain open. This unused map is not the implementation engine for the ten-wave proposal; future Drive work requires its own reviewed launch.
