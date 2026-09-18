---
format: aep.planning-md/1
id: task:integration-batch-workflow
kind: task
status: draft
title: Adopt integration batches and inspect the unused driver
relations:
- derived_from: initiative:next-ten-waves
revision: 1
---
# Integration batch workflow and driver readiness

## Acceptance

Given the operator's requested accumulation flow, when the repository instructions and ten-wave proposal are read, then they consistently direct reviewed units into an integration/wave-YYYYMMDD-NNN branch, followed by an operator-selected PR to main and a separately verified release tag.

## Scope and authority

The operator requested this sequence on 2026-09-18, after requesting foundation reconciliation and committing the planning work. AGENTS.md and docs/adr/0008-integration-batches.md own the delivery rule. Update docs/handoff.md and the ten-wave proposal without starting implementation or closing runtime blockers. Record the driver inspection in verification-report:canonical-driver-readiness. No default batch size, automatic PR merge or release version is invented.

## Foundation reconciliation

The foundations branch points at eb00ebad4bd82f5e31f2ac3cac6aa5f2a540b9fa, which is an ancestor of published main ef912c8dce291f706b59f7a3d35e82d75d0a5043. git log main..foundations is empty. Of 391 residual untracked files, 95 match a published blob at the same path; none of the unmatched files is runtime Rust under crates/, services/ or bins/. Older contracts/projections and private planning history are preserved in a byte-verified local archive and the original managed checkout. No old files were overlaid on corrected main.

## Validation

Run task check, AEP validation, and source/privacy hooks before a bot-authored/committed source commit. This task records workflow adoption, not execution approval of the ten-wave forecast. Publication of the integration branch preserves recovery; PR selection and tagging remain distinct.
