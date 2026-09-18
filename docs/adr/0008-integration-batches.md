# Integration batches, pull requests and releases

Status: accepted by the operator on 2026-09-18.

## Decision

```text
story / feature branches
          |
          v
integration/wave-YYYYMMDD-NNN  <-- successive approved waves
          |
          | operator selects a coherent, validated batch
          v
      pull request
          |
          | review + required checks on the exact candidate
          v
         main
          |
          | requested release version + release checks
          v
      annotated tag / GitHub Release
```

One integration branch is the current accumulation boundary. Its name identifies the batch, not a promise that only one implementation wave may enter it. Each constituent wave still has an approved selection, disjoint unit scopes, independent review and an integration gate. The coordinator replans from the current integration tree after every wave; the ten-wave forecast is not standing execution approval.

Create the integration branch from current verified `main`. Each story/feature branch starts from the current integration head in its own managed worktree. Merge only units whose acceptance, package checks and review evidence pass; record the unit and integration commits in AEP. Resolve shared manifests, generated contracts, gate changes and planning writes serially through the coordinator. A story implemented on the integration branch is not yet merged to main or released, and its evidence must say which commit was checked.

After each wave, run the complete repository gate on the integration candidate. Publish wanted commits through the bot path so worktree cleanup has remote recovery proof. Branch publication is separate from selecting the batch for a PR. Keep the integration checkout while accumulating; retire published unit trees only through the manager after evidence is retained and all leases end.

## Batch selection and PR

“Enough accumulated” is an operator decision based on a coherent outcome, manageable review scope and green evidence; no automatic story count, elapsed time or wave count is implied. A dependency or corrective fix can justify an earlier PR. This preparation batch is not an approval to implement the ten proposed waves.

Once selected, open one PR from the integration branch to `main`. The description names included stories/waves, their observable behavior, unresolved exclusions and exact validation. If main advanced, integrate its changes into the candidate, resolve conflicts, and rerun affected checks before merge. A green result for a previous head never approves the changed head.

Respect the App-only branch authority and required checks without bypass. Commits and publication use the existing Atlas bot path. A GitHub-created merge may use `web-flow` as committer; preserve the App merge action, exact candidate tree and resulting main SHA as evidence. Local main is synchronized only after remote integration. This replaces the generic Wave instruction to merge to main automatically at each wave close.

## Release

A PR merge does not automatically create a version. On the separately selected release, verify the requested version and repository metadata, then tag the exact resulting main commit through the bot path. Do not tag the integration head merely because it passed its earlier gate. If version metadata needs a source change, deliver it through the same PR process before tagging.

Call the source released only after the exact tag, required checks, GitHub Release and required artifacts are verified. A pushed tag with unfinished checks is queued. Ordinary documentation publication remains asynchronous; no Website, Identity or other repository rollout is part of this flow unless separately requested.

## Current reconciliation

The published foundation chain is already in main at `ef912c8dce291f706b59f7a3d35e82d75d0a5043`. The old `foundations` branch points to the initial commit and has no unique commits to merge. Its checkout contains 391 untracked files from an earlier foundation snapshot: 95 exactly match a published version, while the differing runtime package count is zero. Contract, projection and planning differences require preserving the old snapshot, not overlaying it on the corrected main tree. A byte-verified private recovery archive and comparison manifest are retained outside source; the original checkout remains intact pending its owner's retirement decision.

The next planning and workflow batch is `integration/wave-20260918-001`. It carries the ten-wave proposal, this delivery rule and the Drive-readiness record. No implementation wave, PR merge or release is implied by committing this batch.
