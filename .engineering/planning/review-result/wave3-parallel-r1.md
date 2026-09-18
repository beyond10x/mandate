---
format: aep.planning-md/1
id: review-result:wave3-parallel-r1
kind: review-result
status: active
title: Parallel-safety critic, round 1 — wave 3 set
relations:
- reviews: story:check-api
- reviews: story:pkce-sessions
- reviews: story:event-payloads-for-folds
- reviews: story:gate-reads-document-deliverables
revision: 1
---
```
set: story:check-api, story:pkce-sessions, story:event-payloads-for-folds, story:gate-reads-document-deliverables — execution wave 3, one implementor each, in parallel from integration/wave-20260918-004 at the opening commit
verdict: approve
findings: 0
```

## What was read

All four story bodies in full via `aep plan artifact show`, each carrying a `story-scoper`-produced file-level scope table plus an explicit cross-story collision section (`check-api` "Collisions with this wave", `pkce-sessions` "Wave siblings, file overlap", `event-payloads-for-folds` "Collisions with wave 3"). The four owned file sets are disjoint: `crates/mandate-authz/**` vs `crates/mandate-federation/src/{pkce,publicclient,authorize}.rs` + `lib.rs` mod lines + `bins/mandate/**` vs seven `systems/mandate/domains/*.yaml` vs `xtask/src/{main,documents}.rs`. A grep of `crates/mandate-federation/` and `crates/mandate-authz/` for `generated` confirms neither owned test file reads `generated/schema/**` (only `mandate-model`/`mandate-types`/`mandate-proto`/`mandate-identity` tests do, none of which any of the four units edit). `xtask/Cargo.toml:14` and `git status` confirm `serde_json`/`sha2` are pre-landed so no unit needs a `Cargo.lock` change under `--locked`. `check-api` self-imposes "units read nothing under `generated/`" (its `### Excluded`). No pair shares a file or a generated-artifact read; the one directory-granularity entry (`generated`, on `event-payloads-for-folds`) is disclosed as visibility-only.

## Noted, not scored

- `story:gate-reads-document-deliverables` ("### Wave placement") says it runs as the coordinator's own unit on the integration branch, not as a fourth symmetric implementor worktree — a dispatch-correctness question for the design critic; no other item in this set touches `xtask/src/main.rs` either way.
- `check-api`'s collision table cites `pkce-sessions` under its pre-rescoping crate name `mandate-identity` rather than `mandate-federation` — stale, but the "none" conclusion still holds on the current tree.

```yaml
verdict: approve
findings: []
```
