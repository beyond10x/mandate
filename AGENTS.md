# Mandate contributor guidance

## Serves

Mandate serves `vision:mandate`: standalone trusted identity, tenant isolation and constrained authority. Atlas objectives: O1, O2 and O5 (platform intent). Organization objective mappings are maintained through Atlas catalog intent.

## Workflow

Use the Worktree skill and CLI; change source only in a managed checkout with an active lease. Publish bot-authored and bot-committed changes before worktree finish; review exact GC ids. Keep the primary clean.

Use Connectors for integrations; report a missing operation before an alternative client. Organization commits and pushes use the existing Atlas bot publication path. Never bypass hooks or publish private policy, credentials or operator provenance.

AEP 0.55.0 is the sole writer of `.engineering/planning`. ESS 0.26.0 `ess/4` in `systems/mandate` owns contracts; only ESS writes generated projections; ESS 0.26.0 refuses to overwrite output it does not own, so in a fresh checkout run `cargo xtask adopt` once before `cargo xtask generate`. Addendum refinements take precedence. See `docs/requirements.md` and `docs/architecture/unmapped.md`.

Run `task check` before publication. Repository checkers and production executables are Rust. Preserve dependency direction. Authentication context comes from credential validation, never independent organization/audience selectors. Raw credentials must never enter logs, audit records, fixtures or persistent domain records.

Python, shell and other scripting languages are for quick tests, probes and reviews only, and stay outside the repository: never commit a script as a persistent check, gate or tool. A check that is worth keeping is written in Rust — as an `xtask` step, a test, or a workspace binary.

Every durable state is event-sourced through the organization `eventlog` kit: commands produce events, events are the record, reads are folds, state tables are projections. Nothing is deleted; privacy obligations are met by redaction. See `docs/adr/0009-event-sourced-persistence.md`.

## Integration batches

Implement stories/features in managed unit worktrees based on the active `integration/wave-YYYYMMDD-NNN` branch. Reviewed, green units merge into that integration branch; multiple approved waves may accumulate there. The coordinator alone writes the planning store and shared integration files. Replan after every wave against the integration branch's actual state.

This repository's delivery boundary overrides the generic Wave skill's automatic merge to `main`: a completed wave stops at the gated integration branch. Publishing that branch supplies recovery proof and does not approve a PR merge or a release. When the operator selects the accumulated batch, open one PR from the integration branch to `main`, validate the exact candidate and required checks, and merge through the bot-authorized PR workflow. Keep the primary checkout clean.

Tag only the resulting merged `main` commit, after the requested version, repository release requirements and exact-commit checks are satisfied. PR merge and release are separate decisions unless the standing cadence below is in force; no tag is cut from an integration or feature branch. See `docs/adr/0008-integration-batches.md` for the complete flow and recovery rules.

### Standing cadence

Since 2026-09-23 the operator has asked for integration, release and cleanup to happen after every closed batch, not on request. When a batch of up to three waves closes green, the coordinator, without asking again:

1. opens one PR from the integration branch to `main` through the bot, waits for every required check on its exact head, and merges it through the bot;
2. advances `repositories."beyond10x/mandate".baseline` in `gates-policy/policy.json` to that merge commit — the merge is committed by `GitHub`, and until the baseline moves the push guard refuses every branch cut from `main` and every tag;
3. cuts a release from a `release/X.Y.Z` branch: minor when the batch's changelog has a **Breaking** entry, patch otherwise; version in every manifest and `Cargo.lock`, the `[Unreleased]` section headed with the version and date, the full gate, PR, bot merge, an annotated tag on the resulting `main` merge commit and a GitHub Release from the changelog section; reported as released only after the tag, the checks on that commit and the Release are verified;
4. deletes every remote branch that is an ancestor of `main` and removes its own managed trees through `worktree finish` and reviewed `worktree gc`.

The cadence does not cover a wave's own approval, a deployment, or anything outside this repository beyond the baseline advance.

## Milestone boundary

Runtime enforcement belongs to subsequent stories. Corpus validation is not security implementation. Wave and Drive have separate lifecycle owners. Do not launch Drive without a reviewed task and operator-supplied budget and assumed cost. Source publication does not authorize a release, deployment, Identity migration or downstream website changes.

<!-- b10x-docs-operations:start -->
## Public documentation operations

This repository owns the public source and presentation allowlist in `b10x.docs.yaml`. The generated credential-free `.github/workflows/b10x-docs-bundle.yml` passively packages only those declared files for the exact successful `main` commit; it must never run repository code. The generated `.github/workflows/b10x-docs-check.yml` runs the publisher's per-source checks on every pull request and main push, with read-only contents and no credentials; it is deliberately separate from the shared gate, which runs on `pull_request_target` with a secret and never reads candidate source. Atlas selects the latest successful bundle with every other catalog source, and Website plus Docs System own rendering, shared components, search, and feeds. Do not add a standalone docs deployer or put App credentials in this public repository. If Atlas catalogs a former Pages workflow, that file remains repository-owned validation: preserve its bespoke checks while keeping exact read-only permissions, an unconditional pull-request trigger, and no deployment primitives. Project Pages at `/mandate/` is only the generated stable redirect façade in `.github/workflows/b10x-docs-pages.yml`; content-only publication never rebuilds it.

From the complete organization workspace, verify the contract with a clean Atlas checkout at the current remote `main`. Set `B10X_ATLAS_CHECKOUT` to a managed Atlas worktree when the primary checkout is dirty or stale; never infer command availability from the primary alone.

```bash
atlas_checkout="${B10X_ATLAS_CHECKOUT:-atlas}"
atlas_head="$(git -C "$atlas_checkout" rev-parse HEAD)"
atlas_main="$(git -C "$atlas_checkout" ls-remote origin refs/heads/main | awk '{print $1}')"
test -z "$(git -C "$atlas_checkout" status --porcelain)"
test "$atlas_head" = "$atlas_main"
cargo run --manifest-path "$atlas_checkout/Cargo.toml" --locked -q -- \
  --store "$atlas_checkout/catalog/store" docs reconcile --workspace . --check
```

Keep internal plans, stories, ADRs, decisions, worklogs, security material, and research out of the public allowlist unless a repository authority explicitly declares them public.
<!-- b10x-docs-operations:end -->
