# Mandate contributor guidance

## Serves

Mandate serves `vision:mandate`: standalone trusted identity, tenant isolation and constrained authority. Atlas objectives: O1, O2 and O5 (platform intent). Organization objective mappings are maintained through Atlas catalog intent.

## Workflow

Use the Worktree skill and CLI; change source only in a managed checkout with an active lease. Publish bot-authored and bot-committed changes before worktree finish; review exact GC ids. Keep the primary clean.

Use Connectors for integrations; report a missing operation before an alternative client. Organization commits and pushes use the existing Atlas bot publication path. Never bypass hooks or publish private policy, credentials or operator provenance.

AEP 0.55.0 is the sole writer of `.engineering/planning`. ESS 0.25.0 `ess/4` in `systems/mandate` owns contracts; only ESS writes generated projections. Addendum refinements take precedence. See `docs/requirements.md` and `docs/architecture/unmapped.md`.

Run `task check` before publication. Repository checkers and production executables are Rust. Preserve dependency direction. Authentication context comes from credential validation, never independent organization/audience selectors. Raw credentials must never enter logs, audit records, fixtures or persistent domain records.

## Milestone boundary

Runtime enforcement belongs to subsequent stories. Corpus validation is not security implementation. Wave and Drive have separate lifecycle owners. Do not launch Drive without a reviewed task and operator-supplied budget and assumed cost. Source publication does not authorize a release, deployment, Identity migration or downstream website changes.

<!-- b10x-docs-operations:start -->
## Public documentation operations

This repository owns the public source and presentation allowlist in `b10x.docs.yaml`. The generated credential-free `.github/workflows/b10x-docs-bundle.yml` passively packages only those declared files for the exact successful `main` commit; it must never run repository code. Atlas selects the latest successful bundle with every other catalog source, and Website plus Docs System own rendering, shared components, search, and feeds. Do not add a standalone docs deployer or put App credentials in this public repository. If Atlas catalogs a former Pages workflow, that file remains repository-owned validation: preserve its bespoke checks while keeping exact read-only permissions, an unconditional pull-request trigger, and no deployment primitives. Project Pages at `/mandate/` is only the generated stable redirect façade in `.github/workflows/b10x-docs-pages.yml`; content-only publication never rebuilds it.

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
