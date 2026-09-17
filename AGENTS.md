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
