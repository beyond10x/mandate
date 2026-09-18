# Execution handoff

## Next ten waves — proposal only

The [ten-wave proposal](plans/2026-09-18-next-ten-waves.md), owned by `initiative:next-ten-waves`, supersedes the earlier single-story scheduling proposal. Skill: aep-drive:wave 0.8.1. Wave 1 proposes `story:canonical-types` alongside documentation-only `story:runtime-decision-dossier`; their write surfaces are disjoint. No implementation is launched or approved. The remaining nine waves are conditional forecasts and must be replanned after every wave against actual completed dependencies and unresolved decisions.

Canonical-type scope and exclusions are unchanged: four type/model/token/protocol crates plus workspace dependency files; no numeric epochs, invented lifecycle, crypto, PDP or HTTP implementation. Prepare the exact type/exclusion inventory and recheck resource/ownership preflight before dispatch. The dossier prepares decisions; it does not clear them. All runtime stories remain subject to their blockers. Independent scoper and critic evidence belongs to the planning store. Wave and Drive have separate lifecycle owners and cannot run concurrently for the same story.

## Integration and publication

The operator-selected flow is story/feature branches → integration/wave-YYYYMMDD-NNN → PR to main when the accumulated batch is selected → tag only after merge and release checks. This overrides automatic merge-to-main at each wave close. See [ADR 0008](adr/0008-integration-batches.md). The operator selected preparation batch integration/wave-20260918-001 for main through [PR #4](https://github.com/beyond10x/mandate/pull/4). Foundations is already published on main. Its obsolete checkout was retired through the worktree manager on 2026-09-18 after all 391 residual source files and the ESS ownership record were preserved and byte-verified in private recovery storage. No unique foundation commit was missing from main. The next implementation batch starts from verified main after this PR merges; implementation and release still require their own approval.

## Separate Drive task — not launched

Task: `.engineering/tasks/canonical-types.yaml` with `derived_from: [story:canonical-types]`.
Map: `.engineering/drivers/canonical-types.yaml`, id `mandate/canonical-types`, derived from AEP 0.55.0 development/default at the pinned protocol revision and adapted to Mandate packages. Its scope is the same accepted type work plus `xtask` verifier code; driver owns all lifecycle moves if selected. It must never run concurrently with the Wave owner.

The map runs Mandate canonical contract and credential-containment suites, workspace regression and static analysis. Unlike the upstream example it does not run AEP's own conformance or metaharness tests. `cargo xtask type-properties --out <record>` is a required evidence-producing verifier that has not yet been implemented; `decision-blocker:drive-verifier` blocks launch until its record schema and independent verification are reviewed. A zero-test scaffold is not evidence of canonical type realization.

Preflight uses `aep doctor`, `aep govern resolve --root <resolved-pinned-protocol-root> --task .engineering/tasks/canonical-types.yaml`, and `aep govern validate --root <disposable-combined-protocol-tree>` for the explicit project map. AEP 0.55.0 resolve without an explicit root loaded no protocols in this session; doctor locates the pinned cached tree. The combined validation tree copies that exact protocol source and adds the project map without modifying the cache. Automatic map selection is ambiguous because the pinned protocol tree contains development/default and development/checks; the reviewed task explicitly proposes the Mandate map. Never choose one merely to bypass a refusal.

Current inspection: `aep drive status` reports no runs; the task resolves and the combined protocol/map tree validates, but the map has a missing property verifier and contradictory planning-write prompts/scopes. See [.engineering/drivers/README.md](../.engineering/drivers/README.md), verification-report:canonical-driver-readiness and decision-blocker:drive-map-authority.

Launch is intentionally absent. The task must be reviewed and the operator must supply both `--budget-usd` and `--assume-usd-per-run`; neither is inferred here. Once prerequisites are satisfied, first use `--max-iterations 0` with the reviewed explicit map and limits, preserve the preflight result, then launch at most one governed run with `--pause-on-approval`. Do not use --take-lock or --allow-evidence-gap as a workaround. Follow the installed Drive skill; governed completion is experimental and may stop before completion.

## Review and validation evidence

Four installed aep-plan critic charters review frozen drafts independently, with at most three concurrent workers and two rounds. Charters request Sonnet/high; this session uses Codex subagents on the available inherited model, a disclosed harness deviation. The fourth reviewer starts after a slot opens and does not see other verdicts. AEP review-result records retain verbatim findings; outcomes are recorded sequentially.

`task check` validates scaffold behavior, dependency policy, ESS compilation/projection drift, source hashes, corpus ownership and AEP records. It does not prove runtime authorization, cryptography or protocol enforcement. Source publication, documentation-manifest validation and the operator-approved Website publication are milestone requirements. Release tags, service deployments and Identity migration remain excluded.

## Published foundations

The public source gate and publication evidence are recorded on `story:foundation-contracts`. The [foundation docs](https://beyond10x.github.io/docs/mandate/) and [ESS contract viewer](https://beyond10x.github.io/components/mandate/document/) are live and were opened in Brave. The exact production input passed the full Website gate and live viewer interaction checks. The operator explicitly expanded the original source-only milestone to include this Website publication.

The next work remains canonical Rust type realization within the accepted scope above. Drive still requires its reviewed verifier, reviewed task and explicitly supplied spending limits. No Wave or Drive execution, service deployment, release tag or Identity migration occurred.
