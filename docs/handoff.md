# Execution handoff

## First Wave proposal — not dispatched

Skill: aep-drive:wave 0.8.1. Candidate: `story:canonical-types`, after `story:foundation-contracts` is terminal with its published gate/review evidence. One implementor, one independent adversary, one managed worktree with an active lease; coordinator alone writes AEP. Scope: `crates/mandate-types`, `crates/mandate-model`, `crates/mandate-token`, `crates/mandate-proto`, `dependency-boundaries.json`, `Cargo.toml` and `Cargo.lock`. Planned types come from accepted `systems/mandate/domains/core.yaml` plus reviewed model records; empty epoch ownership placeholders and incomplete snapshot values, numeric epochs, lifecycle algorithms and security implementation remain excluded. Exclusion accounting is mandatory. No other story shares this wave.

Acceptance: canonical serialization/round-trip and compile-fail identifier separation suites pass, credential containment remains type safe, and `task check` passes. Unit must establish initially failing tests before realization; adversary independently tests identifier substitution, optional actor preservation and secret containment. Publish wanted commits before managed cleanup. This is a proposal only; wave execution has not been approved or launched.

## Separate Drive task — not launched

Task: `.engineering/tasks/canonical-types.yaml` with `derived_from: [story:canonical-types]`.
Map: `.engineering/drivers/canonical-types.yaml`, id `mandate/canonical-types`, derived from AEP 0.55.0 development/default at the pinned protocol revision and adapted to Mandate packages. Its scope is the same accepted type work plus `xtask` verifier code; driver owns all lifecycle moves if selected. It must never run concurrently with the Wave owner.

The map runs Mandate canonical contract and credential-containment suites, workspace regression and static analysis. Unlike the upstream example it does not run AEP's own conformance or metaharness tests. `cargo xtask type-properties --out <record>` is a required evidence-producing verifier that has not yet been implemented; `decision-blocker:drive-verifier` blocks launch until its record schema and independent verification are reviewed. A zero-test scaffold is not evidence of canonical type realization.

Preflight uses `aep doctor`, `aep govern resolve --root <resolved-pinned-protocol-root> --task .engineering/tasks/canonical-types.yaml`, and `aep govern validate --root <disposable-combined-protocol-tree>` for the explicit project map. AEP 0.55.0 resolve without an explicit root loaded no protocols in this session; doctor locates the pinned cached tree. The combined validation tree copies that exact protocol source and adds the project map without modifying the cache. Automatic map selection is ambiguous because the pinned protocol tree contains development/default and development/checks; the reviewed task explicitly proposes the Mandate map. Never choose one merely to bypass a refusal.

Launch is intentionally absent. The task must be reviewed and the operator must supply both `--budget-usd` and `--assume-usd-per-run`; neither is inferred here. Once prerequisites are satisfied, first use `--max-iterations 0` with the reviewed explicit map and limits, preserve the preflight result, then launch at most one governed run with `--pause-on-approval`. Do not use --take-lock or --allow-evidence-gap as a workaround. Follow the installed Drive skill; governed completion is experimental and may stop before completion.

## Review and validation evidence

Four installed aep-plan critic charters review frozen drafts independently, with at most three concurrent workers and two rounds. Charters request Sonnet/high; this session uses Codex subagents on the available inherited model, a disclosed harness deviation. The fourth reviewer starts after a slot opens and does not see other verdicts. AEP review-result records retain verbatim findings; outcomes are recorded sequentially.

`task check` validates scaffold behavior, dependency policy, ESS compilation/projection drift, source hashes, corpus ownership and AEP records. It does not prove runtime authorization, cryptography or protocol enforcement. Source publication and documentation-manifest validation are milestone requirements; tags, deployments, Identity migration and synchronous Website publication are excluded.
