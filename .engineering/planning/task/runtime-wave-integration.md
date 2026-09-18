---
format: aep.planning-md/1
id: task:runtime-wave-integration
kind: task
status: draft
title: Coordinate shared runtime gates, dependencies and fixture isolation
relations:
- derived_from: initiative:next-ten-waves
revision: 2
---
# Coordinate shared runtime integration surfaces

## Acceptance

Given a concrete proposed runtime wave, when its coordinator runs the opening integration readiness checks, then the recorded readiness checklist reports every required check passed with no skipped check.

## Scope and required observations

The readiness checklist records per-step exit status for the cheap repository gate, affected-package compilation, service-fixture startup probes and scope/dependency consistency checks; it also names the frozen interface revision and each unit's distinct process/port/storage/build/scratch assignment. A missing assignment or unrecorded prerequisite makes the checklist fail.

Coordinator only: Cargo.toml, Cargo.lock, dependency-boundaries.json, xtask and the wave execution page. Before runtime services are exposed, replace the scaffold gate assertion that every `serve` subcommand must fail with explicit per-binary milestone checks and executable security checks; do not drop refusal coverage for still-unimplemented commands. Before adding dependencies, preserve types -> model -> graph/policy -> authz and token -> types direction; the current checker applies the external allowlist to service packages and forbids unlisted test dependencies as well. Capture exact dependencies and policy exceptions with gate evidence rather than silently bypassing the checker.

Reconcile/freeze source contracts before dispatch. When a contract story changes ESS or generated outputs, it owns those declared surfaces; concurrent consumers may run only against an unchanged accepted interface, otherwise replan. Assign per-unit processes, ports, storage, build and scratch roots. This task is recurring coordinator work for future wave proposals, not authorization to implement during planning and not a substitute for runtime story completion. Each concrete wave must own a bounded child task/record and include its opening integration commit in the requested authorization.

Sources: xtask/src/main.rs:96 (dependency check), xtask/src/main.rs:270 (scaffold executable checks), dependency-boundaries.json:1, .cargo/config.toml:1; docs/plans/2026-09-18-next-ten-waves.md. ESS meaning belongs to systems/mandate, never gate code. No new domain entity.
