---
format: aep.planning-md/1
id: story:runtime-service-qualification
kind: story
status: draft
title: Qualify service security and failure behavior with executable evidence
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:oauth-integration
- depends_on: story:agent-security
- depends_on: story:audit-recovery-conformance
- depends_on: story:protocol-adapters
- depends_on: story:recovery-runbooks
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-testkit
revision: 3
---
# Qualify service security and failure behavior with executable evidence

## Acceptance

Given the integrated local service candidate and a manifest of required security scenarios, when its qualification suite runs against the real service boundaries, then every selected scenario executes and passes its specified denial, containment or recovery assertion with zero skipped or unmapped selected cases.

## Required observations

Execute the existing 47 corpus scenarios where their owner stories are implemented, plus concurrent redemption, disable/refresh races, graph revocation, reference-cache revocation, key rollover, denial-audit failure and prompt-origin authority rejection. Assert exact case inventory rather than accepting a zero-test exit. Publish service commits, fixture seed, topology, selected/ran/skipped counts and per-command statuses. Add negative controls proving the harness catches a deliberately faulty fixture. Package uses existing allowed dependencies and external service processes; a dependency or production fix outside this scope requires replan. CLI behavior is separately story:product-cli and cannot be claimed tested while concurrent. This qualification is not production readiness, deployment or a release.

## Contract and provenance

Read systems/mandate/ess-inputs.yaml and tests/security/cases.json; all tested nouns already live in systems/mandate/domains. New contract semantics require ESS validation before changing tests.

Sources: docs/threat-model/README.md:22; docs/sources/original-design.md:2804; docs/sources/architecture-addendum.md:995; crates/mandate-testkit/src/lib.rs:1. Placement in wave 10 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper`.

- **Primary write surface:** `crates/mandate-testkit` — inferred; the story assigns this package, whose existing scaffold describes security scenarios and runtime conformance harnesses.
- **Files and symbols:** expand the package-local library and add local test, fixture, manifest and evidence modules; concrete runtime symbols do not exist yet — inferred.
- **Required behavior:** execute the selected corpus and additional race, revocation, rollover, denial-audit and prompt-origin scenarios through actual service boundaries; assert exact inventory and negative-control detection; report commits, seed, topology, counts and command statuses — cited.
- **Documents:** package-local harness instructions and evidence-format guidance may be needed — inferred.
- **Dependencies:** consume existing allowed dependencies and external service processes; dependency changes or production fixes outside the package require replan — cited.
- **Concurrency boundary:** service qualification cannot claim concurrent product CLI behavior tested; shared manifests, lockfile, dependency policy, integration checker, ESS and generated projections remain coordinator-owned — cited.
- **Confidence:** medium — inferred; package ownership is established, but the harness and prerequisite service interfaces remain future implementation.
- **Would collide with:** any unit modifying `crates/mandate-testkit`, including its package manifest, tests or fixtures; shared service-fixture provisioning also needs separate process, port and storage ownership — inferred.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Every nonterminal prerequisite and open decision blocker must be resolved before dispatch.

## Concurrent execution isolation

The coordinator assigns this suite and concurrent product-cli tests separate process groups, ports, disposable storage roots and tenant fixtures. Share neither mutable service state nor build directories. The manifest names every one of the 47 existing corpus ids once, plus uniquely named additional cases; zero skipped or unmapped required cases is the acceptance boundary. Runtime gating and any parser/client dependency must be admitted before dispatch by task:runtime-wave-integration.
