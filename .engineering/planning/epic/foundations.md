---
format: aep.planning-md/3
id: epic:foundations
kind: epic
status: active
title: Publish Mandate foundations
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-12T16:02:12Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-12T16:02:12Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"review_outcome":1}}}
---
# Publish reviewed foundations

## Deliverables

Scaffold, domain/invariants, threat model, key strategy, API versioning, supply-chain policy and local development; accepted types precede runtime.

## Exit criteria

The exact public foundation commit passes task check and is accompanied by its reviewed roadmap and execution handoff.

## Required observations

task check passes; immutable source hashes agree; contract coverage and four-critic review evidence published; wave and separate Drive handoff prepared.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.

## Product CLI continuation

`story:product-cli` retains original §32: organizations/teams/spaces/grants, check/explain, agent registration, delegation/exchange and audit query commands; authentication alone does not complete the CLI.
