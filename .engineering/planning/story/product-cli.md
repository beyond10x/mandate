---
format: aep.planning-md/1
id: story:product-cli
kind: story
status: draft
title: Deliver the management and diagnostic CLI
relations:
- decomposes: epic:scale-interoperability
- serves: vision:mandate
- depends_on: story:oauth-integration
- depends_on: story:audit-client
- depends_on: story:agent-security
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: bins/mandate
revision: 2
---
# Deliver the management and diagnostic CLI

## Acceptance

Given an authenticated tenant administrator, when the CLI changes a grant and checks the target resource, then its displayed decision matches the service API decision at the resulting revision.

## Required observations

Retain original §32 commands for org/team/space/grant management, resource check/explain, agent registration, delegation/exchange and audit queries, with help and explicit typed errors; credentials never appear in diagnostic output.

## Scope

- `bins/mandate` — cited planned scope.

## Contract

`systems/mandate/ess-inputs.yaml`; `docs/architecture/combined.md`; `task check` and named runtime suites.
