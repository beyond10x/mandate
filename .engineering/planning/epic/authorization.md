---
format: aep.planning-md/1
id: epic:authorization
kind: epic
status: draft
title: Core tenancy and authorization
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
---
# Core tenancy and authorization

## Deliverables

Principals, org memberships, teams, spaces, resource topology, graph adapter, grants, policy, check API, audit, Rust client and Axum example; versioned schemas.

## Exit criteria

A live tenant grant removal changes the next revision-bound resource-service check from allowed to denied without redeploying that service.

## Required observations

Admin changes access without resource redeployment; cross-tenant/parent/ceiling/outage tests fail closed; inheritance works; mutations and decisions audited.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.
