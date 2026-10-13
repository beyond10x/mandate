---
format: aep.planning-md/3
id: epic:agents-workloads
kind: epic
status: active
title: Services, workloads and agents
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-12T16:02:13Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-12T16:02:13Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"review_outcome":1}}}
---
# Services, workloads and agents

## Deliverables

Service/agent principals, installations, persistent grants, delegation, execution IDs, tool PEP, approvals, audit/provenance, SPIFFE-compatible exchange, trust domains, external customer agents, DPoP and/or mTLS.

## Exit criteria

A privileged agent call outside the installation ceiling remains denied under both persistent and delegated authority.

## Required observations

Agent ceiling holds under own and delegated authority; workload/application/execution identities distinct; transitive disabled; revoked delegation denies; prompts confer no authority; high-value sender constraints verified.

## Contract and provenance

`systems/mandate/ess-inputs.yaml`, `docs/architecture/combined.md`, `docs/requirements.md` (all original phases and addendum requirements). Advanced delegation is deferred; other addendum requirements are mandatory.
