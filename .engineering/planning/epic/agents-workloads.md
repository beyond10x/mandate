---
format: aep.planning-md/1
id: epic:agents-workloads
kind: epic
status: draft
title: Services, workloads and agents
relations:
- serves: vision:mandate
- derived_from: specification:combined
revision: 1
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
