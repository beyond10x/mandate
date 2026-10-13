---
format: aep.planning-md/3
id: decision-blocker:identity-uniqueness-ceiling
kind: decision-blocker
status: cleared
title: 'Capability ceiling uniqueness: key, current record and conflict'
relations:
- blocks: story:agent-authority-kernel
revision: 2
transitions:
- {from: "open", to: "cleared", at: "2026-10-12T16:02:05Z", actor: "human:timo", revision: 2}
---
# Capability ceiling uniqueness: key, current record and conflict

## What was undecided

`decision-blocker:identity-uniqueness` requires one current ceiling per (agent, organization-or-platform) and lists the platform representation as unanswered (`docs/architecture/runtime-decisions.md:240`: "It may not stay unanswered at clearance"). `story:agent-authority-kernel` says "Ceiling uniqueness must have a reviewed admission rule before accepting runtime data."

## Decided (operator, 2026-10-12)

- The ceiling key is `(agent_id, organization_id)`. `organization_id` is `Optional<OrganizationId>` (`systems/mandate/domains/delegation.yaml:104-105`); absent means the platform ceiling, as `crates/mandate-authz/src/evaluate.rs:74-76` already reads it.
- The current ceiling for a key is the latest recorded one. Lifecycle is immutable-with-status (`docs/architecture/unmapped.md:13`): an earlier ceiling on the same key is superseded, never edited.
- Two current ceilings on one key are a declared denial. The evaluator never picks one of them.
- Enforcement follows the pattern already shipped for the other composite keys: the fold records the conflict (`crates/mandate-federation/src/record.rs:341,773`; `crates/mandate-token/src/projection.rs:450,1134`) and the decision path denies. A storage unique index waits for persistence, which waits on `decision-blocker:async-runtime`.

## What stays open

This record covers the ceiling half only. The external-principal, audience and exchange-source halves, and admission of runtime ceiling data for `story:agent-security`, stay on `decision-blocker:identity-uniqueness`, which remains open.

## Evidence the implementing story must produce

- A case where two current ceilings on one key deny with the declared clause.
- A property: the permitted set is within both the platform and the tenant ceiling.
- A case where a ceiling recorded for another organization does not apply.
