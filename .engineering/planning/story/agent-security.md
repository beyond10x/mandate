---
format: aep.planning-md/1
id: story:agent-security
kind: story
status: draft
title: Implement constrained agents and execution security
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
- depends_on: story:constrained-exchange
scope:
- confidence: cited
  path: crates/mandate-authz
- confidence: cited
  path: crates/mandate-policy
revision: 3
---
# Implement constrained agents and execution security

## Acceptance

Given an administrator delegates an action outside an agent installation ceiling, when the agent invokes that privileged tool, then the PEP denies the action under the preserved subject and actor identities.

## Required observations

Runtime autonomous-ceiling and approval-required plus actor, authority and expiry properties pass; independently authenticate runtime/workload and application agent; every privileged tool call checks; no prompt-origin authority.

## Scope

- `crates/mandate-policy` — cited planned scope; canonical directory granularity.
- `crates/mandate-authz` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
