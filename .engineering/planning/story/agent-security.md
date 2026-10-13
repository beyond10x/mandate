---
format: aep.planning-md/3
id: story:agent-security
kind: story
status: draft
title: Implement constrained agents and execution security
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
- depends_on: story:constrained-exchange
- depends_on: story:agent-authority-kernel
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: crates/mandate-authz
- confidence: cited
  path: crates/mandate-policy
revision: 5
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

## Ten-wave refinement

Reusable ceiling/delegation evaluation is now story:agent-authority-kernel before exchange. This story retains independently authenticated workload/application identity, per-tool PEP enforcement, approval recheck, execution correlation and subject/actor preservation, consuming the shared evaluator and completed STS exchange. It must not reimplement the shared evaluator independently. Source: docs/architecture/combined.md:7 and this story Required observations.

## Handed over by story:agent-authority-kernel (2026-10-13)

The shared evaluator is `mandate_authz::agent::evaluate_agent_authority` behind the `AgentAuthorityRead` port; it reads `Agent`, `AgentCapabilityCeiling` and `Delegation` records only. This story now owns, in `contracts/`:

- the `mandate.delegation` commands (`CreateDelegation`, `RevokeDelegation`, `CompleteExecution`, `ConsumeApproval`, `RetireAgent`, `SupersedeAgentCapabilityCeiling`), their six events and `mandate.delegation.Denied`, deferred on `decision-blocker:identity-uniqueness`;
- the 15 not-passed `mandate.delegation` conformance scenarios, and the new authored `exchange-ceiling-conflict` scenario sits on `story:declared-writers` (no adapter writes an `Agent`);
- three `sts.json` clauses and one `federation.json` clause on exchange narrowing. These may belong to `story:constrained-exchange`, which owns STS narrowing; decide when either story is scoped.

Gaps the adversary pass on the evaluator recorded for this story:

- An execution-bound delegation is matched by the execution's id only (`crates/mandate-authz/src/agent.rs`, the execution check): a completed or expired `Execution` is not refused, and the permitted expiry can outlive the execution's `expires_at`. Reading `Execution` records belongs to execution integration here.
- When the subject of a delegated request is itself an agent, its own capability ceilings are not intersected; only the actor's are. `docs/architecture/combined.md:9` asks for ceilings when the acting principal is an agent; no document requires the subject's. Decide it when this story is scoped.
- `max_delegation_ttl` is not read by the evaluator; it bounds `CreateDelegation`.
- `Check` still refuses delegated requests; wiring it to the evaluator is not done.
