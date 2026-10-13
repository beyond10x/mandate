---
format: aep.planning-md/3
id: story:agent-security
kind: story
status: active
title: Implement constrained agents and execution security
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
- depends_on: story:constrained-exchange
- depends_on: story:agent-authority-kernel
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: contracts/conformance/injections.json
- confidence: cited
  path: contracts/conformance/obligations-report.json
- confidence: cited
  path: contracts/coverage.json
- confidence: cited
  path: contracts/expected-outcomes.json
- confidence: cited
  path: contracts/obligations/authz.json
- confidence: cited
  path: contracts/obligations/model.json
- confidence: cited
  path: crates/mandate-authz
- confidence: inferred
  path: crates/mandate-authz/Cargo.toml
- confidence: cited
  path: crates/mandate-authz/src/agent.rs
- confidence: cited
  path: crates/mandate-authz/src/context.rs
- confidence: cited
  path: crates/mandate-authz/src/delegation.rs
- confidence: cited
  path: crates/mandate-authz/src/evaluate.rs
- confidence: cited
  path: crates/mandate-authz/src/lib.rs
- confidence: cited
  path: crates/mandate-conformance/src/commands/authz.rs
- confidence: inferred
  path: crates/mandate-conformance/src/commands/delegation.rs
- confidence: cited
  path: crates/mandate-conformance/src/commands/mod.rs
- confidence: inferred
  path: crates/mandate-conformance/src/commands/workload.rs
- confidence: cited
  path: crates/mandate-conformance/src/external.rs
- confidence: cited
  path: crates/mandate-conformance/src/lib.rs
- confidence: inferred
  path: crates/mandate-model/src/lib.rs
- confidence: inferred
  path: crates/mandate-model/src/workload.rs
- confidence: cited
  path: crates/mandate-policy
- confidence: inferred
  path: dependency-boundaries.json
- confidence: cited
  path: generated
- confidence: cited
  path: services/control-plane/src/authority.rs
- confidence: cited
  path: systems/mandate/domains/delegation.yaml
revision: 12
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T06:40:19Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-13T06:40:19Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"review_outcome":1}}}
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

## Wave 7

Wave 7 (2026-10-13, `docs/plans/2026-10-13-wave-7-execution.md`) delivered, on `integration/wave-20261013-002`:

- `Check` decides delegated requests through the evaluator's shared record checks (agent, delegation, execution, ceilings, intersection) read through `AgentAuthorityRead`; `CheckRequest` gains `at` and `Pdp` an agent read; the caller-supplied ceilings are retired. A delegation or agent record of another organization refuses like an unrecorded one, and a disabled subject or actor is refused at `Check` as at the exchange.
- Execution records are read whenever the context names one; a completed, expired, foreign or mismatched execution refuses, and its `expires_at` bounds the permitted expiry. An agent subject is bounded by its own ceilings.
- `RevokeWorkloadIdentity` in `mandate-model`; `CreateDelegation`, `RevokeDelegation`, `RetireAgent`, `CompleteExecution` and `ConsumeApproval` in `mandate-authz`, with their events and a fold that is the agent read `Check` and the exchange decide by. `max_delegation_ttl` bounds `CreateDelegation`. Their `/outcome/denied` scenarios pass.

Still on this story:

- `SupersedeAgentCapabilityCeiling` and its event: ESS 0.59.0 refuses a create beside a move in one outcome (`ESS-COMMAND-009`); the draft is kept outside the repository and the construct is requested of ESS.
- An execution-bound delegation fails closed at `Check`: `CreateDelegation` binds only an execution recorded before the delegation, and `Check` requires that execution's `delegation_id` to name the delegation. Decide how the two records name each other; until then the bound call is refused (`a_delegation_bound_to_an_execution_fails_closed_at_check`).
- Workload and application-agent authentication; an approval consumed inside `Check` (needs a change to `Check`'s input); the `Pdp` in `services/control-plane/src/authority.rs` still holds no delegation fold.
- The fold applies creation monotonically, so a replayed or reordered log keeps a revoked delegation revoked; durable de-duplication waits on persistence.

## Wave 8

Wave 8 (2026-10-13, `docs/plans/2026-10-13-wave-8-execution.md`), on `integration/wave-20261013-003`.

Decided for the execution binding, as the option that can be undone (it admits more than wave 7 and can be narrowed again without a contract change): the delegation names its execution in `execution_binding`; the execution is recorded first and may name no delegation yet. `Check` admits a bound call when the execution is recorded, unexpired and not completed, its `delegation_id` is absent or names this delegation, its `agent_id` is the delegate, its `subject` is absent or the delegator, and its organization is the delegation's; `CreateDelegation` admits the same execution. Why: requiring the execution to name the delegation needs an execution writer this repository does not have, and keeps every bound call refused. Recorded in the `delegation.yaml` header.

Specified before implementation: `mandate.authorization.CheckWithApproval` (the approval consumed by the second check; a new command because ESS refuses an outcome chosen by an identity, and `Check`'s contract stays as other repositories call it) and `mandate.workload.AuthenticateWorkload` (the workload runtime and the application agent authenticated each on its own).

Security review of wave 8 (one for the wave): execution binding, `CheckWithApproval`, the control-plane fold and credential redaction held. Two introduced findings in `AuthenticateWorkload` were fixed in the wave, spec first: a disabled runtime principal is refused, and the named agent may not be the runtime principal itself, so the two identities stay two principals.

Still on this story after wave 8:

- One-use approval under concurrency: two `CheckWithApproval` decisions taken over the same fold before either is applied both succeed, and the fold logs both. The contract puts this on the commit ("one-use consumption cannot commit atomically" refuses), so the event-log adapter must refuse the second `ApprovedDecisionRecorded` for one approval when persistence lands.
- The control plane records any `DelegationEvent` it is given without re-deciding it; no route records events yet, and a served route must pass only decide-function output.
- A SPIFFE / JWT-SVID verifier behind the trust-domain port; `SupersedeAgentCapabilityCeiling` still waits on ESS.
