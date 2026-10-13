# Wave 8 (agent security, second half): proposal and execution

Opened 2026-10-13 on `integration/wave-20261013-003`, cut from `main` at `1e2b64f` (0.8.0).
Approved by the operator before it was proposed. Story: `story:agent-security`
(`epic:agents-workloads`), the part of its "Still on this story" list that does not wait on ESS.

Purpose: the rest of the agent authority a governed run needs. An execution-bound delegation is
decided instead of refused, a workload runtime and the application agent it runs are authenticated
each on its own, the second check after an approval-required decision consumes the approval, and
the control plane's decision point decides over a delegation fold instead of the empty read.

## Spec first (coordinator, before any unit)

Validated with ESS 0.59.0 (`ess validate --path systems/mandate`: valid, the same two
`ESS-ENTITY-019` warnings as on `main`), then regenerated with `cargo xtask generate`.

- `mandate.authorization.CheckWithApproval` (new, `authorization.yaml`): `Check`'s three inputs and
  a required `approval`; `accepted` emits `DecisionRecorded` and `mandate.delegation.ApprovalConsumed`
  and moves `Approval.consume`. A new command rather than an optional `approval` on `Check`: ESS
  refuses an outcome chosen by an identity (`ESS-COMMAND-003`, `unobservable_fact`), and a second
  command leaves `Check`'s contract, which other repositories call, unchanged.
- `mandate.workload.AuthenticateWorkload` (new, `workload.yaml`): a workload proof, the application
  agent and an optional execution; `accepted` emits `mandate.workload.WorkloadAuthenticated`
  carrying the workload identity, the runtime principal it names, the agent, the organization and
  the execution, and creates or moves nothing. The two identities stay distinct: the agent is never
  derived from the workload proof.
- `delegation.yaml` header: how an execution-bound delegation and its execution name each other.

## Decisions taken for the units

1. **Execution binding** (the story's open design point, decided here as the option that can be
   undone: it admits more than today and can be narrowed again without a contract change). The
   delegation names its execution in `execution_binding`; the execution is recorded first and may
   name no delegation yet. `Check` admits a bound call when the execution is recorded, unexpired
   and not completed, its `delegation_id` is absent or names this delegation, its `agent_id` is the
   delegate, its `subject` is absent or the delegator, and its organization is the delegation's.
   `CreateDelegation` admits the same execution. The alternative, an execution that must name the
   delegation, needs an execution writer that does not exist and keeps the bound call refused.
2. An unknown or foreign approval, workload identity, agent or execution refuses exactly like one
   the caller may not see (wave 6, wave 7).
3. `CheckWithApproval` decides every other part of the request through the same path as `Check`;
   an approval that answers a different subject, actor, action or resource, or has expired, is
   refused and stays recorded. A decision that needs no approval still consumes the one named.
4. The workload proof is verified behind a substitutable trust-domain port; a SPIFFE verifier is
   not in this wave. The verified `(trust_domain, external_subject)` resolves to one recorded
   `WorkloadIdentity`; revoked, foreign or ambiguous resolution refuses.
5. The control plane's decision point holds the fold of the `mandate.delegation` events
   (`DelegationProjection`) the deployment records, replacing `AgentRecords::new()`.
6. `SupersedeAgentCapabilityCeiling` stays deferred on ESS (a create and a move in one outcome).

## Units

| unit | owns | order |
|---|---|---|
| U1 `execution-binding` | the execution check in `crates/mandate-authz/src/agent.rs`, the binding rule in `command.rs`, their tests | first, parallel with U2 |
| U2 `workload-authentication` | `crates/mandate-authz/src/workload.rs` (new) and its `lib.rs` line, its tests; `crates/mandate-conformance/src/commands/workload.rs`; `AuthenticateWorkload` in `contracts/obligations/authz.json` | parallel with U1 |
| U3 `approval-check` | `CheckWithApproval` in `crates/mandate-authz/src/lib.rs` and `decision.rs`, its tests; `crates/mandate-conformance/src/commands/authz.rs` | after U1 (same crate files) |
| U4 `control-plane-delegation-fold` | `services/control-plane/src/authority.rs`, the deployment's delegation log in `adapters.rs`, their tests | after U3 |

Shared, merged by the coordinator: the conformance registries (`commands/mod.rs`, `external.rs`,
`lib.rs`), `contracts/expected-outcomes.json`, `contracts/coverage.json`,
`contracts/conformance/{injections,obligations-report}.json`.

## Acceptance

`a_delegation_bound_to_an_execution_fails_closed_at_check` is replaced by a passing bound call and
one refusal per condition of decision 1; `AuthenticateWorkload/outcome/denied` and
`CheckWithApproval/outcome/denied` pass; the control plane decides a delegated request over a
recorded delegation and refuses it after `RevokeDelegation`; `task check` on the integration head.

## Execution

| unit | branch | managed id | stage |
|---|---|---|---|
| U1 `execution-binding` | `impl/w8-execution-binding` | `mandate-w8-execution-binding` | merged `c6395f1` (unit head `e77fb74`) |
| U2 `workload-authentication` | `impl/w8-workload-authentication` | `mandate-w8-workload-authentication` | merged `c60bd16` (unit head `195a997`) |
| U3 `approval-check` | `impl/w8-approval-check` | `mandate-w8-approval-check` | merged `ddd7921` (unit head `f724d4d`) |
| U4 `control-plane-delegation-fold` | `impl/w8-control-plane-delegation-fold` | `mandate-w8-control-plane-fold` | merged `27c3cff` (unit head `dd793ff`) |

- Spec, corrected after the first merge (`d8dff7c`): `CheckWithApproval` first emitted
  `DecisionRecorded` and `ApprovalConsumed`, which gave each event two writers and left the moving
  outcome's first event without the approval's id (`mandate-types` fold-input tests). It emits one
  event of its own, `ApprovedDecisionRecorded {context, decision, approval}`, which the delegation
  fold applies as the approval's consume. `components.yaml` declares both new commands and events.
- U1: the relaxed rule applies to a bound delegation only; an unbound delegation keeps the exact
  wave 7 rule, so no existing security test was loosened.
- U2: the decide function is in `mandate-authz`, which reads the agent records; the
  `WorkloadAuthenticated` payload is `mandate-model`'s, which owns every `mandate.workload` event.
  The obligations registry now files an implemented command with its implementing crate.
- U3: `check` and `check_with_approval` share one decision path, and `ConsumeApproval` and
  `CheckWithApproval` share one approval check.
- U4: recording a delegation event without a configured decision point refuses
  (`DelegationUnrecorded`); serving the delegation commands over HTTP is not in this wave.
- Security review (one for the wave): execution binding, the approval check, the control-plane
  fold and credential redaction held. Two introduced findings in `AuthenticateWorkload` were fixed
  spec first (`aeb78dc`): a disabled runtime principal refuses, and the agent may not be the
  runtime itself. One-use approval under concurrency rests on an atomic commit and stays on the
  story with the persistence adapter.
