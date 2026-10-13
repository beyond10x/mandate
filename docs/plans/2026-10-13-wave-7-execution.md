# Wave 7 (agent security): proposal and execution

Opened 2026-10-13 on `integration/wave-20261013-002`, cut from `main` at `487df0d` (wave 6); the 0.7.1 release merge comes in by a merge from `main`. Approved by
the operator before it was proposed. Story: `story:agent-security` (`epic:agents-workloads`), free
since `decision-blocker:identity-uniqueness` was cleared in wave 6.

Purpose: the PEP denies a delegated action outside an agent's installation ceiling under the
preserved subject and actor, with the delegation commands, their events and fold, the workload
revocation, and the evaluator gaps wave 5a handed on.

## Spec first (coordinator, before any unit)

`systems/mandate/domains/delegation.yaml`, `SupersedeAgentCapabilityCeiling`: today it takes only
`{id, context}` and no command creates a ceiling, so ceiling data has no writer. The intended model:
the command carries the replacement record, creates it in `Recorded`, and moves `supersede` over the
current ceiling on the same `(agent_id, organization_id)` key, none for a first ceiling.

Measured 2026-10-13 under ESS 0.59.0 (`ess/24`): each half validates on its own, the two together do
not. `affects:` beside `creates:` is refused (`ESS-COMMAND-009`, `unsupported_construct`: a secondary
effect is admitted beside `moves:`, `updates:` and `deletes:` only), and an `affects:` entry cannot
create. Creating without the move leaves the `supersede` transition with no cause
(`ESS-ENTITY-005`, `missing_causation`). The specification therefore stays as it is in this wave;
the draft is kept outside the repository and the construct is requested of ESS.
`SupersedeAgentCapabilityCeiling` stays deferred on `story:agent-security`; U1's tests arrange
ceilings as fixtures through the read port.

## Units

| unit | owns | order |
|---|---|---|
| U1 `agent-pdp` | `crates/mandate-authz/src/{agent,delegation,context,evaluate}.rs`, the Check part of `lib.rs`; `Execution` and `Approval` projections; the `Pdp` construction in `services/control-plane/src/authority.rs` and `crates/mandate-conformance/src/commands/authz.rs`; the `autonomous-ceiling` case | first, parallel with U3 |
| U3 `workload-revocation` | `crates/mandate-model/src/workload.rs` (new), its `lib.rs` lines and tests; `contracts/obligations/model.json`; `crates/mandate-conformance/src/commands/workload.rs` (new) | parallel with U1 |
| U2 `delegation-commands` | five handlers (all but `SupersedeAgentCapabilityCeiling`), events, fold and `mandate.delegation.Denied` in `crates/mandate-authz/src/{command,event}.rs` (new) and the delegation part of `lib.rs`; `crates/mandate-conformance/src/commands/delegation.rs` (new); those five commands in `contracts/obligations/authz.json` | after U1 (same files, and the fold implements U1's widened read port) |

Shared, merged by the coordinator (U3, then U1, then U2): the conformance registries
(`commands/mod.rs`, `external.rs`, `lib.rs`), `contracts/expected-outcomes.json`,
`contracts/coverage.json`, `contracts/conformance/{injections,obligations-report}.json`.

## Decisions taken for the units

1. An unknown id refuses like a record the caller may not see (wave 6); the delegation and workload
   `wrong-state` scenarios end `failed` on `story:unknown-instance-non-disclosing`.
2. The `accepted` scenarios whose synthesized inputs name records that do not exist, or an already
   expired window, end `failed` on `story:ess-synthesizer-prerequisites`.
3. Check decides a delegated request through the shared record checks of the evaluator (agent,
   delegation, execution, ceilings, intersection), never a second implementation; `CheckRequest`
   gains `at`, and `Pdp` an agent read. The caller-supplied `CheckRequest.ceilings` is retired for
   ceilings read by `agent_id`.
4. Execution: read whenever the context names one; refused when unrecorded, completed, expired, in
   another organization, or bound to another agent, delegation or subject; its `expires_at` is one
   more input to the earliest expiry.
5. An agent that is the subject of a delegated request is bounded by its own ceilings too, and
   refused without one.
6. `max_delegation_ttl` bounds `expires_at - created_at`, the smallest over the delegate's
   applicable platform and tenant ceilings; the duration parser is shared in `mandate-types`.
7. The delegator is the verified subject of the creating request.
8. External refusals read through one substitutable admission port per command family; clauses that
   need durable storage stay deferred on persistence.
9. `ConsumeApproval` ships as a handler; an approval inside Check needs a spec change to Check's
   input and stays on the story.
10. Workload authentication stays on the story; U3 ships revocation only.
11. The three `sts.json` narrowing clauses move to `story:constrained-exchange`; the
    `federation.json` one to `story:oauth-integration`.

## Acceptance

`a_delegated_action_outside_the_installation_ceiling_is_denied_at_the_pep_under_the_preserved_subject_and_actor`
passes; the seven `/outcome/denied` scenarios of the delegation and workload commands pass; every
other scenario of the story is attributed as above; the evaluator-gap tests named in the unit briefs
pass; `task check` on the integration head.

## Execution

Merged in the order U1, U3, U2: U3 was cut after U1's merge, so the shared files merged without
conflict.

| unit | branch | managed id | stage |
|---|---|---|---|
| U1 `agent-pdp` | `impl/w7-agent-pdp` | `mandate-w7-agent-pdp` | merged `33bbbd0` (unit head `4328a19`) |
| U3 `workload-revocation` | `impl/w7-workload-revocation` | `mandate-w7-workload-revocation` | merged `e2ddcfc` (unit head `a3129ec`) |
| U2 `delegation-commands` | `impl/w7-delegation-commands` | `mandate-w7-delegation-commands` | merged `269e08f` (unit head `1b4ffbe`) |

- U1 security review: three introduced findings. `Check` answered `TenantMismatch` for a
  delegation or an actor agent record of another organization, which told such a record from an
  unrecorded one, and did not read principal standing. Fixed in `4328a19` under decision 1: a
  foreign delegation refuses as `DelegationAbsent` and a foreign agent record as `ActorNotAgent`,
  at `Check` and at the exchange; the shared record checks refuse a disabled subject or actor.
  An unrecorded standing stays the exchange's own refusal. The review's three tests are green.
- U3: `RevokeWorkloadIdentity/outcome/denied` passes; `wrong-state` is on
  `story:unknown-instance-non-disclosing`. `WorkloadIdentity` and its state stay `declared` on
  `story:declared-writers`: no command creates the record. The state account in `mandate-types`
  names the new `WorkloadIdentityState` (`3fcb6b4`).
- U2: the five `/outcome/denied` scenarios pass; four `wrong-state` scenarios are on
  `story:unknown-instance-non-disclosing`, three synthesized `accepted` inputs on
  `story:ess-synthesizer-prerequisites`. `mandate-authz` gains `serde` for the event payloads and
  `mandate-types` the shared duration parser. Security review: a replayed or reordered log could
  put a revoked delegation back in force (no adapter delivers one yet); fixed in `1b4ffbe` by
  applying creation monotonically. An execution-bound delegation fails closed at `Check`, because
  the execution must be recorded before the delegation and name it; how the two records name each
  other is open on the story, guarded by `a_delegation_bound_to_an_execution_fails_closed_at_check`.
- Conformance after U2 (`cargo xtask conform`): 181 scenarios, 46 passed, 71 failed, 0 error,
  64 unsupported (40 / 63 / 78 at 0.7.1). Coverage: 229 implemented, 23 declared, 41 deferred.
- `story:agent-security` stays `active`: `SupersedeAgentCapabilityCeiling` waits on ESS, and
  workload authentication, the approval inside `Check` and the execution binding remain.
