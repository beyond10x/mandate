<!--
generated from mandate v1
model digest fe7572f53936b5997c3bd119e2453943039ed1a53748b3db2385206257a79cd2
contract digest slice-sha256/2:96614eed03cec03b1d7b68d239fe8c7a81597aa8514a9f642475e1d84e58acd3
do not edit: regenerate with `ess generate`
-->

# authorization

`mandate.authorization` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Commands

### `Check`

`mandate.authorization.Check`.

It takes:

- `context` — `mandate.core.VerifiedContext`
- `action` — `mandate.core.Action`
- `resource` — `mandate.core.ResourceRef`

It has two outcomes.

**`accepted`** — The default branch, taken when no other outcome's condition matched. No entity in this specification changes. It emits `mandate.authorization.DecisionRecorded`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: Credential-derived context is invalid/revoked/expired/stale, tenant/audience/resource/space binding mismatches, relationships/policy/ceilings deny, approval is required, or the required PDP/graph/credential authority is unavailable.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.authorization.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

### `CheckWithApproval`

`mandate.authorization.CheckWithApproval`.

It takes:

- `context` — `mandate.core.VerifiedContext`
- `action` — `mandate.core.Action`
- `resource` — `mandate.core.ResourceRef`
- `approval` — `mandate.core.ApprovalId`

It has three outcomes.

**`accepted`** — The second check after an approval-required decision. The approval is recorded, of the verified organization, unexpired at the decision instant, and names this subject, actor, action and resource; every other check of the request is decided as Check decides it, and the approval is consumed by this decision and satisfies no other. The one event records both the decision and the consumption, so the two commit together; the delegation fold applies it as the approval's consume. The default branch, taken when no other outcome's condition matched. It moves a `mandate.delegation.Approval` from `Recorded` to `Consumed`, along the declared move `consume`. The instance is the one named by the input field `approval`. It emits `mandate.authorization.ApprovedDecisionRecorded`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`wrong-state`** — Taken when the subject is resting in a state none of this command's moves start from — a `mandate.delegation.Approval` in `Consumed`, which is what is left of the lifecycle once this command's own moves are taken away. The document lists none of it. No entity in this specification changes. It reports `mandate.authorization.Denied`, carrying `reason`. It emits nothing. A test reaches it by driving an instance into one of those states and then issuing the command, because no input selects this branch.

**`denied`** — Decided outside the input: Anything Check refuses other than approval-required; or the approval is unrecorded, of another organization, expired, or names another subject, actor, action or resource, each refused exactly as an unrecorded approval; or one-use consumption cannot commit atomically with the decision.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.authorization.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

## Events

### `ApprovedDecisionRecorded`

`mandate.authorization.ApprovedDecisionRecorded`.

It carries:

- `context` — `mandate.core.VerifiedContext`
- `decision` — `mandate.core.Decision`
- `approval` — `mandate.core.ApprovalId`

Emitted by `mandate.authorization.CheckWithApproval` on its `accepted` outcome.

Nothing in this system reacts to it.

### `DecisionRecorded`

`mandate.authorization.DecisionRecorded`.

It carries:

- `context` — `mandate.core.VerifiedContext`
- `decision` — `mandate.core.Decision`

Emitted by `mandate.authorization.Check` on its `accepted` outcome.

Nothing in this system reacts to it.

## Errors

### `Denied`

Fail closed; no credential, authority or lifecycle mutation on refusal.

It carries:

- `reason` — `mandate.core.DenialReason`

Reported by `mandate.authorization.Check` on its `denied` outcome.

Reported by `mandate.authorization.CheckWithApproval` on its `wrong-state` and `denied` outcomes.


---

Generated from mandate v1 · model digest `fe7572f53936b5997c3bd119e2453943039ed1a53748b3db2385206257a79cd2` · contract digest `slice-sha256/2:96614eed03cec03b1d7b68d239fe8c7a81597aa8514a9f642475e1d84e58acd3`. Do not edit this file; change the specification and regenerate it with `ess generate`.
