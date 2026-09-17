<!--
generated from mandate v1
model digest 4a856239408291b04081d690cb65f638971dd1711f23b1dbb384b26f4f7a5fd1
contract digest slice-sha256/2:9839f22541e2d3212edbd03aaf7850c59bf3ef550bd4e32c51ee317d1b0436c7
do not edit: regenerate with `ess generate`
-->

# delegation

`mandate.delegation` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Entities

An entity is what this context is about: something with an identity that outlives any one request, a shape, and a lifecycle. The lifecycle is exhaustive — a move that is not drawn below is a move this specification does not permit, and that is the only way it says so. Every move is labelled with the command that takes it, because a move nothing can trigger is refused rather than drawn.

### `Agent`

`mandate.delegation.Agent`.

An instance is identified by `id`, a `mandate.core.PrincipalId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `agent_type` — `String`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `Agent.organization_id`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.delegation.Agent.State`, one of `Recorded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Recorded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> [*]
```

It declares no moves, so nothing changes its state once it exists.

It has one state, so there is no move to permit or to forbid.

No view projects it, so nothing outside this context is promised a way to observe one.

### `AgentCapabilityCeiling`

`mandate.delegation.AgentCapabilityCeiling`.

An instance is identified by `id`, a `mandate.core.AgentCapabilityCeilingId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `agent_id` — `mandate.core.PrincipalId`
- `organization_id` — `Optional<mandate.core.OrganizationId>`, which may be absent
- `allowed_actions` — `List<mandate.core.ActionPattern>`
- `denied_actions` — `List<mandate.core.ActionPattern>`
- `scope` — `mandate.core.AuthorityScope`
- `max_delegation_ttl` — `Duration`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `AgentCapabilityCeiling.organization_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `agent_record`, carried by `AgentCapabilityCeiling.agent_id`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.delegation.AgentCapabilityCeiling.State`, one of `Recorded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Recorded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> [*]
```

It declares no moves, so nothing changes its state once it exists.

It has one state, so there is no move to permit or to forbid.

No view projects it, so nothing outside this context is promised a way to observe one.

### `Approval`

`mandate.delegation.Approval`.

An instance is identified by `id`, a `mandate.core.ApprovalId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `subject` — `mandate.core.PrincipalId`
- `actor` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `action` — `mandate.core.Action`
- `resource` — `mandate.core.ResourceRef`
- `expires_at` — `Timestamp`
- `approver` — `mandate.core.PrincipalId`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `Approval.organization_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `subject_record`, carried by `Approval.subject`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `actor_record`, carried by `Approval.actor`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `approver_record`, carried by `Approval.approver`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.delegation.Approval.State`, one of `Recorded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Recorded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> [*]
```

It declares no moves, so nothing changes its state once it exists.

It has one state, so there is no move to permit or to forbid.

No view projects it, so nothing outside this context is promised a way to observe one.

### `Delegation`

`mandate.delegation.Delegation`.

An instance is identified by `id`, a `mandate.core.DelegationId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `delegator` — `mandate.core.PrincipalId`
- `delegate` — `mandate.core.PrincipalId`
- `scope` — `mandate.core.AuthorityScope`
- `audience` — `mandate.core.Audience`
- `not_before` — `Optional<Timestamp>`, which may be absent
- `expires_at` — `Timestamp`
- `execution_binding` — `Optional<mandate.core.ExecutionId>`, which may be absent
- `transitive` — `Boolean`
- `created_at` — `Timestamp`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `Delegation.organization_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `delegator_record`, carried by `Delegation.delegator`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `delegate_record`, carried by `Delegation.delegate`. It references at most one [`Execution`](#execution), as `execution_binding_record`, carried by `Delegation.execution_binding`.

Every instance satisfies `transitive == false` — a predicate over this entity's own fields, checked against them rather than stored as a sentence, so an invariant reading something the entity does not have is refused instead of documented.

Its state is a `mandate.delegation.Delegation.State`, one of `Active` and `Revoked`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Active`. `Revoked` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Active
    Active --> Revoked: revoke (RevokeDelegation)
    Revoked --> [*]
```

Each move is taken by a declared command outcome, and a move nothing takes is refused as `missing_causation` rather than left as a state change nobody can trigger:

- `revoke` — taken by `mandate.delegation.RevokeDelegation` on its `accepted` outcome

No command here creates one, so an instance arrives from outside this specification.

Illegal transitions are illegal by absence: no rule forbids them, there is simply no arrow, because a rule would be a second place for the same truth to live. A diagram cannot show an absence, so the pairs it does not connect are listed here, derived from the same transitions — anything named below is a move this specification does not permit.

- `Revoked` may not become `Active`

No view projects it, so nothing outside this context is promised a way to observe one.

### `Execution`

`mandate.delegation.Execution`.

An instance is identified by `id`, a `mandate.core.ExecutionId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `agent_id` — `mandate.core.PrincipalId`
- `subject` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `delegation_id` — `Optional<mandate.core.DelegationId>`, which may be absent
- `initiating_session` — `Optional<mandate.core.SessionId>`, which may be absent
- `created_at` — `Timestamp`
- `expires_at` — `Timestamp`
- `policy_version` — `mandate.core.PolicyVersion`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `Execution.organization_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `agent_id_record`, carried by `Execution.agent_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `subject_record`, carried by `Execution.subject`. It references at most one [`Delegation`](#delegation), as `delegation_id_record`, carried by `Execution.delegation_id`. It references at most one [`mandate.identity.Session`](mandate-identity.md#session), as `initiating_session_record`, carried by `Execution.initiating_session`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.delegation.Execution.State`, one of `Recorded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Recorded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> [*]
```

It declares no moves, so nothing changes its state once it exists.

It has one state, so there is no move to permit or to forbid.

No view projects it, so nothing outside this context is promised a way to observe one.

## Commands

### `CreateDelegation`

`mandate.delegation.CreateDelegation`.

It takes:

- `context` — `mandate.core.VerifiedContext`
- `delegate` — `mandate.core.PrincipalId`
- `scope` — `mandate.core.AuthorityScope`
- `audience` — `mandate.core.Audience`
- `expires_at` — `Timestamp`
- `not_before` — `Optional<Timestamp>`, which may be absent
- `execution_binding` — `Optional<mandate.core.ExecutionId>`, which may be absent

It has two outcomes.

**`accepted`** — The default branch, taken when no other outcome's condition matched. No entity in this specification changes. It emits `mandate.delegation.DelegationCreated`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: Caller lacks delegation authority, subject/delegate/tenant/space/registered audience or execution binding fails, requested scope/expiry exceeds source/delegation/policy limits or agent ceilings, or a transitive/approval-required grant would be created.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.delegation.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

### `RevokeDelegation`

`mandate.delegation.RevokeDelegation`.

It takes:

- `id` — `mandate.core.DelegationId`
- `context` — `mandate.core.VerifiedContext`

It has two outcomes.

**`accepted`** — The default branch, taken when no other outcome's condition matched. It moves a `mandate.delegation.Delegation` from `Active` to `Revoked`, along the declared move `revoke`. The instance is the one named by the input field `id`. It emits `mandate.delegation.DelegationRevoked`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: Caller lacks delegation-revocation authority, delegation is outside the verified organization, or durable revocation and affected exchange invalidation fail.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.delegation.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

## Events

### `DelegationCreated`

`mandate.delegation.DelegationCreated`.

It carries:

- `context` — `mandate.core.VerifiedContext`

Emitted by `mandate.delegation.CreateDelegation` on its `accepted` outcome.

Nothing in this system reacts to it.

### `DelegationRevoked`

`mandate.delegation.DelegationRevoked`.

It carries:

- `context` — `mandate.core.VerifiedContext`

Emitted by `mandate.delegation.RevokeDelegation` on its `accepted` outcome.

Nothing in this system reacts to it.

## Errors

### `Denied`

Fail closed; no credential, authority or lifecycle mutation on refusal.

It carries:

- `reason` — `mandate.core.DenialReason`

Reported by `mandate.delegation.CreateDelegation` on its `denied` outcome.

Reported by `mandate.delegation.RevokeDelegation` on its `denied` outcome.


---

Generated from mandate v1 · model digest `4a856239408291b04081d690cb65f638971dd1711f23b1dbb384b26f4f7a5fd1` · contract digest `slice-sha256/2:9839f22541e2d3212edbd03aaf7850c59bf3ef550bd4e32c51ee317d1b0436c7`. Do not edit this file; change the specification and regenerate it with `ess generate`.
