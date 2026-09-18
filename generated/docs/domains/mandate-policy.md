<!--
generated from mandate v1
model digest 49c058592f66660a95621e7b7761e19fc9570b248c3357b240ef72ecd6491a40
contract digest slice-sha256/2:e3af0fa3e1220fdfb1a24652605aff975d1125745cf7db0eb7f3ee819c73b32c
do not edit: regenerate with `ess generate`
-->

# policy

`mandate.policy` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Entities

An entity is what this context is about: something with an identity that outlives any one request, a shape, and a lifecycle. The lifecycle is exhaustive — a move that is not drawn below is a move this specification does not permit, and that is the only way it says so. Every move is labelled with the command that takes it, because a move nothing can trigger is refused rather than drawn.

### `AuthorizationModel`

`mandate.policy.AuthorizationModel`.

An instance is identified by `id`, a `mandate.core.AuthorizationModelId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `version` — `mandate.core.PolicyVersion`
- `schema` — `String`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `AuthorizationModel.organization_id`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.policy.AuthorizationModel.State`, one of `Recorded` and `Superseded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Superseded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> Superseded: supersede (SupersedeAuthorizationModel)
    Superseded --> [*]
```

Each move is taken by a declared command outcome, and a move nothing takes is refused as `missing_causation` rather than left as a state change nobody can trigger:

- `supersede` — taken by `mandate.policy.SupersedeAuthorizationModel` on its `accepted` outcome

No command here creates one, so an instance arrives from outside this specification.

Illegal transitions are illegal by absence: no rule forbids them, there is simply no arrow, because a rule would be a second place for the same truth to live. A diagram cannot show an absence, so the pairs it does not connect are listed here, derived from the same transitions — anything named below is a move this specification does not permit.

- `Superseded` may not become `Recorded`

No view projects it, so nothing outside this context is promised a way to observe one.

### `Policy`

`mandate.policy.Policy`.

An instance is identified by `id`, a `mandate.core.PolicyId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `version` — `mandate.core.PolicyVersion`
- `source` — `String`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `Policy.organization_id`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.policy.Policy.State`, one of `Recorded` and `Superseded`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Superseded` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> Superseded: supersede (SupersedePolicy)
    Superseded --> [*]
```

Each move is taken by a declared command outcome, and a move nothing takes is refused as `missing_causation` rather than left as a state change nobody can trigger:

- `supersede` — taken by `mandate.policy.SupersedePolicy` on its `accepted` outcome

No command here creates one, so an instance arrives from outside this specification.

Illegal transitions are illegal by absence: no rule forbids them, there is simply no arrow, because a rule would be a second place for the same truth to live. A diagram cannot show an absence, so the pairs it does not connect are listed here, derived from the same transitions — anything named below is a move this specification does not permit.

- `Superseded` may not become `Recorded`

No view projects it, so nothing outside this context is promised a way to observe one.

## Commands

### `SupersedeAuthorizationModel`

`mandate.policy.SupersedeAuthorizationModel`.

It takes:

- `id` — `mandate.core.AuthorizationModelId`
- `context` — `mandate.core.VerifiedContext`

It has two outcomes.

**`accepted`** — The recorded schema version stops being the current one and is kept for attribution. A breaking change is a new model version with its own migration; no superseded model is reactivated and none is deleted. The default branch, taken when no other outcome's condition matched. It moves a `mandate.policy.AuthorizationModel` from `Recorded` to `Superseded`, along the declared move `supersede`. The instance is the one named by the input field `id`. It emits `mandate.policy.AuthorizationModelSuperseded`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: Caller lacks authorization-model administration authority, the model is outside the verified organization, no later model version is recorded for that organization, or the relationship revision the later version requires is not yet observable.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.policy.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

### `SupersedePolicy`

`mandate.policy.SupersedePolicy`.

It takes:

- `id` — `mandate.core.PolicyId`
- `context` — `mandate.core.VerifiedContext`

It has two outcomes.

**`accepted`** — The recorded version stops being the current one. Its source is kept, because every decision already made under it stays attributable to it; a rollback is a new version record carrying the earlier source, never a revival of this one. The default branch, taken when no other outcome's condition matched. It moves a `mandate.policy.Policy` from `Recorded` to `Superseded`, along the declared move `supersede`. The instance is the one named by the input field `id`. It emits `mandate.policy.PolicySuperseded`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: Caller lacks policy-administration authority, the policy is outside the verified organization, no later policy version is recorded for that organization, or decisions in flight cannot remain attributable to the version that made them.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.policy.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

## Events

### `AuthorizationModelSuperseded`

`mandate.policy.AuthorizationModelSuperseded`.

It carries:

- `context` — `mandate.core.VerifiedContext`
- `id` — `mandate.core.AuthorizationModelId`

Emitted by `mandate.policy.SupersedeAuthorizationModel` on its `accepted` outcome.

Nothing in this system reacts to it.

### `PolicySuperseded`

`mandate.policy.PolicySuperseded`.

It carries:

- `context` — `mandate.core.VerifiedContext`
- `id` — `mandate.core.PolicyId`

Emitted by `mandate.policy.SupersedePolicy` on its `accepted` outcome.

Nothing in this system reacts to it.

## Errors

### `Denied`

Fail closed; no credential, authority or lifecycle mutation on refusal.

It carries:

- `reason` — `mandate.core.DenialReason`

Reported by `mandate.policy.SupersedeAuthorizationModel` on its `denied` outcome.

Reported by `mandate.policy.SupersedePolicy` on its `denied` outcome.


---

Generated from mandate v1 · model digest `49c058592f66660a95621e7b7761e19fc9570b248c3357b240ef72ecd6491a40` · contract digest `slice-sha256/2:e3af0fa3e1220fdfb1a24652605aff975d1125745cf7db0eb7f3ee819c73b32c`. Do not edit this file; change the specification and regenerate it with `ess generate`.
