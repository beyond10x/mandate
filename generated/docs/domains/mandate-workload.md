<!--
generated from mandate v1
model digest 01de9945d788263e9f6df566e556a0cc122f96c94d48538ad2536276eac2bc74
contract digest slice-sha256/2:8abb0a4ca94d7d73526464782bcd76187c286a63e3d553aa733d9f9e4902b7e6
do not edit: regenerate with `ess generate`
-->

# workload

`mandate.workload` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Entities

An entity is what this context is about: something with an identity that outlives any one request, a shape, and a lifecycle. The lifecycle is exhaustive — a move that is not drawn below is a move this specification does not permit, and that is the only way it says so. Every move is labelled with the command that takes it, because a move nothing can trigger is refused rather than drawn.

### `WorkloadIdentity`

`mandate.workload.WorkloadIdentity`.

An instance is identified by `id`, a `mandate.core.WorkloadIdentityId`. The name is part of the model and not a convention: a view projects the identity under that name, so a projection inventing its own would disagree with the view.

It holds:

- `organization_id` — `mandate.core.OrganizationId`
- `principal_id` — `mandate.core.PrincipalId`
- `trust_domain` — `mandate.core.TrustDomain`
- `external_subject` — `mandate.core.ExternalSubject`

It references at most one [`mandate.tenancy.Organization`](mandate-tenancy.md#organization), as `organization_id_record`, carried by `WorkloadIdentity.organization_id`. It references at most one [`mandate.identity.Principal`](mandate-identity.md#principal), as `principal_id_record`, carried by `WorkloadIdentity.principal_id`.

No invariant is declared, so nothing here constrains an instance at rest.

Its state is a `mandate.workload.WorkloadIdentity.State`, one of `Recorded` and `Revoked`. That enum is synthesised from the lifecycle rather than declared beside it, so the states a view's filter compares and the states drawn below cannot disagree.

An instance is created in `Recorded`. `Revoked` is terminal, so an instance may rest there forever. That is declared rather than inferred from having no way out: an entity that cannot leave a state is either finished or stuck, and only its author knows which.

```mermaid
stateDiagram-v2
    [*] --> Recorded
    Recorded --> Revoked: revoke (RevokeWorkloadIdentity)
    Revoked --> [*]
```

Each move is taken by a declared command outcome, and a move nothing takes is refused as `missing_causation` rather than left as a state change nobody can trigger:

- `revoke` — taken by `mandate.workload.RevokeWorkloadIdentity` on its `accepted` outcome

No command here creates one, so an instance arrives from outside this specification.

Illegal transitions are illegal by absence: no rule forbids them, there is simply no arrow, because a rule would be a second place for the same truth to live. A diagram cannot show an absence, so the pairs it does not connect are listed here, derived from the same transitions — anything named below is a move this specification does not permit.

- `Revoked` may not become `Recorded`

No view projects it, so nothing outside this context is promised a way to observe one.

## Commands

### `RevokeWorkloadIdentity`

`mandate.workload.RevokeWorkloadIdentity`.

It takes:

- `id` — `mandate.core.WorkloadIdentityId`
- `context` — `mandate.core.VerifiedContext`

It has three outcomes.

**`accepted`** — The binding stops being admitted. A workload credential presented under this trust domain and subject is refused from that point, and the record is kept so past exchanges stay attributable. The default branch, taken when no other outcome's condition matched. It moves a `mandate.workload.WorkloadIdentity` from `Recorded` to `Revoked`, along the declared move `revoke`. The instance is the one named by the input field `id`. It emits `mandate.workload.WorkloadIdentityRevoked`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`wrong-state`** — Taken when the subject is resting in a state none of this command's moves start from — a `mandate.workload.WorkloadIdentity` in `Revoked`, which is what is left of the lifecycle once this command's own moves are taken away. The document lists none of it. No entity in this specification changes. It reports `mandate.workload.Denied`, carrying `reason`. It emits nothing. A test reaches it by driving an instance into one of those states and then issuing the command, because no input selects this branch.

**`denied`** — Decided outside the input: Caller lacks workload-identity administration authority, the identity is outside the verified organization, or revocation cannot durably stop the exchange of workload credentials presented under the binding.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.workload.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

## Events

### `WorkloadIdentityRevoked`

`mandate.workload.WorkloadIdentityRevoked`.

It carries:

- `context` — `mandate.core.VerifiedContext`
- `id` — `mandate.core.WorkloadIdentityId`

Emitted by `mandate.workload.RevokeWorkloadIdentity` on its `accepted` outcome.

Nothing in this system reacts to it.

## Errors

### `Denied`

Fail closed; no credential, authority or lifecycle mutation on refusal.

It carries:

- `reason` — `mandate.core.DenialReason`

Reported by `mandate.workload.RevokeWorkloadIdentity` on its `wrong-state` and `denied` outcomes.


---

Generated from mandate v1 · model digest `01de9945d788263e9f6df566e556a0cc122f96c94d48538ad2536276eac2bc74` · contract digest `slice-sha256/2:8abb0a4ca94d7d73526464782bcd76187c286a63e3d553aa733d9f9e4902b7e6`. Do not edit this file; change the specification and regenerate it with `ess generate`.
