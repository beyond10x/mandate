<!--
generated from mandate v1
model digest cc2b92ef62d71301fffac73193657e56997c8c3355bd5026b9a5ca7a6e331078
contract digest slice-sha256/2:e6347abf66eac9f8d1bfa03cddeb00bd6d309e40229ee7a42122604833cbe423
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

### `AuthenticateWorkload`

`mandate.workload.AuthenticateWorkload`.

It takes:

- `workload_proof` — `mandate.core.CredentialProof`
- `agent` — `mandate.core.PrincipalId`
- `execution` — `Optional<mandate.core.ExecutionId>`, which may be absent

It has two outcomes.

**`accepted`** — Two identities, each authenticated on its own. The workload proof is verified by the trust domain that issued it and resolves to one recorded workload identity, which names the runtime principal; the application agent is a recorded agent of the same organization, not retired, and is never derived from the workload proof. When an execution is named it is recorded, not completed, unexpired, of that organization and that agent. Nothing is created or moved, and the event folds into no record. The default branch, taken when no other outcome's condition matched. No entity in this specification changes. It emits `mandate.workload.WorkloadAuthenticated`. A test reaches it by constructing an input that satisfies no other outcome's condition.

**`denied`** — Decided outside the input: The workload proof is malformed, unverified by its trust domain or expired; it resolves to no workload identity, a revoked one, or one in another organization than the agent; the agent is unrecorded, retired, or its principal disabled; or a named execution is unrecorded, completed, expired, or bound to another agent or organization. Each is refused alike, so a caller learns only that the pair is not admitted.. No predicate over the input reaches this branch, and saying `when: false` instead would have claimed it is unreachable, which is a different and false statement. No entity in this specification changes. It reports `mandate.workload.Denied`, carrying `reason`. It emits nothing. A test reaches it by injecting the declared fault, because no input can.

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

### `WorkloadAuthenticated`

`mandate.workload.WorkloadAuthenticated`.

It carries:

- `workload` — `mandate.core.WorkloadIdentityId`
- `runtime` — `mandate.core.PrincipalId`
- `agent` — `mandate.core.PrincipalId`
- `organization` — `mandate.core.OrganizationId`
- `execution` — `Optional<mandate.core.ExecutionId>`, which may be absent
- `authenticated_at` — `Timestamp`

Emitted by `mandate.workload.AuthenticateWorkload` on its `accepted` outcome.

Nothing in this system reacts to it.

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

Reported by `mandate.workload.AuthenticateWorkload` on its `denied` outcome.

Reported by `mandate.workload.RevokeWorkloadIdentity` on its `wrong-state` and `denied` outcomes.


---

Generated from mandate v1 · model digest `cc2b92ef62d71301fffac73193657e56997c8c3355bd5026b9a5ca7a6e331078` · contract digest `slice-sha256/2:e6347abf66eac9f8d1bfa03cddeb00bd6d309e40229ee7a42122604833cbe423`. Do not edit this file; change the specification and regenerate it with `ess generate`.
